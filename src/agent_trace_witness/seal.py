# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martínez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Witness seal: signed readiness profile (T011-T014, T019-stub).

A ``Seal`` is the body of the readiness profile emitted BEFORE the agent
runs: SHA-256 of the system prompt, the tools the agent is allowed to call
(with their scopes), the ISO-8601 UTC timestamp, and the witness identity.

A ``SealedSeal`` adds an HMAC-SHA256 signature over the canonical JSON of
the seal body. Any byte-level tampering of the body invalidates the
signature (``AC-1``).

Determinism: ``sign_seal`` and ``verify_seal`` use only ``hmac`` /
``hashlib`` / ``json`` / ``dataclasses`` from the stdlib. No randomness, no
network, no clock reading other than ``datetime.now(timezone.utc)`` when the
caller does not pass an explicit ``created_at``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .exceptions import WitnessKeyError, WitnessSealError

# Public — re-exported for callers that want to construct inputs without
# importing the internal dataclass hierarchy.
__all__ = [
    "AgentSpec",
    "Anomaly",
    "Seal",
    "SealedSeal",
    "Tool",
    "detect_unsealed_tools",
    "make_seal",
    "seal_from_dict",
    "seal_to_dict",
    "sign_seal",
    "verify_seal",
]

# Name of the environment variable that carries the HMAC key in production.
# Tests override it via ``tests/conftest.py``. See plan.md §Q1 for the open
# production key-management question.
WITNESS_KEY_ENV = "ATW_WITNESS_KEY"

# Witness timestamp env var (only honoured when ``created_at`` is not passed
# explicitly). Tests for ``AC-7`` determinism use this to freeze time.
WITNESS_TS_ENV = "ATW_WITNESS_TS"

# Algorithm tag embedded in the ``signature`` field. Kept short for JSON-LD
# readability. The actual algorithm is fixed to HMAC-SHA256 in MVP (C7).
SIGNATURE_ALGO = "hmac-sha256"

# Minimum HMAC key length, in bytes. plan.md §Seguridad recommends 32 bytes
# but accepts anything >= 16. We do NOT raise below 16 and we do NOT warn
# between 16 and 31 — callers wanting the recommended 32+ must enforce it
# themselves or wait for feature 004 (HMAC key management). This weakness
# is tracked in KNOWN_ISSUES.md §4.
HMAC_KEY_MIN_BYTES = 16
# Informational reference to plan.md §Seguridad. Not enforced at runtime.
HMAC_KEY_RECOMMENDED_BYTES = 32


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tool:
    """A tool the agent is authorised to call under the seal.

    ``scopes`` is a tuple of opaque strings (e.g. ``"read:/data/**"``). The
    witness does not interpret them — interpretation is the responsibility of
    the MCP server (or whatever enforces the policy at the choke point).
    """

    name: str
    scopes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AgentSpec:
    """The unsigned readiness profile the caller hands to ``make_seal``.

    ``system_prompt`` is the EXACT prompt that will be loaded into the agent
    (after any templating). ``witness_id`` is optional and is overridden by
    the explicit ``witness_id`` argument to ``make_seal``.
    """

    system_prompt: str
    tools: tuple[Tool, ...] = field(default_factory=tuple)
    witness_id: str = ""


@dataclass(frozen=True)
class Seal:
    """Unsigned readiness profile body. Output of ``make_seal``.

    Carries the SHA-256 of the system prompt (not the prompt itself — see
    plan.md §Seguridad: JSON-LD output is sanitised, secrets are never
    embedded). Plus the tool list, timestamp, and witness identity.
    """

    system_prompt_sha256: str
    tools: tuple[Tool, ...]
    created_at: str  # ISO-8601 UTC, e.g. "2026-08-30T14:33:00+00:00"
    witness_id: str


@dataclass(frozen=True)
class SealedSeal:
    """``Seal`` plus its HMAC-SHA256 signature.

    The signature covers the canonical JSON of every other field. Any
    modification of those fields invalidates the signature; modification of
    the signature field alone also invalidates (because the signature
    won't match the body anymore).
    """

    system_prompt_sha256: str
    tools: tuple[Tool, ...]
    created_at: str
    witness_id: str
    signature: str  # "hmac-sha256:<hex>"


@dataclass(frozen=True)
class Anomaly:
    """A discrepancy between seal and observed behaviour. Used by AC-2 and
    by ``detect_unsealed_tools``.

    ``severity`` is one of ``"error"`` (definitive policy violation, e.g.
    tool not in seal) or ``"warning"`` (suspicious but not a hard
    violation, e.g. scope mismatch — added in a later feature).
    """

    tool: str
    severity: str  # "error" | "warning"
    detail: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_utc_iso() -> str:
    """ISO-8601 UTC timestamp with explicit +00:00 offset.

    Always returns a deterministic shape (``+00:00``) so JSON canonical
    output stays stable across systems that print ``Z`` vs ``+00:00``.
    """
    return datetime.now(UTC).isoformat()


def _read_key(explicit: str | None) -> bytes:
    """Resolve the HMAC key from the explicit argument or the env var.

    Raises ``WitnessKeyError`` if the key is missing or not a valid hex
    string. Returns raw bytes (decoded from hex).
    """
    raw: str | None = explicit if explicit is not None else os.environ.get(WITNESS_KEY_ENV)
    if raw is None or raw == "":
        raise WitnessKeyError(
            f"HMAC key not provided: pass it explicitly to sign_seal/verify_seal, "
            f"or set the {WITNESS_KEY_ENV} environment variable. "
            f"See spec/features/001-mvp/plan.md §Q1 for production key management."
        )
    raw = raw.strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise WitnessKeyError(
            f"{WITNESS_KEY_ENV} must be a hex-encoded string "
            f"(e.g. 64 hex chars = 32 bytes); got {len(raw)} chars that are not valid hex."
        ) from exc
    if len(key) < HMAC_KEY_MIN_BYTES:
        raise WitnessKeyError(
            f"HMAC key too short: got {len(key)} bytes, minimum is {HMAC_KEY_MIN_BYTES} "
            f"({HMAC_KEY_RECOMMENDED_BYTES} bytes recommended)."
        )
    return key


def _seal_body_to_dict(seal: Seal | SealedSeal) -> dict:
    """Serialise the body of a Seal / SealedSeal to a JSON-safe dict.

    Tools are emitted as ``{"name": ..., "scopes": [...]}`` (lists, not
    tuples, because JSON has no tuples). The ``signature`` field is
    included when present (it MUST be present for ``SealedSeal`` and MUST
    be absent for ``Seal``).
    """
    out: dict = {
        "created_at": seal.created_at,
        "system_prompt_sha256": seal.system_prompt_sha256,
        "tools": [{"name": t.name, "scopes": list(t.scopes)} for t in seal.tools],
        "witness_id": seal.witness_id,
    }
    if isinstance(seal, SealedSeal):
        out["signature"] = seal.signature
    return out


def _canonical_bytes(payload: dict) -> bytes:
    """Canonical JSON encoding of ``payload`` for HMAC computation.

    ``sort_keys=True`` makes the key order deterministic. The separators
    ``(",", ":")`` strip all whitespace, so the hash depends only on the
    content, not on formatting choices. UTF-8 encoded.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hash_prompt(prompt: str) -> str:
    """SHA-256 hex digest of the system prompt (UTF-8)."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def make_seal(
    spec: AgentSpec,
    witness_id: str | None = None,
    created_at: str | None = None,
) -> Seal:
    """Build the unsigned ``Seal`` from an ``AgentSpec``.

    ``witness_id`` defaults to ``spec.witness_id`` if not given, then to
    ``os.environ[ATW_WITNESS_ID]`` if set, then to ``"witness-cli-local"``
    (per plan.md §Environment variables).

    ``created_at`` defaults to the current UTC time, or
    ``os.environ[ATW_WITNESS_TS]`` if set (used by determinism tests).
    """
    if not isinstance(spec, AgentSpec):  # type: ignore[arg-type]
        raise WitnessSealError(f"spec must be an AgentSpec, got {type(spec).__name__}")
    if not spec.system_prompt:
        raise WitnessSealError("spec.system_prompt must be a non-empty string")
    if not spec.tools:
        raise WitnessSealError("spec.tools must contain at least one Tool")

    wid = witness_id or spec.witness_id or os.environ.get("ATW_WITNESS_ID", "witness-cli-local")
    if not wid:
        raise WitnessSealError("witness_id could not be resolved (provide it explicitly)")

    ts = created_at or os.environ.get(WITNESS_TS_ENV) or _now_utc_iso()
    if not ts:
        raise WitnessSealError("created_at could not be resolved")

    return Seal(
        system_prompt_sha256=_hash_prompt(spec.system_prompt),
        tools=spec.tools,
        created_at=ts,
        witness_id=wid,
    )


def sign_seal(seal: Seal, key: str | None = None) -> SealedSeal:
    """Sign a ``Seal`` with HMAC-SHA256, returning a ``SealedSeal``.

    ``key`` is a hex-encoded HMAC key (>= 16 bytes, 32+ recommended). If
    ``None``, the function reads ``ATW_WITNESS_KEY`` from the environment
    (T018 wiring for ``Q1``).
    """
    if not isinstance(seal, Seal):
        raise WitnessSealError(f"seal must be a Seal, got {type(seal).__name__}")
    key_bytes = _read_key(key)
    body = _seal_body_to_dict(seal)  # no "signature" key for unsigned Seal
    mac = hmac.new(key_bytes, _canonical_bytes(body), hashlib.sha256).hexdigest()
    return SealedSeal(
        system_prompt_sha256=seal.system_prompt_sha256,
        tools=seal.tools,
        created_at=seal.created_at,
        witness_id=seal.witness_id,
        signature=f"{SIGNATURE_ALGO}:{mac}",
    )


def verify_seal(sealed: SealedSeal, key: str | None = None) -> bool:
    """Verify a ``SealedSeal``'s HMAC-SHA256 signature.

    Returns ``True`` if the signature matches the canonical body, ``False``
    otherwise (including when the signature field itself has been edited).
    Raises ``WitnessKeyError`` if the key is missing/invalid.

    Uses ``hmac.compare_digest`` to avoid timing oracles.
    """
    if not isinstance(sealed, SealedSeal):
        raise WitnessSealError(f"sealed must be a SealedSeal, got {type(sealed).__name__}")
    key_bytes = _read_key(key)
    body = _seal_body_to_dict(sealed)
    provided_signature = body.pop("signature")
    expected_mac = hmac.new(key_bytes, _canonical_bytes(body), hashlib.sha256).hexdigest()
    # The signature field is "hmac-sha256:<hex>". Compare the hex portion only
    # so that any tampering with the algorithm tag is also detected (the body
    # hasn't changed but the signature field has — we must reject).
    if ":" not in provided_signature:
        return False
    _, _, provided_hex = provided_signature.partition(":")
    return hmac.compare_digest(provided_hex, expected_mac)


def seal_to_dict(sealed: SealedSeal) -> dict:
    """Serialise a ``SealedSeal`` to a plain ``dict`` (JSON-safe)."""
    if not isinstance(sealed, SealedSeal):
        raise WitnessSealError(f"sealed must be a SealedSeal, got {type(sealed).__name__}")
    return _seal_body_to_dict(sealed)


def seal_from_dict(d: dict) -> SealedSeal:
    """Rehydrate a ``SealedSeal`` from a ``dict`` produced by ``seal_to_dict``.

    Validates that every required field is present. Does NOT verify the
    signature — callers should pass the result through ``verify_seal``.
    """
    required = {"system_prompt_sha256", "tools", "created_at", "witness_id", "signature"}
    missing = required - set(d)
    if missing:
        raise WitnessSealError(f"seal dict missing fields: {sorted(missing)}")
    try:
        tools = tuple(Tool(name=t["name"], scopes=tuple(t.get("scopes", []))) for t in d["tools"])
    except (KeyError, TypeError) as exc:
        raise WitnessSealError(f"seal dict has malformed tool entries: {exc}") from exc
    return SealedSeal(
        system_prompt_sha256=str(d["system_prompt_sha256"]),
        tools=tools,
        created_at=str(d["created_at"]),
        witness_id=str(d["witness_id"]),
        signature=str(d["signature"]),
    )


def detect_unsealed_tools(
    tools_used: Iterable[str],
    seal: Seal | SealedSeal,
) -> list[Anomaly]:
    """Return anomalies for every tool observed but NOT authorised by the seal.

    B1 keeps this simple: takes an iterable of tool names already extracted
    from the graph. B4 (``T070``) will introduce the wrapper that parses the
    PROV-DM JSON-LD graph and feeds ``tools_used`` here. The contract is
    stable: ``severity == "error"`` means a definitive policy violation.

    ``AC-2`` test pins: ``seal.tools == ["read_file", "list_dir"]``,
    ``tools_used == ["read_file", "delete_file"]`` →
    ``[Anomaly(tool="delete_file", severity="error")]``.
    """
    authorised = {t.name for t in seal.tools}
    out: list[Anomaly] = []
    seen: set[str] = set()
    for name in tools_used:
        if name in seen:
            continue
        seen.add(name)
        if name not in authorised:
            out.append(
                Anomaly(
                    tool=name,
                    severity="error",
                    detail=f"tool '{name}' was used but is not listed in the seal",
                )
            )
    return out
