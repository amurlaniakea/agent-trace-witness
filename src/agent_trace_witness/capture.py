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

"""Witness capture: choke-point event recording (T031-T036, T011-T012).

The capture layer records events at the five choke points the witness is
allowed to observe (per C1, this module imports MCP-client abstractions
only — it does NOT import or instrument agent code):

- (a) tool_call  — outgoing call to the MCP server
- (b) tool_response — incoming response from the MCP server
- (c) model_input  — message to the model
- (d) model_output — message from the model
- (e) external_effect — side-effect of a tool (file write, network
  request) observed via MCP response inspection / optional FS hook
  (feature 002, AC-11). 001 deferred this; 002 implements it.

Determinism (AC-7): no RNG, no wall clock unless ``ATW_WITNESS_TS`` is
unset (tests set it via ``conftest.py`` so the suite is fully frozen).
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from .exceptions import WitnessCaptureError
from .seal import SealedSeal, _canonical_bytes, _now_utc_iso

if TYPE_CHECKING:
    pass  # placeholder; kept for symmetry with seal.py

# Public re-exports for callers.
__all__ = [
    "CHOKE_POINT_EVENT_TYPES",
    "CaptureEvent",
    "EventTuple",
    "MCPClient",
    "compute_payload_hash",
    "compute_seal_ref",
    "record_external_effect",
    "record_model_input",
    "record_model_output",
    "record_tool_call",
    "record_tool_response",
    "run_capture",
]

# Name of the env var that freezes timestamps across the suite (AC-7).
WITNESS_TS_ENV = "ATW_WITNESS_TS"

# Frozen tuple of the five event types (feature 002 adds external_effect).
# Mirrors tests/fixtures/mcp_client.py so production code and the fixture
# cannot drift silently. T011 decision: Option A — external_effect is a
# distinct type (not a subtipo of tool_response) so the 5 choke points
# stay explicit (a-e) and graph.py can emit a dedicated atw:externalEffect
# node without inferring it from tool_response. Trade-off: callers that
# only inspect tool_response now also need to handle external_effect;
# documented here and in graph.py.
CHOKE_POINT_EVENT_TYPES: tuple[str, ...] = (
    "tool_call",
    "tool_response",
    "model_input",
    "model_output",
    "external_effect",
)

EventType = Literal["tool_call", "tool_response", "model_input", "model_output", "external_effect"]


# ---------------------------------------------------------------------------
# EventTuple — the (ts, type, payload) shape every MCPClient must return.
# Defined here so the MCPClient Protocol can reference it without the
# production module importing the test fixture. The fixture re-uses
# this dataclass via ``from agent_trace_witness.capture import EventTuple``.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventTuple:
    """A ``(timestamp, type, payload)`` tuple, per tasks.md T030.

    The witness serialises these to JSONL when a sink is provided. The
    payload is kept as ``bytes`` so the witness can hash it without
    losing information (no JSON re-encoding round-trip).
    """

    timestamp: str
    type: str  # one of CHOKE_POINT_EVENT_TYPES
    payload: bytes


# ---------------------------------------------------------------------------
# MCPClient protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class MCPClient(Protocol):
    """Minimal contract every MCP client (mock or real) must satisfy.

    The five record_* methods return an ``EventTuple`` so the caller
    (the mock's own log, a real client's stream) can keep its own
    bookkeeping; the witness does not inspect the return value — it
    builds ``CaptureEvent`` from its own arguments. This keeps the
    witness's view independent of the client's state.

    Feature 002 adds ``record_external_effect`` for the 5th choke point.
    """

    def record_tool_call(
        self, tool: str, args: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_tool_response(
        self, tool: str, result: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_model_input(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_model_output(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_external_effect(
        self, tool: str, effect: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def events(self) -> Iterable[EventTuple]: ...


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureEvent:
    """One witness-observed event at a choke point (T031).

    ``payload_sha256`` is the SHA-256 hex of the ORIGINAL payload bytes
    (not of the canonical JSON of this dataclass). The payload itself is
    NEVER embedded — only its hash travels with the event, per plan
    §Seguridad: "JSON-LD output se sanitiza; los payloads de tool call/
    response se hashean, NO se embeben".

    ``seal_ref`` is a string identifying the seal under which the event
    was captured (currently ``compute_seal_ref(sealed_seal)``). The
    witness refuses to record an event with an empty ``seal_ref`` (AC-3
    extended: ``seal_ref`` is required, not optional).

    ``unsealed`` is True when the event references a tool that was NOT
    in the seal's authorised list (T033). The capture pipeline never
    aborts on this; it records the flag and lets the verifier (B4)
    decide.
    """

    ts: str  # ISO-8601 UTC, deterministic shape (+00:00).
    type: EventType
    tool: str | None
    role: str | None
    payload_sha256: str
    seal_ref: str
    unsealed: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_or_frozen_ts(explicit: str | None) -> str:
    """ISO-8601 UTC timestamp. Frozen by ``ATW_WITNESS_TS`` if set."""
    if explicit:
        return explicit
    env = os.environ.get(WITNESS_TS_ENV)
    if env:
        return env
    return _now_utc_iso()


def _coerce_to_bytes(value: bytes | str | dict) -> bytes:
    """Coerce a payload value to UTF-8 bytes for hashing.

    ``dict`` is serialised with canonical JSON so the hash is stable
    across equivalent payloads with different key orderings.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, dict):
        return _canonical_bytes(value)
    raise WitnessCaptureError(f"payload must be bytes | str | dict, got {type(value).__name__}")


def _coerce_to_obj(value: bytes | str | dict) -> dict | str:
    """For sending the payload to the client: keep ``str`` and ``dict`` as
    is; serialise ``bytes`` as hex (so the JSON encoder can handle it).

    Mirrors the fixture's ``_coerce`` so client-side payloads look the
    same regardless of whether they came from a real client or the mock.
    """
    if isinstance(value, bytes):
        return value.hex()
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_payload_hash(payload: bytes | str | dict) -> str:
    """SHA-256 hex of a payload (T032).

    Bytes are hashed directly. Strings are UTF-8 encoded. Dicts are
    serialised with the canonical JSON encoder (sort_keys=True,
    separators=(",", ":")) so equivalent dicts always produce the same
    hash.
    """
    return _hash_bytes(_coerce_to_bytes(payload))


def _hash_bytes(b: bytes) -> str:
    """SHA-256 hex of already-bytes payload (extracted for reuse)."""
    import hashlib

    return hashlib.sha256(b).hexdigest()


def compute_seal_ref(sealed: SealedSeal) -> str:
    """Stable identifier for a sealed seal: SHA-256 of its canonical body.

    The seal_ref travels with every CaptureEvent so the verifier can
    confirm "this event was captured under THIS seal". Any change to the
    seal body (which would invalidate the signature) also changes the
    ref — consistent with AC-1's "any byte of the body invalidates the
    signature" property.
    """
    body = {
        "created_at": sealed.created_at,
        "system_prompt_sha256": sealed.system_prompt_sha256,
        "tools": [{"name": t.name, "scopes": list(t.scopes)} for t in sealed.tools],
        "witness_id": sealed.witness_id,
        "signature": sealed.signature,
    }
    return _hash_bytes(_canonical_bytes(body))


def _authorised_tools(seal: SealedSeal) -> frozenset[str]:
    return frozenset(t.name for t in seal.tools)


def _make_event(
    *,
    type_: EventType,
    tool: str | None,
    role: str | None,
    payload_bytes: bytes,
    seal_ref: str,
    authorised: frozenset[str],
    ts: str | None = None,
) -> CaptureEvent:
    if not seal_ref:
        raise WitnessCaptureError("seal_ref must be a non-empty string (AC-3)")
    if type_ not in CHOKE_POINT_EVENT_TYPES:
        raise WitnessCaptureError(
            f"event type must be one of {CHOKE_POINT_EVENT_TYPES}, got {type_!r}"
        )
    if (type_ in ("tool_call", "tool_response", "external_effect")) and (tool is None):
        raise WitnessCaptureError(f"event type {type_!r} requires a non-None tool")
    if (type_ in ("model_input", "model_output")) and (role is None):
        raise WitnessCaptureError(f"event type {type_!r} requires a non-None role")

    unsealed = tool is not None and tool not in authorised
    return CaptureEvent(
        ts=_now_or_frozen_ts(ts),
        type=type_,
        tool=tool,
        role=role,
        payload_sha256=_hash_bytes(payload_bytes),
        seal_ref=seal_ref,
        unsealed=unsealed,
    )


def record_tool_call(
    client: MCPClient,
    tool: str,
    args: bytes | str | dict,
    seal_ref: str,
    seal: SealedSeal,
    *,
    ts: str | None = None,
) -> CaptureEvent:
    """Record a ``tool_call`` event (T033).

    Hashes ``args`` (never embeds them — see ``CaptureEvent`` docstring).
    If ``tool`` is not in ``seal.tools``, the resulting event carries
    ``unsealed=True`` so the verifier can flag it (B4). The capture
    pipeline never aborts; the witness records what it sees.
    """
    payload = _coerce_to_obj(args)
    # Notify the client (mock or real) so its own log captures the event
    # tuple. The witness does not depend on the client's cooperation to
    # produce the CaptureEvent — that is computed locally from the
    # arguments.
    client.record_tool_call(tool=tool, args=payload, ts=_now_or_frozen_ts(ts))
    payload_bytes = _canonical_bytes({"tool": tool, "args": _coerce_to_obj(args)})
    return _make_event(
        type_="tool_call",
        tool=tool,
        role=None,
        payload_bytes=payload_bytes,
        seal_ref=seal_ref,
        authorised=_authorised_tools(seal),
        ts=ts,
    )


def record_tool_response(
    client: MCPClient,
    tool: str,
    result: bytes | str | dict,
    seal_ref: str,
    seal: SealedSeal,
    *,
    ts: str | None = None,
) -> CaptureEvent:
    """Record a ``tool_response`` event (T034)."""
    payload = _coerce_to_obj(result)
    client.record_tool_response(tool=tool, result=payload, ts=_now_or_frozen_ts(ts))
    payload_bytes = _canonical_bytes({"tool": tool, "result": _coerce_to_obj(result)})
    return _make_event(
        type_="tool_response",
        tool=tool,
        role=None,
        payload_bytes=payload_bytes,
        seal_ref=seal_ref,
        authorised=_authorised_tools(seal),
        ts=ts,
    )


def record_model_input(
    client: MCPClient,
    content: bytes | str | dict,
    seal_ref: str,
    seal: SealedSeal,
    *,
    role: str = "user",
    ts: str | None = None,
) -> CaptureEvent:
    """Record a ``model_input`` event (T035)."""
    client.record_model_input(content=_coerce_to_obj(content), ts=_now_or_frozen_ts(ts))
    payload_bytes = _canonical_bytes({"role": role, "content": _coerce_to_obj(content)})
    return _make_event(
        type_="model_input",
        tool=None,
        role=role,
        payload_bytes=payload_bytes,
        seal_ref=seal_ref,
        authorised=_authorised_tools(seal),
        ts=ts,
    )


def record_model_output(
    client: MCPClient,
    content: bytes | str | dict,
    seal_ref: str,
    seal: SealedSeal,
    *,
    role: str = "assistant",
    ts: str | None = None,
) -> CaptureEvent:
    """Record a ``model_output`` event (T035)."""
    client.record_model_output(content=_coerce_to_obj(content), ts=_now_or_frozen_ts(ts))
    payload_bytes = _canonical_bytes({"role": role, "content": _coerce_to_obj(content)})
    return _make_event(
        type_="model_output",
        tool=None,
        role=role,
        payload_bytes=payload_bytes,
        seal_ref=seal_ref,
        authorised=_authorised_tools(seal),
        ts=ts,
    )


def record_external_effect(
    client: MCPClient,
    tool: str,
    effect: bytes | str | dict,
    seal_ref: str,
    seal: SealedSeal,
    *,
    ts: str | None = None,
) -> CaptureEvent:
    """Record an ``external_effect`` event (T012, 5th choke point).

    ``effect`` is the side-effect description (e.g. ``{"path": "/tmp/x",
    "op": "delete"}``). Like the other record_* helpers, the payload is
    hashed (never embedded) and ``unsealed`` is computed from ``seal``.
    The client is notified via ``record_external_effect`` so a real
    adapter or mock can keep its own log.
    """
    # Notify client — keep parity with the other record_* helpers.
    # Use hasattr check (not try/except AttributeError) so a real client
    # bug inside record_external_effect propagates instead of being
    # swallowed silently (C5 honestidad de alcance).
    if hasattr(client, "record_external_effect"):
        client.record_external_effect(  # type: ignore[attr-defined]
            tool=tool, effect=_coerce_to_obj(effect), ts=_now_or_frozen_ts(ts)
        )
    payload_bytes = _canonical_bytes({"tool": tool, "effect": _coerce_to_obj(effect)})
    return _make_event(
        type_="external_effect",
        tool=tool,
        role=None,
        payload_bytes=payload_bytes,
        seal_ref=seal_ref,
        authorised=_authorised_tools(seal),
        ts=ts,
    )


# ---------------------------------------------------------------------------
# run_capture (T036)
# ---------------------------------------------------------------------------


def run_capture(
    client: MCPClient,
    seal: SealedSeal,
    scenario: Iterable[
        tuple[
            str,
            str,
            bytes | str | dict,
        ]
        | tuple[str, str, bytes | str | dict, dict]
    ],
    *,
    sink: Path | None = None,
) -> list[CaptureEvent]:
    """Drive a scenario through the witness and return the events (T036).

    ``scenario`` is an iterable of tuples. Each tuple is either:

    - ``("tool_call",    tool_name, args)``
    - ``("tool_response", tool_name, result)``
    - ``("model_input",  "",        content[, {"role": "user"}])``
    - ``("model_output", "",        content[, {"role": "assistant"}])``

    The second element is the tool name (ignored for model_* events;
    pass ``""``). The optional 4th element is a kwargs dict (currently
    just ``role`` for model events).

    If ``sink`` is provided, every event is appended as one JSONL line
    to that file (atomic per line; no buffering across calls).

    Raises ``WitnessCaptureError`` if any tuple has an unknown type. The
    capture continues past errors PER TUPLE if ``scenario`` is a
    generator; if you want all-or-nothing, wrap the iterable in a list
    and check the result.
    """
    seal_ref = compute_seal_ref(seal)
    out: list[CaptureEvent] = []

    def _events_to_jsonl() -> Iterator[str]:
        for ev in out:
            yield _event_to_jsonl(ev) + "\n"

    # NOTE: We open the sink lazily so an empty scenario does not create
    # an empty file. For an empty scenario with no sink, this is a no-op.
    sink_fh = None
    try:
        for raw in scenario:
            kind = raw[0]
            tool = raw[1]
            payload = raw[2]
            extra = raw[3] if len(raw) > 3 else {}
            role = extra.get("role")  # may be None; record_* picks defaults

            if kind == "tool_call":
                ev = record_tool_call(client, tool, payload, seal_ref, seal)
            elif kind == "tool_response":
                ev = record_tool_response(client, tool, payload, seal_ref, seal)
            elif kind == "model_input":
                kwargs = {"ts": None, "role": role or "user"}
                ev = record_model_input(client, payload, seal_ref, seal, **kwargs)
            elif kind == "model_output":
                kwargs = {"ts": None, "role": role or "assistant"}
                ev = record_model_output(client, payload, seal_ref, seal, **kwargs)
            elif kind == "external_effect":
                ts_override = extra.get("ts")
                ev = record_external_effect(client, tool, payload, seal_ref, seal, ts=ts_override)
            else:
                raise WitnessCaptureError(f"unknown scenario kind: {kind!r}")

            out.append(ev)

            if sink is not None:
                if sink_fh is None:
                    sink.parent.mkdir(parents=True, exist_ok=True)
                    sink_fh = sink.open("a", encoding="utf-8")
                sink_fh.write(_event_to_jsonl(ev) + "\n")
                sink_fh.flush()
    finally:
        if sink_fh is not None:
            sink_fh.close()

    return out


def _event_to_jsonl(ev: CaptureEvent) -> str:
    """Serialise one CaptureEvent as a single JSON line (no trailing \\n)."""
    return json.dumps(
        {
            "ts": ev.ts,
            "type": ev.type,
            "tool": ev.tool,
            "role": ev.role,
            "payload_sha256": ev.payload_sha256,
            "seal_ref": ev.seal_ref,
            "unsealed": ev.unsealed,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
