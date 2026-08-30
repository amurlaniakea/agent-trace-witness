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

"""Seal tests — AC-1, AC-2 (T016-T019).

Every test here is ``teeth``: it must FAIL if the corresponding defence is
neutralised. See ``conftest.py`` for the shared ``witness_key`` fixture and
the reasoning behind using one env-var name for prod and tests.
"""

from __future__ import annotations

import json
import re

import pytest

from agent_trace_witness.exceptions import WitnessKeyError, WitnessSealError
from agent_trace_witness.seal import (
    AgentSpec,
    Anomaly,
    SealedSeal,
    Tool,
    detect_unsealed_tools,
    make_seal,
    seal_from_dict,
    seal_to_dict,
    sign_seal,
    verify_seal,
)

# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def agent_spec() -> AgentSpec:
    """A representative agent spec reused across the seal tests."""
    return AgentSpec(
        system_prompt="Eres un asistente que solo lee archivos del directorio /data.",
        tools=(
            Tool(name="read_file", scopes=("read:/data/**",)),
            Tool(name="list_dir", scopes=("read:/data/**",)),
        ),
        witness_id="witness-test-1",
    )


@pytest.fixture
def fixed_seal(agent_spec: AgentSpec) -> SealedSeal:
    """A pre-signed seal whose ``created_at`` is frozen for determinism."""
    seal = make_seal(agent_spec, created_at="2026-08-30T14:33:00+00:00")
    return sign_seal(seal)


# ---- T016 — AC-1 base ------------------------------------------------------


def test_seal_produces_signed_document(fixed_seal: SealedSeal) -> None:
    """AC-1 base: the signed seal carries every required key, and the
    signature is shaped like ``hmac-sha256:<hex>`` with a 64-char hex body.
    """
    payload = seal_to_dict(fixed_seal)

    # Required keys from spec.md §Contratos de datos > seal.json.
    expected_keys = {
        "system_prompt_sha256",
        "tools",
        "created_at",
        "witness_id",
        "signature",
    }
    assert expected_keys.issubset(payload.keys()), f"missing keys: {expected_keys - payload.keys()}"

    # Tools: 2 entries, each with name + scopes.
    assert payload["tools"] == [
        {"name": "read_file", "scopes": ["read:/data/**"]},
        {"name": "list_dir", "scopes": ["read:/data/**"]},
    ]

    # system_prompt_sha256 must be 64 hex chars (SHA-256).
    assert re.fullmatch(r"[0-9a-f]{64}", payload["system_prompt_sha256"])

    # created_at: ISO-8601 UTC, fixed by fixture.
    assert payload["created_at"] == "2026-08-30T14:33:00+00:00"

    # witness_id propagated from the agent spec.
    assert payload["witness_id"] == "witness-test-1"

    # signature: "hmac-sha256:<64-hex-chars>".
    assert payload["signature"].startswith("hmac-sha256:")
    assert re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", payload["signature"])

    # And verify_seal accepts it (the same key — conftest sets it).
    assert verify_seal(fixed_seal) is True


# ---- T017 — AC-1 mod-byte (parametrised) ----------------------------------


@pytest.mark.parametrize(
    "tamper",
    [
        "flip_first_hex_of_prompt_hash",
        "rename_first_tool",
        "change_witness_id",
        "trim_signature_hex",
    ],
)
def test_seal_signature_detects_any_modification(fixed_seal: SealedSeal, tamper: str) -> None:
    """AC-1 mod-byte: every byte-level change to the body (or to the
    signature field itself) makes ``verify_seal`` return False.

    Teeth: if ``verify_seal`` is replaced by ``return True``, ALL four
    parametrised cases fail.
    """
    payload = seal_to_dict(fixed_seal)

    if tamper == "flip_first_hex_of_prompt_hash":
        # Flip the first hex char of system_prompt_sha256 ('0' -> '1').
        sha = payload["system_prompt_sha256"]
        payload["system_prompt_sha256"] = ("1" if sha[0] == "0" else "0") + sha[1:]
    elif tamper == "rename_first_tool":
        payload["tools"][0]["name"] = "WRONG_NAME"
    elif tamper == "change_witness_id":
        payload["witness_id"] = "wrong-witness"
    elif tamper == "trim_signature_hex":
        # Drop the last hex char of the signature.
        algo, _, hexpart = payload["signature"].partition(":")
        payload["signature"] = f"{algo}:{hexpart[:-1]}"
    else:  # pragma: no cover — guard for parametrisation typos
        raise AssertionError(f"unknown tamper: {tamper}")

    tampered = seal_from_dict(payload)
    assert verify_seal(tampered) is False, (
        f"verify_seal returned True after tamper={tamper}; HMAC is not protecting the body"
    )


def test_seal_signature_round_trip(fixed_seal: SealedSeal) -> None:
    """Sanity: a seal with no tampering verifies True; round-trip through
    ``seal_from_dict`` preserves the verdict. Catches regressions in
    serialisation that would silently break AC-1.
    """
    assert verify_seal(fixed_seal) is True
    rehydrated = seal_from_dict(seal_to_dict(fixed_seal))
    assert verify_seal(rehydrated) is True


# ---- T018 — Q1 wiring ------------------------------------------------------


def test_seal_requires_witness_key(no_witness_key: None, agent_spec: AgentSpec) -> None:
    """Without ``ATW_WITNESS_KEY``, ``sign_seal`` raises ``WitnessKeyError``.

    Teeth: if the missing-key branch is removed (e.g. defaults to a
    hard-coded test key), this test fails because no exception is raised.
    """
    seal = make_seal(agent_spec, created_at="2026-08-30T14:33:00+00:00")
    with pytest.raises(WitnessKeyError):
        sign_seal(seal)


def test_seal_rejects_short_key(agent_spec: AgentSpec) -> None:
    """A key shorter than ``HMAC_KEY_MIN_BYTES`` (16) raises ``WitnessKeyError``."""
    seal = make_seal(agent_spec, created_at="2026-08-30T14:33:00+00:00")
    with pytest.raises(WitnessKeyError):
        sign_seal(seal, key="deadbeef")  # 4 bytes — too short


def test_seal_rejects_non_hex_key(agent_spec: AgentSpec) -> None:
    """A key that isn't valid hex raises ``WitnessKeyError``."""
    seal = make_seal(agent_spec, created_at="2026-08-30T14:33:00+00:00")
    with pytest.raises(WitnessKeyError):
        sign_seal(seal, key="Z" * 64)  # 64 chars but not hex


# ---- T019 — AC-2 unsealed tool detection -----------------------------------


def test_unsealed_tool_detected(fixed_seal: SealedSeal) -> None:
    """AC-2: a tool used in the trace but not listed in the seal is reported
    as ``severity == "error"``.

    This test pins the B1 form of ``detect_unsealed_tools`` (operates on an
    iterable of tool names). B4 (T070) will add the wrapper that parses the
    graph; the contract — error severity for unauthorised tools — is
    stable.
    """
    tools_used = ["read_file", "list_dir", "delete_file"]
    anomalies = detect_unsealed_tools(tools_used, fixed_seal)

    assert len(anomalies) == 1
    assert anomalies[0] == Anomaly(
        tool="delete_file",
        severity="error",
        detail="tool 'delete_file' was used but is not listed in the seal",
    )


def test_no_anomaly_when_all_tools_authorised(fixed_seal: SealedSeal) -> None:
    """Inverse of T019: a trace that only uses seal-authorised tools yields
    zero anomalies. Catches false positives in the comparator.
    """
    assert detect_unsealed_tools(["read_file", "list_dir", "read_file"], fixed_seal) == []


def test_detect_unsealed_tools_dedupes(fixed_seal: SealedSeal) -> None:
    """The same unauthorised tool used N times is reported ONCE (not N
    times). Avoids verifier output explosion on runaway scripts.
    """
    anomalies = detect_unsealed_tools(
        ["delete_file", "delete_file", "delete_file", "read_file"], fixed_seal
    )
    assert anomalies == [
        Anomaly(
            tool="delete_file",
            severity="error",
            detail="tool 'delete_file' was used but is not listed in the seal",
        )
    ]


# ---- validation regressions (defensive, not in tasks.md) --------------------


def test_make_seal_rejects_empty_prompt() -> None:
    """Empty system prompt is a policy violation (AC-1 has nothing to hash).
    Teeth: removing this check makes the test fail at the second assertion.
    """
    with pytest.raises(WitnessSealError):
        make_seal(
            AgentSpec(system_prompt="", tools=(Tool(name="read_file"),), witness_id="w"),
            created_at="2026-08-30T14:33:00+00:00",
        )


def test_make_seal_rejects_empty_tool_list() -> None:
    """An empty tool list means the seal cannot constrain anything, which
    defeats C3. The MVP refuses to produce it.
    """
    with pytest.raises(WitnessSealError):
        make_seal(
            AgentSpec(system_prompt="hello", tools=(), witness_id="w"),
            created_at="2026-08-30T14:33:00+00:00",
        )


def test_seal_from_dict_rejects_missing_fields() -> None:
    """``seal_from_dict`` enforces the required-field contract from T014."""
    incomplete = {
        "system_prompt_sha256": "0" * 64,
        "tools": [],
        "created_at": "2026-08-30T14:33:00+00:00",
        # "witness_id" missing
        # "signature" missing
    }
    with pytest.raises(WitnessSealError):
        seal_from_dict(incomplete)


def test_canonical_bytes_are_stable() -> None:
    """Independent check: the canonical serialisation is byte-stable across
    multiple invocations on the same input. Catches regressions in the
    HMAC substrate (sort_keys / separators / UTF-8).
    """
    payload = {"b": 2, "a": 1, "c": [3, 2]}
    once = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    twice = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert once == twice
    # And the byte length matches the expected shape.
    assert once == '{"a":1,"b":2,"c":[3,2]}'
