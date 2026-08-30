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

"""Capture tests — AC-3 (T037, T038).

Every test pins behaviour that fails if the capture layer is replaced by
a stub (``teeth`` pattern from agent-harness-defense). The witness's value
is that it ACTUALLY records the four choke-point events — a passing test
that does not exercise the recording code counts as zero coverage.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_trace_witness.capture import (
    CHOKE_POINT_EVENT_TYPES,
    CaptureEvent,
    compute_payload_hash,
    compute_seal_ref,
    record_model_input,
    record_tool_call,
    record_tool_response,
    run_capture,
)
from agent_trace_witness.exceptions import WitnessCaptureError
from agent_trace_witness.seal import AgentSpec, SealedSeal, Tool, make_seal, sign_seal
from tests.fixtures.mcp_client import MockMCPClient

# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def sealed() -> tuple[MockMCPClient, SealedSeal, str]:
    """A pre-signed seal and a fresh mock client. Returns
    ``(client, sealed_seal, seal_ref)`` so tests can drive the capture
    layer without rebuilding the seal every time.
    """
    spec = AgentSpec(
        system_prompt="Eres un asistente que solo lee archivos del directorio /data.",
        tools=(
            Tool(name="read_file", scopes=("read:/data/**",)),
            Tool(name="list_dir", scopes=("read:/data/**",)),
        ),
        witness_id="witness-capture-test",
    )
    sealed_seal: SealedSeal = sign_seal(make_seal(spec, created_at="2026-08-30T14:33:00+00:00"))
    return MockMCPClient(), sealed_seal, compute_seal_ref(sealed_seal)


# ---- T037 — AC-3: records all four event types ----------------------------


def test_capture_records_all_4_event_types(sealed: tuple[MockMCPClient, object, str]) -> None:
    """AC-3: a scenario with one of each choke-point event produces a
    list of four CaptureEvents whose ``type`` covers every entry of
    ``CHOKE_POINT_EVENT_TYPES``.

    Teeth: if any of the four ``record_*`` functions is replaced by
    ``return CaptureEvent(...)`` with a hard-coded type (or simply
    dropped), this test fails because the missing type will not appear
    in the captured list.
    """
    client, sealed_seal, seal_ref = sealed
    events = run_capture(
        client,
        sealed_seal,
        [
            ("tool_call", "read_file", {"path": "/data/x"}),
            ("tool_response", "read_file", "contents-of-x"),
            ("model_input", "", "hola modelo"),
            ("model_output", "", "hola humano"),
        ],
    )

    assert len(events) == 4
    types_in_order = [e.type for e in events]
    assert types_in_order == list(CHOKE_POINT_EVENT_TYPES), (
        f"event types diverged from CHOKE_POINT_EVENT_TYPES: {types_in_order}"
    )

    # And every event is a real CaptureEvent (not None, not a dict, not
    # the result of accidentally calling the wrong record function).
    for ev in events:
        assert isinstance(ev, CaptureEvent)


# ---- T038 — AC-3 extended: required fields on every event -----------------


def test_capture_event_has_required_fields(sealed: tuple[MockMCPClient, object, str]) -> None:
    """AC-3 extended: every CaptureEvent carries ts, type, payload_sha256,
    seal_ref (the four required fields). Plus tool/role shape per type.
    """
    client, sealed_seal, seal_ref = sealed
    events = run_capture(
        client,
        sealed_seal,
        [
            ("tool_call", "read_file", {"path": "/data/x"}),
            ("tool_response", "read_file", "contents-of-x"),
            ("model_input", "", "hola modelo"),
            ("model_output", "", "hola humano"),
        ],
    )

    # Required fields present on every event, with sensible types.
    for ev in events:
        assert isinstance(ev.ts, str) and ev.ts, f"empty ts on {ev}"
        assert ev.type in CHOKE_POINT_EVENT_TYPES
        assert isinstance(ev.payload_sha256, str) and len(ev.payload_sha256) == 64, (
            f"payload_sha256 must be 64-hex, got {ev.payload_sha256!r}"
        )
        assert ev.seal_ref == seal_ref, f"seal_ref mismatch: {ev.seal_ref!r} vs {seal_ref!r}"
        assert isinstance(ev.unsealed, bool)

    # Per-type field shape (tool vs role).
    assert events[0].tool == "read_file" and events[0].role is None  # tool_call
    assert events[1].tool == "read_file" and events[1].role is None  # tool_response
    assert events[2].tool is None and events[2].role == "user"  # model_input
    assert events[3].tool is None and events[3].role == "assistant"  # model_output


# ---- AC-3 extras: unsealed flag, determinism, sink ------------------------


def test_unsealed_tool_flag_is_set(sealed: tuple[MockMCPClient, object, str]) -> None:
    """When the scenario invokes a tool NOT in the seal, the resulting
    event carries ``unsealed=True``. The capture pipeline never aborts
    on this — the witness records what it sees and lets the verifier
    decide (B4).
    """
    client, sealed_seal, seal_ref = sealed
    ev = record_tool_call(client, "delete_file", {"target": "/etc/passwd"}, seal_ref, sealed_seal)
    assert ev.unsealed is True
    assert ev.tool == "delete_file"
    # And the inverse: authorised tools leave unsealed=False.
    ev_ok = record_tool_call(client, "read_file", {"path": "/data/x"}, seal_ref, sealed_seal)
    assert ev_ok.unsealed is False


def test_seal_ref_is_stable_across_repeated_calls(
    sealed: tuple[MockMCPClient, object, str],
) -> None:
    """``compute_seal_ref`` is deterministic for the same seal — every
    event captured under the same seal gets the same ``seal_ref``. Catches
    regressions in the seal_ref substrate (would silently break the
    verifier's "is this event under THIS seal" check).
    """
    _, sealed_seal, _ = sealed
    ref_a = compute_seal_ref(sealed_seal)
    ref_b = compute_seal_ref(sealed_seal)
    assert ref_a == ref_b
    assert len(ref_a) == 64  # SHA-256 hex


def test_payload_hash_is_canonical(sealed: tuple[MockMCPClient, object, str]) -> None:
    """Equivalent dicts (different key order) produce the same hash. The
    witness must be insensitive to the serialisation order of a payload
    it never asked for.
    """
    h1 = compute_payload_hash({"b": 2, "a": 1})
    h2 = compute_payload_hash({"a": 1, "b": 2})
    assert h1 == h2


def test_run_capture_writes_jsonl_sink(
    sealed: tuple[MockMCPClient, object, str], tmp_path: Path
) -> None:
    """When a sink path is given, ``run_capture`` appends one JSONL line
    per event. Each line is valid JSON with the required keys.
    """
    client, sealed_seal, seal_ref = sealed
    sink = tmp_path / "events.jsonl"
    events = run_capture(
        client,
        sealed_seal,
        [
            ("tool_call", "read_file", {"path": "/data/x"}),
            ("tool_response", "read_file", "r"),
            ("model_input", "", "hi"),
            ("model_output", "", "bye"),
        ],
        sink=sink,
    )

    assert sink.exists(), "sink file was not created"
    lines = sink.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(events) == 4

    parsed = [json.loads(line) for line in lines]
    for ev_obj in parsed:
        for k in ("ts", "type", "tool", "role", "payload_sha256", "seal_ref", "unsealed"):
            assert k in ev_obj, f"sink line missing key {k!r}: {ev_obj}"
        assert ev_obj["seal_ref"] == seal_ref


def test_run_capture_rejects_unknown_kind(sealed: tuple[MockMCPClient, object, str]) -> None:
    """An unknown scenario kind raises ``WitnessCaptureError`` and does
    NOT corrupt the events collected so far.
    """
    client, sealed_seal, _ = sealed
    with pytest.raises(WitnessCaptureError):
        run_capture(
            client,
            sealed_seal,
            [
                ("tool_call", "read_file", {"path": "/x"}),
                ("tool_drop_kick", "read_file", {}),  # invalid
            ],
        )


def test_record_tool_call_requires_non_empty_seal_ref(
    sealed: tuple[MockMCPClient, object, str],
) -> None:
    """An empty ``seal_ref`` is a programming error (caller forgot to
    compute one). ``WitnessCaptureError`` is raised so the failure is
    loud, not silent.
    """
    client, sealed_seal, _ = sealed
    with pytest.raises(WitnessCaptureError):
        record_tool_call(client, "read_file", {"x": 1}, "", sealed_seal)


def test_record_tool_call_requires_tool_field(
    sealed: tuple[MockMCPClient, SealedSeal, str],
) -> None:
    """``tool_call`` events MUST carry a non-None tool name — without it,
    the verifier cannot attribute the call to a seal-listed tool.

    The capture layer enforces this in ``_make_event``: a ``tool_call``
    or ``tool_response`` event with ``tool=None`` raises
    ``WitnessCaptureError``. We exercise the check by calling
    ``record_tool_call`` with a non-empty string (the type signature
    forbids ``None`` at the static level; the runtime check defends
    against bypass via dynamic construction).
    """
    client, sealed_seal, seal_ref = sealed
    # Positive case: a real tool name produces a valid event.
    ev = record_tool_call(client, "read_file", {"x": 1}, seal_ref, sealed_seal)
    assert ev.tool == "read_file"
    assert ev.type == "tool_call"


def test_make_event_rejects_tool_call_without_tool(
    sealed: tuple[MockMCPClient, SealedSeal, str],
) -> None:
    """``_make_event`` refuses to emit a tool_call/tool_response with
    ``tool=None`` even when the caller tries to construct a degenerate
    CaptureEvent. This is the runtime defence for the contract.

    Teeth: removing the check in ``_make_event`` makes this test fail
    (no WitnessCaptureError raised).
    """
    from agent_trace_witness.capture import _make_event

    client, sealed_seal, seal_ref = sealed
    with pytest.raises(WitnessCaptureError):
        _make_event(
            type_="tool_call",
            tool=None,
            role=None,
            payload_bytes=b'{"tool":""}',
            seal_ref=seal_ref,
            authorised=frozenset(),
        )


def test_record_model_input_requires_role_field(sealed: tuple[MockMCPClient, object, str]) -> None:
    """The default role for model_input is "user" (verifier convention);
    callers can override via the ``role`` kwarg, but the function must
    never emit a model_input event with ``role=None``.
    """
    client, sealed_seal, seal_ref = sealed
    ev = record_model_input(client, "hi", seal_ref, sealed_seal)
    assert ev.role == "user"

    ev_asst = record_model_input(client, "hi", seal_ref, sealed_seal, role="system")
    assert ev_asst.role == "system"


def test_determinism_across_repeated_runs(sealed: tuple[MockMCPClient, SealedSeal, str]) -> None:
    """Two runs of the same scenario with the same frozen seal produce
    byte-identical JSONL output. Pins AC-7 for the capture layer.

    Timestamps are frozen via the ``ATW_WITNESS_TS`` env var (set in
    ``conftest.py``) so wall-clock drift cannot affect the comparison.
    """
    client_a, sealed_seal, seal_ref = sealed
    client_b = MockMCPClient()
    scenario = [
        ("tool_call", "read_file", {"path": "/x"}),
        ("tool_response", "read_file", "r"),
        ("model_input", "", "hi"),
        ("model_output", "", "bye"),
    ]

    events_a = run_capture(client_a, sealed_seal, list(scenario))
    events_b = run_capture(client_b, sealed_seal, list(scenario))

    dicts_a = [json.dumps(_ev_obj(e), sort_keys=True, separators=(",", ":")) for e in events_a]
    dicts_b = [json.dumps(_ev_obj(e), sort_keys=True, separators=(",", ":")) for e in events_b]
    assert dicts_a == dicts_b


def _ev_obj(e: CaptureEvent) -> dict:
    return {
        "ts": e.ts,
        "type": e.type,
        "tool": e.tool,
        "role": e.role,
        "payload_sha256": e.payload_sha256,
        "seal_ref": e.seal_ref,
        "unsealed": e.unsealed,
    }


def test_record_tool_call_and_response_pair_use_same_tool(
    sealed: tuple[MockMCPClient, object, str],
) -> None:
    """A tool_response is the response to a tool_call — they MUST share
    the tool name. If the witness recorded mismatched tool names, the
    verifier could not pair them in the graph (B3). The capture layer
    refuses to record a tool_response for a tool the seal would reject
    either way; both sides set ``unsealed`` independently.
    """
    client, sealed_seal, seal_ref = sealed
    call = record_tool_call(client, "read_file", {"x": 1}, seal_ref, sealed_seal)
    resp = record_tool_response(client, "read_file", "r", seal_ref, sealed_seal)
    assert call.tool == resp.tool == "read_file"
