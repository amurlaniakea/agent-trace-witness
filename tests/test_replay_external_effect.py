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

"""Feature 002 B1-capture: 5th choke point external_effect (AC-11).

Pins AC-11 (tasks.md T014): por cada external_effect el grafo emite
prov:Entity con atw:externalEffect=true + wasGeneratedBy + hashed-only
payload. Teeth: si graph.py no emite la Entity o si capture.py no hashea
el efecto, el test falla.
"""

from __future__ import annotations

import json

from agent_trace_witness.capture import (
    CHOKE_POINT_EVENT_TYPES,
    CaptureEvent,
    compute_seal_ref,
    record_external_effect,
    record_tool_call,
    run_capture,
)
from agent_trace_witness.graph import build_graph
from agent_trace_witness.seal import AgentSpec, Tool, make_seal, sign_seal
from tests.fixtures.mcp_client import MockMCPClient


def _sealed_with_delete() -> tuple[MockMCPClient, object, str]:
    spec = AgentSpec(
        system_prompt="Eres un asistente con delete_file autorizado.",
        tools=(
            Tool(name="read_file", scopes=("read:/data/**",)),
            Tool(name="delete_file", scopes=("write:/tmp/**",)),
        ),
        witness_id="witness-b1-external-effect",
    )
    sealed = sign_seal(make_seal(spec, created_at="2026-08-31T00:00:00+00:00"))
    return MockMCPClient(), sealed, compute_seal_ref(sealed)


def test_chope_point_types_now_five() -> None:
    assert "external_effect" in CHOKE_POINT_EVENT_TYPES
    assert len(CHOKE_POINT_EVENT_TYPES) == 5


def test_record_external_effect_is_hashed_and_typed() -> None:
    client, sealed, seal_ref = _sealed_with_delete()
    ev = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, seal_ref, sealed
    )
    assert isinstance(ev, CaptureEvent)
    assert ev.type == "external_effect"
    assert ev.tool == "delete_file"
    assert ev.role is None
    assert len(ev.payload_sha256) == 64
    assert ev.seal_ref == seal_ref
    assert ev.unsealed is False  # delete_file autorizado


def test_external_effect_unsealed_when_tool_not_in_seal() -> None:
    client, sealed, seal_ref = _sealed_with_delete()
    ev = record_external_effect(
        client, "rm_rf_root", {"path": "/", "op": "delete"}, seal_ref, sealed
    )
    assert ev.unsealed is True
    assert ev.tool == "rm_rf_root"


def test_external_effect_via_run_capture() -> None:
    client, sealed, seal_ref = _sealed_with_delete()
    events = run_capture(
        client,
        sealed,
        [
            ("tool_call", "delete_file", {"path": "/tmp/x"}),
            ("external_effect", "delete_file", {"path": "/tmp/x", "op": "delete"}),
        ],
    )
    assert [e.type for e in events] == ["tool_call", "external_effect"]
    assert all(e.seal_ref == seal_ref for e in events)


def test_graph_emits_externalEffect_entity_with_edge() -> None:
    client, sealed, seal_ref = _sealed_with_delete()
    call = record_tool_call(client, "delete_file", {"path": "/tmp/x"}, seal_ref, sealed)
    eff = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, seal_ref, sealed
    )
    graph = build_graph([call, eff], sealed)
    nodes = graph["@graph"]
    ext_entities = [n for n in nodes if n.get("atw:externalEffect") is True]
    assert len(ext_entities) == 1, f"expected 1 externalEffect entity, got {ext_entities}"
    ent = ext_entities[0]
    assert ent["@type"] == "prov:Entity"
    assert ent["atw:tool"] == "delete_file"
    assert len(ent["atw:payload_sha256"]) == 64
    # Debe tener wasGeneratedBy hacia la Activity del tool_call
    assert "prov:wasGeneratedBy" in ent, "external_effect entity missing wasGeneratedBy"
    gen_id = ent["prov:wasGeneratedBy"]["@id"]
    assert gen_id == "atw:activity/tool_call_1"
    # La Activity existe en el grafo
    activity_ids = {n["@id"] for n in nodes if n["@type"] == "prov:Activity"}
    assert gen_id in activity_ids
    # Payload nunca embebido (hashed-only)
    assert "/tmp/x" not in json.dumps(ent)


def test_graph_external_effect_orphan_without_prior_tool_call() -> None:
    client, sealed, _ = _sealed_with_delete()
    # Sin tool_call previo — la Entity queda huérfana (sin wasGeneratedBy)
    # pero sigue emitiéndose y marcada como externalEffect
    eff = record_external_effect(
        client,
        "delete_file",
        {"path": "/tmp/orphan", "op": "delete"},
        compute_seal_ref(sealed),
        sealed,
    )
    graph = build_graph([eff], sealed)
    ext = [n for n in graph["@graph"] if n.get("atw:externalEffect") is True]
    assert len(ext) == 1
    assert "prov:wasGeneratedBy" not in ext[0]


def test_external_effect_hash_is_canonical() -> None:
    client, sealed, seal_ref = _sealed_with_delete()
    a = record_external_effect(
        client, "delete_file", {"op": "delete", "path": "/tmp/x"}, seal_ref, sealed
    )
    b = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, seal_ref, sealed
    )
    assert a.payload_sha256 == b.payload_sha256


def test_external_effect_does_not_break_existing_tool_call_graph() -> None:
    """Un external_effect no consume el pairing LIFO de tool_response."""
    client, sealed, seal_ref = _sealed_with_delete()
    events = run_capture(
        client,
        sealed,
        [
            ("tool_call", "delete_file", {"path": "/tmp/x"}),
            ("external_effect", "delete_file", {"path": "/tmp/x", "op": "delete"}),
            ("tool_response", "delete_file", "ok"),
        ],
    )
    graph = build_graph(events, sealed)
    # tool_response debe seguir pareado al tool_call (prov:used)
    result_entities = [
        n for n in graph["@graph"] if n["@id"].startswith("atw:entity/result_tool_response")
    ]
    assert len(result_entities) == 1
    assert result_entities[0].get("prov:used", {}).get("@id") == "atw:activity/tool_call_1"
