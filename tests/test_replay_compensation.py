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

"""AC-12 compensation_set: excluye efecto del tool eliminado (T023)."""

from __future__ import annotations

from agent_trace_witness.capture import (
    compute_seal_ref,
    record_external_effect,
    record_tool_call,
    record_tool_response,
)
from agent_trace_witness.graph import build_graph
from agent_trace_witness.replay import Counterfactual, replay
from agent_trace_witness.seal import AgentSpec, Tool, make_seal, sign_seal
from tests.fixtures.mcp_client import MockMCPClient


def _hansard_like_graph() -> tuple[dict, object, Counterfactual]:
    """Fixture HANSARD-like 6 eventos: delete_file dañino + 2 benignos.

    - tool_call delete_file (/tmp/x) -> external_effect delete -> response
    - tool_call read_file (/tmp/y) -> response
    - tool_call read_file (/tmp/z) -> response
    compensation_set al eliminar tool_call_1 debe quitar el external_effect
    de delete_file pero conservar los 2 benignos.
    """
    spec = AgentSpec(
        system_prompt="hansard fixture",
        tools=(
            Tool(name="delete_file", scopes=("write:/tmp/**",)),
            Tool(name="read_file", scopes=("read:/tmp/**",)),
        ),
        witness_id="witness-hansard-replay",
    )
    sealed = sign_seal(make_seal(spec, created_at="2026-08-31T00:00:00+00:00"))
    client = MockMCPClient()
    ref = compute_seal_ref(sealed)
    c1 = record_tool_call(client, "delete_file", {"path": "/tmp/x"}, ref, sealed)
    e1 = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, ref, sealed
    )
    r1 = record_tool_response(client, "delete_file", "ok", ref, sealed)
    c2 = record_tool_call(client, "read_file", {"path": "/tmp/y"}, ref, sealed)
    r2 = record_tool_response(client, "read_file", "content-y", ref, sealed)
    c3 = record_tool_call(client, "read_file", {"path": "/tmp/z"}, ref, sealed)
    r3 = record_tool_response(client, "read_file", "content-z", ref, sealed)
    graph = build_graph([c1, e1, r1, c2, r2, c3, r3], sealed)
    # delete_file es tool_call_1 (primer tool_call)
    cf = Counterfactual(remove="atw:activity/tool_call_1")
    return graph, sealed, cf


def test_replay_compensation_excludes_removed_tool() -> None:
    graph, sealed, cf = _hansard_like_graph()
    result = replay(graph, cf, sealed)

    assert result.not_replayable == []
    comp_ids = {n["@id"] for n in result.compensation_set["@graph"]}

    # Eliminado: Activity + args + external_effect + result del delete_file
    assert "atw:activity/tool_call_1" not in comp_ids
    assert "atw:entity/args_tool_call_1" not in comp_ids
    assert "atw:entity/external_effect_1" not in comp_ids
    assert "atw:entity/result_tool_response_1" not in comp_ids

    # Conservados: los 2 benignos (tool_call_2/3 y sus entities)
    assert "atw:activity/tool_call_2" in comp_ids
    assert "atw:activity/tool_call_3" in comp_ids
    assert "atw:entity/args_tool_call_2" in comp_ids
    assert "atw:entity/args_tool_call_3" in comp_ids

    # synergy_residual debe ser False (no queda externalEffect tras quitar el dañino)
    assert result.synergy_residual is False


def test_replay_preserves_benign_when_removing_benign() -> None:
    graph, sealed, _ = _hansard_like_graph()
    cf_benign = Counterfactual(remove="atw:activity/tool_call_2")
    result = replay(graph, cf_benign, sealed)
    comp_ids = {n["@id"] for n in result.compensation_set["@graph"]}
    # Quitado el benigno 2, pero el dañino permanece
    assert "atw:activity/tool_call_2" not in comp_ids
    assert "atw:activity/tool_call_1" in comp_ids
    assert "atw:entity/external_effect_1" in comp_ids
    # synergy_residual True porque aún queda externalEffect dañino
    assert result.synergy_residual is True


def test_replay_not_replayable_for_unknown_id() -> None:
    graph, sealed, _ = _hansard_like_graph()
    cf_bad = Counterfactual(remove="atw:activity/tool_call_99")
    result = replay(graph, cf_bad, sealed)
    assert result.not_replayable == ["atw:activity/tool_call_99"]
    # compensation_set = grafo original intacto
    assert len(result.compensation_set["@graph"]) == len(graph["@graph"])


def test_replay_dict_counterfactual_also_works() -> None:
    graph, sealed, _ = _hansard_like_graph()
    result = replay(graph, {"remove": "atw:activity/tool_call_1"}, sealed)
    comp_ids = {n["@id"] for n in result.compensation_set["@graph"]}
    assert "atw:activity/tool_call_1" not in comp_ids
