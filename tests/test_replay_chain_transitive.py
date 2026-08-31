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

"""AC-12 laundering chain: replay debe ser transitivo (no solo 1-hop).

Este test distingue una implementación débil (solo vecinos directos)
de la requerida por HANSARD mecanismo 4: el acto se dispersa en cadena
(tool_call_1 -> result_1 -> tool_call_2 usa result_1 -> ...). Si replay
solo poda vecinos directos, tool_call_2 y sus derivados sobrevivirían
aunque causalmente dependan del tool eliminado.
"""

from __future__ import annotations

from agent_trace_witness.replay import Counterfactual, replay


def _chain_graph() -> dict:
    """Grafo sintético con cadena causal explícita:

    Agent
    Activity tool_call_1 (delete_file) --wasAssociatedWith--> Agent
      Entity args_tool_call_1 --wasGeneratedBy--> Activity_1
      Entity external_effect_1 --wasGeneratedBy--> Activity_1
      Entity result_1 --used--> Activity_1
    Activity tool_call_2 (write_file) --wasAssociatedWith--> Agent
      --used--> result_1  (laundering: usa el resultado del dañino)
      Entity args_tool_call_2 --wasGeneratedBy--> Activity_2
      Entity result_2 --used--> Activity_2
    """
    return {
        "@context": {
            "prov": "http://www.w3.org/ns/prov#",
            "atw": "https://amurlaniakea.github.io/agent-trace-witness/vocab#",
        },
        "@graph": [
            {"@id": "atw:agent/w", "@type": "prov:Agent", "atw:witness_id": "w"},
            {
                "@id": "atw:activity/tool_call_1",
                "@type": "prov:Activity",
                "prov:wasAssociatedWith": {"@id": "atw:agent/w"},
                "atw:tool": "delete_file",
                "atw:unsealed": False,
            },
            {
                "@id": "atw:entity/args_tool_call_1",
                "@type": "prov:Entity",
                "prov:wasGeneratedBy": {"@id": "atw:activity/tool_call_1"},
                "atw:tool": "delete_file",
            },
            {
                "@id": "atw:entity/external_effect_1",
                "@type": "prov:Entity",
                "prov:wasGeneratedBy": {"@id": "atw:activity/tool_call_1"},
                "atw:tool": "delete_file",
                "atw:externalEffect": True,
            },
            {
                "@id": "atw:entity/result_tool_response_1",
                "@type": "prov:Entity",
                "prov:used": {"@id": "atw:activity/tool_call_1"},
                "atw:tool": "delete_file",
            },
            # Cadena: tool_call_2 depende de result_1
            {
                "@id": "atw:activity/tool_call_2",
                "@type": "prov:Activity",
                "prov:wasAssociatedWith": {"@id": "atw:agent/w"},
                "prov:used": {"@id": "atw:entity/result_tool_response_1"},
                "atw:tool": "write_file",
                "atw:unsealed": False,
            },
            {
                "@id": "atw:entity/args_tool_call_2",
                "@type": "prov:Entity",
                "prov:wasGeneratedBy": {"@id": "atw:activity/tool_call_2"},
                "atw:tool": "write_file",
            },
            {
                "@id": "atw:entity/result_tool_response_2",
                "@type": "prov:Entity",
                "prov:used": {"@id": "atw:activity/tool_call_2"},
                "atw:tool": "write_file",
            },
        ],
    }


def test_replay_is_transitive_over_chain() -> None:
    graph = _chain_graph()
    result = replay(graph, Counterfactual(remove="atw:activity/tool_call_1"), None)
    comp_ids = {n["@id"] for n in result.compensation_set["@graph"]}

    # Vecinos directos eliminados (1-hop)
    assert "atw:activity/tool_call_1" not in comp_ids
    assert "atw:entity/args_tool_call_1" not in comp_ids
    assert "atw:entity/external_effect_1" not in comp_ids
    assert "atw:entity/result_tool_response_1" not in comp_ids

    # Transitivo: Activity_2 usó result_1, por lo tanto también se va
    assert "atw:activity/tool_call_2" not in comp_ids, (
        "replay debe ser transitivo: tool_call_2 depende de result_1"
    )
    assert "atw:entity/args_tool_call_2" not in comp_ids, (
        "args_2 depende transitivamente de Activity_1"
    )
    assert "atw:entity/result_tool_response_2" not in comp_ids

    # Solo queda el Agent
    assert comp_ids == {"atw:agent/w"}
    assert result.not_replayable == []


def test_replay_preserves_chain_when_removing_leaf() -> None:
    graph = _chain_graph()
    result = replay(graph, Counterfactual(remove="atw:activity/tool_call_2"), None)
    comp_ids = {n["@id"] for n in result.compensation_set["@graph"]}
    # Quitar la hoja no arrastra la raíz
    assert "atw:activity/tool_call_1" in comp_ids
    assert "atw:entity/result_tool_response_1" in comp_ids
    assert "atw:activity/tool_call_2" not in comp_ids
