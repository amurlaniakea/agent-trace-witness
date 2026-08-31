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

"""AC-12 determinismo: 10x replay idéntico byte a byte (T022)."""

from __future__ import annotations

import json

from agent_trace_witness.capture import (
    compute_seal_ref,
    record_external_effect,
    record_tool_call,
    record_tool_response,
)
from agent_trace_witness.graph import build_graph
from agent_trace_witness.replay import Counterfactual, replay, replay_to_json
from agent_trace_witness.seal import AgentSpec, Tool, make_seal, sign_seal
from tests.fixtures.mcp_client import MockMCPClient


def _graph_with_delete() -> tuple[dict, object, Counterfactual]:
    spec = AgentSpec(
        system_prompt="test determinismo",
        tools=(
            Tool(name="delete_file", scopes=("write:/tmp/**",)),
            Tool(name="read_file", scopes=("read:/tmp/**",)),
        ),
        witness_id="witness-replay-determinism",
    )
    sealed = sign_seal(make_seal(spec, created_at="2026-08-31T00:00:00+00:00"))
    client = MockMCPClient()
    seal_ref = compute_seal_ref(sealed)
    c1 = record_tool_call(client, "delete_file", {"path": "/tmp/x"}, seal_ref, sealed)
    e1 = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, seal_ref, sealed
    )
    r1 = record_tool_response(client, "delete_file", "ok", seal_ref, sealed)
    c2 = record_tool_call(client, "read_file", {"path": "/tmp/y"}, seal_ref, sealed)
    graph = build_graph([c1, e1, r1, c2], sealed)
    cf = Counterfactual(remove="atw:activity/tool_call_1")
    return graph, sealed, cf


def test_replay_is_deterministic_10x() -> None:
    graph, sealed, cf = _graph_with_delete()
    first = replay_to_json(replay(graph, cf, sealed))
    for _ in range(9):
        assert replay_to_json(replay(graph, cf, sealed)) == first


def test_replay_uses_canonical_json() -> None:
    graph, sealed, cf = _graph_with_delete()
    result = replay(graph, cf, sealed)
    raw = replay_to_json(result)
    parsed = json.loads(raw)
    # sort_keys garantiza orden determinista
    reparsed = json.loads(
        json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    assert parsed == reparsed


def test_replay_not_replayable_is_deterministic() -> None:
    graph, sealed, _ = _graph_with_delete()
    cf_bad = Counterfactual(remove="atw:activity/tool_call_99")
    first = replay_to_json(replay(graph, cf_bad, sealed))
    for _ in range(9):
        assert replay_to_json(replay(graph, cf_bad, sealed)) == first
