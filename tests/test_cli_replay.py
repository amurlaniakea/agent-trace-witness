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

"""AC-15: CLI witness replay — mecanismo 4 HANSARD."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

WITNESS_BIN = Path(sys.executable).parent / "witness"
pytestmark = pytest.mark.skipif(
    not WITNESS_BIN.exists(),
    reason=f"witness entry point not found at {WITNESS_BIN}",
)


def _run(args: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    import os

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    return subprocess.run(
        [str(WITNESS_BIN), *args],
        capture_output=True,
        text=True,
        env=full_env,
        check=False,
    )


def test_cli_replay_help() -> None:
    from typer.testing import CliRunner

    from agent_trace_witness.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["replay", "--help"])
    assert result.exit_code == 0, f"replay --help exited {result.exit_code}: {result.output!r}"
    out = result.output.lower()
    assert "replay" in out
    assert "counterfactual" in out
    assert "graph" in out


def test_cli_replay_end_to_end(tmp_path: Path) -> None:
    env = {"ATW_WITNESS_KEY": "0" * 64, "ATW_WITNESS_TS": "2026-08-30T14:33:00+00:00"}
    # Build seal + events + graph via CLI + python
    from agent_trace_witness.capture import compute_seal_ref, record_tool_call, record_tool_response
    from agent_trace_witness.graph import build_graph, graph_to_jsonld
    from agent_trace_witness.seal import (
        AgentSpec,
        Tool,
        make_seal,
        seal_to_dict,
        sign_seal,
    )

    spec = AgentSpec(
        system_prompt="cli replay test",
        tools=(
            Tool(name="read_file", scopes=("read:/tmp/**",)),
            Tool(name="delete_file", scopes=("write:/tmp/**",)),
        ),
        witness_id="witness-cli-replay",
    )
    sealed = sign_seal(make_seal(spec, created_at="2026-08-31T00:00:00+00:00"))
    seal_path = tmp_path / "seal.json"
    seal_path.write_text(json.dumps(seal_to_dict(sealed), indent=2), encoding="utf-8")

    # Use MockMCPClient via capture layer determinista
    from tests.fixtures.mcp_client import MockMCPClient

    client = MockMCPClient()
    ref = compute_seal_ref(sealed)
    c1 = record_tool_call(client, "delete_file", {"path": "/tmp/x"}, ref, sealed)
    r1 = record_tool_response(client, "delete_file", "ok", ref, sealed)
    c2 = record_tool_call(client, "read_file", {"path": "/tmp/y"}, ref, sealed)
    r2 = record_tool_response(client, "read_file", "ok2", ref, sealed)
    # also record external_effect for delete_file to have synergy_residual
    from agent_trace_witness.capture import record_external_effect

    e1 = record_external_effect(
        client, "delete_file", {"path": "/tmp/x", "op": "delete"}, ref, sealed
    )
    graph = build_graph([c1, e1, r1, c2, r2], sealed)
    graph_path = tmp_path / "graph.jsonld"
    graph_path.write_text(graph_to_jsonld(graph), encoding="utf-8")

    out_path = tmp_path / "replay.json"
    cf = '{"remove":"atw:activity/tool_call_1"}'
    result = _run(
        [
            "replay",
            "--graph",
            str(graph_path),
            "--seal",
            str(seal_path),
            "--counterfactual",
            cf,
            "--out",
            str(out_path),
        ],
        env=env,
    )
    assert result.returncode == 0, (
        f"replay exit {result.returncode}: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "compensation_set" in data
    assert "synergy_residual" in data
    assert "not_replayable" in data
    comp_ids = {n["@id"] for n in data["compensation_set"]["@graph"]}
    assert "atw:activity/tool_call_1" not in comp_ids
    # jq chainable
    jq = shutil.which("jq")
    if jq:
        proc = subprocess.run(
            [jq, ".compensation_set", str(out_path)], capture_output=True, text=True, check=True
        )
        assert "compensation_set" in proc.stdout or "@graph" in proc.stdout


def test_cli_replay_exit_codes(tmp_path: Path) -> None:
    env = {"ATW_WITNESS_KEY": "0" * 64}
    # 1) seal con firma inválida -> exit 1
    bogus = tmp_path / "bogus.json"
    bogus.write_text(
        json.dumps(
            {
                "system_prompt_sha256": "0" * 64,
                "tools": [{"name": "read_file", "scopes": []}],
                "created_at": "2026-08-31T00:00:00+00:00",
                "witness_id": "witness-bogus",
                "signature": "hmac-sha256:" + "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    graph = tmp_path / "g.jsonld"
    graph.write_text(json.dumps({"@context": {}, "@graph": []}), encoding="utf-8")
    out = tmp_path / "out.json"
    r1 = _run(
        [
            "replay",
            "--graph",
            str(graph),
            "--seal",
            str(bogus),
            "--counterfactual",
            '{"remove":"atw:activity/tool_call_1"}',
            "--out",
            str(out),
        ],
        env=env,
    )
    assert r1.returncode == 1
    assert "signature" in r1.stderr.lower()

    # 2) counterfactual con ID inexistente -> exit 1 con not_replayable
    from agent_trace_witness.seal import (
        AgentSpec,
        Tool,
        make_seal,
        seal_to_dict,
        sign_seal,
    )

    spec = AgentSpec(
        system_prompt="x", tools=(Tool(name="read_file", scopes=()),), witness_id="witness-exit2"
    )
    sealed = sign_seal(make_seal(spec, created_at="2026-08-31T00:00:00+00:00"))
    seal_ok = tmp_path / "seal_ok.json"
    seal_ok.write_text(json.dumps(seal_to_dict(sealed)), encoding="utf-8")
    # graph mínimo con un activity
    from agent_trace_witness.capture import compute_seal_ref, record_tool_call
    from agent_trace_witness.graph import build_graph, graph_to_jsonld
    from tests.fixtures.mcp_client import MockMCPClient

    client = MockMCPClient()
    ref = compute_seal_ref(sealed)
    c1 = record_tool_call(client, "read_file", {"path": "/tmp/a"}, ref, sealed)
    g2 = build_graph([c1], sealed)
    g2_path = tmp_path / "g2.jsonld"
    g2_path.write_text(graph_to_jsonld(g2), encoding="utf-8")
    out2 = tmp_path / "out2.json"
    r2 = _run(
        [
            "replay",
            "--graph",
            str(g2_path),
            "--seal",
            str(seal_ok),
            "--counterfactual",
            '{"remove":"atw:activity/tool_call_99"}',
            "--out",
            str(out2),
        ],
        env=env,
    )
    assert r2.returncode == 1
    assert "not_replayable" in r2.stderr.lower() or "not_replayable" in out2.read_text(
        encoding="utf-8"
    )

    # 3) I/O error -> exit 2 (out parent is file)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    bad_out = blocker / "sub" / "out.json"
    r3 = _run(
        [
            "replay",
            "--graph",
            str(g2_path),
            "--seal",
            str(seal_ok),
            "--counterfactual",
            '{"remove":"atw:activity/tool_call_1"}',
            "--out",
            str(bad_out),
        ],
        env=env,
    )
    assert r3.returncode == 2
    assert "internal error" in r3.stderr.lower()


def test_cli_capture_with_external_effect_via_cli(tmp_path: Path) -> None:
    """Regresión B1-B4: witness capture CLI debe aceptar external_effect (5º choke point).

    El CLI validaba kind contra CHOKE_POINT_EVENT_TYPES (5) pero el elif
    solo ramificaba 4 tipos — external_effect se rechazaba con 'kind unknown'
    aunque capture.run_capture() sí lo soportara. Este test habría cazado la
    discontinuidad librería vs CLI.
    """
    env = {"ATW_WITNESS_KEY": "0" * 64, "ATW_WITNESS_TS": "2026-08-31T00:00:00+00:00"}
    # 1) seal via CLI
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "system_prompt": "test external_effect via cli",
                "tools": [
                    {"name": "read_file", "scopes": ["read:/tmp/**"]},
                    {"name": "delete_file", "scopes": ["write:/tmp/**"]},
                ],
                "witness_id": "witness-cli-external",
            }
        ),
        encoding="utf-8",
    )
    seal_path = tmp_path / "seal.json"
    r_seal = _run(["seal", "--spec", str(spec_path), "--out", str(seal_path)], env=env)
    assert r_seal.returncode == 0, f"seal failed: {r_seal.stderr!r}"

    # 2) capture con external_effect via CLI (el bug rechazaba aquí)
    scenario = tmp_path / "scenario.json"
    scenario.write_text(
        json.dumps(
            [
                {"kind": "tool_call", "tool": "delete_file", "payload": {"path": "/tmp/x"}},
                {
                    "kind": "external_effect",
                    "tool": "delete_file",
                    "payload": {"path": "/tmp/x", "op": "delete"},
                },
                {"kind": "tool_response", "tool": "delete_file", "payload": "ok"},
                {"kind": "tool_call", "tool": "read_file", "payload": {"path": "/tmp/y"}},
                {"kind": "tool_response", "tool": "read_file", "payload": "content-y"},
            ]
        ),
        encoding="utf-8",
    )
    events_path = tmp_path / "events.jsonl"
    r_cap = _run(
        [
            "capture",
            "--scenario",
            str(scenario),
            "--seal",
            str(seal_path),
            "--out",
            str(events_path),
        ],
        env=env,
    )
    assert r_cap.returncode == 0, (
        f"capture with external_effect failed: stdout={r_cap.stdout!r} stderr={r_cap.stderr!r}"
    )
    lines = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 5
    assert any(entry["type"] == "external_effect" for entry in lines)

    # 3) graph debe contener atw:externalEffect
    graph_path = tmp_path / "graph.jsonld"
    r_graph = _run(
        ["graph", "--events", str(events_path), "--seal", str(seal_path), "--out", str(graph_path)],
        env=env,
    )
    assert r_graph.returncode == 0, f"graph failed: {r_graph.stderr!r}"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert any(n.get("atw:externalEffect") is True for n in graph["@graph"])
