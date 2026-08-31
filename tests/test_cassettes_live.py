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

"""AC-17: cassettes live — ATW_RECORD=1 + replay sin servidor (T022).

La cassette ``mcp_stdio_live_001.jsonl`` (grabada contra el stub vivo
con ``ATW_RECORD=1`` y commiteada) se reproduce en CI:

- sin servidor vivo (no Popen), sin red, sin ``ATW_RECORD``;
- ``build_graph`` + ``verify_graph`` pasan sobre el mismo scenario;
- el directorio de cassettes total queda < 1 MB (R13);
- la cassette no contiene secretos (sanitización).

El test de grabación (``test_atw_record_writes_cassette_on_close``)
regraba una cassette efímera en ``tmp_path`` — nunca pisa la
commiteada — y verifica que el hook de ``close()`` produce el JSONL
canónico. CI nunca fija ``ATW_RECORD``: la variable solo la activa un
operador fuera de CI (KNOWN_ISSUES §6 / cassettes README).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_trace_witness.capture import run_capture
from agent_trace_witness.graph import build_graph
from agent_trace_witness.mcp_adapter import RealMCPClient
from agent_trace_witness.replay import Counterfactual, replay
from agent_trace_witness.seal import AgentSpec, SealedSeal, Tool, make_seal, sign_seal
from agent_trace_witness.verify import verify_graph

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_CASSETTE = FIXTURES / "cassettes" / "mcp_stdio_live_001.jsonl"
STUB = FIXTURES / "stubs" / "mcp_stdio_stub.py"

FROZEN_TS = "2026-08-30T14:33:00+00:00"

SCENARIO: list[tuple[str, str, object]] = [
    ("tool_call", "delete_file", {"path": "/tmp/recorded"}),
    ("tool_response", "delete_file", None),
    ("external_effect", "delete_file", None),
    ("model_input", "", "delete /tmp/recorded"),
    ("model_output", "", "done"),
]


def _spec() -> AgentSpec:
    return AgentSpec(
        system_prompt="ac17 live cassette",
        tools=(Tool(name="delete_file", scopes=("delete:/tmp/**",)),),
        witness_id="witness-ac17",
    )


def _sealed() -> SealedSeal:
    return sign_seal(make_seal(_spec(), created_at=FROZEN_TS))


def test_committed_live_cassette_replays_without_server() -> None:
    """AC-17: la cassette live commiteada se reproduce sin Popen/red."""
    assert LIVE_CASSETTE.exists(), "cassette live commiteada ausente"
    client = RealMCPClient.from_cassette(LIVE_CASSETTE)
    assert client._transport is None, (
        "from_cassette debe tener transporte None (sin Popen, sin red)"
    )
    events = client.events()
    assert len(events) == 5, f"cassette live debe tener 5 eventos, {len(events)}"
    assert [ev.type for ev in events] == [
        "tool_call",
        "tool_response",
        "external_effect",
        "model_input",
        "model_output",
    ]

    # build_graph + verify_graph pasan sobre el mismo scenario, sin red.
    sealed = _sealed()
    cap_events = run_capture(client, sealed, SCENARIO)
    graph = build_graph(cap_events, sealed)
    assert "@graph" in graph
    assert any(n.get("atw:externalEffect") is True for n in graph["@graph"])
    report = verify_graph(graph, sealed)
    assert report.anomalies == [], f"verify_graph debería ser limpio, got: {report.anomalies}"

    # replay determinista sobre el grafo del cassette.
    activity_ids = [
        n["@id"]
        for n in graph["@graph"]
        if n.get("@type") == "prov:Activity" and n.get("atw:tool") == "delete_file"
    ]
    assert activity_ids, "sin Activity delete_file en el grafo"
    result = replay(graph, Counterfactual(remove=activity_ids[0]), sealed)
    canon = json.dumps(result.compensation_set, sort_keys=True, separators=(",", ":"))
    assert json.loads(canon) == result.compensation_set


def test_cassettes_directory_under_1mb() -> None:
    """R13: el directorio total de cassettes queda < 1 MB."""
    total = sum(p.stat().st_size for p in FIXTURES.glob("cassettes/*.jsonl"))
    assert total < 1_000_000, f"directorio cassettes = {total} B (límite 1 MB)"


def test_committed_cassette_is_sanitized() -> None:
    """AC-17: la cassette no contiene secretos ni paths de producción."""
    text = LIVE_CASSETTE.read_text(encoding="utf-8")
    for token in ("ATW_WITNESS_KEY", "BEGIN", "PRIVATE", "api_key", "Bearer "):
        assert token not in text, f"token prohibido {token!r} en cassette"
    assert "/mnt/c" not in text and "/home/sil" not in text, "paths reales del host en la cassette"
    # Cada línea es JSON canónico parseable.
    for line in text.splitlines():
        obj = json.loads(line)
        assert set(obj) == {"timestamp", "type", "payload"}, (
            f"línea con shape inesperado: {sorted(obj)}"
        )


def test_atw_record_writes_cassette_on_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """El hook ATW_RECORD=1 escribe el JSONL canónico en close()."""
    out = tmp_path / "recorded.jsonl"
    monkeypatch.setenv("ATW_RECORD", "1")
    monkeypatch.setenv("ATW_RECORD_OUT", str(out))
    monkeypatch.setenv("ATW_WITNESS_TS", FROZEN_TS)

    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    run_capture(client, _sealed(), SCENARIO)
    client.close()

    # El hook solo existe en modo live: la cassette no debe existir si no
    # se grabó (aquí sí debe existir, y con 5 líneas canónicas).
    assert out.exists(), "ATW_RECORD=1 + close() debe escribir la cassette"
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    for line in lines:
        obj = json.loads(line)
        assert set(obj) == {"timestamp", "type", "payload"}
        assert obj["timestamp"] == FROZEN_TS, "timestamp no congelado en la grabación"
    # El JSONL es canónico: re-serializar línea a línea da el mismo byte.
    for line in lines:
        obj = json.loads(line)
        assert json.dumps(obj, sort_keys=True, separators=(",", ":")) == line, (
            "línea no canónica (sort_keys/separators)"
        )


def test_atw_record_unset_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Sin ATW_RECORD, close() no escribe nada (CI nunca graba)."""
    out = tmp_path / "should_not_exist.jsonl"
    monkeypatch.delenv("ATW_RECORD", raising=False)
    monkeypatch.delenv("ATW_RECORD_OUT", raising=False)

    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    run_capture(client, _sealed(), SCENARIO)
    client.close()
    assert not out.exists()
