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

"""AC-18: no regresión live vs cassette — mismo scenario, grafo idéntico (T023).

Dos comprobaciones (anotación AC-18 de spec.md/plan.md: este test
garantiza **fidelidad de la grabación**, no equivalencia general de dos
ejecuciones independientes):

(A) **Mismo scenario → mismo grafo.** El scenario explícito se conduce
    dos veces: en modo live (``from_stdio`` contra el stub; el adapter
    hace el ``tools/call`` real) y en modo cassette (``from_cassette``,
    sin servidor). Con idénticas entradas a ``run_capture``, los
    ``CaptureEvent`` deben ser idénticos y el ``build_graph``
    byte-idéntico (``sort_keys=True``), con el mismo reporte
    ``verify_graph`` y el mismo ``compensation_set`` de ``replay``.
    Si el modo live rompiese el flujo de eventos o el modo cassette
    divergiese en el pipeline capture→graph, falla.

(B) **Round-trip sin pérdida (ATW_RECORD=1).** El stream de
    ``EventTuple`` de la ejecución live debe ser exactamente lo que
    ``write_cassette`` serializa en el JSONL y lo que ``from_cassette``
    re-carga: línea a línea, ``{"timestamp","type","payload"}``
    byte-idéntico al stream original. El ``result`` real del servidor
    (``content``/``isError``) debe llegar íntegro al archivo — es la
    fidelidad que un auditor del cassette puede inspeccionar.
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
STUB = FIXTURES / "stubs" / "mcp_stdio_stub.py"

FROZEN_TS = "2026-08-30T14:33:00+00:00"

# Scenario explícido: tool_response/external_effect pasan el valor
# neutro "" porque en modo live el result real del servidor aún no es
# conocido al llamar a capture (arquitectura 001/002: capture hace hash
# del argumento pasado; el adapter notifica al transport y graba el
# result real en su propio EventTuple — verificado en (B)).
SCENARIO: list[tuple[str, str, bytes | str | dict[str, object]]] = [
    ("tool_call", "delete_file", {"path": "/tmp/determinism"}),
    ("tool_response", "delete_file", ""),
    ("external_effect", "delete_file", ""),
    ("model_input", "", "delete /tmp/determinism"),
    ("model_output", "", "done"),
]


def _sealed() -> SealedSeal:
    spec = AgentSpec(
        system_prompt="ac18 determinism",
        tools=(Tool(name="delete_file", scopes=("delete:/tmp/**",)),),
        witness_id="witness-ac18",
    )
    return sign_seal(make_seal(spec, created_at=FROZEN_TS))


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def test_same_scenario_live_and_cassette_identical_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """(A) Mismo scenario → capture(live) vs capture(cassette) → graph byte-idéntico."""
    sealed = _sealed()

    # ---- Run 1: live stdio contra el stub -----------------------------
    client_live = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    cap_live = run_capture(client_live, sealed, SCENARIO)
    live_events = client_live.events()
    client_live.write_cassette(tmp_path / "ac18.jsonl")
    client_live.close()
    assert len(cap_live) == 5
    assert len(live_events) == 5

    # ---- Run 2: cassette sin servidor, mismo scenario explícito --------
    client_cass = RealMCPClient.from_cassette(tmp_path / "ac18.jsonl")
    assert client_cass._transport is None, "from_cassette no debe tener transport"
    cap_cass = run_capture(client_cass, sealed, SCENARIO)
    assert len(cap_cass) == 5

    # ---- CaptureEvent a CaptureEvent ------------------------------------
    for le, ce in zip(cap_live, cap_cass, strict=True):
        assert le.type == ce.type
        assert le.tool == ce.tool
        assert le.role == ce.role
        assert le.ts == ce.ts, f"ts diverge en {le.type}: {le.ts!r} != {ce.ts!r}"
        assert le.seal_ref == ce.seal_ref
        assert le.unsealed == ce.unsealed
        assert le.payload_sha256 == ce.payload_sha256, (
            f"payload_sha256 diverge en {le.type}: "
            f"live={le.payload_sha256} cassette={ce.payload_sha256}"
        )

    # ---- build_graph byte-idéntico --------------------------------------
    graph_live = build_graph(cap_live, sealed)
    graph_cass = build_graph(cap_cass, sealed)
    assert _canonical(graph_live) == _canonical(graph_cass), (
        "grafo canónico diverge entre live y cassette"
    )

    # ---- verify_graph mismo reporte -------------------------------------
    rep_live = verify_graph(graph_live, sealed)
    rep_cass = verify_graph(graph_cass, sealed)
    assert [(a.tool, a.severity) for a in rep_live.anomalies] == [
        (a.tool, a.severity) for a in rep_cass.anomalies
    ]
    assert rep_live.summary == rep_cass.summary

    # ---- replay mismo compensation_set ----------------------------------
    activity = next(
        n["@id"]
        for n in graph_live["@graph"]
        if n.get("@type") == "prov:Activity" and n.get("atw:tool") == "delete_file"
    )
    res_live = replay(graph_live, Counterfactual(remove=activity), sealed)
    res_cass = replay(graph_cass, Counterfactual(remove=activity), sealed)
    assert _canonical(res_live.compensation_set) == _canonical(res_cass.compensation_set)
    assert res_live.not_replayable == res_cass.not_replayable


def test_atw_record_roundtrip_lossless(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """(B) live stream → ATW_RECORD=1 → JSONL → from_cassette: sin pérdida."""
    out = tmp_path / "recorded.jsonl"
    monkeypatch.setenv("ATW_RECORD", "1")
    monkeypatch.setenv("ATW_RECORD_OUT", str(out))

    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    run_capture(client, _sealed(), SCENARIO)
    client.close()  # el hook ATW_RECORD=1 escribe `out`

    assert out.exists(), "ATW_RECORD=1 + close() debe escribir la cassette"
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5

    # B.1: el archivo es un JSONL canónico (cada línea == su re-serialización).
    for line in lines:
        assert _canonical(json.loads(line)) == line, "línea no canónica"

    # B.2: stream live serializado == stream del archivo, campo a campo.
    live_stream = [
        {
            "timestamp": ev.timestamp,
            "type": ev.type,
            "payload": json.loads(ev.payload.decode("utf-8")),
        }
        for ev in client.events()
    ]
    assert live_stream == [json.loads(line) for line in lines], (
        "ATW_RECORD=1 no conserva el stream live (fidelidad de grabación rota)"
    )

    # B.3: el result REAL del servidor llegó íntegro al archivo.
    resp = json.loads(lines[1])
    assert resp["type"] == "tool_response"
    assert resp["payload"]["result"]["isError"] is False
    content = resp["payload"]["result"]["content"][0]
    assert content["type"] == "text"
    assert "/tmp/determinism" in content["text"], "echo del path del stub ausente"

    # B.4: external_effect derivado == MISMO result (misma data, misma línea).
    eff = json.loads(lines[2])
    assert eff["payload"]["effect"] == resp["payload"]["result"], (
        "external_effect debe derivar del MISMO result.content/isError"
    )

    # B.5: from_cassette re-carga el mismo stream (timestamp/type/payload).
    client2 = RealMCPClient.from_cassette(out)
    reloaded = [
        {
            "timestamp": ev.timestamp,
            "type": ev.type,
            "payload": json.loads(ev.payload.decode("utf-8")),
        }
        for ev in client2.events()
    ]
    assert reloaded == live_stream, "from_cassette no reproduce el stream grabado"
