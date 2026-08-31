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

"""Typer CLI entrypoint for agent-trace-witness.

Subcommands (B5 of the plan):

- ``seal``:    generate a signed readiness profile from an agent spec.
- ``capture``: record events at the 4 choke points from a scenario file.
- ``graph``:   emit a PROV-DM JSON-LD causal graph from captured events.
- ``verify``:  check a graph against a seal and report anomalies.
- ``replay``:  counterfactual replay over a graph (mecanismo 4 HANSARD).

Exit codes (T081):
  0  success (including verify when anomalies are present).
  1  input error (file missing, JSON malformed, seal signature invalid).
  2  internal error (unclassified WitnessError or unexpected exception).

AC-10: every subcommand has ``--help``, exit codes are coherent, and
the output can be chained in shell pipelines (``witness seal ... | jq
.signature``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import NoReturn

import typer

from .capture import (
    CHOKE_POINT_EVENT_TYPES,
    CaptureEvent,
    compute_seal_ref,
    record_external_effect,
    record_model_input,
    record_model_output,
    record_tool_call,
    record_tool_response,
)
from .exceptions import WitnessError
from .graph import build_graph, graph_to_jsonld
from .replay import Counterfactual, replay_to_json
from .replay import replay as replay_engine
from .seal import (
    AgentSpec,
    Tool,
    make_seal,
    seal_from_dict,
    seal_to_dict,
    sign_seal,
    verify_seal,
)
from .verify import verify_graph

app = typer.Typer(
    name="witness",
    help=(
        "External witness for autonomous multi-agent AI systems: signed "
        "readiness seal, choke-point capture, and PROV-DM causal graphs "
        "for post-incident reconstruction."
    ),
    no_args_is_help=True,
    add_completion=False,
)


# ---------------------------------------------------------------------------
# Exit-code helpers (T081)
# ---------------------------------------------------------------------------


def _die_input(msg: str) -> NoReturn:
    """Print an INPUT error to stderr and exit with code 1."""
    typer.echo(f"witness: error: {msg}", err=True)
    raise typer.Exit(code=1)


def _die_internal(msg: str) -> NoReturn:
    """Print an INTERNAL error to stderr and exit with code 2."""
    typer.echo(f"witness: internal error: {msg}", err=True)
    raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# JSON / file helpers
# ---------------------------------------------------------------------------


def _read_json(path: Path, *, what: str) -> dict:
    """Read a JSON file or die with exit 1 (input error).

    ``what`` is a human label for the file (used in the error message).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _die_input(f"{what} not found: {path}")
    except OSError as exc:
        _die_input(f"could not read {what} {path}: {exc}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _die_input(f"{what} {path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        _die_input(f"{what} {path} must be a JSON object, got {type(data).__name__}")
    return data


def _write_json(path: Path, payload: dict, *, indent: int | None = None) -> None:
    """Write a JSON file or die with exit 2 (internal I/O error)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        _die_internal(f"could not write {path}: {exc}")


def _read_jsonl(path: Path, *, what: str) -> list[dict]:
    """Read a JSONL file. Each non-empty line is one dict.

    A malformed line is an input error (exit 1) — the file is supposed
    to come from ``witness capture`` or a curated external recorder.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _die_input(f"{what} not found: {path}")
    except OSError as exc:
        _die_input(f"could not read {what} {path}: {exc}")
    out: list[dict] = []
    for ln_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            _die_input(f"{what} {path} line {ln_no} is not valid JSON: {exc}")
        if not isinstance(obj, dict):
            _die_input(
                f"{what} {path} line {ln_no} must be a JSON object, got {type(obj).__name__}"
            )
        out.append(obj)
    return out


def _write_jsonl(path: Path, lines: Iterable[str]) -> None:
    """Write JSONL. Newline-terminated lines."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
    except OSError as exc:
        _die_internal(f"could not write {path}: {exc}")


# ---------------------------------------------------------------------------
# seal (T082)
# ---------------------------------------------------------------------------


@app.command()
def seal(
    spec: str = typer.Option(..., "--spec", help="Path to agent spec JSON."),
    out: str = typer.Option(..., "--out", help="Path to write the signed seal."),
) -> None:
    """Generate a signed readiness seal from an agent spec."""
    spec_path = Path(spec)
    out_path = Path(out)

    raw = _read_json(spec_path, what="agent spec")

    # Build AgentSpec from the dict. Required: system_prompt, tools.
    # Optional: witness_id (defaults via make_seal).
    try:
        tools_raw = raw.get("tools", [])
        if not isinstance(tools_raw, list):
            _die_input("agent spec 'tools' must be a list")
        tools = tuple(
            Tool(
                name=str(t["name"]),
                scopes=tuple(str(s) for s in t.get("scopes", [])),
            )
            for t in tools_raw
        )
        agent_spec = AgentSpec(
            system_prompt=str(raw.get("system_prompt", "")),
            tools=tools,
            witness_id=str(raw.get("witness_id", "")),
        )
    except (KeyError, TypeError) as exc:
        _die_input(f"agent spec {spec_path} is malformed: {exc}")

    try:
        unsigned = make_seal(agent_spec)
        sealed_seal = sign_seal(unsigned)
    except WitnessError as exc:
        _die_input(f"could not sign seal: {exc}")

    _write_json(out_path, seal_to_dict(sealed_seal), indent=2)


# ---------------------------------------------------------------------------
# capture (T083)
# ---------------------------------------------------------------------------


@app.command()
def capture(
    scenario: str = typer.Option(
        ..., "--scenario", help="Path to a scenario JSON file (list of events)."
    ),
    seal_path: str = typer.Option(
        ..., "--seal", help="Path to the signed seal to attribute events under."
    ),
    out: str = typer.Option(..., "--out", help="Path to write captured events (JSONL)."),
) -> None:
    """Record events at the 5 choke points from a scenario file.

    The MVP does NOT integrate with a real MCP client (see
    ``KNOWN_ISSUES.md §3``). The scenario file is a JSON list of event
    descriptors; the CLI runs each one through the capture layer and
    writes the resulting ``CaptureEvent`` JSONL.

    Event descriptor shape::

        {"kind": "tool_call",       "tool": "read_file", "payload": {...}}
        {"kind": "tool_response",   "tool": "read_file", "payload": {...}}
        {"kind": "model_input",     "role": "user",      "payload": "..."}
        {"kind": "model_output",    "role": "assistant", "payload": "..."}
        {"kind": "external_effect", "tool": "delete_file", "payload": {"path": "/tmp/x", "op": "delete"}}

    Feature 002 will add a real-MCP-client mode (no scenario file).
    """
    scenario_path = Path(scenario)
    seal_file = Path(seal_path)
    out_path = Path(out)

    # Validate the seal first — events captured under an invalid seal
    # are useless to the verifier.
    seal_raw = _read_json(seal_file, what="seal")
    try:
        sealed_seal = seal_from_dict(seal_raw)
    except WitnessError as exc:
        _die_input(f"seal {seal_file} is malformed: {exc}")
    if not verify_seal(sealed_seal):
        _die_input(f"seal {seal_file} signature did not verify")

    s_ref = compute_seal_ref(sealed_seal)

    # Load the scenario. Each element is an event descriptor.
    scenario_text = scenario_path.read_text(encoding="utf-8") if scenario_path.exists() else None
    if scenario_text is None:
        _die_input(f"scenario not found: {scenario_path}")
    try:
        scenario_list = json.loads(scenario_text)
    except json.JSONDecodeError as exc:
        _die_input(f"scenario {scenario_path} is not valid JSON: {exc}")
    if not isinstance(scenario_list, list):
        _die_input(
            f"scenario {scenario_path} must be a JSON list, got {type(scenario_list).__name__}"
        )

    # Build a discardable MCP client for the capture layer (the MVP
    # capture layer only requires that the client expose the protocol;
    # it doesn't read the returned EventTuple).
    from .capture import EventTuple

    class _DiscardClient:
        # Returns empty EventTuples — the witness doesn't inspect them,
        # but the MCPClient Protocol requires the return type to be
        # EventTuple (not None), so static type checkers accept it.
        def record_tool_call(self, *a, **k):  # noqa: ARG002
            return EventTuple(timestamp="", type="tool_call", payload=b"")

        def record_tool_response(self, *a, **k):  # noqa: ARG002
            return EventTuple(timestamp="", type="tool_response", payload=b"")

        def record_model_input(self, *a, **k):  # noqa: ARG002
            return EventTuple(timestamp="", type="model_input", payload=b"")

        def record_model_output(self, *a, **k):  # noqa: ARG002
            return EventTuple(timestamp="", type="model_output", payload=b"")

        def record_external_effect(self, *a, **k):  # noqa: ARG002
            return EventTuple(timestamp="", type="external_effect", payload=b"")

        def events(self):
            return []

    client = _DiscardClient()
    out_events: list[CaptureEvent] = []
    for idx, desc in enumerate(scenario_list):
        if not isinstance(desc, dict):
            _die_input(f"scenario[{idx}] must be a JSON object, got {type(desc).__name__}")
        kind = desc.get("kind")
        if kind not in CHOKE_POINT_EVENT_TYPES:
            _die_input(
                f"scenario[{idx}].kind must be one of {CHOKE_POINT_EVENT_TYPES}, got {kind!r}"
            )
        payload = desc.get("payload")

        try:
            if kind == "tool_call":
                ev = record_tool_call(
                    client, str(desc.get("tool", "")), payload, s_ref, sealed_seal
                )
            elif kind == "tool_response":
                ev = record_tool_response(
                    client, str(desc.get("tool", "")), payload, s_ref, sealed_seal
                )
            elif kind == "model_input":
                ev = record_model_input(
                    client,
                    payload,
                    s_ref,
                    sealed_seal,
                    role=str(desc.get("role", "user")),
                )
            elif kind == "model_output":
                ev = record_model_output(
                    client,
                    payload,
                    s_ref,
                    sealed_seal,
                    role=str(desc.get("role", "assistant")),
                )
            elif kind == "external_effect":
                ev = record_external_effect(
                    client, str(desc.get("tool", "")), payload, s_ref, sealed_seal
                )
            else:
                # Defensive — kind was checked above but the type
                # checker doesn't know.
                _die_input(f"scenario[{idx}].kind unknown: {kind!r}")
        except WitnessError as exc:
            _die_input(f"scenario[{idx}] rejected by capture layer: {exc}")

        out_events.append(ev)

    # JSONL output (one event per line, sorted keys for stability).
    def _lines() -> Iterable[str]:
        for ev in out_events:
            yield _event_to_jsonl(ev)

    _write_jsonl(out_path, _lines())

    typer.echo(f"witness: captured {len(out_events)} events to {out_path}")


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


# ---------------------------------------------------------------------------
# graph (T084)
# ---------------------------------------------------------------------------


@app.command()
def graph(
    events: str = typer.Option(..., "--events", help="Path to captured events JSONL."),
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
    out: str = typer.Option(..., "--out", help="Path to write the PROV-DM graph (JSON-LD)."),
) -> None:
    """Emit a PROV-DM JSON-LD causal graph from captured events."""
    events_path = Path(events)
    seal_file = Path(seal_path)
    out_path = Path(out)

    seal_raw = _read_json(seal_file, what="seal")
    try:
        sealed_seal = seal_from_dict(seal_raw)
    except WitnessError as exc:
        _die_input(f"seal {seal_file} is malformed: {exc}")
    if not verify_seal(sealed_seal):
        _die_input(f"seal {seal_file} signature did not verify")

    event_dicts = _read_jsonl(events_path, what="events JSONL")
    # Re-hydrate CaptureEvent dataclasses.
    events_list: list[CaptureEvent] = []
    for d in event_dicts:
        try:
            events_list.append(
                CaptureEvent(
                    ts=str(d["ts"]),
                    type=d["type"],
                    tool=d.get("tool"),
                    role=d.get("role"),
                    payload_sha256=str(d["payload_sha256"]),
                    seal_ref=str(d["seal_ref"]),
                    unsealed=bool(d.get("unsealed", False)),
                )
            )
        except KeyError as exc:
            _die_input(f"event missing required key {exc}: {d}")

    g = build_graph(events_list, sealed_seal)
    try:
        text = graph_to_jsonld(g)
    except WitnessError as exc:
        _die_input(f"could not serialise graph: {exc}")

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    except OSError as exc:
        _die_internal(f"could not write {out_path}: {exc}")

    typer.echo(f"witness: wrote graph ({len(g.get('@graph', []))} nodes) to {out_path}")


# ---------------------------------------------------------------------------
# replay (T040 — AC-15)
# ---------------------------------------------------------------------------


@app.command()
def replay(
    graph_path: str = typer.Option(..., "--graph", help="Path to the PROV-DM graph (JSON-LD)."),
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
    counterfactual: str = typer.Option(
        ...,
        "--counterfactual",
        help='Counterfactual JSON string or path to JSON file, e.g. \'{"remove":"atw:activity/tool_call_1"}\' (URI acoplado a graph.py §Decisión B4 — ver KNOWN_ISSUES §6 y plan.md).',
    ),
    out: str = typer.Option(..., "--out", help="Path to write replay result JSON."),
) -> None:
    """Replay contrafactual sobre un grafo PROV-DM (mecanismo 4 HANSARD).

    Lee el grafo y el seal, aplica el counterfactual (solo \'remove\' URI
    acoplado a graph.py en 002 — ver plan.md §Decisión abierta resuelta en
    B4: se mantiene URI atw:activity/... como interfaz pública en 002 por
    estabilidad de IDs deterministas; payload_sha256/event_index quedan para
    003+), y escribe JSON canónico con compensation_set + synergy_residual
    + not_replayable. Exit 0 ok, 1 input error, 2 internal I/O error.
    """
    import json as _json
    from pathlib import Path as _Path

    g_file = _Path(graph_path)
    s_file = _Path(seal_path)
    out_path = _Path(out)

    # Seal primero (input error si no verifica)
    seal_raw = _read_json(s_file, what="seal")
    try:
        from .seal import seal_from_dict, verify_seal

        sealed = seal_from_dict(seal_raw)
    except Exception as exc:
        _die_input(f"seal {s_file} is malformed: {exc}")
    # verify_seal returns bool; False -> input error
    try:
        if not verify_seal(sealed):
            _die_input(f"seal {s_file} signature did not verify")
    except Exception as exc:
        _die_input(f"seal {s_file} signature did not verify: {exc}")

    graph_raw = _read_json(g_file, what="graph")
    if "@graph" not in graph_raw or not isinstance(graph_raw.get("@graph"), list):
        _die_input(f"graph {g_file} is not a PROV-DM JSON-LD doc (missing or malformed @graph)")

    # Counterfactual: file path or inline JSON string
    cf_raw: dict
    cf_path = _Path(counterfactual)
    # Si es fichero existente y contiene JSON, leer fichero; si no, parsear string inline
    if cf_path.exists() and cf_path.is_file():
        cf_raw = _read_json(cf_path, what="counterfactual")
    else:
        try:
            cf_raw = _json.loads(counterfactual)
        except _json.JSONDecodeError as exc:
            _die_input(f"counterfactual is not valid JSON: {exc}")
        if not isinstance(cf_raw, dict):
            _die_input(
                f"counterfactual must be a JSON object with 'remove', got {type(cf_raw).__name__}"
            )

    # Validación temprana de forma (C5)
    if "remove" not in cf_raw or not isinstance(cf_raw["remove"], str) or not cf_raw["remove"]:
        _die_input(
            "counterfactual must contain non-empty string field 'remove' (e.g. 'atw:activity/tool_call_1')"
        )

    # Ejecutar replay
    try:
        from .exceptions import WitnessReplayError

        cf = Counterfactual(remove=cf_raw["remove"])
        result = replay_engine(graph_raw, cf, sealed)
    except WitnessReplayError as exc:
        _die_input(f"replay rejected counterfactual: {exc}")
    except Exception as exc:
        # No clasificado -> internal
        _die_internal(f"replay failed: {exc}")

    # Serializar resultado canónico
    try:
        text = replay_to_json(result)
        payload = _json.loads(text)
    except Exception as exc:
        _die_internal(f"could not serialise replay result: {exc}")

    # Escribir out (I/O -> exit 2)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            _json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        _die_internal(f"could not write {out_path}: {exc}")

    # not_replayable -> input error (C5) pero con fichero ya escrito
    if result.not_replayable:
        typer.echo(
            f"witness replay: not_replayable: {result.not_replayable} (written to {out_path})",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(f"witness replay: wrote {out_path} (synergy_residual={result.synergy_residual})")


# ---------------------------------------------------------------------------
# verify (T085)
# ---------------------------------------------------------------------------


@app.command()
def verify(
    graph_path: str = typer.Option(..., "--graph", help="Path to the PROV-DM graph."),
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the report as JSON instead of human-readable text.",
    ),
) -> None:
    """Check a graph against a seal and report anomalies.

    Exit code is ALWAYS 0 when the seal verifies, even if anomalies are
    present — anomalies are REPORT-ONLY, not errors. Exit 1 only when
    the seal signature fails to verify (input is malformed).
    """
    g_file = Path(graph_path)
    s_file = Path(seal_path)

    seal_raw = _read_json(s_file, what="seal")
    try:
        sealed_seal = seal_from_dict(seal_raw)
    except WitnessError as exc:
        _die_input(f"seal {s_file} is malformed: {exc}")
    if not verify_seal(sealed_seal):
        _die_input(f"seal {s_file} signature did not verify")

    graph_raw = _read_json(g_file, what="graph")
    if "@graph" not in graph_raw or not isinstance(graph_raw.get("@graph"), list):
        _die_input(f"graph {g_file} is not a PROV-DM JSON-LD doc (missing or malformed @graph)")

    try:
        report = verify_graph(graph_raw, sealed_seal)
    except WitnessError as exc:
        _die_input(f"verify failed: {exc}")

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "summary": report.summary,
                    "anomalies": [
                        {
                            "tool": a.tool,
                            "severity": a.severity,
                            "detail": a.detail,
                        }
                        for a in report.anomalies
                    ],
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        typer.echo(f"witness verify: {report.summary}")
        if report.anomalies:
            typer.echo("")
            for a in report.anomalies:
                typer.echo(f"  [{a.severity.upper():7}] {a.tool}: {a.detail}")

    # Exit 0 even when anomalies are present (per T085).


if __name__ == "__main__":
    app()
