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

"""External-validity tests — AC-9 (T074).

The HANSARD fixture models attribution laundering: a destructive tool
call (``delete_file``) interleaved with benign lookups
(``read_file``, ``list_dir``). The seal lists only the benign tools.

The test does NOT assume a specific graph topology — it asserts on
properties that hold regardless of internal implementation choices:

1. The seal is verifiable (signature integrity).
2. The graph contains a PROV Activity carrying ``atw:tool=delete_file``
   and ``atw:unsealed=true``.
3. The verifier (``verify_graph``) reports an anomaly with
   ``tool="delete_file"`` and ``severity="error"``.

If the verifier were ever loosened to "ignore unsealed tools", or if
the seal were extended to authorise ``delete_file``, this test would
fail — which is the teeth we want.

The fixture is built from the HANSARD paper description, NOT from the
witness's expected behaviour (see plan.md §Anti-AC-circular).
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_trace_witness.capture import CaptureEvent
from agent_trace_witness.graph import build_graph
from agent_trace_witness.seal import SealedSeal, seal_from_dict, verify_seal
from agent_trace_witness.verify import VerificationReport, verify_graph

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


# ---- helpers ---------------------------------------------------------------


def _load_seal() -> SealedSeal:
    """Load the seal fixture and rehydrate as ``SealedSeal``."""
    raw = (FIXTURES_DIR / "seal_without_damaging_tool.json").read_text(encoding="utf-8")
    return seal_from_dict(json.loads(raw))


def _load_events() -> list[CaptureEvent]:
    """Load the HANSARD scenario JSONL into ``CaptureEvent`` instances.

    Each JSONL line is an already-serialised event dict (the format
    written by ``capture._event_to_jsonl``). The witness re-hydrates
    them as dataclasses to feed ``build_graph``.
    """
    raw = (FIXTURES_DIR / "hansard_scenario_1.jsonl").read_text(encoding="utf-8")
    out: list[CaptureEvent] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out.append(
            CaptureEvent(
                ts=d["ts"],
                type=d["type"],
                tool=d.get("tool"),
                role=d.get("role"),
                payload_sha256=d["payload_sha256"],
                seal_ref=d["seal_ref"],
                unsealed=d.get("unsealed", False),
            )
        )
    return out


# ---- T074 — AC-9 main test ------------------------------------------------


def test_hansard_scenario_detected() -> None:
    """AC-9: the HANSARD attribution-laundering scenario produces:

    1. A verifiable seal (signature integrity baseline).
    2. A graph where the damaging call is a PROV Activity visible to
       any PROV-aware auditor, attributed to the witness, and marked
       ``atw:unsealed=true``.
    3. A verifier report containing an anomaly with
       ``tool="delete_file"`` and ``severity="error"``.

    These three properties together prove AC-9: the witness detects the
    anomaly AND preserves the causal chain. If either half fails, the
    test fails — which is the teeth.
    """
    seal = _load_seal()
    events = _load_events()

    # (1) The seal is verifiable.
    assert verify_seal(seal) is True, "seal fixture signature did not verify"

    # The witness_id matches the fixture's claim (defence against
    # accidental overwrites of the fixture).
    assert seal.witness_id == "witness-fixture-1", (
        f"seal fixture witness_id drift: got {seal.witness_id!r}"
    )

    # (2) The graph carries the damaging call as a visible Activity.
    graph = build_graph(events, seal)
    activity_nodes = [n for n in graph["@graph"] if n.get("@type") == "prov:Activity"]
    delete_activities = [a for a in activity_nodes if a.get("atw:tool") == "delete_file"]
    assert len(delete_activities) >= 1, (
        f"no prov:Activity with atw:tool=delete_file in graph "
        f"(found {len(activity_nodes)} activities total)"
    )
    delete_activity = delete_activities[0]
    # The damaging call is attributed to the witness and flagged unsealed.
    assert delete_activity["atw:unsealed"] is True, (
        "the delete_file activity must be marked atw:unsealed=true so "
        "the causal chain is honest about the policy violation"
    )
    assoc = delete_activity.get("prov:wasAssociatedWith", {})
    assert assoc.get("@id") == f"atw:agent/{seal.witness_id}", (
        f"delete_file activity attributed to wrong agent: {assoc}"
    )

    # And the args entity (the actual payload reference) is reachable
    # via prov:wasGeneratedBy from the same Activity. This is the
    # "causal chain" AC-9 requires: the verifier sees not just the
    # anomaly flag, but the exact call that produced the offending args.
    args_entity_id = delete_activity["@id"].replace("activity/", "entity/args_")
    args_entities = [n for n in graph["@graph"] if n.get("@id") == args_entity_id]
    assert len(args_entities) == 1, f"missing args entity {args_entity_id!r}; causal chain broken"
    assert args_entities[0].get("prov:wasGeneratedBy", {}).get("@id") == delete_activity["@id"]

    # (3) The verifier reports the anomaly with the right severity.
    report = verify_graph(graph, seal)
    assert isinstance(report, VerificationReport)
    delete_anomalies = [a for a in report.anomalies if a.tool == "delete_file"]
    assert len(delete_anomalies) >= 1, (
        f"verify_graph did not flag delete_file; got anomalies: {report.anomalies}"
    )
    anomaly = delete_anomalies[0]
    assert anomaly.severity == "error", (
        f"delete_file anomaly should be severity=error, got {anomaly.severity}"
    )

    # And the summary line is informative (not just "no anomalies").
    assert "no anomalies" not in report.summary.lower(), (
        f"verify_graph summary suggests clean trace but an unsealed tool "
        f"was used: summary={report.summary!r}"
    )


# ---- additional fixture-shape invariants ---------------------------------


def test_seal_fixture_authorises_only_benign_tools() -> None:
    """Defence against accidental overwrites: the seal fixture must
    NOT list ``delete_file``. If a future "fix" added it to the seal,
    AC-9 would silently start passing because the verifier would no
    longer flag the damaging call.
    """
    seal = _load_seal()
    tool_names = {t.name for t in seal.tools}
    assert tool_names == {"read_file", "list_dir"}, (
        f"seal fixture must authorise ONLY read_file + list_dir, got {tool_names}"
    )
    assert "delete_file" not in tool_names


def test_hansard_scenario_has_six_events() -> None:
    """The HANSARD fixture models attribution laundering with 6 events
    (3 tool_calls + 3 tool_responses, interleaved). If anyone shortens
    the fixture to "make the test pass", the causal chain is no longer
    the multi-step scenario the paper describes.
    """
    events = _load_events()
    assert len(events) == 6, f"expected 6 events, got {len(events)}"

    types = [e.type for e in events]
    assert types.count("tool_call") == 3, f"expected 3 tool_call, got {types.count('tool_call')}"
    assert types.count("tool_response") == 3, (
        f"expected 3 tool_response, got {types.count('tool_response')}"
    )

    # The damaging call (``delete_file``) MUST be in the trace. If a
    # future "fix" drops it, AC-9 stops being about attribution
    # laundering.
    tools_used = [e.tool for e in events]
    assert "delete_file" in tools_used, (
        f"delete_file must appear in the fixture, got tools={tools_used}"
    )


def test_delete_file_event_is_marked_unsealed_in_fixture() -> None:
    """The capture layer sets ``unsealed=True`` for tools not in the
    seal. The fixture encodes this in JSON. If the fixture's
    ``unsealed`` flag is wrong (e.g. someone hand-edits it to false),
    the test would still pass — but the graph would LIE about the
    anomaly. This test pins the fixture's honesty.
    """
    events = _load_events()
    delete_calls = [e for e in events if e.tool == "delete_file" and e.type == "tool_call"]
    assert len(delete_calls) == 1, (
        f"expected exactly 1 delete_file tool_call, got {len(delete_calls)}"
    )
    assert delete_calls[0].unsealed is True, (
        "fixture's delete_file tool_call must have unsealed=true "
        "(capture layer decided the tool was not in the seal)"
    )


def test_all_fixture_events_share_one_seal_ref() -> None:
    """Every event in the JSONL must point to the same seal — if any
    event leaks a different seal_ref, the trace is incoherent (events
    captured under different seals should not be merged into one
    graph).
    """
    events = _load_events()
    refs = {e.seal_ref for e in events}
    assert len(refs) == 1, f"events must all share one seal_ref; got {refs}"


def test_verify_graph_summary_is_informative_on_no_anomalies(
    tmp_path: Path,
) -> None:
    """Inverse test: a clean trace (no unsealed tools) yields a
    ``"no anomalies"`` summary. Catches false positives where the
    verifier flags benign behaviour.
    """
    from agent_trace_witness.capture import run_capture
    from agent_trace_witness.seal import AgentSpec, Tool, make_seal, sign_seal
    from tests.fixtures.mcp_client import MockMCPClient

    spec = AgentSpec(
        system_prompt="clean",
        tools=(Tool(name="read_file"), Tool(name="list_dir")),
        witness_id="witness-clean-test",
    )
    seal = sign_seal(make_seal(spec, created_at="2026-08-30T14:33:00+00:00"))
    events = run_capture(
        MockMCPClient(),
        seal,
        [
            ("tool_call", "read_file", {"x": 1}),
            ("tool_response", "read_file", "r"),
            ("tool_call", "list_dir", {"y": 2}),
            ("tool_response", "list_dir", "[]"),
        ],
    )
    graph = build_graph(events, seal)
    report = verify_graph(graph, seal)
    assert report.anomalies == []
    assert report.summary == "no anomalies"
