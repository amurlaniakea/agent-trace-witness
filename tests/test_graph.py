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

"""Graph tests — AC-5, AC-6, partial AC-7 (T055-T058).

The MVP does NOT use ``rdflib`` (no runtime deps). Validation is by
manual inspection of the emitted JSON-LD plus structural assertions on
the dict shape. If a future feature wants ``rdflib`` for stronger
guarantees, feature 002 can opt in.
"""

from __future__ import annotations

import json

import pytest

from agent_trace_witness.capture import run_capture
from agent_trace_witness.graph import ATW_NS, PROV_NS, build_graph, graph_to_jsonld
from agent_trace_witness.seal import AgentSpec, SealedSeal, Tool, make_seal, sign_seal
from tests.fixtures.mcp_client import MockMCPClient

# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def sealed() -> SealedSeal:
    """A pre-signed seal with two tools. Used by every graph test."""
    spec = AgentSpec(
        system_prompt="Eres un asistente que solo lee archivos del directorio /data.",
        tools=(
            Tool(name="read_file", scopes=("read:/data/**",)),
            Tool(name="list_dir", scopes=("read:/data/**",)),
        ),
        witness_id="witness-graph-test",
    )
    return sign_seal(make_seal(spec, created_at="2026-08-30T14:33:00+00:00"))


@pytest.fixture
def simple_events(sealed: SealedSeal) -> tuple[MockMCPClient, list]:
    """A scenario with one tool_call + one tool_response + one
    model_input + one model_output, plus the mock client (so the
    test can re-use the events list).

    Teeth: AC-6 reads these events; if ``run_capture`` is broken, both
    this fixture and AC-6 fail.
    """
    client = MockMCPClient()
    events = run_capture(
        client,
        sealed,
        [
            ("tool_call", "read_file", {"path": "/data/x"}),
            ("tool_response", "read_file", "contents-of-x"),
            ("model_input", "", "hola"),
            ("model_output", "", "adios"),
        ],
    )
    return client, events


# ---- helpers ---------------------------------------------------------------


def _nodes_by_type(graph: dict) -> dict[str, list[dict]]:
    """Group @graph nodes by their @type (stripped of the ``prov:`` prefix).

    Returns a dict like ``{"Agent": [...], "Activity": [...], "Entity": [...]}``.
    Missing types map to empty lists.
    """
    by_type: dict[str, list[dict]] = {"Agent": [], "Activity": [], "Entity": []}
    for n in graph.get("@graph", []):
        t = n.get("@type", "")
        if ":" in t:
            t = t.split(":", 1)[1]
        if t in by_type:
            by_type[t].append(n)
    return by_type


def _find_node(nodes: list[dict], atw_local: str) -> dict | None:
    """Find a node whose @id is ``atw:<atw_local>``. None if absent."""
    target = f"atw:{atw_local}"
    for n in nodes:
        if n.get("@id") == target:
            return n
    return None


# ---- T055 — AC-5 base: PROV-DM context is emitted -------------------------


def test_graph_has_prov_dm_context(sealed: SealedSeal) -> None:
    """AC-5 base: the graph's @context must include the standard
    PROV-DM namespace URI ``http://www.w3.org/ns/prov#``.

    Teeth: if the @context is changed to a wrong URI, the assertion
    fails and the verifier (B4) would also break.
    """
    graph = build_graph([], sealed)
    ctx = graph["@context"]

    assert PROV_NS in ctx.values(), f"@context must include PROV_NS ({PROV_NS!r}), got {ctx}"
    # And the atw: namespace, per spec.md.
    assert ATW_NS in ctx.values(), f"@context must include ATW_NS ({ATW_NS!r}), got {ctx}"


# ---- T056 — AC-5 full: all three PROV node types present ------------------


def test_graph_has_all_three_node_types(sealed: SealedSeal) -> None:
    """AC-5 full: the graph contains at least one node of each of
    ``prov:Entity``, ``prov:Activity``, ``prov:Agent``.

    The witness Agent is always present (B3 design). Activities and
    Entities appear when there is at least one tool_call in the events.
    """
    graph = build_graph(
        [
            *run_capture(
                MockMCPClient(),
                sealed,
                [
                    ("tool_call", "read_file", {"path": "/data/x"}),
                    ("tool_response", "read_file", "contents"),
                    ("model_input", "", "hi"),
                    ("model_output", "", "bye"),
                ],
            )
        ],
        sealed,
    )
    by_type = _nodes_by_type(graph)

    assert len(by_type["Agent"]) >= 1, "no prov:Agent in the graph"
    assert len(by_type["Activity"]) >= 1, "no prov:Activity in the graph"
    assert len(by_type["Entity"]) >= 1, "no prov:Entity in the graph"


def test_graph_has_only_witness_agent_when_no_events(sealed: SealedSeal) -> None:
    """Edge case: an empty events list yields ONLY the witness Agent.
    Catches regressions that emit phantom entities for the missing events.
    """
    graph = build_graph([], sealed)
    by_type = _nodes_by_type(graph)
    assert len(by_type["Agent"]) == 1
    assert len(by_type["Activity"]) == 0
    assert len(by_type["Entity"]) == 0


# ---- T057 — AC-6: PROV relations correct ----------------------------------


def test_prov_dm_relations_correct(
    sealed: SealedSeal, simple_events: tuple[MockMCPClient, list]
) -> None:
    """AC-6: a tool_call + tool_response scenario produces:

    - 1 ``prov:Activity`` (the tool_call)
    - 1 ``prov:Entity`` for the call args, with
      ``prov:wasGeneratedBy`` → the Activity
    - 1 ``prov:Entity`` for the response result, with
      ``prov:used`` → the Activity

    This is the core of the causal graph. If the emitter drops or
    re-points any of these arrows, AC-6 is broken — and so is any
    downstream causal reconstruction (HANSARD mechanism 3).
    """
    _, events = simple_events
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)

    # One Activity.
    assert len(by_type["Activity"]) == 1, (
        f"expected 1 Activity for 1 tool_call, got {len(by_type['Activity'])}"
    )
    activity = by_type["Activity"][0]

    # The Activity carries wasAssociatedWith to the witness.
    assoc = activity.get("prov:wasAssociatedWith")
    assert assoc is not None, "Activity missing prov:wasAssociatedWith"
    assert assoc.get("@id") == f"atw:agent/{sealed.witness_id}", (
        f"Activity wasAssociatedWith wrong agent: {assoc}"
    )

    # Two tool Entities (args + result) + two model Entities.
    assert len(by_type["Entity"]) == 4, (
        f"expected 4 Entities (args + result + model_input + model_output), "
        f"got {len(by_type['Entity'])}"
    )

    # args entity has prov:wasGeneratedBy → the Activity.
    args_entity = _find_node(by_type["Entity"], "entity/args_tool_call_1")
    assert args_entity is not None, "missing entity/args_tool_call_1"
    wgb = args_entity.get("prov:wasGeneratedBy")
    assert wgb is not None, "args entity missing prov:wasGeneratedBy"
    assert wgb.get("@id") == activity["@id"], f"args entity wasGeneratedBy wrong Activity: {wgb}"

    # result entity has prov:used → the Activity.
    result_entity = _find_node(by_type["Entity"], "entity/result_tool_response_1")
    assert result_entity is not None, "missing entity/result_tool_response_1"
    used = result_entity.get("prov:used")
    assert used is not None, "result entity missing prov:used"
    assert used.get("@id") == activity["@id"], f"result entity used wrong Activity: {used}"


def test_prov_dm_relations_chain_across_multiple_calls(
    sealed: SealedSeal,
) -> None:
    """When multiple tool_call/tool_response pairs occur, each response
    pairs with the MOST RECENTLY OPENED unmatched call (LIFO / stack
    semantics). This pins the pairing semantics: a response always
    points to the most recent open call, not the first one.

    Example (4 events in order):
        tool_call_1, tool_call_2, tool_response_1, tool_response_2
    → response_1 pairs with call_2 (most recent open at that moment)
    → response_2 pairs with call_1 (next most recent open)
    """
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            ("tool_call", "read_file", {"n": 1}),
            ("tool_call", "list_dir", {"n": 2}),
            ("tool_response", "list_dir", "r2"),  # pairs with call 2
            ("tool_response", "read_file", "r1"),  # pairs with call 1
        ],
    )
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)
    activities = {a["@id"]: a for a in by_type["Activity"]}

    call_1 = "atw:activity/tool_call_1"
    call_2 = "atw:activity/tool_call_2"
    assert call_1 in activities and call_2 in activities

    # The first response (result_tool_response_1) should pair with
    # call_2 (most recent open at the moment of the response).
    # The second response (result_tool_response_2) should pair with
    # call_1 (next most recent open).
    r1 = _find_node(by_type["Entity"], "entity/result_tool_response_1")
    r2 = _find_node(by_type["Entity"], "entity/result_tool_response_2")
    assert r1 is not None and r2 is not None
    assert r1["prov:used"]["@id"] == call_2, (
        f"first response should pair with most-recent open call ({call_2}); "
        f"got {r1['prov:used']['@id']}"
    )
    assert r2["prov:used"]["@id"] == call_1


def test_orphan_tool_response_emits_entity_without_used(
    sealed: SealedSeal,
) -> None:
    """A tool_response without a preceding tool_call is an anomaly
    (the witness saw a result without seeing the call). The emitter
    still records the Entity but WITHOUT a ``prov:used`` arrow so the
    verifier (B4) can flag the orphan.
    """
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            ("tool_response", "read_file", "r"),  # no preceding tool_call
        ],
    )
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)
    result = _find_node(by_type["Entity"], "entity/result_tool_response_1")
    assert result is not None
    assert "prov:used" not in result, (
        "orphan tool_response must NOT have a prov:used arrow (would lie about the causal pairing)"
    )


# ---- T058 — AC-7 partial: graph is byte-deterministic ---------------------


def test_graph_is_deterministic(
    sealed: SealedSeal, simple_events: tuple[MockMCPClient, list]
) -> None:
    """AC-7 partial: 10 invocations of ``build_graph`` on the same inputs
    produce byte-identical output.

    This pins the determinism property for the graph layer. The contract
    holds because:

    1. Counters are plain integers (no RNG).
    2. Timestamps are NOT included in URIs (they live INSIDE nodes, not
       in their @id).
    3. ``graph_to_jsonld`` uses ``sort_keys=True``.
    """
    _, events = simple_events

    first = graph_to_jsonld(build_graph(events, sealed))
    for i in range(9):
        again = graph_to_jsonld(build_graph(events, sealed))
        assert again == first, (
            f"run {i + 1} differed from first:\n  first:   {first[:200]}\n  again:   {again[:200]}"
        )


def test_graph_to_jsonld_is_canonical(
    sealed: SealedSeal, simple_events: tuple[MockMCPClient, list]
) -> None:
    """Independent check: ``graph_to_jsonld`` produces sorted-key output.
    The verifier (B4) and external PROV tools depend on this for
    reproducible hashing.
    """
    _, events = simple_events
    out = graph_to_jsonld(build_graph(events, sealed))

    # Round-trip parse and verify key order at the top level.
    parsed = json.loads(out)
    top_keys = list(parsed.keys())
    assert top_keys == sorted(top_keys), f"top-level keys not sorted: {top_keys}"


# ---- additional PROV-shape invariants -------------------------------------


def test_witness_agent_carries_seal_identity(sealed: SealedSeal) -> None:
    """The witness Agent is identified by ``seal.witness_id`` — if the
    seal changes, the graph's Agent @id changes accordingly. This pins
    the binding.
    """
    graph = build_graph([], sealed)
    by_type = _nodes_by_type(graph)
    assert len(by_type["Agent"]) == 1
    agent = by_type["Agent"][0]
    assert agent["@id"] == f"atw:agent/{sealed.witness_id}"
    assert agent.get("atw:witness_id") == sealed.witness_id


def test_atw_tool_field_propagates_unsealed_flag(
    sealed: SealedSeal,
) -> None:
    """The ``atw:unsealed`` field on the tool_call Activity reflects the
    capture layer's flag. The graph does NOT recompute it (the capture
    layer already consulted the seal). This pins the propagation.
    """
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            ("tool_call", "delete_file", {"target": "/etc"}),  # NOT in seal
            ("tool_call", "read_file", {"x": 1}),  # IN seal
        ],
    )
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)
    activities = sorted(by_type["Activity"], key=lambda a: a["@id"])

    assert activities[0]["atw:tool"] == "delete_file"
    assert activities[0]["atw:unsealed"] is True
    assert activities[1]["atw:tool"] == "read_file"
    assert activities[1]["atw:unsealed"] is False


def test_model_events_have_role_and_attribution(sealed: SealedSeal) -> None:
    """Model events (model_input / model_output) carry ``atw:role`` and
    are attributed to the witness via ``prov:wasAttributedTo``.
    """
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            ("model_input", "", "hola"),
            ("model_output", "", "hola humano"),
        ],
    )
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)
    entities = sorted(by_type["Entity"], key=lambda e: e["@id"])

    mi = _find_node(entities, "entity/model_input_1")
    mo = _find_node(entities, "entity/model_output_1")
    assert mi is not None and mo is not None

    assert mi["atw:role"] == "user"
    assert mo["atw:role"] == "assistant"
    assert mi["prov:wasAttributedTo"]["@id"] == f"atw:agent/{sealed.witness_id}"
    assert mo["prov:wasAttributedTo"]["@id"] == f"atw:agent/{sealed.witness_id}"


def test_no_atw_iri_leaks_into_prov_namespace(sealed: SealedSeal) -> None:
    """PROV keys must start with ``prov:`` (not ``atw:``); atw: is the
    project's own vocabulary and must NOT pollute PROV. Catches a class
    of regressions where a custom field ends up in the standard
    namespace.
    """
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            ("tool_call", "read_file", {"x": 1}),
            ("tool_response", "read_file", "r"),
            ("model_input", "", "hi"),
            ("model_output", "", "bye"),
        ],
    )
    graph = build_graph(events, sealed)
    for node in graph["@graph"]:
        for k in node:
            if k.startswith("atw:"):
                continue
            if k.startswith("prov:"):
                continue
            if k in ("@id", "@type"):
                continue
            pytest.fail(f"unexpected non-PROV / non-atw key {k!r} in node {node}")


def test_build_graph_rejects_non_sealedseal() -> None:
    """Defence: ``build_graph`` requires a ``SealedSeal``, not any
    object with a ``witness_id`` attribute. Prevents accidental use of
    an unsigned Seal (which would be a C3 violation).
    """
    with pytest.raises(TypeError):
        build_graph([], "not a seal")  # type: ignore[arg-type]


# ---- counter sanity: total node count is bounded -------------------------


def test_node_count_is_bounded_by_events(sealed: SealedSeal) -> None:
    """A scenario with N events produces a known number of nodes:
    tool_call events emit 2 (Activity + args Entity); tool_response,
    model_input and model_output emit 1 each. Plus the witness Agent.

    This is a defensive check that catches bugs that emit duplicate
    nodes or phantom entities.
    """
    n = 5  # 5 of each type → 20 events total
    scenario = []
    for i in range(n):
        scenario.append(("tool_call", "read_file", {"i": i}))
        scenario.append(("tool_response", "read_file", f"r{i}"))
        scenario.append(("model_input", "", f"in{i}"))
        scenario.append(("model_output", "", f"out{i}"))

    events = run_capture(MockMCPClient(), sealed, scenario)
    graph = build_graph(events, sealed)

    # n tool_call → 2n nodes; n tool_response → n; n model_input → n;
    # n model_output → n; +1 Agent. Total: 5n + 1.
    expected = 2 * n + 1 * n + 1 * n + 1 * n + 1  # = 5n + 1
    assert expected == 5 * 5 + 1  # sanity: 26 for n=5
    assert len(graph["@graph"]) == expected, (
        f"expected {expected} nodes for {4 * n} events, got {len(graph['@graph'])}"
    )


def test_node_type_counts_match_choke_point_distribution(
    sealed: SealedSeal,
) -> None:
    """Cross-check: counts of each node type follow from the number of
    each event type. Pins the structural accounting.
    """
    n_tool = 3
    n_model = 2
    events = run_capture(
        MockMCPClient(),
        sealed,
        [
            *([("tool_call", "read_file", {"i": i}) for i in range(n_tool)]),
            *([("tool_response", "read_file", f"r{i}") for i in range(n_tool)]),
            *([("model_input", "", "in") for _ in range(n_model)]),
            *([("model_output", "", "out") for _ in range(n_model)]),
        ],
    )
    graph = build_graph(events, sealed)
    by_type = _nodes_by_type(graph)
    assert len(by_type["Agent"]) == 1
    assert len(by_type["Activity"]) == n_tool
    # tool_call args + tool_response result + model_input + model_output
    assert len(by_type["Entity"]) == n_tool + n_tool + n_model + n_model
