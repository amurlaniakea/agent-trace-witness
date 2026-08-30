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

"""Witness graph: PROV-DM JSON-LD emitter (T050-T054).

Builds a W3C PROV-DM compliant causal graph from the capture layer's
events and a sealed seal. The output is a ``dict`` (later serialised to
JSON-LD by ``graph_to_jsonld``) that is interoperable with PROV tools
(PROV Toolbox, prov-pip, etc.) via the standard ``prov:`` namespace.

Mapping rules (per spec.md §AC-6 + tasks.md T051-T053):

- 1 ``prov:Agent`` for the witness (always emitted, identified by
  ``seal.witness_id``).
- For each ``tool_call`` event:
  - 1 ``prov:Activity`` with ``prov:wasAssociatedWith`` → the witness
    Agent. Carries ``atw:tool`` and ``atw:unsealed``.
  - 1 ``prov:Entity`` for the call arguments, with
    ``prov:wasGeneratedBy`` → the Activity.
- For each ``tool_response`` event:
  - 1 ``prov:Entity`` for the response result, with ``prov:used`` →
    the most-recent unmatched tool_call Activity (positional pairing).
- For each ``model_input`` / ``model_output`` event:
  - 1 ``prov:Entity`` with ``prov:wasAttributedTo`` → the witness
    Agent. Carries ``atw:role`` (user / assistant / system).

C2: the graph is the PRIMARY representation of the trace. It is JSON-LD
with the standard ``prov:`` namespace, so any PROV-compliant tool can
consume it. The MVP does NOT use ``rdflib`` (no runtime deps for the
graph layer); validation is by manual inspection of the emitted JSON
plus a minimal JSON-LD parser in ``tests/test_graph.py``.

Determinism (AC-7): the graph has NO dependency on wall-clock time,
RNG, or external state. Two runs on the same ``events`` + ``seal``
produce byte-identical JSON-LD (T058).
"""

from __future__ import annotations

import json
from typing import Any

from .capture import CHOKE_POINT_EVENT_TYPES, CaptureEvent
from .seal import SealedSeal

# Public API.
__all__ = [
    "PROV_NS",
    "ATW_NS",
    "build_graph",
    "graph_to_jsonld",
]

# Standard W3C PROV-DM namespace URI. Per spec.md §API/Interfaces.
PROV_NS = "http://www.w3.org/ns/prov#"

# atw: compact namespace for this project. The URL is the spec.md URL;
# the actual vocabulary is implicit (atw:tool, atw:role, atw:unsealed).
# Per spec.md §API/Interfaces.
ATW_NS = "https://amurlaniakea.github.io/agent-trace-witness/vocab#"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iri_id(local: str) -> str:
    """Prefix a local name with the ``atw:`` compact namespace.

    The resulting value is what PROV serialises as ``{"@id": "atw:X"}``
    inside a JSON-LD document. We keep the compact form in the dict so
    the graph stays human-readable in logs; ``graph_to_jsonld`` expands
    it (or, more accurately, leaves it as the @id value, since compact
    IRIs are valid in JSON-LD when the @context is in scope).
    """
    return f"atw:{local}"


def _node(node_id: str, type_: str, **extra: Any) -> dict:
    """Build a PROV node dict with @id and @type, plus extras."""
    out: dict = {"@id": node_id, "@type": type_}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_graph(events: list[CaptureEvent], seal: SealedSeal) -> dict:
    """Build a PROV-DM JSON-LD graph from capture events (T050).

    Returns a dict shaped as a JSON-LD document with:

    - ``@context``: compact IRIs for ``prov:`` and ``atw:``.
    - ``@graph``: list of PROV nodes (Agent, Activity, Entity).

    The graph is COMPLETE: every emitted event becomes at least one
    node. The graph is DETERMINISTIC: same inputs → same dict, byte for
    byte, every time (no RNG, no wall clock).

    The ``seal`` argument is required (not just the seal_ref) so the
    graph can carry the witness identity (``seal.witness_id``) and the
    tool authorisations (``seal.tools``) — needed to compute the
    ``atw:unsealed`` flag consistently with the capture layer.
    """
    if not isinstance(seal, SealedSeal):
        raise TypeError(f"seal must be a SealedSeal, got {type(seal).__name__}")

    witness_id = _iri_id(f"agent/{seal.witness_id}")
    graph_nodes: list[dict] = []

    # -- prov:Agent for the witness ----------------------------------------
    graph_nodes.append(
        _node(
            witness_id,
            "prov:Agent",
            **{"atw:witness_id": seal.witness_id},
        )
    )

    # Counters give stable, content-independent URIs (no RNG, no clock).
    counters = {kind: 0 for kind in CHOKE_POINT_EVENT_TYPES}
    # Open tool_call activities paired LIFO with tool_responses.
    #
    # Each ``tool_call`` is pushed onto ``open_tool_calls``; each
    # ``tool_response`` pops the MOST RECENTLY pushed open call
    # (``list.pop()`` with no index pops from the end). This means
    # the n-th tool_response in a sequence is paired with the n-th
    # tool_call counting backwards from the current position.
    #
    # Example (events in this order):
    #   tool_call_1, tool_call_2, tool_response_1, tool_response_2
    # → response_1 pairs with call_2 (most recent open)
    # → response_2 pairs with call_1 (next most recent open)
    #
    # Why LIFO and not FIFO?  See plan.md §Decisiones de diseño and
    # tasks.md T052 ("la Activity previa") — the semantics chosen by
    # the MVP are: a response is attributed to the immediately
    # preceding open call, which matches the natural causal intuition
    # for sequential MCP traces. Feature 002 will need to extend this
    # if real MCP clients emit concurrent or nested calls (then an
    # explicit ``call_id`` must replace positional pairing).
    open_tool_calls: list[str] = []

    for ev in events:
        if ev.type not in CHOKE_POINT_EVENT_TYPES:
            # Unknown event type — skip rather than abort. The capture
            # layer rejects unknowns at write time (T036); reaching here
            # means a caller passed a hand-built CaptureEvent. Forward
            # compatibility: don't fail the whole graph for one odd
            # event.
            continue

        counters[ev.type] += 1
        n = counters[ev.type]

        if ev.type == "tool_call":
            assert ev.tool is not None, "tool_call event must carry tool"
            activity_id = _iri_id(f"activity/tool_call_{n}")
            args_entity_id = _iri_id(f"entity/args_tool_call_{n}")

            graph_nodes.append(
                _node(
                    activity_id,
                    "prov:Activity",
                    **{
                        "prov:wasAssociatedWith": {"@id": witness_id},
                        "atw:tool": ev.tool,
                        "atw:unsealed": ev.unsealed,
                        "atw:payload_sha256": ev.payload_sha256,
                    },
                )
            )
            graph_nodes.append(
                _node(
                    args_entity_id,
                    "prov:Entity",
                    **{
                        "prov:wasGeneratedBy": {"@id": activity_id},
                        "atw:tool": ev.tool,
                        "atw:payload_sha256": ev.payload_sha256,
                    },
                )
            )
            open_tool_calls.append(activity_id)

        elif ev.type == "tool_response":
            assert ev.tool is not None, "tool_response event must carry tool"
            result_entity_id = _iri_id(f"entity/result_tool_response_{n}")

            # Pair with the most recent open tool_call. If there is
            # none, the response is unattached (orphan) — we still emit
            # the entity but with no ``prov:used`` arrow. This makes the
            # anomaly visible to the verifier.
            used: dict | None = None
            if open_tool_calls:
                paired = open_tool_calls.pop()
                used = {"@id": paired}

            extra: dict[str, Any] = {
                "atw:tool": ev.tool,
                "atw:payload_sha256": ev.payload_sha256,
            }
            if used is not None:
                extra["prov:used"] = used
            graph_nodes.append(_node(result_entity_id, "prov:Entity", **extra))

        elif ev.type == "model_input":
            assert ev.role is not None, "model_input event must carry role"
            entity_id = _iri_id(f"entity/model_input_{n}")
            graph_nodes.append(
                _node(
                    entity_id,
                    "prov:Entity",
                    **{
                        "prov:wasAttributedTo": {"@id": witness_id},
                        "atw:role": ev.role,
                        "atw:payload_sha256": ev.payload_sha256,
                        "atw:ts": ev.ts,
                    },
                )
            )

        elif ev.type == "model_output":
            assert ev.role is not None, "model_output event must carry role"
            entity_id = _iri_id(f"entity/model_output_{n}")
            graph_nodes.append(
                _node(
                    entity_id,
                    "prov:Entity",
                    **{
                        "prov:wasAttributedTo": {"@id": witness_id},
                        "atw:role": ev.role,
                        "atw:payload_sha256": ev.payload_sha256,
                        "atw:ts": ev.ts,
                    },
                )
            )

    return {
        "@context": {
            "prov": PROV_NS,
            "atw": ATW_NS,
        },
        "@graph": graph_nodes,
    }


def graph_to_jsonld(graph: dict) -> str:
    """Serialise a graph dict to canonical JSON-LD text (T054).

    ``sort_keys=True`` is mandatory: the verifier (B4) and tests rely on
    byte-stable output (AC-7 determinism). ``ensure_ascii=False`` keeps
    non-ASCII content (e.g. a witness_id in Spanish) as-is; the witness
    does not embed any non-ASCII content in the graph itself, but the
    setting is defensive against future extensions.
    """
    return json.dumps(
        graph,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
