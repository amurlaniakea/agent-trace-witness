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

"""Witness verify: anomaly detection against the seal (T070-T071).

This module sits between the graph (PROV-DM JSON-LD, see ``graph.py``)
and the operator who wants a verdict: "does this trace look like it
followed the contract the seal agreed to?".

The MVP detects ONE anomaly class (T070): tool calls in the trace that
are NOT in the seal's authorised tool list (``detect_unsealed_tools``).
Future features add more checks (orphan responses, time anomalies,
broken causal chains) — they plug into ``verify_graph`` by appending
to the ``anomalies`` list.

The re-exported ``Anomaly`` dataclass (defined in ``seal.py``) keeps a
single shape across the package: every anomaly has a ``tool`` name, a
``severity`` (``"error"`` or ``"warning"``), and a ``detail`` string.

This module is the bridge that turns the B1 interin
``detect_unsealed_tools(tools_used, seal)`` helper (operates on an
iterable of tool names) into the spec-required
``detect_unsealed_tools(graph, seal)`` (operates on a JSON-LD graph
dict).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .exceptions import WitnessGraphError
from .seal import Anomaly, SealedSeal
from .seal import detect_unsealed_tools as _detect_unsealed_tools_from_seal

if TYPE_CHECKING:
    pass  # keeps symmetry with seal.py / capture.py / graph.py

# Public API.
__all__ = [
    "VerificationReport",
    "detect_unsealed_tools",
    "extract_tools_from_graph",
    "verify_graph",
    "verify_seal",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationReport:
    """Result of ``verify_graph`` (T071).

    ``anomalies`` is the FULL list of every check that failed (errors
    AND warnings). ``summary`` is a one-line human-readable description
    suitable for stdout in ``witness verify``.

    The MVP intentionally treats anomalies as REPORT-ONLY: the verifier
    does NOT raise on an anomaly. The caller decides what to do with
    them (block a deploy, raise an alert, etc.). The MVP's CLI
    (``witness verify``) prints the summary and exits 0 even when
    anomalies are present — see tasks.md T085.
    """

    anomalies: list[Anomaly] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_prov_activity(node: dict) -> bool:
    """True iff the node is a PROV Activity carrying an ``atw:tool``."""
    t = node.get("@type", "")
    if not isinstance(t, str):
        return False
    if not t.startswith("prov:"):
        return False
    short = t.split(":", 1)[1]
    return short == "Activity" and "atw:tool" in node


def extract_tools_from_graph(graph: dict) -> list[str]:
    """Extract the tool names referenced by every Activity in the graph.

    Returns the names in document order (the order the nodes appear in
    ``graph["@graph"]``). Duplicates are KEPT — the caller can dedupe
    if needed. ``detect_unsealed_tools`` dedupes internally, so feeding
    duplicates is safe.

    Empty list if the graph has no Activities (e.g. an empty events list
    or a graph that only carries the witness Agent).
    """
    if not isinstance(graph, dict):
        raise WitnessGraphError(f"graph must be a dict, got {type(graph).__name__}")
    nodes = graph.get("@graph", [])
    if not isinstance(nodes, list):
        raise WitnessGraphError(f"graph['@graph'] must be a list, got {type(nodes).__name__}")

    tools: list[str] = []
    for n in nodes:
        if _is_prov_activity(n):
            tool = n["atw:tool"]
            if isinstance(tool, str):
                tools.append(tool)
    return tools


# ---------------------------------------------------------------------------
# Public API (T070, T071)
# ---------------------------------------------------------------------------


def detect_unsealed_tools(graph: dict, seal: SealedSeal) -> list[Anomaly]:
    """Detect tool calls in the graph that were not authorised by the seal.

    This is the T070 wrapper around the B1 interin function (same name,
    different signature). The B1 version (in ``seal.py``) takes an
    ``Iterable[str]``; this one takes a JSON-LD graph dict and extracts
    the tool names itself via ``extract_tools_from_graph``.

    The contract is stable (same as the B1 interin):

    - ``severity == "error"`` for tools used but not in the seal.
    - Duplicates are deduplicated.
    - ``Anomaly.detail`` names the offending tool.

    Raises ``WitnessGraphError`` if ``graph`` is not a dict (malformed
    input) or ``seal`` is not a ``SealedSeal``.
    """
    if not isinstance(seal, SealedSeal):
        raise WitnessGraphError(f"seal must be a SealedSeal, got {type(seal).__name__}")
    tools_used = extract_tools_from_graph(graph)
    return _detect_unsealed_tools_from_seal(tools_used, seal)


def verify_graph(graph: dict, seal: SealedSeal) -> VerificationReport:
    """Run every anomaly check against the graph (T071).

    MVP checks:

    - unsealed tools (T070).

    The report aggregates ALL anomalies (errors + warnings). The
    ``summary`` is a short, single-line human description suitable for
    ``witness verify`` stdout.

    Raises ``WitnessGraphError`` only for malformed input (graph not a
    dict, seal wrong type). Anomalies themselves never raise.
    """
    if not isinstance(seal, SealedSeal):
        raise WitnessGraphError(f"seal must be a SealedSeal, got {type(seal).__name__}")

    anomalies: list[Anomaly] = []
    anomalies.extend(detect_unsealed_tools(graph, seal))

    # Summary line. n errors / n warnings; if none, "no anomalies".
    n_errors = sum(1 for a in anomalies if a.severity == "error")
    n_warnings = sum(1 for a in anomalies if a.severity == "warning")
    if not anomalies:
        summary = "no anomalies"
    else:
        parts: list[str] = []
        if n_errors:
            parts.append(f"{n_errors} error(s)")
        if n_warnings:
            parts.append(f"{n_warnings} warning(s)")
        summary = ", ".join(parts) + " detected"

    return VerificationReport(anomalies=anomalies, summary=summary)


def verify_seal(sealed: SealedSeal, key: str | None = None) -> bool:
    """Re-export of ``seal.verify_seal`` for callers that import
    ``verify`` as the single entry point for verification. Defers to
    the canonical implementation in ``seal.py`` — does not duplicate
    the HMAC machinery here.
    """
    from .seal import verify_seal as _verify_seal

    return _verify_seal(sealed, key)
