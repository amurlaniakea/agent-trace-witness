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

"""Witness replay: counterfactual engine — mecanismo 4 HANSARD (T020-T021).

Opera sobre el grafo PROV-DM JSON-LD ya emitido por ``graph.build_graph``,
no sobre el JSONL crudo (C2). Dada una actividad ``tool_call`` a eliminar,
produce:

- ``compensation_set``: subgrafo que excluye la Activity y todo lo que
  ``wasGeneratedBy`` / ``used`` desde ella (args, result, external_effect).
- ``synergy_residual``: booleano cualitativo — true si queda algún
  ``atw:externalEffect`` no eliminado (proxy de mecanismo 5 sin scoring
  numérico; full scoring es 003+).
- ``not_replayable``: IDs que no se pudieron replayar (C5 honestidad).

Determinismo (C4/AC-7/AC-12): sin RNG, sin ``time``, serialización
canónica ``sort_keys=True``. 10× mismo input → mismo output byte a byte.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .exceptions import WitnessReplayError
from .seal import SealedSeal


@dataclass(frozen=True)
class Counterfactual:
    """Qué eliminar del grafo (T020).

    ``remove`` es el ``@id`` de una ``prov:Activity`` de tipo
    ``tool_call`` (ej. ``atw:activity/tool_call_1``). Ver plan.md
    §Decisión abierta: el CLI hoy expone este URI; el engine acepta
    también un dict ``{\"remove\": \"…\"}`` para no acoplar tests al
    tipado.
    """

    remove: str


@dataclass(frozen=True)
class ReplayResult:
    """Resultado de ``replay`` (T020).

    ``compensation_set`` es un JSON-LD dict (``@context`` + ``@graph``)
    determinista. ``synergy_residual`` es booleano cualitativo (true
    si queda externalEffect tras la eliminación). ``not_replayable``
    lista IDs no replayables (C5).
    """

    compensation_set: dict[str, Any]
    synergy_residual: bool | dict[str, Any]
    not_replayable: list[str]


def _as_counterfactual(cf: Counterfactual | dict[str, Any]) -> Counterfactual:
    if isinstance(cf, Counterfactual):
        return cf
    if isinstance(cf, dict) and "remove" in cf and isinstance(cf["remove"], str):
        return Counterfactual(remove=cf["remove"])
    raise WitnessReplayError(
        f"counterfactual must be Counterfactual or {{remove: str}}, got {cf!r}"
    )


def replay(
    graph: dict[str, Any],
    counterfactual: Counterfactual | dict[str, Any],
    seal: SealedSeal | None = None,
) -> ReplayResult:
    """Replay contrafactual sobre un grafo PROV-DM (T020-T021).

    - Valida que ``graph`` sea un JSON-LD con ``@graph`` list.
    - Si ``counterfactual.remove`` no existe en ``@graph`` como
      ``prov:Activity``, retorna ``not_replayable=[remove]`` y
      ``compensation_set`` = grafo original (sin inventar).
    - En caso contrario, excluye la Activity + todo nodo con
      ``prov:wasGeneratedBy == remove`` o ``prov:used == remove``
      (args, result, external_effect directos). No hace transitividad
      profunda (grafo pequeño HANSARD, R13) — suficiente para AC-12.

    ``seal`` es opcional en 002 (validación seal-constrained queda para
    verify.py si se integra); si se pasa y no es ``SealedSeal``, se
    rechaza (defensa de tipado).
    """
    cf = _as_counterfactual(counterfactual)

    if (
        not isinstance(graph, dict)
        or "@graph" not in graph
        or not isinstance(graph["@graph"], list)
    ):
        raise WitnessReplayError("graph must be a JSON-LD dict with @graph list")

    if seal is not None and not isinstance(seal, SealedSeal):
        raise WitnessReplayError(f"seal must be SealedSeal or None, got {type(seal).__name__}")

    if not cf.remove or not isinstance(cf.remove, str):
        raise WitnessReplayError("counterfactual.remove must be a non-empty string")

    nodes: list[dict[str, Any]] = graph["@graph"]
    context = graph.get("@context", {})

    # Índice rápido de IDs
    ids = {n.get("@id") for n in nodes if isinstance(n, dict) and "@id" in n}

    if cf.remove not in ids:
        # C5: no se puede replayar — no inventar
        return ReplayResult(
            compensation_set={"@context": context, "@graph": list(nodes)},
            synergy_residual=False,
            not_replayable=[cf.remove],
        )

    # Verificar que el nodo a eliminar sea Activity (si no, también not_replayable)
    target = next((n for n in nodes if n.get("@id") == cf.remove), None)
    if target is None or target.get("@type") != "prov:Activity":
        return ReplayResult(
            compensation_set={"@context": context, "@graph": list(nodes)},
            synergy_residual=False,
            not_replayable=[cf.remove],
        )

    remove_id = cf.remove

    def _is_removed(n: dict[str, Any]) -> bool:
        if n.get("@id") == remove_id:
            return True
        was = n.get("prov:wasGeneratedBy")
        if isinstance(was, dict) and was.get("@id") == remove_id:
            return True
        used = n.get("prov:used")
        if isinstance(used, dict) and used.get("@id") == remove_id:
            return True
        return False

    kept = [n for n in nodes if not _is_removed(n)]

    # synergy_residual booleano: true si queda algún externalEffect tras la poda
    residual = any(n.get("atw:externalEffect") is True for n in kept if isinstance(n, dict))

    # compensation_set determinista: ordenar por @id para que 10× sea byte-idéntico
    # (el grafo de entrada ya es determinista por build_graph, pero ordenar
    # evita dependencia del orden de filtrado si en el futuro hay múltiples removes)
    kept_sorted = sorted(kept, key=lambda n: n.get("@id", ""))

    comp = {"@context": context, "@graph": kept_sorted}

    return ReplayResult(
        compensation_set=comp,
        synergy_residual=residual,
        not_replayable=[],
    )


def replay_to_json(result: ReplayResult) -> str:
    """Serializa ``ReplayResult`` a JSON canónico (sort_keys, sin RNG)."""
    return json.dumps(
        {
            "compensation_set": result.compensation_set,
            "synergy_residual": result.synergy_residual,
            "not_replayable": result.not_replayable,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
