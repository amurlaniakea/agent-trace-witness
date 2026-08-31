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

"""Real MCP client — adapter stdio (T030, AC-13) — estado 002.

Implementa ``MCPClient`` Protocol (mismo contrato que MockMCPClient) sin
importar codigo del agente (C1) y sin patch dinamico. En 002 solo stdio;
SSE queda explícitamente fuera (ver spec.md No-Goals, pertenece a 003+).

Estado honesto en 002 (C5):

- **Cassette (CI, implementado):** ``RealMCPClient.from_cassette(path)``
  lee JSONL congelado ``tests/fixtures/cassettes/*.jsonl`` sin red, sin
  ``ATW_RECORD``, sin credenciales. Cada linea es un EventTuple
  serializado ``{"timestamp": ..., "type": ..., "payload": <hex|json>}``.
  Este es el unico modo con transporte real en 002.
- **Live stdio (NO implementado en 002):** el spawn de subprocess MCP via
  stdio (Popen + lectura stdin/stdout + parsing protocolo MCP) es TODO y
  pertenece a 003+ o a un follow-up de 002 si se prioriza. El nombre
  ``RealMCPClient`` no implica que hoy hable con un servidor real; en 002
  es cassette + memoria, mismo patron que MockMCPClient pero con fichero
  congelado en vez de eventos sinteticos en test. Ver KNOWN_ISSUES §6.

El adapter no importa agente/LLM ni hace patch dinamico — verificado por
``test_capture_architecture.py``.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .capture import CHOKE_POINT_EVENT_TYPES, EventTuple

WITNESS_TS_ENV = "ATW_WITNESS_TS"


def _now_or_frozen_ts(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get(WITNESS_TS_ENV)
    if env:
        return env
    return datetime.now(UTC).isoformat()


def _payload_to_bytes(payload: Any) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        # Riesgo conocido (no bloqueante B3): heuristica "si parece hex par
        # solo [0-9a-fA-F] decodifica como hex" puede colisionar con una
        # palabra legitima par solo-hex (poco comun pero posible). No se
        # corrige en 002 para no romper cassettes existentes; queda anotado
        # en KNOWN_ISSUES §6 junto al gap live-stdio. Fix futuro: marcar
        # payloads hex con prefijo explicito o tipo aparte.
        try:
            if len(payload) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in payload):
                return bytes.fromhex(payload)
        except Exception:
            pass
        return payload.encode("utf-8")
    # dict / list -> canonical json
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_event_tuple(obj: dict[str, Any]) -> EventTuple:
    ts = obj.get("timestamp") or obj.get("ts") or _now_or_frozen_ts()
    typ = obj.get("type")
    if typ not in CHOKE_POINT_EVENT_TYPES:
        raise ValueError(f"cassette type must be one of {CHOKE_POINT_EVENT_TYPES}, got {typ!r}")
    payload_raw = obj.get("payload")
    # payload en cassette puede ser hex string, json string, dict, o bytes
    if isinstance(payload_raw, str):
        # intenta hex -> bytes, si falla utf-8
        try:
            if (
                len(payload_raw) % 2 == 0
                and all(c in "0123456789abcdefABCDEF" for c in payload_raw)
                and payload_raw
            ):
                b = bytes.fromhex(payload_raw)
                # si original era str, el hex decode produciría bytes que no son json; mantenemos bytes tal cual
                # El caller no distingue, payload es bytes opaco
                payload = b
            else:
                payload = payload_raw.encode("utf-8")
        except Exception:
            payload = payload_raw.encode("utf-8")
    elif isinstance(payload_raw, dict):
        payload = json.dumps(payload_raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(payload_raw, bytes):
        payload = payload_raw
    else:
        payload = (
            json.dumps(payload_raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if payload_raw is not None
            else b""
        )
    return EventTuple(timestamp=ts, type=typ, payload=payload)


class RealMCPClient:
    """Adapter stdio que implementa MCPClient Protocol (AC-13) — 002 cassette-only.

    CI usa ``from_cassette`` (JSONL congelado). Live subprocess stdio no
    implementado en 002; ver docstring de modulo y KNOWN_ISSUES §6 (C5).
    """

    def __init__(self, cassette: Path | None = None) -> None:
        self._events: list[EventTuple] = []
        self._cassette = cassette
        if cassette is not None and cassette.exists():
            self._load_cassette(cassette)

    @classmethod
    def from_cassette(cls, path: Path | str) -> RealMCPClient:
        p = Path(path)
        return cls(cassette=p)

    def _load_cassette(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            ev = _load_event_tuple(obj)
            self._events.append(ev)

    # -- MCPClient Protocol implementation (5 methods) -----------------------

    def record_tool_call(self, tool: str, args: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = json.dumps(
            {"tool": tool, "args": args}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="tool_call", payload=payload)
        self._events.append(ev)
        return ev

    def record_tool_response(self, tool: str, result: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = json.dumps(
            {"tool": tool, "result": result}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="tool_response", payload=payload)
        self._events.append(ev)
        return ev

    def record_model_input(self, content: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = json.dumps(
            {"role": "user", "content": content}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="model_input", payload=payload)
        self._events.append(ev)
        return ev

    def record_model_output(self, content: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = json.dumps(
            {"role": "assistant", "content": content}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="model_output", payload=payload)
        self._events.append(ev)
        return ev

    def record_external_effect(
        self, tool: str, effect: Any, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = json.dumps(
            {"tool": tool, "effect": effect}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="external_effect", payload=payload)
        self._events.append(ev)
        return ev

    def events(self) -> list[EventTuple]:
        return list(self._events)
