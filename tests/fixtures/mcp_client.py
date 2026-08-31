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

"""Mock MCP client fixture for agent-trace-witness tests (T030).

Implements the ``MCPClient`` protocol defined in
``agent_trace_witness.capture`` and emits the five choke-point event types
that the witness must capture (per HANSARD §5, mechanisms 1+2+3 of this
spec capture 4 of the 5 choke points; the 5th — external effect — is
feature 002, B1-capture).

CONTRACT for a real MCP client (feature 002 will replace this mock)
====================================================================

A real client must satisfy ``agent_trace_witness.capture.MCPClient``
(``typing.Protocol``). The five methods below are the minimal API the
witness needs. Anything beyond them is the client's concern, not the
witness's.

The five methods are stateless from the witness's point of view: each
call returns a fresh ``EventTuple`` and appends it to the client's
event log. The witness does NOT depend on the client maintaining state
between calls.

Why a Protocol, not a concrete class?
-------------------------------------

The witness must not be coupled to any specific MCP SDK. A ``Protocol``
keeps the dependency surface at "shape only" — when feature 002 wires the
real client, the witness code in ``capture.py`` stays unchanged. Tests
pin the contract via this mock and the static checks in
``tests/test_capture_architecture.py`` (AC-4).

Determinism
-----------

The mock never reads the wall clock. Timestamps come from
``ATW_WITNESS_TS`` (if set) or from the explicit ``ts`` argument to each
method. This keeps AC-7 (every test < 1s, no network) satisfiable in CI.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from agent_trace_witness.capture import CHOKE_POINT_EVENT_TYPES, EventTuple

# Re-exported from the production module so tests can import them from
# the fixture without reaching into the production package.
__all__ = ["CHOKE_POINT_EVENT_TYPES", "EventTuple", "MCPClient", "MockMCPClient"]

# Same constant name as seal.py and capture.py to keep wiring consistent
# across modules.
WITNESS_TS_ENV = "ATW_WITNESS_TS"


def _now_or_frozen_ts(explicit: str | None) -> str:
    """ISO-8601 UTC, frozen if ``ATW_WITNESS_TS`` is set, else wall clock.

    Same shape as ``seal._now_utc_iso`` (deterministic ``+00:00`` offset,
    never the trailing ``Z`` form) so timestamps in events can be
    diffed deterministically across the suite.
    """
    if explicit:
        return explicit
    env = os.environ.get(WITNESS_TS_ENV)
    if env:
        return env
    return datetime.now(UTC).isoformat()


@runtime_checkable
class MCPClient(Protocol):
    """Protocol every MCP client (mock or real) must satisfy.

    Methods return an ``EventTuple`` (defined in ``capture``). The
    witness does not inspect the return value — it builds
    ``CaptureEvent`` from its own arguments. This keeps the witness's
    view independent of the client's bookkeeping.
    """

    def record_tool_call(
        self, tool: str, args: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_tool_response(
        self, tool: str, result: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_model_input(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_model_output(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def record_external_effect(
        self, tool: str, effect: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple: ...

    def events(self) -> Iterable[EventTuple]:
        """Read-only view of every event the client has emitted, in order.

        The witness uses this to build the JSONL sink in ``run_capture``.
        Real clients should stream events (not accumulate them forever)
        — feature 002 will define the streaming boundary.
        """
        ...


class MockMCPClient:
    """In-memory MCP client used by the test suite (and only by tests).

    Constructor takes an optional list of ``EventTuple`` to PRE-POPULATE
    the log, useful for cassettes in feature 002 (T031..T036 document
    this; MVP only uses the empty constructor).

    Why a concrete class and not just the Protocol?
    ------------------------------------------------

    Tests need to ASSERT on the emitted events. A Protocol is structural
    only — ``isinstance(x, MCPClient)`` works thanks to
    ``@runtime_checkable``, but the mock also exposes ``events()`` as a
    real method (not just declared) so tests can iterate, count, and
    grep the log.
    """

    def __init__(self, seed: Iterable[EventTuple] = ()) -> None:
        self._events: list[EventTuple] = list(seed)

    # -- MCPClient protocol implementation ---------------------------------

    def record_tool_call(
        self, tool: str, args: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = _pack_tool_payload(tool=tool, args=args)
        ev = EventTuple(timestamp=ts, type="tool_call", payload=payload)
        self._events.append(ev)
        return ev

    def record_tool_response(
        self, tool: str, result: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = _pack_tool_payload(tool=tool, result=result)
        ev = EventTuple(timestamp=ts, type="tool_response", payload=payload)
        self._events.append(ev)
        return ev

    def record_model_input(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = _pack_model_payload(role="user", content=content)
        ev = EventTuple(timestamp=ts, type="model_input", payload=payload)
        self._events.append(ev)
        return ev

    def record_model_output(
        self, content: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = _pack_model_payload(role="assistant", content=content)
        ev = EventTuple(timestamp=ts, type="model_output", payload=payload)
        self._events.append(ev)
        return ev

    def record_external_effect(
        self, tool: str, effect: bytes | str | dict, *, ts: str | None = None
    ) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        payload = _pack_external_effect_payload(tool=tool, effect=effect)
        ev = EventTuple(timestamp=ts, type="external_effect", payload=payload)
        self._events.append(ev)
        return ev

    def events(self) -> list[EventTuple]:
        """Return a copy of the event log (defensive: prevents test
        code from mutating the internal list).
        """
        return list(self._events)


# ---------------------------------------------------------------------------
# Payload packing helpers (private to the fixture)
# ---------------------------------------------------------------------------


def _pack_tool_payload(
    *,
    tool: str,
    args: bytes | str | dict | None = None,
    result: bytes | str | dict | None = None,
) -> bytes:
    """Pack a tool event payload into canonical JSON bytes.

    Canonical = ``json.dumps(..., sort_keys=True, separators=(",", ":"))``,
    matching ``seal._canonical_bytes`` so hashes are stable across the
    suite. The payload carries ``tool`` plus either ``args`` (for
    ``tool_call``) or ``result`` (for ``tool_response``), never both.
    """
    obj: dict = {"tool": tool}
    if args is not None:
        obj["args"] = _coerce(args)
    if result is not None:
        obj["result"] = _coerce(result)
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pack_model_payload(*, role: str, content: bytes | str | dict) -> bytes:
    """Pack a model event payload (model_input / model_output)."""
    return json.dumps(
        {"role": role, "content": _coerce(content)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _pack_external_effect_payload(*, tool: str, effect: bytes | str | dict) -> bytes:
    """Pack an external_effect event payload (5th choke point, B1)."""
    return json.dumps(
        {"tool": tool, "effect": _coerce(effect)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _coerce(value: bytes | str | dict) -> str | dict:
    """Bytes → hex string; str → str; dict → dict (kept as-is)."""
    if isinstance(value, bytes):
        return value.hex()
    return value
