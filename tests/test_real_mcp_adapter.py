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

"""AC-13: RealMCPClient implementa MCPClient Protocol y lee cassette stdio."""

from __future__ import annotations

from pathlib import Path

from agent_trace_witness.capture import CHOKE_POINT_EVENT_TYPES
from agent_trace_witness.mcp_adapter import RealMCPClient
from tests.fixtures.mcp_client import MockMCPClient

CASSETTE = Path(__file__).parent / "fixtures" / "cassettes" / "mcp_stdio_001.jsonl"


def test_real_mcp_client_implements_protocol() -> None:
    client = RealMCPClient()
    # isinstance Protocol runtime_checkable
    from agent_trace_witness.capture import MCPClient

    assert isinstance(client, MCPClient)


def test_real_mcp_client_reads_cassette_typed() -> None:
    assert CASSETTE.exists(), f"cassette missing: {CASSETTE}"
    client = RealMCPClient.from_cassette(CASSETTE)
    events = client.events()
    assert len(events) == 5
    types = [e.type for e in events]
    assert types == ["tool_call", "tool_response", "external_effect", "model_input", "model_output"]
    for e in events:
        assert e.type in CHOKE_POINT_EVENT_TYPES
        assert isinstance(e.timestamp, str) and e.timestamp
        assert isinstance(e.payload, (bytes, bytearray))


def test_real_mcp_client_not_alias_of_mock() -> None:
    real = RealMCPClient.from_cassette(CASSETTE)
    mock = MockMCPClient()
    # Deben ser clases distintas y no compartir estado
    assert type(real) is not type(mock)
    assert real.events() != mock.events()
    # Real tiene 5 eventos del cassette, mock vacío
    assert len(real.events()) == 5
    assert len(mock.events()) == 0


def test_real_mcp_client_record_methods_work() -> None:
    client = RealMCPClient()
    client.record_tool_call("read_file", {"path": "/tmp/x"})
    client.record_external_effect("read_file", {"path": "/tmp/x", "op": "read"})
    assert len(client.events()) == 2
    assert client.events()[1].type == "external_effect"
