# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""AC-16: live stdio real conforme a spec 2025-03-26 (T013).

Spawnea el stub como proceso real (``subprocess.Popen``, sin
``shell=True``) y verifica que el wire muestra:

  1. ``initialize`` con ``protocolVersion``/``capabilities``/
     ``clientInfo`` anidados, id=1.
  2. ``result`` con ``protocolVersion``/``capabilities``/``serverInfo``.
  3. ``notifications/initialized`` sin ``id``.
  4. **Un solo** ``tools/call`` por tool (``name`` + ``arguments``
     reales), no ``record_*`` inventados.
  5. ``result`` con ``content``/``isError`` se traduce a 3 choke
     points (``tool_call``/``tool_response``/``external_effect``) sin
     segunda RPC en el wire.

Anti-circularidad (KNOWN_ISSUES §7): el stub y ``RealMCPClient`` son
ambos autoría Hermes. El wire se inspecciona literal, no por coincidencia
de resultado; cualquier divergencia con la spec debe saltar al ojo.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_trace_witness.mcp_adapter import (
    CLIENT_INFO_NAME,
    CLIENT_INFO_VERSION,
    MCP_PROTOCOL_VERSION,
    RealMCPClient,
)

STUB = Path(__file__).resolve().parent / "fixtures" / "stubs" / "mcp_stdio_stub.py"


def _wire(wire):
    return [(d, line) for d, line in wire]


def test_initialize_handshake_conforms_to_spec() -> None:
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        wire = _wire(client.wire_log())
        assert len(wire) == 3, f"expected 3 wire lines (handshake), got {len(wire)}: {wire}"
        d0, line0 = wire[0]
        d1, line1 = wire[1]
        d2, line2 = wire[2]
        assert d0 == "->" and d1 == "<-" and d2 == "->"

        req = json.loads(line0)
        assert req["jsonrpc"] == "2.0"
        assert req["id"] == 1
        assert req["method"] == "initialize"
        params = req["params"]
        # Per spec lifecycle §Initialization — every field mandatory.
        assert params["protocolVersion"] == MCP_PROTOCOL_VERSION == "2025-03-26"
        assert "capabilities" in params
        assert "clientInfo" in params
        assert params["clientInfo"]["name"] == CLIENT_INFO_NAME
        assert params["clientInfo"]["version"] == CLIENT_INFO_VERSION

        resp = json.loads(line1)
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert "result" in resp
        result = resp["result"]
        assert "protocolVersion" in result
        assert "capabilities" in result
        assert "serverInfo" in result

        notif = json.loads(line2)
        # Notification: no `id` per JSON-RPC 2.0.
        assert "id" not in notif, (
            f"notifications/initialized MUST be notification (no id), got: {notif}"
        )
        assert notif["method"] == "notifications/initialized"
    finally:
        client.close()


def test_single_tools_call_per_invocation_with_real_name() -> None:
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        before = len(client.wire_log())
        client.record_tool_call("delete_file", {"path": "/tmp/spec-check"})
        client.record_tool_response("delete_file", None)
        client.record_external_effect("delete_file", None)
        after = client.wire_log()

        new_lines = after[before:]
        # 1 outbound tools/call, 1 inbound result. NOT 3 outbound.
        outbound = [line for d, line in new_lines if d == "->"]
        inbound = [line for d, line in new_lines if d == "<-"]
        assert len(outbound) == 1, (
            f"expected exactly ONE outbound tools/call per tool, got {len(outbound)}: {outbound}"
        )
        assert len(inbound) == 1, f"expected ONE inbound result, got {len(inbound)}"

        call = json.loads(outbound[0])
        assert call["method"] == "tools/call"
        assert call["params"]["name"] == "delete_file"
        assert call["params"]["arguments"] == {"path": "/tmp/spec-check"}
        # No record_* method names leaked onto the wire (ef7bfc3 mistake).
        assert "record_tool_call" not in call["method"]
        assert "record_external_effect" not in call["method"]

        result = json.loads(inbound[0])
        assert "result" in result
        r = result["result"]
        assert "content" in r
        assert "isError" in r
        assert r["isError"] is False
    finally:
        client.close()


def test_three_choke_points_derive_from_single_round_trip() -> None:
    """tool_call / tool_response / external_effect all share the wire RPC."""
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        before = len(client.wire_log())
        client.record_tool_call("delete_file", {"path": "/tmp/derive"})
        client.record_tool_response("delete_file", None)
        client.record_external_effect("delete_file", None)
        new_wire = client.wire_log()[before:]

        # 3 events on the client side, 1 RPC on the wire.
        events = client.events()
        types = [e.type for e in events[-3:]]
        assert types == ["tool_call", "tool_response", "external_effect"]

        rpcs = [line for d, line in new_wire if d == "->"]
        assert len(rpcs) == 1, (
            f"3 events MUST share 1 tools/call (response inspection), got {len(rpcs)} RPCs"
        )

        # And the external_effect payload must be derived from the SAME
        # result.content that produced the tool_response.
        eff = json.loads(events[-1].payload.decode("utf-8"))
        resp = json.loads(events[-2].payload.decode("utf-8"))
        assert "effect" in eff and "result" in resp
        assert eff["effect"]["content"] == resp["result"]["content"]
        assert eff["effect"]["isError"] == resp["result"]["isError"]
    finally:
        client.close()


def test_two_consecutive_tools_each_emit_one_rpc() -> None:
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        for path in ("/tmp/consec-1", "/tmp/consec-2"):
            client.record_tool_call("delete_file", {"path": path})
            client.record_tool_response("delete_file", None)
            client.record_external_effect("delete_file", None)
        rpcs = [line for d, line in client.wire_log() if d == "->" and "tools/call" in line]
        assert len(rpcs) == 2, f"expected 2 tools/call RPCs, got {len(rpcs)}"
        ids = [json.loads(r)["id"] for r in rpcs]
        assert ids == [2, 3], f"ids must increment per RPC, got {ids}"
    finally:
        client.close()


def test_process_is_real_subprocess_not_cassette_alias() -> None:
    """Anti-circular: the transport must hold a real Popen + reader thread."""
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        transport = client._transport
        assert transport is not None
        # Real subprocess.Popen, not a cassette alias.
        import subprocess as _sp

        assert isinstance(transport._proc, _sp.Popen)
        # Reader thread is alive — proves a real thread pumps the pipe.
        assert transport._reader_thread is not None
        assert transport._reader_thread.is_alive()
    finally:
        client.close()


def test_no_cassette_fallback_when_live() -> None:
    """If a live client is constructed, ``_events`` is populated from
    actual server responses, not from a cassette file."""
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    try:
        client.record_tool_call("delete_file", {"path": "/tmp/nocassette"})
        client.record_tool_response("delete_file", None)
        client.record_external_effect("delete_file", None)
        # The response payload MUST contain the path the stub echoed.
        ev_resp = client.events()[-2]
        body = json.loads(ev_resp.payload.decode("utf-8"))
        assert "/tmp/nocassette" in body["result"]["content"][0]["text"]
    finally:
        client.close()


def test_stub_is_authored_by_hermes_not_third_party_reference() -> None:
    """Documentation assertion so a future contributor does not mistake
    the stub for a third-party reference implementation.

    See KNOWN_ISSUES §7: conformity is verified against the spec text,
    not against a third-party server.
    """
    text = STUB.read_text(encoding="utf-8")
    assert "atw-test-stub" in text
    assert "KNOWN_ISSUES" in text
