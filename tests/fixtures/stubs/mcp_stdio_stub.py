#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP server stub for live-stdio tests (003 AC-16, KNOWN_ISSUES §7).

This stub is a **real MCP server** in protocol terms: it implements the
handshake (``initialize`` → response → ``notifications/initialized``)
and ``tools/call`` per spec 2025-03-26. It is intentionally **not a
reference implementation of a third party** — both this stub and
``RealMCPClient.from_stdio`` are Hermes-authored, so the same risks of
shared misunderstanding apply (see KNOWN_ISSUES §7). Conformity has
been checked against the spec text, not against a third-party server.

Wire conventions (mirrors the spec):

- One JSON-RPC message per line on stdin/stdout (``\\n`` delimited, UTF-8,
  no embedded newlines).
- ``initialize``: requires ``params.protocolVersion`` (we echo the
  client's), advertises ``tools`` capability, returns ``serverInfo``.
- ``tools/call``: returns ``{content: [{type: "text", text: ...}],
  isError: bool}`` derived from the call's ``name`` and ``arguments``.
- A special ``name == "sleep"`` with ``arguments.secs`` makes the stub
  sleep before responding — used by the lifecycle test (AC-19) to
  exercise the client's timeout path.
- A special ``name == "fail"`` returns ``isError: true`` with a text
  payload — used to verify the client surfaces server errors.
- Unknown methods reply with JSON-RPC error ``-32601`` (Method not found).
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

SERVER_PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "atw-test-stub"
SERVER_VERSION = "0.3.0"


def _send(message: dict[str, Any]) -> None:
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    if "\n" in raw:
        raise RuntimeError(f"refusing to send JSON-RPC message with embedded newline: {raw!r}")
    sys.stdout.buffer.write((raw + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _recv() -> dict[str, Any] | None:
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    text = line.decode("utf-8", errors="strict").rstrip("\n")
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON-RPC object, got {type(obj).__name__}")
    return obj


def _do_initialize(req: dict[str, Any]) -> None:
    params = req.get("params") or {}
    client_protocol = params.get("protocolVersion", SERVER_PROTOCOL_VERSION)
    _send(
        {
            "jsonrpc": "2.0",
            "id": req["id"],
            "result": {
                "protocolVersion": client_protocol,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            },
        }
    )


def _do_tools_call(req: dict[str, Any]) -> None:
    params = req.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name == "sleep":
        secs = float(arguments.get("secs", 1.0))
        time.sleep(secs)
        result = {"content": [{"type": "text", "text": f" slept {secs}s"}], "isError": False}
    elif name == "fail":
        result = {
            "content": [{"type": "text", "text": f"stub forced failure: {arguments!r}"}],
            "isError": True,
        }
    elif name == "delete_file":
        # We do not actually delete anything in the stub (C1 / no
        # side-effects on host). The result mirrors what a real server
        # would return for a successful tool invocation: a content block
        # describing the effect. The witness treats that same block as
        # the external_effect derivation input (response inspection).
        result = {
            "content": [
                {
                    "type": "text",
                    "text": f"deleted {arguments.get('path', '<unknown>')!r}",
                }
            ],
            "isError": False,
        }
    else:
        # Protocol-level "method not found" for tools/call would not be
        # right here (the method exists); an unknown tool name surfaces
        # as a tool execution error per spec §tools §Error Handling.
        result = {
            "content": [{"type": "text", "text": f"unknown tool: {name!r}"}],
            "isError": True,
        }
    _send({"jsonrpc": "2.0", "id": req["id"], "result": result})


_DISPATCH: dict[str, Any] = {
    "initialize": _do_initialize,
    "tools/call": _do_tools_call,
}


def serve() -> None:
    """Read JSON-RPC messages from stdin, write responses to stdout.

    Exits cleanly when stdin EOFs (the parent closed the pipe).
    Notifications (messages without ``id``) are accepted but produce no
    response — we only reply to requests.
    """
    # Mark stderr so tests can confirm the server is alive.
    print(
        f"stub: ready (protocol={SERVER_PROTOCOL_VERSION}, name={SERVER_NAME})",
        file=sys.stderr,
    )
    sys.stderr.flush()
    while True:
        msg = _recv()
        if msg is None:
            return
        if "id" not in msg:
            # Notification: ack silently, do not reply.
            continue
        method = msg.get("method")
        handler = _DISPATCH.get(method)
        if handler is None:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32601, "message": f"Method not found: {method!r}"},
                }
            )
            continue
        try:
            handler(msg)
        except Exception as exc:  # noqa: BLE001
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32603, "message": f"Internal error: {exc}"},
                }
            )


if __name__ == "__main__":
    serve()
