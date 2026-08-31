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

"""Real MCP client — adapter stdio (AC-13/AC-16) — estado 003-live-stdio.

Implementa ``MCPClient`` Protocol (mismo contrato que MockMCPClient) sin
importar código del agente (C1) y sin patch dinámico.

Dos modos (stdlib-only, sin ``mcp`` SDK, sin ``httpx``/``anyio``):

- **Cassette (CI):** ``RealMCPClient.from_cassette(path)`` lee JSONL congelado
  sin red. Modo exclusivo en 002; sigue presente en 003.
- **Live stdio (003):** ``RealMCPClient.from_stdio(command)`` spawnea un
  servidor MCP vía ``subprocess.Popen`` y habla **JSON-RPC 2.0
  newline-delimited** conforme a spec
  ``modelcontextprotocol.io/specification/2025-03-26``:

  - Framing: cada mensaje ``json.dumps(...) + "\\n"`` sobre stdin/stdout,
    UTF-8 strict, ``MUST NOT`` embedded newlines (transports §stdio).
  - Handshake (lifecycle §Initialization): cliente envía ``initialize``
    con ``params: {protocolVersion, capabilities, clientInfo}``, espera
    ``result: {protocolVersion, capabilities, serverInfo}``, luego envía
    ``notifications/initialized`` **sin** ``id`` (notificación, no request).
  - Por cada tool: **un solo** ``tools/call`` con
    ``params: {name, arguments}`` → ``result: {content, isError}``.
    El mismo ``result`` produce los 3 choke points del witness:
    (a) ``tool_call`` al enviar, (b) ``tool_response`` al recibir,
    (e) ``external_effect`` **derivado** del mismo ``result.content``
    (segunda lectura, no segunda RPC — igual que 002: response inspection).

El adapter no importa agente/LLM ni hace patch dinámico — verificado por
``test_capture_architecture.py``. Sin ``shell=True``, sin ``mcp``/``httpx``.
Ver ``KNOWN_ISSUES.md`` §7 (circularidad stub/cliente, riesgo C5).
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .capture import CHOKE_POINT_EVENT_TYPES, EventTuple
from .exceptions import WitnessTimeoutError

WITNESS_TS_ENV = "ATW_WITNESS_TS"
RECORD_ENV = "ATW_RECORD"
RECORD_OUT_ENV = "ATW_RECORD_OUT"

# MCP protocol version we announce in `initialize` (spec 2025-03-26).
MCP_PROTOCOL_VERSION = "2025-03-26"
CLIENT_INFO_NAME = "agent-trace-witness"
CLIENT_INFO_VERSION = "0.3.0"


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
        # Riesgo conocido (no bloqueante B3): heurística "si parece hex par
        # solo [0-9a-fA-F] decodifica como hex" puede colisionar con una
        # palabra legítima par solo-hex (poco común pero posible). No se
        # corrige en 002 para no romper cassettes existentes; queda anotado
        # en KNOWN_ISSUES §6 junto al gap live-stdio. Fix futuro: marcar
        # payloads hex con prefijo explícito o tipo aparte.
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


# ---------------------------------------------------------------------------
# Live stdio — JSON-RPC 2.0 newline-delimited (MCP spec 2025-03-26 §stdio)
# ---------------------------------------------------------------------------


def _encode_message(payload: dict[str, Any]) -> bytes:
    """Serialize a JSON-RPC message per spec: UTF-8, no embedded newlines.

    The spec is explicit: ``MUST NOT contain embedded newlines``. We
    reject at the boundary rather than silently escape, so a malformed
    message surfaces immediately instead of corrupting the wire.
    """
    if "jsonrpc" not in payload:
        payload = {"jsonrpc": "2.0", **payload}
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if "\n" in raw:
        raise ValueError(f"refusing to send JSON-RPC message with embedded newline: {raw!r}")
    return raw.encode("utf-8") + b"\n"


def _decode_message(line: bytes) -> dict[str, Any]:
    """Parse one newline-delimited JSON-RPC message from the wire.

    Strips the trailing newline, validates UTF-8 strict, and rejects
    anything that is not a JSON object.
    """
    if not line.endswith(b"\n"):
        raise ValueError(f"expected newline-terminated message, got: {line!r}")
    body = line[:-1]
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"server message is not strict UTF-8: {exc}") from exc
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError(f"server message must be a JSON object, got {type(obj).__name__}")
    return obj


class _StdioTransport:
    """Process + newline-delimited JSON-RPC framed read/write (AC-16).

    Single-threaded write to stdin (caller owns ordering). A background
    thread pumps stdout into a queue so the caller can do
    ``recv(timeout=...)`` without busy-waiting. The transport is
    deliberately tiny: it does not interpret JSON-RPC semantics beyond
    newline framing — that is ``RealMCPClient``'s job.
    """

    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        *,
        timeout: float = 5.0,
    ) -> None:
        self._proc = proc
        self._timeout = timeout
        self._lock = threading.Lock()
        self._stdout_buf = bytearray()
        self._stdout_lock = threading.Lock()
        self._stdout_eof = threading.Event()
        self._stderr_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None
        self._wire_log: list[tuple[str, str]] = []  # (direction, line) for inspection
        self._wire_log_lock = threading.Lock()
        self._closed = False
        self._start_reader()

    def _start_reader(self) -> None:
        assert self._proc.stdout is not None
        self._reader_thread = threading.Thread(
            target=self._pump_stdout,
            name="atw-stdio-reader",
            daemon=True,
        )
        self._reader_thread.start()
        if self._proc.stderr is not None:
            self._stderr_thread = threading.Thread(
                target=self._pump_stderr,
                name="atw-stdio-stderr",
                daemon=True,
            )
            self._stderr_thread.start()

    def _pump_stdout(self) -> None:
        assert self._proc.stdout is not None
        try:
            while True:
                chunk = self._proc.stdout.read(1)
                if not chunk:
                    self._stdout_eof.set()
                    return
                with self._stdout_lock:
                    self._stdout_buf.extend(chunk)
        except Exception:
            self._stdout_eof.set()

    def _pump_stderr(self) -> None:
        # We only consume stderr to keep the child's pipe from filling;
        # we do not interpret it. RealMCPClient surfaces it via `stderr_log`.
        assert self._proc.stderr is not None
        try:
            while True:
                chunk = self._proc.stderr.read(4096)
                if not chunk:
                    return
        except Exception:
            return

    def send(self, message: dict[str, Any]) -> None:
        if self._closed:
            raise RuntimeError("transport closed")
        wire = _encode_message(message)
        line = wire.decode("utf-8").rstrip("\n")
        with self._wire_log_lock:
            self._wire_log.append(("->", line))
        with self._lock:
            assert self._proc.stdin is not None
            try:
                self._proc.stdin.write(wire)
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise RuntimeError(f"server stdin closed: {exc}") from exc

    def _pop_message(self, deadline: float) -> dict[str, Any]:
        # Read bytes until newline OR EOF, with timeout measured against `deadline`.
        while True:
            with self._stdout_lock:
                buf = self._stdout_buf
                newline_idx = buf.find(b"\n")
                if newline_idx >= 0:
                    line = bytes(buf[: newline_idx + 1])
                    del buf[: newline_idx + 1]
                else:
                    line = b""
            if line:
                msg = _decode_message(line)
                with self._wire_log_lock:
                    self._wire_log.append(("<-", msg_line_for_log(msg)))
                return msg
            # No full line yet — wait or fail.
            now = datetime.now(UTC).timestamp()
            remaining = deadline - now
            if remaining <= 0:
                raise WitnessTimeoutError("stdio: no message received before deadline")
            # Block on either more data or EOF, with a short poll so we can
            # re-check the deadline. The pump thread fills `_stdout_buf`.
            self._stdout_eof.wait(timeout=min(0.05, remaining))
            if self._stdout_eof.is_set() and not self._stdout_buf:
                raise RuntimeError("server stdout closed before any message")

    def recv(self, timeout: float | None = None) -> dict[str, Any]:
        if timeout is None:
            timeout = self._timeout
        deadline = datetime.now(UTC).timestamp() + timeout
        return self._pop_message(deadline)

    def wire_log(self) -> list[tuple[str, str]]:
        with self._wire_log_lock:
            return list(self._wire_log)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        # 1) close stdin (lifecycle §stdio shutdown step 1)
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass
        # 2) wait briefly, then terminate, then kill (steps 2-3)
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass


def msg_line_for_log(msg: dict[str, Any]) -> str:
    """Compact one-line representation of a decoded JSON-RPC message.

    Used by ``wire_log`` to keep the test stdout readable.
    """
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# RealMCPClient
# ---------------------------------------------------------------------------


class RealMCPClient:
    """Adapter stdio que implementa MCPClient Protocol (AC-13/AC-16).

    - ``from_cassette(path)`` — modo CI 002: lee JSONL congelado sin red.
    - ``from_stdio(command)`` — modo live 003: spawnea el binario y habla
      JSON-RPC 2.0 conforme a spec 2025-03-26.

    En modo live, los 5 ``record_*`` (tool_call / tool_response /
    model_input / model_output / external_effect) se mapean a mensajes
    JSON-RPC reales:

    - ``record_tool_call(tool, args)`` y ``record_tool_response(tool,
      result)`` y ``record_external_effect(tool, effect)`` comparten el
      mismo `tools/call`: un solo round-trip por invocación real, con el
      mismo ``id``. El mismo ``result.content`` del servidor produce
      (b) ``tool_response`` y (e) ``external_effect`` derivado (response
      inspection, no segunda RPC).
    - ``record_model_input`` / ``record_model_output`` son **fuera de
      scope** del transporte MCP (MCP no transporta prompts de modelo);
      en live stdio se persisten en el log interno sin enviar al server.
      El cassette sí los reproduce.
    """

    def __init__(
        self,
        cassette: Path | None = None,
        transport: _StdioTransport | None = None,
    ) -> None:
        self._events: list[EventTuple] = []
        self._cassette = cassette
        self._transport = transport
        if cassette is not None and cassette.exists():
            self._load_cassette(cassette)
        # ATW_RECORD hook (003 B2): if ATW_RECORD=1 and a live transport
        # is configured, the close() method will write the events to a
        # JSONL cassette (path from ATW_RECORD_OUT or default). CI never
        # sets ATW_RECORD; it is a manual operator action.
        self._record_path: Path | None = None
        if os.environ.get(RECORD_ENV) == "1" and transport is not None:
            out = os.environ.get(RECORD_OUT_ENV)
            self._record_path = Path(out) if out else None

    @classmethod
    def from_cassette(cls, path: Path | str) -> RealMCPClient:
        p = Path(path)
        return cls(cassette=p)

    @classmethod
    def from_stdio(
        cls,
        command: str | list[str],
        *,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
        timeout: float = 5.0,
    ) -> RealMCPClient:
        """Spawn an MCP server subprocess and do the spec-conformant handshake.

        Performs the full ``initialize`` → ``result`` → ``notifications/
        initialized`` flow before returning, so callers can immediately
        start issuing ``record_tool_call`` (which maps to ``tools/call``).
        """
        if isinstance(command, str):
            argv: list[str] = [command, *(args or [])]
        else:
            if args:
                raise ValueError("`args` must be None when `command` is a list")
            argv = list(command)
        if not argv:
            raise ValueError("`command` must be a non-empty program path or argv[0]")
        # `shlex` is used only to split a *string* command (the list branch
        # is passed straight to execve with no shell). We never pass
        # `shell=True` to Popen — see C4/AC-7 and KNOWN_ISSUES §6.
        if isinstance(command, str) and args is None and len(argv) == 1:
            # Allow passing a single shell-like string for ergonomics
            # (still no shell: we re-tokenize with shlex and execve).
            argv = shlex.split(command)
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            shell=False,  # explicit; required by C4/AC-7
        )
        transport = _StdioTransport(proc, timeout=timeout)
        client = cls(transport=transport)
        try:
            client._handshake()
        except Exception:
            client.close()
            raise
        return client

    def _handshake(self) -> None:
        """Spec-conformant MCP handshake (lifecycle §Initialization).

        1. Send ``initialize`` with protocolVersion / capabilities / clientInfo.
        2. Wait for server's ``initialize`` response (must include
           protocolVersion, capabilities, serverInfo).
        3. Send ``notifications/initialized`` (no ``id`` — notification, not request).
        """
        assert self._transport is not None
        # Step 1: initialize request (id=1)
        self._rpc_id = 1
        self._transport.send(
            {
                "id": self._rpc_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": CLIENT_INFO_NAME,
                        "version": CLIENT_INFO_VERSION,
                    },
                },
            }
        )
        # Step 2: wait for initialize response
        init_response = self._transport.recv()
        if init_response.get("id") != self._rpc_id:
            raise ValueError(
                f"initialize response id mismatch: expected {self._rpc_id}, got {init_response.get('id')!r}"
            )
        if "error" in init_response:
            err = init_response["error"]
            raise ValueError(f"server rejected initialize: {err}")
        result = init_response.get("result")
        if not isinstance(result, dict):
            raise ValueError(f"initialize result must be an object, got {type(result).__name__}")
        for required in ("protocolVersion", "capabilities", "serverInfo"):
            if required not in result:
                raise ValueError(f"initialize result missing required field: {required!r}")
        self._server_info: dict[str, Any] = result
        # Step 3: notifications/initialized (no id — it's a notification)
        self._transport.send(
            {
                "method": "notifications/initialized",
            }
        )

    def _load_cassette(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            ev = _load_event_tuple(obj)
            self._events.append(ev)

    # -- Live stdio: one tools/call → derives tool_call/response/external_effect
    def _next_id(self) -> int:
        assert self._transport is not None
        self._rpc_id += 1
        return self._rpc_id

    def _live_invoke_tool(self, tool: str, args: Any) -> dict[str, Any]:
        """Send a single ``tools/call`` and return the server ``result`` object.

        This is the only place where the witness crosses the MCP wire for
        a tool invocation. ``record_tool_call`` /
        ``record_tool_response`` / ``record_external_effect`` all share
        the round-trip produced here — external_effect is derived from
        the same ``result`` after the response arrives, not sent as a
        second RPC.
        """
        assert self._transport is not None
        call_id = self._next_id()
        request = {
            "id": call_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
        self._transport.send(request)
        response = self._transport.recv()
        if response.get("id") != call_id:
            raise ValueError(
                f"tools/call response id mismatch: expected {call_id}, got {response.get('id')!r}"
            )
        if "error" in response:
            err = response["error"]
            # Map server protocol errors to a runtime error that capture
            # can surface. We still let the call fail loudly (C5) — we
            # do not pretend the tool succeeded.
            raise RuntimeError(f"server error for tools/call({tool!r}): {err}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise ValueError(f"tools/call result must be an object, got {type(result).__name__}")
        return result

    def _derive_external_effect(self, result: dict[str, Any]) -> dict[str, Any]:
        """Second read of the same ``result`` for the 5th choke point.

        Per spec §tools the result is ``{content: [...], isError: bool}``.
        We surface a compact, hash-stable view: ``{"content": [...],
        "isError": bool}``. We deliberately do NOT issue a second RPC;
        the ``record_external_effect`` event comes from inspecting the
        same data the ``record_tool_response`` event was built from.
        """
        return {
            "content": result.get("content", []),
            "isError": bool(result.get("isError", False)),
        }

    # -- MCPClient Protocol implementation (5 methods) -----------------------

    def record_tool_call(self, tool: str, args: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        if self._transport is not None:
            # Live: this drives the actual tools/call. We capture the
            # outbound payload as the tool_call event so the wire log
            # shows the same JSON-RPC the server received.
            call_payload = {"tool": tool, "args": args}
            ev = EventTuple(
                timestamp=ts,
                type="tool_call",
                payload=json.dumps(call_payload, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                ),
            )
            # Stash the live result on the event so the matching
            # record_tool_response / record_external_effect (which are
            # invoked right after by capture.run_capture / caller) can
            # reuse the same round-trip without re-issuing the call.
            self._pending_result: dict[str, Any] | None = self._live_invoke_tool(tool, args)
            self._events.append(ev)
            return ev
        payload = json.dumps(
            {"tool": tool, "args": args}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="tool_call", payload=payload)
        self._events.append(ev)
        return ev

    def record_tool_response(self, tool: str, result: Any, *, ts: str | None = None) -> EventTuple:
        ts = _now_or_frozen_ts(ts)
        if self._transport is not None and getattr(self, "_pending_result", None) is not None:
            # Reuse the result from the tools/call that record_tool_call
            # already issued; serialize as a real tool_response. We do
            # NOT consume `_pending_result` here — record_external_effect
            # derives from the same result (spec: response inspection,
            # not a second RPC).
            live_result = self._pending_result
            payload = json.dumps(
                {"tool": tool, "result": live_result}, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            ev = EventTuple(timestamp=ts, type="tool_response", payload=payload)
            self._events.append(ev)
            return ev
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
        if self._transport is not None and getattr(self, "_pending_result", None) is not None:
            # Derived from the SAME tools/call that record_tool_call
            # issued — no second RPC. The same `_pending_result` was
            # already consumed by record_tool_response (in canonical
            # order call → response → effect). After we read it here we
            # clear the slot so the next tool's record_tool_call starts
            # with a fresh RPC.
            live_result = self._pending_result
            self._pending_result = None
            derived = self._derive_external_effect(live_result)
            payload = json.dumps(
                {"tool": tool, "effect": derived}, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            ev = EventTuple(timestamp=ts, type="external_effect", payload=payload)
            self._events.append(ev)
            return ev
        payload = json.dumps(
            {"tool": tool, "effect": effect}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ev = EventTuple(timestamp=ts, type="external_effect", payload=payload)
        self._events.append(ev)
        return ev

    def events(self) -> list[EventTuple]:
        return list(self._events)

    def wire_log(self) -> list[tuple[str, str]]:
        if self._transport is None:
            return []
        return self._transport.wire_log()

    def write_cassette(self, path: Path | str) -> None:
        """Write the captured events to a JSONL cassette file (003 B2).

        Each line is ``{timestamp, type, payload: <json>}`` with
        ``sort_keys=True`` and ``separators=(",", ":")`` so the file is
        byte-deterministic. The payload is decoded to JSON if it is
        canonical JSON bytes; otherwise it is hex-encoded (preserves
        any binary captured by a custom client).

        This method is the building block of ``ATW_RECORD=1`` — see
        ``close()`` for the env-driven hook.
        """
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for ev in self._events:
                payload = _payload_to_jsonl_field(ev.payload)
                obj = {
                    "timestamp": ev.timestamp,
                    "type": ev.type,
                    "payload": payload,
                }
                fh.write(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
        # ATW_RECORD=1 hook: if a record path was set at construction
        # time, dump the captured events to it now (after the transport
        # is closed, so no in-flight messages remain).
        if self._record_path is not None:
            self.write_cassette(self._record_path)


def _payload_to_jsonl_field(payload: bytes) -> Any:
    """Decode canonical-JSON bytes back to a JSON object for the cassette.

    The internal ``EventTuple.payload`` is canonical-JSON bytes (we
    serialise it that way in every ``record_*`` path). For the cassette
    we want the human-readable dict, not the byte representation, so
    ``from_cassette`` can re-load it transparently.
    """
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return payload.hex()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return payload.hex()
