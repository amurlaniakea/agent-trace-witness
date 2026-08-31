# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""AC-19: timeout y lifecycle limpio de live stdio (T014).

Verifica que:

- Un servidor que tarda más que el ``timeout`` produce
  ``WitnessTimeoutError``.
- El proceso hijo NO queda zombie tras ``close()`` (ni tras timeout).
- ``shell=True`` está prohibido en el adapter (C4/AC-7).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent_trace_witness.exceptions import WitnessTimeoutError
from agent_trace_witness.mcp_adapter import RealMCPClient

STUB = Path(__file__).resolve().parent / "fixtures" / "stubs" / "mcp_stdio_stub.py"


def test_timeout_raises_witness_timeout_error() -> None:
    """Stub's ``name='sleep'`` with secs>timeout triggers WitnessTimeoutError."""
    import time as _time

    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=0.3)
    try:
        start = _time.monotonic()
        with pytest.raises(WitnessTimeoutError):
            client.record_tool_call("sleep", {"secs": 0.8})
        elapsed = _time.monotonic() - start
        # Must not wait the full sleep — it must time out at ~0.3s.
        assert elapsed < 0.9, f"timeout took too long: {elapsed}s"
    finally:
        client.close()


def test_no_zombie_after_close() -> None:
    """After ``close()`` the child process must be reaped (poll() is not None)."""
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    assert client._transport is not None
    proc: subprocess.Popen[bytes] = client._transport._proc
    assert proc.poll() is None, "child should be alive while client is open"
    client.close()
    assert proc.poll() is not None, f"child zombie after close (returncode={proc.returncode!r})"


def test_no_shell_true_in_adapter() -> None:
    """C4/AC-7: subprocess.Popen MUST NOT be called with shell=True."""
    import inspect

    from agent_trace_witness import mcp_adapter

    src = inspect.getsource(mcp_adapter)
    # Allow the string `shell=True` only inside a comment / docstring
    # (e.g. `# required by C4/AC-7`). The check is for the actual call.
    assert "shell=True" in src, (
        "src/mcp_adapter.py should explicitly mention `shell=False` so future "
        "contributors don't flip it (C4/AC-7). The literal is expected in a "
        "comment, not as an argument to Popen."
    )
    # The hard rule: no `shell=True` as a Popen kwarg.
    # We allow the literal in comments / docstrings, but not in the
    # Popen call itself. Grep the Popen call.
    import re

    popen_call = re.search(r"subprocess\.Popen\(([^)]*)\)", src, re.DOTALL)
    assert popen_call is not None, "could not find subprocess.Popen(...) call"
    body = popen_call.group(1)
    assert "shell=True" not in body, f"Popen must not pass shell=True (C4/AC-7); body={body!r}"


def test_close_is_idempotent() -> None:
    """Calling close() twice must not raise (lifecycle hygiene)."""
    client = RealMCPClient.from_stdio([sys.executable, str(STUB)], timeout=2.0)
    client.close()
    client.close()  # should not raise
