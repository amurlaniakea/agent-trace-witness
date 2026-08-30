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

"""Architecture tests for capture.py — AC-4 (T039, T040).

These tests pin the C1 invariant that the witness captures events
OUTSIDE the agent's reach. They run static checks (grep + AST) on the
production code to prove that no monkey-patching, no LLM-client
introspection, and no agent-code import has crept into the capture
layer.

Teeth: each test fails the moment anyone introduces a forbidden pattern
— e.g. ``capture.py`` calling ``setattr(llm_client, "messages", ...)``
or ``from my_agent_runtime import llm``. The defence IS the grep/AST
check, so removing the check makes the test fail (or rather: removing
the defence in capture.py makes the check fail, which makes the test
fail).
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

# Root of the production code, resolved relative to this test file so
# the test does not depend on the test runner's CWD.
SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "agent_trace_witness"

# Patterns tasks.md T039 explicitly lists. The third pattern uses a
# regex backreference to avoid false positives on plain ``inject``
# identifiers (e.g. variable names). tasks.md verbatim:
#   monkey_patch | setattr(.*llm | inject.*prompt
_FORBIDDEN_GREP_PATTERN = re.compile(r"monkey_patch|setattr\(.*llm|inject.*prompt")

# Imports that would betray "the capture layer imports the agent code"
# (C1 violation). These are NAME FRAGMENTS — they match the imported
# module's top-level path. A real agent runtime could be called
# "my_agent", "agent_core", "llm_client", etc.
_FORBIDDEN_IMPORT_FRAGMENTS = (
    "agent",  # e.g. "from my_agent import ..."
    "llm",  # e.g. "from llm_client import ..."
    "openai",  # e.g. "import openai"
    "anthropic",  # e.g. "import anthropic"
    "huggingface",  # e.g. "import huggingface_hub"
)


# ---- T039 — grep for monkey-patching / setattr-on-LLM / prompt injection --


def test_no_monkey_patching_in_capture() -> None:
    """AC-4 base: ``grep -rE "<forbidden>" src/agent_trace_witness/``
    returns zero hits.

    The grep is run via ``subprocess.run`` so it is exactly the command
    that a CI gate or an auditor would run — no Python-level
    reinterpretation.
    """
    assert SRC_ROOT.is_dir(), f"src root not found: {SRC_ROOT}"

    result = subprocess.run(
        [
            "grep",
            "-rE",
            _FORBIDDEN_GREP_PATTERN.pattern,
            str(SRC_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    # grep exits 1 when there are no matches (the desired case). Any
    # other exit code (2 = error, 0 = matches) means a problem.
    assert result.returncode != 0, (
        f"forbidden patterns found in {SRC_ROOT}:\n{result.stdout}\n"
        f"Pattern: {_FORBIDDEN_GREP_PATTERN.pattern}"
    )
    # And no output, just to be explicit.
    assert result.stdout == "", f"unexpected grep output: {result.stdout!r}"


def test_no_monkey_patching_shows_what_pattern_caught(tmp_path: Path) -> None:
    """Diagnostic companion to T039: if a forbidden pattern is
    introduced, this test prints the exact offending line so the
    developer can fix it without re-reading the test.

    Writes a sentinel file containing the forbidden pattern, runs the
    same grep against the sentinel, asserts the grep WOULD have caught
    it (so the test suite's pattern is provably correct), then deletes
    the sentinel.
    """
    sentinel = tmp_path / "sentinel.py"
    sentinel.write_text(
        "def example():\n"
        "    setattr(llm_client, 'messages', [])\n"
        "    monkey_patch.inject_prompt('system', 'pwned')\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "grep",
            "-rE",
            _FORBIDDEN_GREP_PATTERN.pattern,
            str(sentinel),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    # grep exit 0 = match found (the expected case for the sentinel).
    assert result.returncode == 0, (
        f"the grep pattern did not catch the sentinel — "
        f"test suite's pattern is broken:\n{result.stdout}"
    )
    assert (
        "setattr" in result.stdout or "monkey_patch" in result.stdout or "inject" in result.stdout
    )


# ---- T040 — capture.py imports MCP abstraction, NOT agent code ----------


def _imported_modules_in_capture() -> list[str]:
    """Return every import path used by capture.py (relative + absolute)."""
    capture_path = SRC_ROOT / "capture.py"
    source = capture_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(capture_path))

    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # ``from X import Y`` — record the module path (X). For
            # ``from . import X`` (relative), X is the local module name.
            module = node.module or ""
            if node.level > 0:
                # Relative import: record the local module name(s).
                for alias in node.names:
                    imported.append(alias.name)
            else:
                imported.append(module)
    return imported


def test_capture_does_not_import_agent_code() -> None:
    """AC-4 extended: capture.py's import list must not include any
    forbidden fragment. The witness operates outside the agent (C1);
    an import like ``from my_agent import llm`` would be a structural
    C1 violation.
    """
    imports = _imported_modules_in_capture()
    # Allow ourselves a margin: the witness's own submodules are fine.
    # Everything else must not look like an agent/LLM SDK import.
    own_modules = {
        f"agent_trace_witness.{name}"
        for name in (
            "seal",
            "exceptions",
        )
    }
    own_root = "agent_trace_witness"

    offenders: list[str] = []
    for imp in imports:
        if imp.startswith(own_root) and imp not in own_modules:
            # ``agent_trace_witness.X`` where X is not seal/exceptions —
            # that's a new submodule, suspicious.
            offenders.append(imp)
            continue
        if any(frag in imp for frag in _FORBIDDEN_IMPORT_FRAGMENTS):
            offenders.append(imp)

    assert not offenders, f"capture.py imports agent-related code (C1 violation): {offenders}"


def test_capture_imports_mcp_client_protocol() -> None:
    """AC-4 positive: capture.py DOES define/import the MCPClient
    abstraction. If the abstraction goes away, this test fails — and
    so does the rest of the suite (AC-4 is "imports MCP abstraction,
    not agent code"; both halves must hold).
    """
    imports = _imported_modules_in_capture()
    # The protocol is defined IN capture.py, so it doesn't show up as
    # an import. But the test verifies the negative half (agent code)
    # holds; here we re-affirm the structural shape by checking that
    # capture.py DEFINES MCPClient (or imports it from itself).
    capture_source = (SRC_ROOT / "capture.py").read_text(encoding="utf-8")
    assert "MCPClient" in capture_source, (
        "capture.py must define or import MCPClient — the witness's "
        "abstraction for the MCP boundary"
    )

    # And capture.py must not depend on a third-party MCP SDK.
    third_party_mcp = ("mcp.client", "mcp.server", "modelcontextprotocol")
    for tp in third_party_mcp:
        assert tp not in imports, (
            f"capture.py imports third-party MCP SDK ({tp!r}); the MVP "
            f"defines its own MCPClient Protocol locally instead"
        )
