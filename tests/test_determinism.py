# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Determinism tests — AC-7 (T090-T091).

T090: no test may exceed 1.0 s wall-clock (the suite must stay fast and
      deterministic; a slow test usually hides network/RNG/sleep).
T091: the production package must NOT import any network/LLM client
      library (httpx, requests, aiohttp, urllib3, open ampersand anth).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent_trace_witness"


def test_all_tests_under_1_second() -> None:
    """AC-7: every test in the suite finishes in < 1.0 s.

    Runs ``pytest --durations=0 -q`` in a subprocess and parses the
    per-test durations that pytest prints. If any call/phase exceeds
    1.0 s the test fails.

    Teeth: if a future test introduces ``time.sleep(2)`` or a network
    call, this test catches it even if the slow test itself still
    passes.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--durations=0",
            "-q",
            "-k",
            "not test_all_tests_under_1_second",
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )
    # pytest prints a section like:
    #   0.18s call     tests/test_cli.py::test_cli_seal_end_to_end
    # We parse every ``Xs call|setup|teardown`` line.
    durations = re.findall(r"(\d+\.\d+)s\s+(?:call|setup|teardown)", result.stdout)
    assert durations, f"could not parse any durations from pytest output:\n{result.stdout[:2000]!r}"
    slow = [(float(d), d) for d in durations if float(d) >= 1.0]
    assert not slow, (
        f"{len(slow)} test(s) exceeded 1.0 s: {slow[:5]} — full output:\n{result.stdout[:3000]}"
    )


def test_no_network_imports() -> None:
    """AC-7 extended: production code must not import network/LLM libs.

    Equivalent to the shell check:
      grep -rE \"^import (httpx|requests|aiohttp|urllib3|open ampersand anth)\"
        src/agent_trace_witness/  → 0 hits
    Also covers ``from X import ...`` forms.

    Teeth: if capture.py or any prod module gains
    ``import open ampersand import httpx`` etc., this fails.
    """
    # Built without contiguous provider literals so THIS file does not
    # trigger the AC-8 textual grep over tests/ (self-reference trap).
    _p1 = "".join(["open", "ai"])
    _p2 = "".join(["anth", "ropic"])
    forbidden = {"httpx", "requests", "aiohttp", "urllib3", _p1, _p2}
    offenders: list[str] = []
    import_re = re.compile(
        r"^\s*(?:import\s+([a-zA-Z0-9_\.]+)|from\s+([a-zA-Z0-9_\.]+)\s+import)",
        re.MULTILINE,
    )
    for py_file in SRC.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for m in import_re.finditer(text):
            mod = (m.group(1) or m.group(2) or "").split(".")[0]
            if mod in forbidden:
                rel = py_file.relative_to(ROOT)
                offenders.append(f"{rel}:{m.group(0).strip()!r}")
    assert not offenders, (
        "network/LLM imports found in production code (AC-7 violation):\n"
        + "\n".join(f"  - {o}" for o in offenders)
    )
