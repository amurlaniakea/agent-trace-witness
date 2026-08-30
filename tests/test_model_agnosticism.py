# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Model-agnosticism tests — AC-8 (T092).

The witness must not depend on any particular LLM provider. Tests must
also stay agnostic: they cannot import provider SDKs.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"


def test_no_llm_imports_in_tests() -> None:
    """AC-8: no file under tests/ may mention provider SDKs.

    Equivalent to the shell check (provider names fragmented so this
    file does not self-match the grep):
      grep -rE \"(open\"+\"ai|anth\"+\"ropic|olla\"+\"ma)\" tests/ → 0 hits

    The check is textual (not just import statements) because even a
    comment or string literal mentioning a provider SDK signals a
    provider-specific assumption that violates AC-8.

    Teeth: if a future test does ``import open\"+\"ai`` or crafts a prompt
    for a specific provider, this fails.
    """
    # Build forbidden list without writing the provider names as
    # contiguous literals in THIS file — otherwise the checker would
    # flag itself (self-reference trap, same class as the HMAC comment
    # lie: a description that contradicts its implementation). The
    # fragments below join to the provider names at runtime but grep
    # for the literal strings over THIS file will not match.
    p1 = "".join(["open", "ai"])
    p2 = "".join(["anth", "ropic"])
    p3 = "".join(["olla", "ma"])
    pattern = re.compile(f"({p1}|{p2}|{p3})", re.IGNORECASE)
    # These files MUST mention provider names to define the check;
    # they are excluded from the scan (same rationale as the T019
    # interin signature note in tasks.md: the checker documents its
    # own limitation).
    skip = {
        "tests/test_model_agnosticism.py",
        "tests/test_determinism.py",
        "tests/test_capture_architecture.py",
    }
    offenders: list[str] = []
    for py_file in TESTS_DIR.rglob("*.py"):
        rel_str = str(py_file.relative_to(ROOT))
        if rel_str in skip:
            continue
        text = py_file.read_text(encoding="utf-8")
        for idx, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                rel = py_file.relative_to(ROOT)
                offenders.append(f"{rel}:{idx}:{line.strip()!r}")
    # Also check JSON/JSONL fixtures — they should not embed provider names
    # either (e.g. a recorded model_input that is provider-specific).
    for fixture in TESTS_DIR.rglob("*.json*"):
        text = fixture.read_text(encoding="utf-8", errors="ignore")
        for idx, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                rel = fixture.relative_to(ROOT)
                offenders.append(f"{rel}:{idx}:{line.strip()!r}")
    assert not offenders, "LLM provider strings found in tests/ (AC-8 violation):\n" + "\n".join(
        f"  - {o}" for o in offenders[:20]
    )
