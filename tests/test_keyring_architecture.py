# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Architecture guard for feature 004 (T042-decision).

Prohibe que keyring.py adquiera dependencias que violen D3 (stdlib-only,
CLI fuera del module de lógica). Esto NO es C4/AC-7 (que protege contra
imports de red en production code) — es una guarda de *layering*:
el module de key management (keyring.py) no debe contener CLI/Typer,
porque el entry point real del repo es cli:app
(agent_trace_witness/cli.py). Un segundo Typer() en keyring.py no se
registraría, y un import de typer allí por "comodidad" haría imposible
que los tests lo detecten como violación de arquitectura.

Patrón idéntico a test_capture_architecture.py (que prohíbe que
capture.py importe código del agente).

Este test es no-vacío: si alguien añade 'import typer' a keyring.py,
falla.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_trace_witness"

# Modules that keyring.py is ALLOWED to import (stdlib + internal logic).
# typer is deliberately forbidden here — CLI lives in cli.py.
FORBIDDEN_IMPORTS_IN_KEYRING = {"typer"}


class TestKeyringArchitecture:
    """keyring.py must remain pure logic: stdlib-only, no typer."""

    def test_keyring_does_not_import_typer(self) -> None:
        """D3: keyring.py no importa typer. Si alguien lo añade, este test
        falla — el mismo patrón que capture.py vs agent code."""
        target = SRC / "keyring.py"
        text = target.read_text(encoding="utf-8")
        import_re = re.compile(
            r"^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_.]+)\s+import)",
            re.MULTILINE,
        )
        offenders = []
        for m in import_re.finditer(text):
            mod = (m.group(1) or m.group(2) or "").split(".")[0]
            if mod in FORBIDDEN_IMPORTS_IN_KEYRING:
                offenders.append(f"{target.name}: {m.group(0).strip()!r}")
        assert not offenders, (
            "keyring.py must not import typer or other CLI/transport "
            f"dependencies (D3). Violations:\n  - {offenders}"
        )

    def test_keyring_only_imports_stdlib(self) -> None:
        """D3 reforzado: todo import de keyring.py debe ser stdlib o
        intra-package (agent_trace_witness.*). No typer, no cryptography."""
        target = SRC / "keyring.py"
        text = target.read_text(encoding="utf-8")
        allowed_stdlib = {
            "datetime",
            "json",
            "os",
            "secrets",
            "dataclasses",
            "pathlib",
            "typing",
            "re",
            "__future__",
        }
        import_re = re.compile(
            r"^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_.]+)\s+import)",
            re.MULTILINE,
        )
        for m in import_re.finditer(text):
            mod = (m.group(1) or m.group(2) or "").split(".")[0]
            if mod == "agent_trace_witness":
                continue
            assert mod in allowed_stdlib, (
                f"keyring.py imports {mod!r} which is not stdlib or intra-package — violates D3"
            )
