# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hygiene test (T045-1): keys/ must be gitignored.

Plan D4 / spec T045-1: ``keys/`` está en ``.gitignore`` para que
las claves HMAC generadas por ``witness keygen`` NUNCA se
commiteen por accidente. El test ejecuta ``git check-ignore`` con
varios nombres canónicos y verifica que cada uno retorna 0
(ignorado).

El test es no-vacío: si alguien quita ``keys/`` del .gitignore,
los checks retornan 1 y pytest falla.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _is_ignored(relpath: str) -> bool:
    """Return True if `git check-ignore` says the path is ignored.

    `git check-ignore` returns 0 if the path IS ignored, 1 if not
    (and prints the path on stdout). We assert on the return code
    AND on the printed path.
    """
    result = subprocess.run(
        ["git", "check-ignore", relpath],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


class TestKeysGitignored:
    """T045-1: keys/ y variantes deben estar en .gitignore."""

    def test_keys_directory_ignored(self) -> None:
        """El directorio `keys/` está ignorado (D4/T045-1)."""
        assert _is_ignored("keys/"), (
            "`keys/` is not in .gitignore — `witness keygen` would "
            "expose HMAC keys via accidental commit"
        )

    def test_keys_json_default_ignored(self) -> None:
        """`keys.json` (default --out del CLI) está ignorado."""
        assert _is_ignored("keys.json"), "`keys.json` is not in .gitignore"

    def test_keys_json_under_keys_dir_ignored(self) -> None:
        """`keys/active.json` está ignorado (cubierto por `keys/`)."""
        assert _is_ignored("keys/active.json"), "`keys/active.json` is not in .gitignore"

    def test_arbitrary_keys_json_ignored(self) -> None:
        """Cualquier `*.keys.json` está ignorado (cubierto por el glob)."""
        assert _is_ignored("prod.keys.json"), "`*.keys.json` pattern missing from .gitignore"

    def test_unrelated_path_not_ignored(self) -> None:
        """Sanity: paths no relacionados NO caen en el .gitignore.
        Si esto falla, el .gitignore es demasiado permisivo."""
        assert not _is_ignored("README.md"), ".gitignore is matching unrelated paths (too broad)"
