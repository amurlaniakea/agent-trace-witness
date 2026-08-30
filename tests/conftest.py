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

"""Shared pytest fixtures for agent-trace-witness tests (T015).

The only fixture exposed here is ``witness_key``: it sets
``ATW_WITNESS_KEY`` to a fixed hex-encoded 32-byte HMAC key for every test,
so production code paths exercise the real env-var wiring instead of a
test-only branch (per plan.md §Configuración: "un único nombre
ATW_WITNESS_KEY para prod y tests").

If a test needs the key to be ABSENT (e.g. T018), it uses the
``no_witness_key`` fixture, which clears the env var for that test only.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest

# Fixed 32-byte HMAC key, hex-encoded (64 chars). Stable across the suite
# so signatures produced in one test are verifiable in another.
# This value is NOT secret: it is the test key, never used outside pytest.
_FIXED_KEY_HEX = "0" * 64


@pytest.fixture(autouse=True)
def witness_key() -> Generator[None, None, None]:
    """Set ``ATW_WITNESS_KEY`` to a fixed test value for every test.

    Saves the previous value (if any) and restores it on teardown so the
    fixture is safe to run alongside other suites that may set the same
    variable.
    """
    saved = os.environ.get("ATW_WITNESS_KEY")
    os.environ["ATW_WITNESS_KEY"] = _FIXED_KEY_HEX
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("ATW_WITNESS_KEY", None)
        else:
            os.environ["ATW_WITNESS_KEY"] = saved


@pytest.fixture
def no_witness_key() -> Generator[None, None, None]:
    """Temporarily unset ``ATW_WITNESS_KEY`` for the duration of one test.

    Used by ``T018`` to verify that ``sign_seal`` raises
    ``WitnessKeyError`` when no key is provided.
    """
    saved = os.environ.pop("ATW_WITNESS_KEY", None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ["ATW_WITNESS_KEY"] = saved
