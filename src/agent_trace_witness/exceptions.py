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

"""Exception hierarchy for agent-trace-witness (T010).

All public functions raise one of these. Tests pin the type so callers can
distinguish witness failures from generic ``ValueError`` / ``KeyError`` / etc.
"""


class WitnessError(Exception):
    """Base class for every error raised by agent-trace-witness."""


class WitnessKeyError(WitnessError, ValueError):
    """``ATW_WITNESS_KEY`` is missing, empty, or not a valid 32-byte HMAC key.

    Raised by ``seal.sign_seal`` and ``seal.verify_seal``. ``Q1`` keeps the
    production-side key management open; tests fix the key via a fixture.
    """


class WitnessSealError(WitnessError, ValueError):
    """A seal could not be produced, signed, or verified.

    Covers malformed ``AgentSpec`` inputs, signature mismatches, JSON-LD
    canonicalization failures, and any other condition that prevents a
    well-formed signed seal.
    """


class WitnessCaptureError(WitnessError, RuntimeError):
    """The capture pipeline could not record an event.

    Covers a missing/inactive seal reference, an event type outside the 4
    choke points, a payload that cannot be hashed, or an MCP client that
    rejected the request.
    """


class WitnessGraphError(WitnessError, ValueError):
    """The graph emitter could not produce or validate a PROV-DM JSON-LD doc.

    Covers missing required fields in events, broken causal chains, or
    malformed PROV URIs in the input. Distinct from ``WitnessSealError``
    because the seal itself may be intact while the graph built from it is
    inconsistent.
    """


class WitnessReplayError(WitnessError, ValueError):
    """The replay engine could not produce a counterfactual result (T010).

    Covers a ``counterfactual`` that references an unknown Activity ID,
    a graph that is not a valid PROV-DM JSON-LD doc, or a compensation
    set that cannot be computed deterministically. Distinct from
    ``WitnessGraphError`` because the graph itself may be valid while
    the requested counterfactual is not replayable (C5: ``not_replayable``).
    """
