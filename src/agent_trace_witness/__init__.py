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
# You should have received a copy of the GNU Affero General Public
# License along with this program. If not, see
# <https://www.gnu.org/licenses/>.

"""agent-trace-witness: external witness for autonomous multi-agent AI systems.

Implements mechanisms 1+2+3 of HANSARD (arXiv:2608.22512) as a Python
library and CLI:

- ``seal``: signed readiness profile, generated before the agent starts.
- ``capture``: choke-point event capture, external to the agent.
- ``graph``: PROV-DM JSON-LD causal graph emitter.

Replay (mechanism 4) and synergy residual (mechanism 5) are out of scope
for the MVP and addressed in follow-up features. See KNOWN_ISSUES.md.
"""

__version__ = "0.1.0"
