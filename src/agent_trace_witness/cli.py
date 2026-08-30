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

"""Typer CLI entrypoint for agent-trace-witness.

Subcommands (implemented across B1..B5 of the plan):

- ``seal``:    generate a signed readiness profile from an agent spec.
- ``capture``: record events at the 4 choke points (external to the agent).
- ``graph``:   emit a PROV-DM JSON-LD causal graph from captured events.
- ``verify``:  check a graph against a seal and report anomalies.

B0 ships the structural skeleton only. Logic is added block by block.
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="witness",
    help=(
        "External witness for autonomous multi-agent AI systems: signed "
        "readiness seal, choke-point capture, and PROV-DM causal graphs "
        "for post-incident reconstruction."
    ),
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def seal(
    spec: str = typer.Option(..., "--spec", help="Path to agent spec JSON."),
    out: str = typer.Option(..., "--out", help="Path to write the signed seal."),
) -> None:
    """Generate a signed readiness seal (B1, T082)."""
    raise NotImplementedError("seal command ships in B1 (T082).")


@app.command()
def capture(
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
    out: str = typer.Option(..., "--out", help="Path to write captured events (JSONL)."),
) -> None:
    """Record events at the 4 choke points (B2, T083)."""
    raise NotImplementedError("capture command ships in B2 (T083).")


@app.command()
def graph(
    events: str = typer.Option(..., "--events", help="Path to captured events JSONL."),
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
    out: str = typer.Option(..., "--out", help="Path to write the PROV-DM graph (JSON-LD)."),
) -> None:
    """Emit a PROV-DM JSON-LD causal graph (B3, T084)."""
    raise NotImplementedError("graph command ships in B3 (T084).")


@app.command()
def verify(
    graph_path: str = typer.Option(..., "--graph", help="Path to the PROV-DM graph."),
    seal_path: str = typer.Option(..., "--seal", help="Path to the signed seal."),
) -> None:
    """Check a graph against a seal and report anomalies (B4, T085)."""
    raise NotImplementedError("verify command ships in B4 (T085).")


if __name__ == "__main__":
    app()
