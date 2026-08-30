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

"""CLI tests — AC-10 (T086-T089).

Every test exercises the CLI via ``subprocess.run`` so the entire Typer
+ entry-point + exit-code chain is verified, not just the Python
functions under test. The two help-only tests use Typer's in-memory
CliRunner instead (no process spawn) to stay under the 1.0 s per-test
budget that T090 (AC-7) enforces — subprocess for every --help would
push test_cli_help_works to ~1.4 s (5× ~0.25 s spawn) and violate the
determinism gate. Behaviour is identical: CliRunner still exercises the
same Typer app + exit codes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

WITNESS_BIN = Path(sys.executable).parent / "witness"

# Skip the whole module if the witness entry point isn't on PATH —
# happens if the editable install is broken or pytest runs in a
# different venv than expected.
pytestmark = pytest.mark.skipif(
    not WITNESS_BIN.exists(),
    reason=f"witness entry point not found at {WITNESS_BIN}",
)


def _run(args: list[str], *, env: dict | None = None) -> subprocess.CompletedProcess:
    """Invoke the CLI as a subprocess. ``env`` is added to os.environ."""
    import os

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    return subprocess.run(
        [str(WITNESS_BIN), *args],
        capture_output=True,
        text=True,
        env=full_env,
        check=False,
    )


def _fixture_spec(tmp_path: Path) -> Path:
    """Write a minimal agent spec fixture, return its path."""
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "system_prompt": "Solo lee archivos en /data",
                "tools": [
                    {"name": "read_file", "scopes": ["read:/data/**"]},
                    {"name": "list_dir", "scopes": ["read:/data/**"]},
                ],
                "witness_id": "witness-cli-test",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return spec_path


# ---- T086 — AC-10 part 1: --help works for every subcommand --------------


def test_cli_help_works() -> None:
    """The CLI prints a help screen for ``witness --help`` and every
    subcommand (``seal``, ``capture``, ``graph``, ``verify``).

    Each invocation exits 0 and the stdout contains a description.
    Uses CliRunner (in-memory) to stay under the 1.0 s budget of T090.
    """
    from typer.testing import CliRunner

    from agent_trace_witness.cli import app

    runner = CliRunner()
    for cmd in [[], ["seal"], ["capture"], ["graph"], ["verify"]]:
        result = runner.invoke(app, [*cmd, "--help"])
        assert result.exit_code == 0, (
            f"`witness {' '.join(cmd)} --help` exited {result.exit_code}: stderr={result.output!r}"
        )
        assert result.output.strip(), f"`witness {' '.join(cmd)} --help` produced empty output"
        assert "witness" in result.output.lower(), (
            f"`witness {' '.join(cmd)} --help` output missing 'witness': {result.output[:200]!r}"
        )


def test_cli_root_help_lists_all_subcommands() -> None:
    """The root help screen mentions every subcommand. A new operator
    should be able to discover all four from a single ``--help`` call.
    Uses CliRunner (in-memory) for speed — see test_cli_help_works.
    """
    from typer.testing import CliRunner

    from agent_trace_witness.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for sub in ("seal", "capture", "graph", "verify"):
        assert sub in result.output, (
            f"root --help missing subcommand {sub!r}: {result.output[:300]!r}"
        )


# ---- T087 — AC-10 part 2: seal end-to-end --------------------------------


def test_cli_seal_end_to_end(tmp_path: Path) -> None:
    """``witness seal --spec X --out Y`` produces a valid signed seal.

    Y is parseable JSON, has every required key, and the signature
    verifies against the same HMAC key the rest of the suite uses.
    """
    spec_path = _fixture_spec(tmp_path)
    out_path = tmp_path / "seal.json"

    result = _run(["seal", "--spec", str(spec_path), "--out", str(out_path)])
    assert result.returncode == 0, (
        f"seal exited {result.returncode}: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    assert out_path.exists(), "seal --out file was not created"

    data = json.loads(out_path.read_text(encoding="utf-8"))
    required = {"system_prompt_sha256", "tools", "created_at", "witness_id", "signature"}
    missing = required - data.keys()
    assert not missing, f"seal output missing keys: {missing}"

    # Signature format: "hmac-sha256:<64-hex>".
    sig = data["signature"]
    assert sig.startswith("hmac-sha256:")
    hexpart = sig.split(":", 1)[1]
    assert len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart), (
        f"malformed signature: {sig!r}"
    )

    # And the seal is verifiable end-to-end through the library API
    # (same code path the verifier uses).
    from agent_trace_witness.seal import seal_from_dict, verify_seal

    sealed = seal_from_dict(data)
    assert verify_seal(sealed) is True


# ---- T088 — AC-10 part 3: exit codes --------------------------------------


def test_cli_exit_code_on_missing_spec(tmp_path: Path) -> None:
    """A missing input file produces exit code 1 (input error).

    The CLI must NOT crash with a stack trace; it must print a clear
    error and exit with the documented code.
    """
    result = _run(
        [
            "seal",
            "--spec",
            str(tmp_path / "does_not_exist.json"),
            "--out",
            str(tmp_path / "out.json"),
        ]
    )
    assert result.returncode == 1, (
        f"missing --spec should exit 1, got {result.returncode}; stderr={result.stderr!r}"
    )
    assert "error" in result.stderr.lower()
    assert "not found" in result.stderr.lower()


def test_cli_exit_code_on_malformed_spec_json(tmp_path: Path) -> None:
    """Malformed JSON in the input produces exit code 1."""
    spec_path = tmp_path / "bad.json"
    spec_path.write_text("{not json", encoding="utf-8")
    result = _run(["seal", "--spec", str(spec_path), "--out", str(tmp_path / "out.json")])
    assert result.returncode == 1, f"malformed JSON should exit 1, got {result.returncode}"
    assert "not valid json" in result.stderr.lower()


def test_cli_exit_code_on_invalid_seal_signature(tmp_path: Path) -> None:
    """A seal whose signature does not verify produces exit code 1
    (input error) when fed to ``witness graph``.

    Teeth: if the CLI skipped signature verification, this test would
    pass (no exception); the teeth are the exit code assertion.
    """
    # Create a syntactically valid seal with a bogus signature.
    bogus_seal = tmp_path / "bogus.json"
    bogus_seal.write_text(
        json.dumps(
            {
                "system_prompt_sha256": "0" * 64,
                "tools": [{"name": "read_file", "scopes": []}],
                "created_at": "2026-08-30T14:33:00+00:00",
                "witness_id": "witness-bogus",
                "signature": "hmac-sha256:" + "f" * 64,  # wrong
            }
        ),
        encoding="utf-8",
    )
    events_path = tmp_path / "events.jsonl"
    events_path.write_text("", encoding="utf-8")
    out_path = tmp_path / "graph.jsonld"

    result = _run(
        ["graph", "--events", str(events_path), "--seal", str(bogus_seal), "--out", str(out_path)]
    )
    assert result.returncode == 1, (
        f"bogus seal signature should exit 1, got {result.returncode}; stderr={result.stderr!r}"
    )
    assert "signature" in result.stderr.lower()


def test_cli_exit_code_on_unwritable_output(tmp_path: Path) -> None:
    """A write failure (output path inside a file, not a dir) produces
    exit code 2 (internal error).

    T081/AC-10 explicit: 2 = internal error. We hit _die_internal via
    _write_json's OSError handler by pointing --out at a path whose
    parent component is a regular file (not a directory). mkdir(parents=True)
    raises NotADirectoryError (subclass of OSError) → _die_internal →
    typer.Exit(code=2).
    """
    spec_path = _fixture_spec(tmp_path)
    # /output_file_dir does not exist; tmp_path/blocker is a file, so
    # mkdir(parents=True) on tmp_path/blocker/sub will fail.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    bad_out = blocker / "sub" / "seal.json"  # parent 'sub' is under 'blocker' (a file)

    result = _run(["seal", "--spec", str(spec_path), "--out", str(bad_out)])
    assert result.returncode == 2, (
        f"unwritable output should exit 2 (internal error), got {result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    assert "internal error" in result.stderr.lower()
    assert "could not write" in result.stderr.lower()


def test_cli_verify_exits_zero_even_when_anomalies_present(tmp_path: Path) -> None:
    """``witness verify`` exits 0 even when the trace contains unsealed
    tools (T085 explicit). Anomalies are report-only.

    This test uses the HANSARD fixture (delete_file not in seal) and
    confirms exit 0.
    """

    # Set the test key so the seal verifies.
    env = {"ATW_WITNESS_KEY": "0" * 64, "ATW_WITNESS_TS": "2026-08-30T14:33:00+00:00"}
    seal_src = Path(__file__).resolve().parent / "fixtures" / "seal_without_damaging_tool.json"
    events_src = Path(__file__).resolve().parent / "fixtures" / "hansard_scenario_1.jsonl"
    seal_dst = tmp_path / "seal.json"
    events_dst = tmp_path / "events.jsonl"
    graph_dst = tmp_path / "graph.jsonld"
    shutil.copy(seal_src, seal_dst)
    shutil.copy(events_src, events_dst)

    # Build the graph first.
    r_graph = _run(
        ["graph", "--events", str(events_dst), "--seal", str(seal_dst), "--out", str(graph_dst)],
        env=env,
    )
    assert r_graph.returncode == 0, f"graph step failed: {r_graph.stderr!r}"

    # Now verify. Anomalies will be reported (delete_file is unsealed).
    # Exit code MUST be 0.
    r_verify = _run(
        ["verify", "--graph", str(graph_dst), "--seal", str(seal_dst)],
        env=env,
    )
    assert r_verify.returncode == 0, (
        f"verify should exit 0 even with anomalies; got {r_verify.returncode}: "
        f"stderr={r_verify.stderr!r} stdout={r_verify.stdout!r}"
    )
    assert "delete_file" in r_verify.stdout, (
        f"verify stdout should mention delete_file anomaly: {r_verify.stdout!r}"
    )


# ---- T089 — AC-10 part 4: shell-chainable output -------------------------


def test_cli_can_be_chained_in_shell(tmp_path: Path) -> None:
    """The seal output is valid JSON; ``jq .signature`` extracts the
    signature field. This proves the output is consumable by standard
    shell tooling without manual parsing.

    ``jq`` is an external dependency of THIS TEST, not of the code. If
    jq is not installed, the test is skipped.
    """
    jq = shutil.which("jq")
    if jq is None:
        pytest.skip("jq not installed on this system")

    spec_path = _fixture_spec(tmp_path)
    seal_path = tmp_path / "seal.json"

    # First, generate the seal.
    r1 = _run(["seal", "--spec", str(spec_path), "--out", str(seal_path)])
    assert r1.returncode == 0

    # Now pipe it through jq.
    proc = subprocess.run(
        [jq, ".signature", str(seal_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    sig = proc.stdout.strip()
    assert sig.startswith("hmac-sha256:")
    assert len(sig.split(":", 1)[1]) == 64


# ---- additional CLI invariants --------------------------------------------


def test_cli_capture_writes_jsonl(tmp_path: Path) -> None:
    """End-to-end: ``witness capture --scenario X --seal Y --out Z``
    produces a JSONL file where every line is a valid JSON object with
    the required CaptureEvent keys.
    """
    spec_path = _fixture_spec(tmp_path)
    seal_path = tmp_path / "seal.json"
    _run(["seal", "--spec", str(spec_path), "--out", str(seal_path)])

    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(
        json.dumps(
            [
                {"kind": "tool_call", "tool": "read_file", "payload": {"path": "/data/x"}},
                {"kind": "tool_response", "tool": "read_file", "payload": "contents"},
            ]
        ),
        encoding="utf-8",
    )
    events_path = tmp_path / "events.jsonl"

    r = _run(
        [
            "capture",
            "--scenario",
            str(scenario_path),
            "--seal",
            str(seal_path),
            "--out",
            str(events_path),
        ]
    )
    assert r.returncode == 0, f"capture failed: {r.stderr!r}"
    assert events_path.exists()

    lines = events_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        d = json.loads(line)
        for k in ("ts", "type", "payload_sha256", "seal_ref"):
            assert k in d, f"event line missing key {k!r}: {line}"


def test_cli_verify_json_output(tmp_path: Path) -> None:
    """``witness verify --json`` emits a JSON document with ``summary``
    and ``anomalies`` keys. Useful for piping into jq / dashboards.
    """

    env = {"ATW_WITNESS_KEY": "0" * 64, "ATW_WITNESS_TS": "2026-08-30T14:33:00+00:00"}
    seal_src = Path(__file__).resolve().parent / "fixtures" / "seal_without_damaging_tool.json"
    events_src = Path(__file__).resolve().parent / "fixtures" / "hansard_scenario_1.jsonl"
    seal_dst = tmp_path / "seal.json"
    events_dst = tmp_path / "events.jsonl"
    graph_dst = tmp_path / "graph.jsonld"
    shutil.copy(seal_src, seal_dst)
    shutil.copy(events_src, events_dst)

    _run(
        ["graph", "--events", str(events_dst), "--seal", str(seal_dst), "--out", str(graph_dst)],
        env=env,
    )

    r = _run(
        ["verify", "--graph", str(graph_dst), "--seal", str(seal_dst), "--json"],
        env=env,
    )
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert "summary" in payload
    assert "anomalies" in payload
    assert any(a["tool"] == "delete_file" for a in payload["anomalies"])


def test_cli_emits_to_stderr_for_errors(tmp_path: Path) -> None:
    """Errors go to stderr (so they don't pollute a JSON pipeline on
    stdout). An operator piping the output to jq should not see the
    error message in the JSON stream.
    """
    spec_path = tmp_path / "missing.json"  # does not exist
    r = _run(["seal", "--spec", str(spec_path), "--out", str(tmp_path / "out.json")])
    assert r.returncode == 1
    # stderr has the message; stdout is empty (or has only Typer's
    # usage banner, which is fine — we just check the message isn't
    # silently swallowed into stdout).
    assert r.stderr.strip()
    # And stdout is NOT the error message (it can be empty or Typer's
    # usage info, but not the error itself).
    assert "error:" not in r.stdout.lower() or r.stdout == ""
