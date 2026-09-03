# agent-trace-witness

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

External witness for autonomous multi-agent AI systems: signed readiness seal, choke-point capture, and PROV-DM causal graphs for post-incident reconstruction.

Implements mechanisms 1 + 2 + 3 of [HANSARD](https://arxiv.org/abs/2608.22512) (arXiv:2608.22512) as a Python library + CLI. Post-execution forensics — not prevention, not live observability.

## Features

| Mechanism | What it does | CLI | Spec |
|-----------|--------------|-----|------|
| **Seal** (C3) | Signed readiness profile *before* the agent runs: SHA-256 of system prompt, tool list with scopes, timestamp, witness identity, HMAC-SHA256 signature. Any byte changed in the body invalidates the signature. | `witness seal` | AC-1, AC-2 |
| **Capture** (C1) | External witness at 5 choke points — (a) tool call before MCP, (b) MCP response, (c) message to model, (d) model response, (e) external effect (`external_effect` via `record_external_effect` + `witness capture` CLI) — outside the agent's reach (no monkey-patching). | `witness capture` | AC-3, AC-4, AC-11 |
| **Replay** (C2/C4) | Counterfactual replay mecanismo 4 HANSARD — `replay(graph, {remove: URI})` + `witness replay` CLI, compensation_set con cierre transitivo BFS, `synergy_residual` proxy de mecanismo 5, determinismo 10x byte-idéntico. | `witness replay` | AC-12, AC-15 |
| **MCP cassette + live stdio** (C1/C4) | `RealMCPClient.from_cassette(path)` lee JSONL congelado sin red/credenciales (002); `from_stdio(cmd, args, timeout=)` spawnea el binario y habla JSON-RPC 2.0 conforme a spec 2025-03-26 (003, AC-16). `ATW_RECORD=1` graba cassettes live con `close()` hook (003 B2). | `from_cassette` / `from_stdio` | AC-13, AC-14, AC-16, AC-17, AC-18 |
| **Graph** (C2) | Causal graph as PROV-DM JSON-LD (`Entity` / `Activity` / `Agent` + `wasGeneratedBy` / `used` / `wasAssociatedWith`). Canonical, deterministic, interoperable with PROV tools. | `witness graph` + `witness verify` | AC-5, AC-6, AC-9 |

Offline, deterministic, model-agnostic. CPU-only. No network in tests, no LLM calls. Every test < 1 s (AC-7, AC-8).

## Installation

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"   # dev extras: pytest, pytest-cov, ruff
witness --help
```

Without dev extras (library + CLI only):

```bash
pip install -e .
```

## Quickstart — end-to-end (shell-chainable)

```bash
# 1. Generate the HMAC key once with the witness CLI (recommended).
#    Stores the key in ./keys.json (gitignored) with mode 0600.
#    Skip this step if you prefer to set ATW_WITNESS_KEY manually.
witness keygen -o keys.json

#    Alternative (still supported, uses the legacy env-var path):
#    python -c "import secrets; print(secrets.token_hex(32))"
#    export ATW_WITNESS_KEY="<64-hex-chars>"

# 2. Seal — signed readiness profile from an agent spec.
cat > /tmp/agent_spec.json <<'JSON'
{
  "system_prompt": "Solo lee archivos en /data",
  "tools": [
    {"name": "read_file", "scopes": ["read:/data/**"]},
    {"name": "list_dir",  "scopes": ["read:/data/**"]}
  ],
  "witness_id": "witness-cli-1"
}
JSON
witness seal --spec /tmp/agent_spec.json --out /tmp/seal.json
cat /tmp/seal.json | jq .signature   # hmac-sha256:<64-hex>

# 3. Capture — 5 choke points from a scenario file (4 MVP + external_effect via CLI y librería; live MCP stdio es 003+).
cat > /tmp/scenario.json <<'JSON'
[
  {"kind": "tool_call",     "tool": "read_file", "payload": {"path": "/data/x"}},
  {"kind": "tool_response", "tool": "read_file", "payload": "contents"},
  {"kind": "model_input",   "role": "user",      "payload": "read /data/x"},
  {"kind": "model_output",  "role": "assistant", "payload": "done"}
]
JSON
witness capture --scenario /tmp/scenario.json --seal /tmp/seal.json --out /tmp/events.jsonl
cat /tmp/events.jsonl | jq .type

# 4. Graph — PROV-DM JSON-LD causal graph.
witness graph --events /tmp/events.jsonl --seal /tmp/seal.json --out /tmp/graph.jsonld
cat /tmp/graph.jsonld | jq '."@context".prov'   # http://www.w3.org/ns/prov#

# 5. Verify — seal-constrained anomaly detection (exit 0 even with anomalies; anomalies are report-only).
witness verify --graph /tmp/graph.jsonld --seal /tmp/seal.json
witness verify --graph /tmp/graph.jsonld --seal /tmp/seal.json --json | jq .anomalies

# Pipeline form:
witness seal --spec /tmp/agent_spec.json --out /tmp/seal.json && \
witness capture --scenario /tmp/scenario.json --seal /tmp/seal.json --out /tmp/events.jsonl && \
witness graph --events /tmp/events.jsonl --seal /tmp/seal.json --out /tmp/graph.jsonld && \
witness verify --graph /tmp/graph.jsonld --seal /tmp/seal.json --json | jq .
```

Exit codes: `0` success (including `verify` with anomalies), `1` input error (missing file, bad JSON, bad seal signature), `2` internal error.

## Development

```bash
ruff check .            # lint (E, F, I, W, B, UP)
ruff format --check .   # formatting
pytest -q               # 68 passed, 1 skipped (jq)
pytest -v               # per-test names
pytest --durations=0 -v # AC-7 determinism check
```

## Scope

### What it DOES (001-mvp + 002-replay + 003-live-stdio — C1 + C2 + C3 + C4 + C5)

- Generates a **signed seal** before execution (AC-1). Detects any post-hoc tampering via HMAC-SHA256 (constant-time compare). Reads the key from `ATW_WITNESS_KEY` (single name for prod and tests; no test-only branch).
- **Captures** at 5 choke points outside the agent's code (AC-3, AC-4, AC-11) — (a) tool call, (b) MCP response, (c) model input, (d) model output, (e) external effect (`record_external_effect` + `witness capture --scenario` con `kind: external_effect` vía CLI y librería). `capture.py` + `mcp_adapter.py` importan abstracción MCP, nunca el agente. Verificado por static grep — 0 hits para monkey-patching.
- **Emits** a PROV-DM JSON-LD graph (AC-5, AC-6) con typed nodes/relations + `atw:externalEffect=true` para el 5º choke point, canónico (`sort_keys=True`) y determinista (10x run byte-idéntico).
- **Replays** contrafactual (HANSARD mecanismo 4, AC-12/AC-15): `replay(graph, {remove: atw:activity/tool_call_n})` + `witness replay --graph --seal --counterfactual --out` produce `compensation_set` (subgrafo con cierre transitivo BFS sobre `wasGeneratedBy/used/wasDerivedFrom`) + `synergy_residual` proxy de mecanismo 5 (booleano cualitativo, ver KNOWN_ISSUES §6) + `not_replayable` (C5). Determinismo 10x byte-idéntico, sin RNG/time.
- **Real MCP — cassette y live stdio** (AC-13/AC-14/AC-16/AC-17/AC-18): `RealMCPClient.from_cassette(path)` lee JSONL congelado `<1 MB` sin red/credenciales (002); `from_stdio(cmd, args, timeout=)` spawnea el binario y habla JSON-RPC 2.0 conforme a spec MCP 2025-03-26 — `initialize` con `protocolVersion`/`capabilities`/`clientInfo`, `notifications/initialized` sin `id`, un solo `tools/call` con `params.name`/`arguments` reales, `external_effect` derivado del mismo `result.content` (003). `ATW_RECORD=1` graba cassettes live con hook en `close()`; CI nunca graba, solo lee.
- **Verifies** a graph against its seal and reports `unsealed_tool` anomalies with `severity: error` (AC-2, AC-9). External-validity fixture `hansard_scenario_1.jsonl` built from HANSARD §attribution laundering, not from expected witness output.
- CLI is shell-chainable: every artifact is JSON/JSONL/JSON-LD and `jq` can consume it without manual parsing (AC-10, AC-15). Pipeline `seal → capture(5) → graph → replay → verify` ejercitado de punta a punta vía CLI (incluido `not_replayable` exit 1).

### What it DOES NOT (declared, not hidden — C5 / KNOWN_ISSUES.md)

- **No synergy scoring numérico completo** (mecanismo 5 full) — 002/003 produce `synergy_residual` booleano proxy; score continuo es 006 (ver KNOWN_ISSUES §6, reconciliación de numeración post-003).
- **No streamable-HTTP transport** MCP — 003 cubre solo stdio (newline-delimited JSON-RPC). Streamable HTTP es 005.
- **No eBPF / kernel tracing** para efectos externos — alcance es filesystem/subprocess/MCP-response inspection a nivel biblioteca, no syscall del SO.
- **No BekchiAI** (live observability + remote termination, arXiv:2608.26867), **no TraceGrant** (contract-governed prevention, arXiv:2608.21126), **no CTF-ABACUS solve profiles** (arXiv:2608.26237). Position is complementary: the witness produces the post-execution graph that those systems can consume. See `spec/constitution.md` C8.
- **No Ed25519.** Signs with HMAC-SHA256. Distributed verification (multi-witness, public-key verification) is feature 004 (Q1).
- **No server / REST API.** Library + CLI that the caller integrates. Server is 007.
- **HMAC key management** is implemented in feature 004 (merged `e1b8a15`, PR #1). Generate, store, and rotate keys with `witness keygen`, `witness rotate-key`, `witness revoke-key`, and `witness list-keys`. The default `keys.json` is created with `0600` permissions on POSIX. Distributed verification (multi-witness, public-key) is feature 005 (Ed25519).

If something you expected is in the list above, it is not a bug — it is declared scope. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the living list.

## Q1 — HMAC key management (IMPLEMENTED in 004)

`witness keygen` generates a 32-byte (64 hex chars) HMAC key, registers it
in a `keys.json` (default `./keys.json`, gitignored), and locks the file
to `0600` on POSIX. The key is selected for signing by the active entry
in the keyring. Rotation and revocation are CLI subcommands.

```bash
# One-time per operator: generate and register the active key.
witness keygen -o keys.json
# -> generated key_id=2026-09-01T00:00:00.000001Z algorithm=hmac -> keys.json
# -> keys.json mode: 0600 (POSIX; Windows has no chmod bit)

# Rotate (old key becomes inactive, new one becomes active; history
# preserved for v1 backward-compat verification).
witness rotate-key -o keys.json

# Revoke (excluded from verification; kept in the file for audit).
witness revoke-key <key_id> -o keys.json

# Inspect.
witness list-keys -o keys.json
```

**The legacy path still works**: `export ATW_WITNESS_KEY=<64-hex>` is
honored by `witness seal/verify` when no `keyring=` argument is passed.
This keeps 001/002/003 cassettes and pipelines operational without
modification.

**Backward compatibility (D5–D7 of plan.md)**: a `SealedSeal` written
before 004 (no `key_id` field) verifies correctly via `verify_seal(
sealed, keyring=kr)` — the verifier tries every non-revoked key in
the keyring until one matches. The 001 fixture
`tests/fixtures/seal_without_damaging_tool.json` (signature
`dc91ea...`) was used as the regression test target during 004
development and continues to verify.

**Ed25519 / multi-witness distributed verification is NOT in 004.**
HMAC is symmetric, so M2 (threshold quorum with independent verifiers)
is structurally impossible with HMAC. Ed25519 enables M1+M2+M3
whereas HMAC only enables M1+M3. Ed25519 is feature 005.

Detail: `spec/features/004-q1-key-management/{spec,plan,tasks}.md`
in the Obsidian vault (not in this repo).

## License

[AGPL-3.0-or-later](LICENSE) — Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>.

SPDX headers on every `.py` file. See [LICENSE](LICENSE) for the full text.
