# agent-trace-witness

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

External witness for autonomous multi-agent AI systems: signed readiness seal, choke-point capture, and PROV-DM causal graphs for post-incident reconstruction.

Implements mechanisms 1 + 2 + 3 of [HANSARD](https://arxiv.org/abs/2608.22512) (arXiv:2608.22512) as a Python library + CLI. Post-execution forensics — not prevention, not live observability.

## Features

| Mechanism | What it does | CLI | Spec |
|-----------|--------------|-----|------|
| **Seal** (C3) | Signed readiness profile *before* the agent runs: SHA-256 of system prompt, tool list with scopes, timestamp, witness identity, HMAC-SHA256 signature. Any byte changed in the body invalidates the signature. | `witness seal` | AC-1, AC-2 |
| **Capture** (C1) | External witness at 4 choke points — (a) tool call before MCP, (b) MCP response, (c) message to model, (d) model response — outside the agent's reach (no monkey-patching). | `witness capture` | AC-3, AC-4 |
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
# 1. Generate the HMAC key once (never commit it — see §Q1 below).
#    Store it in your secret manager or env; tests use a fixed value
#    via conftest.py, production reads ATW_WITNESS_KEY.
python -c "import secrets; print(secrets.token_hex(32))"
export ATW_WITNESS_KEY="<64-hex-chars>"

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

# 3. Capture — 4 choke points from a scenario file (MVP; feature 002 adds live MCP mode).
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

### What it DOES (MVP 001 — C1 + C2 + C3)

- Generates a **signed seal** before execution (AC-1). Detects any post-hoc tampering via HMAC-SHA256 (constant-time compare). Reads the key from `ATW_WITNESS_KEY` (single name for prod and tests; no test-only branch).
- **Captures** at 4 choke points outside the agent's code (AC-3, AC-4). `capture.py` imports `mcp` abstraction, never the agent. Verified by static grep — 0 hits for monkey-patching patterns.
- **Emits** a PROV-DM JSON-LD graph (AC-5, AC-6) with typed nodes and relations, canonical (`sort_keys=True`) and deterministic (10× run identical byte-for-byte).
- **Verifies** a graph against its seal and reports `unsealed_tool` anomalies with `severity: error` (AC-2, AC-9). External-validity fixture `hansard_scenario_1.jsonl` built from HANSARD §attribution laundering, not from expected witness output.
- CLI is shell-chainable: every artifact is JSON/JSONL/JSON-LD and `jq` can consume it without manual parsing (AC-10).

### What it DOES NOT (declared, not hidden — C5 / KNOWN_ISSUES.md)

- **No external-effect capture.** The 5th choke point (file write, network request) requires a replay engine — feature 002. The MVP captures 4/5; `verify_graph` explicitly reports external effects as `not captured`.
- **No replay contrafactual** (HANSARD mechanism 4) and **no synergy residual** (mechanism 5) — features 002+.
- **No BekchiAI** (live observability + remote termination, arXiv:2608.26867), **no TraceGrant** (contract-governed prevention, arXiv:2608.21126), **no CTF-ABACUS solve profiles** (arXiv:2608.26237). Position is complementary: the witness produces the post-execution graph that those systems can consume. See `spec/constitution.md` C8.
- **No Ed25519.** MVP signs with HMAC-SHA256. Distributed verification (multi-witness, public-key verification) is feature 004 if demanded.
- **No server / REST API.** Library + CLI that the caller integrates. Server is feature 005+.
- **No real MCP client integration.** `tests/fixtures/mcp_client.py` is a `MockMCPClient` that documents the contract a real client must satisfy. `AC-3` runs against the mock in this MVP; it will re-run against real-client cassettes when feature 002 lands.
- **No HMAC key management.** Q1 is OPEN — documented in `spec/features/001-mvp/plan.md` §Q1 and `KNOWN_ISSUES.md` §2. Key generation, storage, rotation, and distributed verification are feature 004.

If something you expected is in the list above, it is not a bug — it is declared scope. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the living list.

## Q1 — HMAC key management (OPEN)

`ATW_WITNESS_KEY` is a 64-hex-char (32-byte) HMAC key the operator generates:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

- Never in the repo, never in versioned `.env`. Use a secret manager, orchestrator vault, or service env.
- Rotation, multi-witness, and Ed25519 are feature 004.
- Tests set the key via `tests/conftest.py` to `0`×64 so the suite runs without external secrets.

Detail: `spec/features/001-mvp/plan.md` §Q1. Q1 does not close without explicit review by Sil.

## License

[AGPL-3.0-or-later](LICENSE) — Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>.

SPDX headers on every `.py` file. See [LICENSE](LICENSE) for the full text.
