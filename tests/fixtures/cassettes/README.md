# Cassettes — agent-trace-witness (feature 002)

Grabación manual con `ATW_RECORD=1` fuera de CI; CI solo lee.

## Cómo grabar

```bash
ATW_RECORD=1 python -m agent_trace_witness.record --scenario tests/fixtures/cassettes/scenario.json --out tests/fixtures/cassettes/mcp_stdio_001.jsonl
# o manualmente: el adapter escribe una línea JSON por EventTuple
# {"timestamp": "2026-08-31T00:00:00+00:00", "type": "tool_call", "payload": {"tool":"read_file","args":{"path":"/tmp/x"}}}
```

Cada línea es un `EventTuple` serializado con `timestamp`, `type` (uno de 5 choke points) y `payload` (dict/hex/str). Tamaño objetivo <1 MB total (R13).

## Cómo reproducir en CI

```python
from agent_trace_witness.mcp_adapter import RealMCPClient

client = RealMCPClient.from_cassette("tests/fixtures/cassettes/mcp_stdio_001.jsonl")
for ev in client.events():
    ...  # sin red, sin ATW_RECORD, sin credenciales
```

## Sanitización

Antes de commit, sanitizar payloads: hashes, no contenido sensible. No commitear API keys ni paths reales de producción.
