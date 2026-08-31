# Known Issues — agent-trace-witness

> Documento vivo. Lo que el motor NO hace (o hace peor de lo que la spec
> recomienda) se declara aquí, no se maquilla. C5: "lo que no esté
> implementado se declara en KNOWN_ISSUES.md, no se maquilla."

## §1 — 002 captura 5 de 5 choke points vía CLI y librería (cierre de MVP)

El motor captura (desde 002):

- (a) tool call antes de salir hacia el servidor MCP,
- (b) respuesta del servidor MCP,
- (c) mensaje al modelo,
- (d) respuesta del modelo,
- (e) efecto externo del tool (`external_effect` — file write, delete,
  side-effect) vía `capture.record_external_effect` y `witness capture`
  con `kind: external_effect` (fix B4 c57e1fa: el CLI ya expone el 5º choke
  point; antes de ese fix la librería lo soportaba pero el CLI lo rechazaba).

El `Verify` emite el 5º choke point como `prov:Entity` con
`atw:externalEffect=true` + `prov:wasGeneratedBy`. El `replay` (mecanismo 4)
opera sobre ese grafo con cierre transitivo BFS — ver §6 para proxy
`synergy_residual` y limitación eBPF.

Legado MVP (001): 001 capturaba 4/5 y `verify_graph` reportaba external
effects como "no captured". Desde 002 esa limitación queda cerrada para
biblioteca y CLI; eBPF/kernel tracing sigue fuera de alcance (biblioteca,
no syscall SO).

## §2 — Q1 (gestión de clave HMAC) ABIERTA

La gestión de la clave HMAC en runtime NO está resuelta en el MVP:

- Quién genera la clave: el operador (comando sugerido en README:
  `python -c "import secrets; print(secrets.token_hex(32))"`).
- Dónde vive: NO en el repo, NO en `.env` versionado. Opciones razonables:
  secret manager del SO, vault del orquestador, variable de entorno del
  servicio.
- Rotación: NO implementada. Cabe en feature 004 "key management".
- Verificación distribuida (multi-witness): NO soportada. HMAC con clave
  compartida no escala a múltiples verificadores independientes; Ed25519
  cabe en feature 004 si la demanda lo requiere.

Detalle completo en `spec/features/001-mvp/plan.md §Q1`. Q1 NO se cierra
sin revisión explícita de Sil.

## §3 — Integración MCP real vía cassettes (002); live stdio pendiente (003+)

Desde 002:

- `src/agent_trace_witness/mcp_adapter.py::RealMCPClient` implementa
  `MCPClient` Protocol y lee **cassettes** `tests/fixtures/cassettes/*.jsonl`
  vía `from_cassette(path)` — sin red, sin credenciales. `AC-13/AC-14`
  se verifican contra cassettes; tests `test_real_mcp_adapter.py` +
  `test_cassettes.py` lo cubren.
- `tests/fixtures/mcp_client.py::MockMCPClient` **no se elimina**: queda
  como contrato del Protocol y como referencia para tests unitarios.
  `AC-3` original sigue corriendo contra mock; `AC-13/AC-14` complementan
  con cassettes reales — el mock no reemplaza la verificación con
  cassettes.
- **Live stdio** (`subprocess.Popen` + framing MCP real) **no está
  implementado en 002** — ver §6. El nombre `RealMCPClient` no implica
  transporte vivo en 002 (es cassette + memoria en este corte). Pertenece
  a 003+.

## §4 — Claves HMAC de 16–31 bytes se aceptan sin aviso

`seal.sign_seal` rechaza claves de menos de 16 bytes (raise
`WitnessKeyError`). Plan §Seguridad recomienda 32 bytes pero NO se exige
en el MVP: claves entre 16 y 31 bytes pasan silenciosamente sin warning.

Implicación para C3: un seal firmado con una clave de 16 bytes es
criptográficamente más débil que uno firmado con 32+. La firma sigue siendo
válida (HMAC-SHA256 funciona con cualquier longitud ≥ bloque del hash = 16
bytes para SHA-256), pero la seguridad forward de la clave es menor.

Mitigación hasta feature 004:

- Los operadores DEBEN usar 32+ bytes (documentado en README).
- `HMAC_KEY_RECOMMENDED_BYTES = 32` está como constante informativa en
  `seal.py`; cualquier código que quiera endurecer puede compararla.
- El test `test_seal_rejects_short_key` cubre el límite inferior (<16).
  NO hay test que distinga 16 de 32 bytes a propósito (esa política no
  está implementada todavía).

Endurecimiento (raise por debajo de 32) pertenece a feature 004 junto con
el resto de Q1.

## §5 — Clave de test hardcodeada en fixtures (no es secreto, pero se declara)

La suite usa una clave HMAC fija `0`×64 (32 bytes de ceros, hex) definida
en `tests/conftest.py` (`_FIXED_KEY_HEX`) y un seal pre-firmado
`tests/fixtures/seal_without_damaging_tool.json` firmado con esa misma clave
(`witness-fixture-1`, signature `dc91ea10…`). Esto es **intencional y
documentado** — no es un leak:

- La clave de test NO es la clave de producción. Prod lee
  `ATW_WITNESS_KEY` del entorno del operador; tests la sobreescriben vía
  fixture `autouse` `witness_key` que setea `ATW_WITNESS_KEY=0…0` y
  `ATW_WITNESS_TS=2026-08-30T14:33:00+00:00` para determinismo (AC-7).
- El fixture `seal_without_damaging_tool.json` verifica end-to-end (su
  `signature` pasa `verify_seal` con la test key) y se carga en
  `test_external_validity.py` + `test_cli.py::test_cli_verify_*`.
- Fuera de tests, el código hace `raise WitnessKeyError` si `ATW_WITNESS_KEY`
  falta (sin default en prod). Ver `plan.md` §Q1 y `seal.py::sign_seal`.
- `ATW_WITNESS_TS` congela timestamps de capture para que `pytest` sea
  byte-idéntico entre runs (T090/T091); los tests de seal pasan
  `created_at` explícito y no dependen de esa var.

Si un escáner de secretos flaggea `0`×64 o `dc91ea10…`, es falso positivo
de test — añadir excepción para `tests/` + `tests/fixtures/`.

## §6 — RealMCPClient en 002 es cassette-only (live stdio NO implementado)

`src/agent_trace_witness/mcp_adapter.py::RealMCPClient` (T030, AC-13)
implementa `MCPClient` Protocol y en 002 **solo** lee cassettes congeladas
`tests/fixtures/cassettes/*.jsonl` vía `from_cassette(path)` — sin red,
sin `ATW_RECORD`, sin credenciales. No hace `subprocess.Popen`, no lee
`stdin`/`stdout`, no parsea protocolo MCP real en este corte.

El docstring original prometía "Live (cuando hay servidor): context manager
que spawnea subprocess MCP vía stdio" — esa promesa NO se cumple en 002 y
se corrigió para no inducir a error (C5). El nombre `RealMCPClient` no
implica transporte live en 002: en 002 es cassette + memoria, mismo patrón
que `MockMCPClient` pero con fichero congelado en vez de eventos sintéticos
en el test. El test `test_real_mcp_client_not_alias_of_mock` solo prueba
que son clases distintas con distinto origen de eventos, no que uno hable
stdio real.

Consecuencia: AC-13 "lectura de eventos reales del transporte MCP" en 002
se verifica contra cassettes pregrabadas, no contra un servidor MCP vivo.
El spawn live stdio (Popen + framing MCP) pertenece a 003+ (o a un
follow-up de 002 si se prioriza).

Riesgo menor anotado en `mcp_adapter.py::_payload_to_bytes`: la heurística
"si string parece hex par solo [0-9a-fA-F], decodifica como hex" puede
colisionar silenciosamente con una palabra legítima par solo-hex (poco
común pero posible). No bloqueante para B3; fix futuro: prefijo explícito
o tipo aparte para payloads hex.

`synergy_residual` (replay): proxy booleano "queda cualquier
`atw:externalEffect` tras la poda" — puede dar falso positivo si sobrevive
un efecto externo benigno no relacionado. No distingue "daño reaparece por
otra vía" de "hay un efecto cualquiera". Declarado como proxy cualitativo
sin scoring (C5); scoring numérico es 003+.

## §7 — Stub de test para live stdio es autoría propia (003, C5)

`tests/fixtures/stubs/mcp_stdio_stub.py` (003) y
`src/agent_trace_witness/mcp_adapter.py::RealMCPClient.from_stdio()` son
ambos autoría de Hermes, basados en su lectura de la spec
`modelcontextprotocol.io/specification/2025-03-26/basic/transports` §stdio
+ `.../basic/lifecycle` §Initialization + `.../server/tools` §Calling Tools
(newline-delimited JSON-RPC UTF-8, `\n` MUST NOT embebido, `initialize`
con `protocolVersion`/`capabilities`/`clientInfo` + `notifications/initialized`,
`tools/call` con `{"name":...,"arguments":...}` → `{"content":[...],"isError":...}`).
Si ambos comparten el mismo malentendido de un detalle del framing o de la
semántica (shape de `initialize`, inventar `record_*` como métodos RPC en
vez de `tools/call` real), AC-16 puede pasar en verde sin hablar con un
servidor MCP conforme a spec. B1 `ef7bfc3` demostró que esto no es
hipotético: ambos lados inventaron `record_tool_call` como método RPC —
misma circularidad cazada con los fixtures HANSARD en AC-9, pero a nivel de
protocolo completo. Tras el revert, 003 exige `initialize` real +
`tools/call` real + `external_effect` **derivado** del mismo `result.content`
(no como RPC separada, igual que 002: response inspection).

No se trae un servidor MCP de terceros a CI (rompería C4). Conformidad
verificada contra la spec escrita, no contra un servidor MCP independiente.
El stub no es implementación de referencia de terceros. Prueba manual de
humo fuera de la suite automatizada contra un servidor MCP real instalable
(`npx`/`uvx`, sin ser dependencia de CI) es opcional y valiosa para dar
confianza real, pero no bloqueante para AC-16. Si esa prueba manual se
hace, se documenta en `tests/fixtures/cassettes/README.md`.
