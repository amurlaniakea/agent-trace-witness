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

## §2 — Q1 (gestión de clave HMAC) CERRADA en 004

La gestión de la clave HMAC en runtime quedó resuelta en feature 004
(merged `e1b8a15`, PR #1). El estado histórico de esta sección se
preserva abajo como trazabilidad; para el estado actual, ver
`README.md` §Q1 y la nueva `## §10 — Cerradas en 004` (más abajo).

**Estado al cierre (2026-09-01):**

- Quién genera la clave: `witness keygen` (CLI). Backend en
  `src/agent_trace_witness/keyring.py` (`KeyEntry.from_generated()`,
  entropía de `secrets.token_hex(32)`).
- Dónde vive: `keys.json` (default `./keys.json`, gitignored,
  modo `0600` en POSIX — ver `## §10` (b)).
- Rotación: `witness rotate-key`. History preservada para
  backward-compat con sellos v1 (sin `key_id`).
- Verificación distribuida (multi-witness): M1 (rotación) y M3
  (varios procesos witness) implementados con HMAC en 004. M2
  (quorum con verificadores independientes) requiere Ed25519
  (clave pública) — sale a 005.
- Backward compat: sellos v1 (sin `key_id`) verifican via
  `verify_seal(sealed, keyring=kr)` con try-all. Fixture
  `tests/fixtures/seal_without_damaging_tool.json` (firma
  `dc91ea...`) sigue verificando byte a byte.

**Histórico (estado antes de 004, preservado para trazabilidad):**

> La gestión de la clave HMAC en runtime NO está resuelta en el MVP:
>
> - Quién genera la clave: el operador (comando sugerido en README:
>   `python -c "import secrets; print(secrets.token_hex(32))"`).
> - Dónde vive: NO en el repo, NO en `.env` versionado. Opciones razonables:
>   secret manager del SO, vault del orquestador, variable de entorno del
>   servicio.
> - Rotación: NO implementada. Cabe en feature 004 "key management".
> - Verificación distribuida (multi-witness): NO soportada. HMAC con clave
>   compartida no escala a múltiples verificadores independientes; Ed25519
>   cabe en feature 004 si la demanda lo requiere.
>
> Detalle completo en `spec/features/001-mvp/plan.md §Q1`. Q1 NO se cierra
> sin revisión explícita de Sil.

Para más detalle de la implementación, ver
`spec/features/004-q1-key-management/{spec,plan,tasks}.md` en el
vault.

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

## §6 — Lo que 003 NO cierra (live stdio implementado; quedan scoring + heurística hex)

`src/agent_trace_witness/mcp_adapter.py::RealMCPClient` (003) implementa
`MCPClient` Protocol con dos modos:

- `from_cassette(path)` (002) — lee cassettes JSONL congeladas sin red,
  sin `ATW_RECORD`, sin credenciales.
- `from_stdio(cmd, args, timeout=)` (003, AC-16) — spawnea el binario
  con `subprocess.Popen` (sin `shell=True`, sin SDK `mcp`/`httpx`/`anyio`),
  hace handshake JSON-RPC 2.0 conforme a spec MCP 2025-03-26
  (`initialize` con `protocolVersion`/`capabilities`/`clientInfo` →
  respuesta con `protocolVersion`/`capabilities`/`serverInfo` →
  `notifications/initialized` sin `id`), y por cada invocación de tool
  emite un único `tools/call` con `params.name`/`arguments` reales;
  `tool_response` y `external_effect` derivan del mismo `result.content`
  (response inspection, no segunda RPC). Tests: 7 en
  `tests/test_live_stdio.py` + 4 en `tests/test_live_stdio_lifecycle.py`
  + 5+2 en `test_cassettes_live.py` y `test_live_stdio_determinism.py`.
  Stub autoral: `tests/fixtures/stubs/mcp_stdio_stub.py` (ver §7 sobre
  circularidad stub/cliente).

`synergy_residual` (replay, AC-15): sigue siendo proxy booleano "queda
algún `atw:externalEffect` tras la poda" — puede dar falso positivo si
sobrevive un efecto externo benigno no relacionado. No distingue "daño
reaparece por otra vía" de "hay un efecto cualquiera". Declarado como
proxy cualitativo sin scoring (C5); scoring numérico es 006
(reconciliación de numeración post-003: scoring estaba en
003/spec.md §No-Goals como 005, después B3 lo movió a 004+ por error
de numeración; ahora se ancla en 006 sinergy, no 004 Q1 ni 005
streamable HTTP).

Riesgo menor anotado en `mcp_adapter.py::_payload_to_bytes`: la
heurística "si string parece hex par solo [0-9a-fA-F], decodifica como
hex" puede colisionar silenciosamente con una palabra legítima par
solo-hex (poco común pero posible). No bloqueante; fix futuro: prefijo
explícito o tipo aparte para payloads hex.

Cosa que 003 SÍ cierra (movida aquí para que un auditor vea el delta
sin tener que leer el commit B3): el antiguo bullet "live stdio NO
implementado" ya no es cierto — `from_stdio` está vivo, con handshake
real y `ATW_RECORD=1` para grabar cassettes. Cierre de este item: 003,
commit `2e8a6a2`.

### §6.1 — Nota de gobernanza: dos intents del commit B2 antes del definitivo (003)

El commit B2 que cierra esta sección (`2e8a6a2`) no es el primer
intento. El operador lo recommiteó dos veces dentro de esta sesión
porque el cuerpo del commit describía contenido que el diff no tenía:

- `5dd290e` (intento 1): cuerpo afirmaba `+3` tests en
  `test_live_stdio.py` y `+1` en `test_live_stdio_lifecycle.py` que en
  realidad vivían en el commit previo `e770d39` o no existían en el
  repo. Diff real: 4 files / 446 insertions. La discrepancia fue
  detectada por el propio agente cotejando el mensaje contra `git
  diff --stat HEAD~1`, no por el pipeline CI.
- `deaa1e7` (intento 2): cuerpo corregido para describir solo los 4
  files reales, pero el conteo de tests (línea "Verificación")
  citaba `105 passed, 1 skipped` (conteo de `e770d39`) en vez del
  conteo real del propio commit (`112 passed, 1 skipped` tras los
  +7 tests B2). Detectado otra vez por el propio agente al contrastar
  el número contra el output crudo de `pytest` en un worktree aislado.
- `2e8a6a2` (definitivo, este commit): cuerpo verificado contra el
  diff y contra el output de pytest en worktree. Diff: 4 files /
  446 insertions. Conteos: 94+1 (B5 cierre 002) → 105+1 (B1) →
  112+1 (B2). Numeración 1-a-1 con la realidad.

El reflog local conserva los tres commits (`5dd290e`, `deaa1e7`,
`2e8a6a2`) hasta el próximo `gc`. Ambos intents intermedios
permanecieron siempre en local, nunca se pushearon; ningún
colaborador externo los vio. La auditoría del mensaje contra el
diff se hizo con `git diff --cached --stat` + `git show --stat` y
conteos verificados en worktrees aislados por SHA (`f530110`,
`e770d39`, `2e8a6a2`).

Lección operativa: el cuerpo de un commit es un claim, no un resumen.
Antes de `git commit` se coteja cada línea del cuerpo (números,
nombres de tests, paths, conteos) contra el diff staged y contra
ejecución real de pytest/ruff en un worktree limpio. Si el cuerpo
no se verifica 1-a-1, se reescribe — no se commitea con la
discrepancia adentro "porque la idea es correcta".

## §7 — Stub de test para live stdio es autoría propia (003, C5)

`tests/fixtures/stubs/mcp_stdio_stub.py` (003) y
`src/agent_trace_witness/mcp_adapter.py::RealMCPClient.from_stdio()` son
ambos autoría de Hermes, basados en su lectura de la spec
`modelcontextprotocol.io/specification/2025-03-26/basic/transports` §stdio
+ `.../basic/lifecycle` §Initialization + `.../server/tools` §Calling Tools
(newline-delimited JSON-RPC UTF-8, `\n` MUST NOT embebido, `initialize`
con `protocolVersion`/`capabilities`/`clientInfo` + `notifications/initialized`
sin `id`, `tools/call` con `{"name":...,"arguments":...}` → `{"content":[...], "isError":...}`).
**El riesgo de circularidad stub/cliente se materializó durante 003:**
B1 `ef7bfc3` (revertido en `520a0e7`, no pusheado) demostró que ambos
lados podían inventar el mismo método RPC falso (`record_tool_call` como
método JSON-RPC en vez de `tools/call` real). El commit `e770d39`
corrigió la implementación a spec 2025-03-26 conforme.

**Mitigación aplicada (003):** el stub responde `-32601 Method not
found` ante cualquier método JSON-RPC desconocido. La verificación
adversarial (ejecutada a mano por el operador y por la suite de tests
tras la corrección) confirmó que `record_tool_call` (y otros métodos
inventados) salen rechazados con ese error — exactamente como respondería
un servidor MCP real. La forma `initialize` con `protocolVersion`/
`capabilities`/`clientInfo` anidados y la respuesta con `serverInfo` se
verifican literal-campo-a-campo en `test_initialize_handshake_conforms_to_spec`.

**Lo que NO se hace:** no se trae un servidor MCP de terceros a CI
(rompería C4 / AC-7). Conformidad verificada contra la spec escrita, no
contra un servidor MCP independiente. El stub no es implementación de
referencia de terceros. Prueba manual de humo fuera de la suite
automatizada contra un servidor MCP real instalable (`npx`/`uvx`, sin
ser dependencia de CI) es opcional y valiosa para dar confianza real,
pero no bloqueante para AC-16. Si esa prueba manual se hace, se
documenta en `tests/fixtures/cassettes/README.md`.

## §10 — Cerradas en 004 (trazabilidad)

Issues que estaban ABIERTOS antes de feature 004 y se cerraron con el
merge de `e1b8a15` (PR #1). Listados aquí para que un auditor que
lea el histórico del repo pueda reconstruir cuándo y cómo se
cerraron. No son issues activos — sólo referencia.

**(a) Rotación de claves HMAC.** Antes de 004, ninguna rotación; el
operador cambiaba la key a mano. 004 implementa `witness rotate-key`
con preservación de history (commit `5a04e4a` backend, `f2d39af`
CLI). Atomicidad: una rotación fallida deja el keyring INALTERADO
(bug no-atómico cazado en revisión de T042, fix en `c5991f0`).

**(b) Permisos del archivo de claves.** El docstring de
`KeyEntry.to_public()` prometía `0600` desde 004 original, pero
`keyring.py` no aplicaba el chmod hasta el commit `d494241`
(2026-09, fix/keyring-permissions-and-docs). El archivo se creaba
con `0644` por defecto — world-readable, brecha entre lo
documentado y lo implementado. El fix añadió `os.chmod(target,
0o600)` gated por `os.name == "posix"` tras el `os.replace` de la
escritura atómica, más 2 tests no-vacíos en `test_keyring.py`
(caso feliz + migración de un `keys.json` heredado en `0644`).
Auditado externamente: SHA `d494241272c1dd4ba5a98164e88ac0d520d24782`.

## §11 — Issues activos fuera de scope de 004

Estos issues se identificaron durante la auditoría post-004 y se
dejan registrados para futura decisión. NO son bugs, son
decisiones de scope que requieren input del operador.

### §11 (a) — Cobertura de tests vs gate declarado

`pyproject.toml` declara `fail_under = 80` en la config de
`pytest-cov`, pero NO hay GitHub Actions que aplique ese gate. La
cobertura real local medida con `pytest --cov=agent_trace_witness`
en este entorno (2026-09-03) reporta **69.67%** (`164 passed, 1
skipped`, con 1220 stmts totales y 370 sin cubrir). El auditor
externo midió 66% en su entorno; la diferencia es de versión de
`coverage` y selección de tests. El gap principal es `cli.py`
(14%, 305 stmts / 262 miss) porque sus tests se ejecutan vía
`subprocess.run` con `CliRunner` indirecto — la cobertura por
import no captura la ejecución del proceso. `keyring.py` está en
97% con los tests de 004 (los nuevos del chmod incluidos); el gap
NO está en 004.

**Acción propuesta (NO implementada):** añadir un workflow de
GitHub Actions mínimo (`.github/workflows/ci.yml`) que corra
`ruff check`, `ruff format --check`, y `pytest --cov` con
`fail_under` relajado temporalmente al 70% (≈ 69.67% actual,
redondeado hacia arriba para que CI no marque en falso) hasta
que `cli.py` llegue a cobertura razonable. Subir el gate a 80% es
un TODO que requiere tests de CLI adicionales.

**Decisión pendiente:** scope de hardening de CI no es parte de
004. Esperar al input de Sil sobre si este trabajo entra en 005,
006, o un sprint dedicado.

### §11 (b) — `KeyEntry` frozen + `object.__setattr__`

`KeyEntry` está declarado `@dataclass(frozen=True)`, pero
`Keyring.rotate_key` y `Keyring.revoke_key` lo mutan vía
`object.__setattr__` (workaround explícito, comentado). Funciona y
tiene tests, pero es chapucero frente a `dataclasses.replace`
(idiomático) o frente a no declararlo `frozen` (más simple pero
pierde la inmutabilidad lógica). La razón original fue evitar
rebuildar todas las fields en cada rotación; revisitar es un
refactor de ~30 LOC.

**Decisión pendiente:** refactor no es bug. Esperar al input de
Sil sobre si entra en 005, 006, o se queda así.

## §12 — Próxima auditoría pendiente

El reporte del auditor independiente que cerró 004 también incluyó
una nota sobre el autor del merge commit `e1b8a15`:
`name=Fenix email=amurlaniakea@gmail.com`. El auditor aplicó la
regla de MEMORY.md (identidad-por-canal) y pidió confirmación
directa. Confirmado por el operador: "Fenix" es el alias de su
blog personal en dev.to, no una identidad de terceros. La
configuración local de `user.name = Fenix` quedó activa en el
entorno desde el que se ejecutó `gh pr merge --squash`, y GitHub
usó esa identidad para el campo `author` del commit mergeado
(el campo `committer` muestra `GitHub <noreply@github.com>`,
firma estándar de squash-m vía la API de GitHub).

**Cierre:** no hay reescritura del commit. No se considera un
issue de seguridad, fue una verificación de identidad que resolvió
en benigno. Documentado aquí para que el siguiente auditor no
re-abra el mismo hilo.
