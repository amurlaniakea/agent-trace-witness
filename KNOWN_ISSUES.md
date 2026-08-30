# Known Issues — agent-trace-witness

> Documento vivo. Lo que el motor NO hace (o hace peor de lo que la spec
> recomienda) se declara aquí, no se maquilla. C5: "lo que no esté
> implementado se declara en KNOWN_ISSUES.md, no se maquilla."

## §1 — MVP captura 4 de 5 choke points

El motor captura:

- (a) tool call antes de salir hacia el servidor MCP,
- (b) respuesta del servidor MCP,
- (c) mensaje al modelo,
- (d) respuesta del modelo.

**No** captura (e) el efecto externo del tool (file write, network request,
side-effect en el sistema). El quinto choke point requiere un replay engine
que pueda aislar el efecto de una hipotética eliminación del tool, lo que
pertenece al mecanismo 4 de HANSARD (replay contrafactual). Se aborda en
feature 002.

Consecuencia para el caller: si el incidente a posteriori muestra un efecto
externo no trazado, el witness lo declara explícitamente como "no captured"
en `verify_graph` — no se inventa cobertura que no tuvo.

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

## §3 — Sin integración con cliente MCP real

El MVP usa un `MockMCPClient` en `tests/fixtures/mcp_client.py`. La
documentación del contrato que un cliente real debe cumplir vive en el
docstring de ese módulo. La integración con un cliente MCP de producción
(lectura de eventos reales, sin cassettes) pertenece a feature 002.

Consecuencia: `AC-3` corre contra el mock en este MVP. Cuando se integre el
cliente real, `AC-3` debe re-correr contra cassettes pregrabadas del
cliente real — el mock NO debe reemplazar la verificación end-to-end.

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