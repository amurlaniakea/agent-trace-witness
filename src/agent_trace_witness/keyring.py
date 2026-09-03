# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Q1 key management (feature 004) — HMAC operativa.

No se toca seal.py: este modulo es independente. El Keyring carga
``keys.json`` (multi-clave versionada) y provee la API que T044
usará para sign/verify con key_id lookup + backward compat v1.

Decisiones ancladas (plan.md D1-D7):
- D1: ``--algorithm hmac`` default explícito, no implícito.
- D3: 0 dependencias nuevas (secrets, json, dataclasses, pathlib, os).
- D4: ``keys/`` está en .gitignore.
- D6/D7: key_id via metadata del contenedor, no del body firmado.

Este modulo NO contiene CLI. Los subcommands typer viven en cli.py
(witness = "agent_trace_witness.cli:app"), consistente con C7/C5.
"""

from __future__ import annotations

import datetime
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

ALGORITHM_HMAC = "hmac"
_ALGORITHMS = (ALGORITHM_HMAC,)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyEntry:
    """Una entrada en el archivo de claves.

    key_id: timestamp ISO-8601 UTC (ej. "2026-09-01T12:00:00Z"). Sirve como
      selector de clave en verify, NO como field firmado (D6).
    algorithm: "hmac" hoy. "ed25519" reservado para 005 (D2).
    secret: 64 hex chars = 32 bytes (32-byte HMAC-SHA256 recomendado).
    created_at: timestamp de creación (ISO-8601 UTC).
    active: True = usar para firmar. Sólo debe haber una active.
    revoked_at: None o timestamp. Si no es None, excluida de verify.
    """

    key_id: str
    algorithm: Literal["hmac"]
    secret: str  # 64 hex chars
    created_at: str
    active: bool = False
    revoked_at: str | None = None

    def __post_init__(self) -> None:
        if self.algorithm not in _ALGORITHMS:
            raise ValueError(
                f"algorithm {self.algorithm!r} is not implemented in 004; "
                f"implemented: {_ALGORITHMS}. Use feature 005 for ed25519."
            )
        decoded = bytes.fromhex(self.secret)
        if len(decoded) != 32:
            raise ValueError(
                f"HMAC secret must decode to exactly 32 bytes (64 hex chars), "
                f"got {len(decoded)} bytes"
            )
        if not self.key_id:
            raise ValueError("key_id must be a non-empty timestamp")

    @classmethod
    def from_generated(cls, algorithm: str = ALGORITHM_HMAC, key_id: str | None = None) -> KeyEntry:
        """Genera una nueva entry con entropía de ``secrets`` (stdlib)."""
        if algorithm not in _ALGORITHMS:
            raise NotImplementedError(
                f"keygen algorithm {algorithm!r} is feature 005; implemented in 004: {_ALGORITHMS}"
            )
        kid = key_id or _utc_timestamp()
        secret_hex = secrets.token_hex(32)
        return cls(
            key_id=kid,
            algorithm=algorithm,
            secret=secret_hex,
            created_at=kid,
            active=True,
        )

    def to_public(self) -> dict:
        """Serialización para keys.json (excluye nada sensible, la secret
        va al archivo; en disco el archivo debe estar en 0600)."""
        return asdict(self)


@dataclass
class Keyring:
    """Multi-clave versionada para rotación + verificación.

    - ``active_key()``: la única entrada con active=True, revoked_at=None.
    - ``verification_keys()``: active + no-revoked (para verify v1 fallback).
    - ``rotate_key()``: marca activa como inactive, genera nueva active.
    - ``revoke_key(key_id)``: set revoked_at, la excluye de verify.
    """

    keys: list[KeyEntry] = field(default_factory=list)
    path: str | None = None

    # -- persistence ----------------------------------------------------------

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Keyring:
        """Load keyring from a JSON file.

        File schema (v1):
            {"keys": [KeyEntry.to_dict(), ...]}

        If the file does not exist, returns an empty Keyring with no keys.
        """
        p = Path(path)
        if not p.exists():
            return cls(path=str(path))
        data = json.loads(p.read_text(encoding="utf-8"))
        keys = [
            KeyEntry(
                key_id=e["key_id"],
                algorithm=e["algorithm"],
                secret=e["secret"],
                created_at=e["created_at"],
                active=e.get("active", False),
                revoked_at=e.get("revoked_at"),
            )
            for e in data.get("keys", [])
        ]
        return cls(keys=keys, path=str(path))

    def save(self, path: str | os.PathLike[str] | None = None) -> None:
        """Atomic write a ``keys.json`` (temporal + os.replace).

        Previene torn writes si el proceso crashea a mitad de flush.
        """
        target = Path(path or self.path or "keys.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"keys": [k.to_public() for k in self.keys]}
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, target)
        # Restrict permissions on POSIX (the file contains HMAC secrets in
        # clear). 0600 = owner read/write only. Best-effort: on Windows
        # the mode bit is meaningless, so we skip silently. This honors
        # the docstring of KeyEntry.to_public() (line ~92): "en disco el
        # archivo debe estar en 0600".
        if os.name == "posix":
            os.chmod(target, 0o600)

    # -- accessors -----------------------------------------------------------

    def active_key(self) -> KeyEntry:
        """La única key activa y no revocada. AssertionError si 0 o >1."""
        act = [k for k in self.keys if k.active and k.revoked_at is None]
        if len(act) != 1:
            raise AssertionError(f"expected exactly 1 active non-revoked key, found {len(act)}")
        return act[0]

    def verification_keys(self) -> list[KeyEntry]:
        """Todas las keys aceptadas para verify (any active; revoked excluded)."""
        return [k for k in self.keys if k.revoked_at is None]

    def get_key(self, key_id: str) -> KeyEntry | None:
        """Exact-match lookup por key_id. Devuelve None si no existe o está revocado."""
        for k in self.keys:
            if k.key_id == key_id and k.revoked_at is None:
                return k
        return None

    # -- mutations -----------------------------------------------------------

    def add_key(self, entry: KeyEntry) -> None:
        """Añade una entry. Falla si ya existe el key_id."""
        if any(k.key_id == entry.key_id for k in self.keys):
            raise ValueError(f"key_id {entry.key_id!r} already exists")
        self.keys.append(entry)

    def rotate_key(self) -> KeyEntry:
        """Marca la active actual como inactive y genera una nueva active.

        **Atómico:** la desactivación de la clave vieja y la promoción de
        la nueva ocurren como un solo paso al final, DESPUÉS de confirmar
        que la nueva se generó con key_id único. Si los reintentos se
        agotan, NINGUNA mutación ocurre — el keyring queda exactamente
        como estaba. Esto es el invariante que el test
        ``test_rotate_failure_is_atomic`` verifica: una rotación fallida
        no debe dejar el sistema sin claves activas.

        Preserva todas las entradas anteriores (no-revoked) para verify
        v1. El retry cubre el caso residual de colisión de timestamp a
        microsegundos (extremadamente raro: necesitaría dos llamadas a
        ``datetime.now(UTC)`` en el mismo microsegundo).
        """
        active = self.active_key()
        for _ in range(3):
            new_entry = KeyEntry.from_generated()
            if not any(k.key_id == new_entry.key_id for k in self.keys):
                # Atomic transition: old -> inactive, new -> in keys.
                # Sólo llegamos aquí si la nueva es válida y única.
                object.__setattr__(active, "active", False)
                self.keys.append(new_entry)
                return new_entry
        # 3 reintentos agotados: NO mutamos el keyring. El operador
        # conserva la clave activa que tenía.
        raise RuntimeError(
            "Could not generate a unique key_id after 3 attempts "
            "(timestamp collision within same microsecond)"
        )

    def revoke_key(self, key_id: str) -> None:
        """Revoca (no elimina) una key: set revoked_at."""
        for k in self.keys:
            if k.key_id == key_id:
                object.__setattr__(k, "revoked_at", _utc_timestamp())
                return
        raise KeyError(f"key_id {key_id!r} not found in keyring")

    def is_empty(self) -> bool:
        return len(self.keys) == 0


# -- helpers -----------------------------------------------------------------


def _utc_timestamp() -> str:
    """ISO-8601 UTC con microsegundos.

    Microsegundos (no segundos) porque key_id debe ser único incluso
    cuando dos claves se generan dentro del mismo segundo — el smoke
    test del CLI (T042) cazó que dos rotate_key() en <1s colisionaban
    y el retry de rotate_key agotaba sus 3 intentos. Con precisión de
    microsegundos la colisión es improbable y el retry queda como red.
    """
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def keygen(algorithm: str = ALGORITHM_HMAC) -> KeyEntry:
    """Genera una KeyEntry nueva con entropía de secrets (stdlib, no-red).

    Public API para T042 (CLI) y directo por operadores.
    """
    return KeyEntry.from_generated(algorithm=algorithm)
