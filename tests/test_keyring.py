# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for feature 004 T041 (keyring.py core).

Cubre KeyEntry, Keyring.load/save, keygen(), active_key(), rotate_key(),
revoke_key(), get_key(), verification_keys().

No hace network: solo secrets + json + tempfile (stdlib).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_trace_witness.keyring import (
    ALGORITHM_HMAC,
    KeyEntry,
    Keyring,
    keygen,
)

# ---------------------------------------------------------------------------
# T041-2 / T041-3: Keyring persistence (load/save atomic)
# ---------------------------------------------------------------------------


class TestKeyringPersistence:
    def test_load_missing_returns_empty(self, tmp_path: Path) -> None:
        """T041-2: load sobre archivo inexistente -> Keyring vacío."""
        kr = Keyring.load(tmp_path / "nonexistent.json")
        assert kr.keys == []
        assert kr.is_empty()

    def test_load_empty_file_returns_empty(self, tmp_path: Path) -> None:
        """T041-2: load sobre {} -> Keyring vacío."""
        p = tmp_path / "empty.json"
        p.write_text("{}")
        kr = Keyring.load(p)
        assert kr.is_empty()

    def test_save_then_load_roundtrip(self, tmp_path: Path) -> None:
        """T041-3: save -> load preserva todas las fields."""
        kr = Keyring(path=str(tmp_path / "keys.json"))
        entry = keygen()
        kr.add_key(entry)
        kr.save()
        loaded = Keyring.load(tmp_path / "keys.json")
        assert len(loaded.keys) == 1
        assert loaded.keys[0].key_id == entry.key_id
        assert loaded.keys[0].secret == entry.secret
        assert loaded.keys[0].active is True

    def test_save_is_atomic_creates_no_tmp(self, tmp_path: Path) -> None:
        """T041-3: after save, no .tmp file lingers."""
        kr = Keyring(path=str(tmp_path / "keys.json"))
        kr.add_key(keygen())
        kr.save()
        assert not (tmp_path / "keys.json.tmp").exists()


# ---------------------------------------------------------------------------
# T041-1 / T041-4: KeyEntry + keygen
# ---------------------------------------------------------------------------


class TestKeyEntryAndKeygen:
    def test_keygen_returns_64_hex_hmac(self) -> None:
        """T041-4: keygen() produce 64 hex chars, algorithm=hmac."""
        entry = keygen()
        assert isinstance(entry, KeyEntry)
        decoded = bytes.fromhex(entry.secret)
        assert len(entry.secret) == 64  # 32 bytes = 64 hex
        assert len(decoded) == 32
        assert entry.algorithm == ALGORITHM_HMAC
        assert entry.active is True

    def test_keygen_is_deterministic_entropy_not_predictable(self) -> None:
        """Two keygen calls must produce different secrets (entropía real)."""
        a = keygen()
        b = keygen()
        assert a.secret != b.secret

    def test_keyentry_rejects_wrong_algorithm(self) -> None:
        """T041-1: KeyEntry con ed25519 lanza ValueError (005)."""
        with pytest.raises(ValueError, match="feature 005"):
            KeyEntry(
                key_id="2026-01-01T00:00:00Z",
                algorithm="ed25519",
                secret="a" * 64,
                created_at="2026-01-01T00:00:00Z",
            )

    def test_keyentry_rejects_short_secret(self) -> None:
        """T041-1: < 32 bytes lanza ValueError."""
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            KeyEntry(
                key_id="2026-01-01T00:00:00Z",
                algorithm="hmac",
                secret="00",  # 1 byte
                created_at="2026-01-01T00:00:00Z",
            )

    def test_keyentry_rejects_empty_key_id(self) -> None:
        """T041-1: key_id vacío lanza ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            KeyEntry(
                key_id="",
                algorithm="hmac",
                secret="0" * 64,
                created_at="2026-01-01T00:00:00Z",
            )

    def test_to_public_roundtrip(self) -> None:
        """T041-1: to_public produce dict con todas las keys."""
        entry = KeyEntry.from_generated(key_id="2026-01-01T00:00:00Z")
        d = entry.to_public()
        assert set(d.keys()) == {
            "key_id",
            "algorithm",
            "secret",
            "created_at",
            "active",
            "revoked_at",
        }


# ---------------------------------------------------------------------------
# T041-5: active_key
# ---------------------------------------------------------------------------


class TestActiveKey:
    def test_active_key_single(self) -> None:
        """T041-5: exactamente 1 active -> se devuelve."""
        kr = Keyring()
        e1 = keygen()
        object.__setattr__(e1, "active", True)
        kr.add_key(e1)
        assert kr.active_key() is e1

    def test_active_key_none_raises(self) -> None:
        """T041-5: 0 active -> AssertionError."""
        kr = Keyring()
        with pytest.raises(AssertionError, match="expected exactly 1"):
            kr.active_key()

    def test_active_key_multiple_raises(self) -> None:
        """T041-5: >1 active -> AssertionError.

        Usa key_ids distintos para evitar colisión de timestamp (el test
        corre en <1s, y keygen() usa timestamp a segundos como key_id).
        """
        kr = Keyring()
        e1 = keygen()
        object.__setattr__(e1, "active", True)
        e2 = KeyEntry(
            key_id="2026-08-31T19:00:00Z",
            algorithm=ALGORITHM_HMAC,
            secret="a" * 64,
            created_at="2026-08-31T19:00:00Z",
            active=True,
        )
        kr.add_key(e1)
        kr.add_key(e2)
        with pytest.raises(AssertionError, match="expected exactly 1"):
            kr.active_key()


# ---------------------------------------------------------------------------
# T043: rotate + revoke
# ---------------------------------------------------------------------------


class TestRotateAndRevoke:
    def test_rotate_key_chain(self) -> None:
        """T043-1: 3 rotaciones -> 3 entries, última active."""
        kr = Keyring()
        first = keygen()
        kr.add_key(first)
        assert kr.active_key() is first
        second = kr.rotate_key()
        assert kr.active_key() is second
        assert first.active is False
        third = kr.rotate_key()
        assert kr.active_key() is third
        assert len(kr.keys) == 3

    def test_rotate_failure_is_atomic(self) -> None:
        """T043-1-fix: una rotación fallida deja el keyring INALTERADO.

        Bug cazado en revisión de T042: el test anterior
        (test_rotate_never_duplicates_key_id) verificaba ``e1.active is
        False`` tras el fallo, lo que CODIFICABA el bug como correcto.
        El bug real: rotate_key desactivaba la clave vieja ANTES de
        generar la nueva, así que si los 3 reintentos colisionan, el
        keyring queda sin activas (active_key() -> AssertionError) y
        el witness no puede firmar.

        El invariante correcto: rotación fallida = keyring exactamente
        como estaba. Este test lo verifica forzando colisión garantizada
        (monkeypatch de _utc_timestamp que siempre devuelve el key_id de
        e1) y asintiendo que tras el RuntimeError:
        - len(kr.keys) == 1 (no se añadió nueva)
        - e1.active is True (NO se desactivó)
        - active_key() devuelve e1 (no AssertionError de 0 activas)
        """
        import agent_trace_witness.keyring as kr_mod
        from agent_trace_witness.keyring import _utc_timestamp as orig_ts

        kr = Keyring()
        e1 = keygen()
        kr.add_key(e1)

        # Force ALL new timestamps to equal e1's (guaranteed collision).
        kr_mod._utc_timestamp = lambda: e1.key_id  # type: ignore[assignment]
        try:
            with pytest.raises(RuntimeError, match="unique key_id"):
                kr.rotate_key()
        finally:
            kr_mod._utc_timestamp = orig_ts  # noqa: E731

        # Atomic invariant: keyring unchanged after a failed rotation.
        assert len(kr.keys) == 1
        assert e1.active is True
        assert kr.active_key() is e1  # no AssertionError, keyring usable

    def test_revoked_key_excluded(self) -> None:
        """T043-2: revoked_at excluye de verification_keys()."""
        kr = Keyring()
        e = keygen()
        kr.add_key(e)
        assert len(kr.verification_keys()) == 1
        kr.revoke_key(e.key_id)
        assert len(kr.verification_keys()) == 0
        assert kr.get_key(e.key_id) is None

    def test_rotating_twice_preserves_history(self) -> None:
        """T043-1: no-revoked history permanece para verify."""
        kr = Keyring()
        e1 = keygen()
        kr.add_key(e1)
        kr.rotate_key()  # e1 -> inactive, pero no revocado
        kr.rotate_key()  # e2 -> inactive, e3 -> active
        assert len(kr.keys) == 3
        assert len(kr.verification_keys()) == 3  # ninguna revocada

    def test_revoked_key_still_in_keys_list(self) -> None:
        """La revocación no borra; excluye de verify_keys()."""
        kr = Keyring()
        e = keygen()
        kr.add_key(e)
        kr.revoke_key(e.key_id)
        assert len(kr.keys) == 1  # sigue en la lista
        assert len(kr.verification_keys()) == 0  # excluida de verify


# ---------------------------------------------------------------------------
# T044-0 helper: get_key
# ---------------------------------------------------------------------------


class TestGetKey:
    def test_get_key_exact_match(self) -> None:
        kr = Keyring()
        e = keygen()
        kr.add_key(e)
        assert kr.get_key(e.key_id) is e
        assert kr.get_key("nonexistent") is None

    def test_get_key_excludes_revoked(self) -> None:
        kr = Keyring()
        e = keygen()
        kr.add_key(e)
        kr.revoke_key(e.key_id)
        assert kr.get_key(e.key_id) is None
