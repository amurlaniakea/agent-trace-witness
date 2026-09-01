# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for sign_seal(keyring=...) and verify_seal(keyring=...).

Feature 004 T044-2, T044-3, T044-4.

These tests focus on the integration between the seal module and
the Q1 keyring. D6/D7 (key_id is post-signature metadata, not in
the HMAC body) is enforced here too.
"""

from __future__ import annotations

import pytest

from agent_trace_witness.keyring import KeyEntry, Keyring
from agent_trace_witness.seal import (
    AgentSpec,
    Seal,
    SealedSeal,
    Tool,
    make_seal,
    sign_seal,
    verify_seal,
)

FIXTURE_KEY = "0" * 64  # 32 zero bytes


def _make_unsigned_seal() -> Seal:
    """Build an unsigned Seal deterministically (no env vars)."""
    spec = AgentSpec(
        system_prompt="test",
        tools=(Tool(name="read_file", scopes=("read",)),),
        witness_id="witness-test",
    )
    return make_seal(spec, witness_id="witness-test", created_at="2026-09-01T00:00:00+00:00")


class TestSignSealWithKeyring:
    """T044-2: sign_seal(keyring=...) embeds key_id in the SealedSeal."""

    def test_sign_with_keyring_sets_key_id(self) -> None:
        """sign_seal(keyring=...) puts the active key_id in the SealedSeal."""
        seal = _make_unsigned_seal()
        entry = KeyEntry(
            key_id="2026-09-01T00:00:00.000001Z",
            algorithm="hmac",
            secret=FIXTURE_KEY,
            created_at="2026-09-01T00:00:00.000001Z",
            active=True,
        )
        kr = Keyring(keys=[entry])
        signed = sign_seal(seal, keyring=kr)
        assert isinstance(signed, SealedSeal)
        assert signed.key_id == "2026-09-01T00:00:00.000001Z"

    def test_sign_with_keyring_signature_uses_active_key(self) -> None:
        """The signature in the SealedSeal is the HMAC over the body with
        the keyring's active key (verifiable via verify_seal with the
        same key)."""
        seal = _make_unsigned_seal()
        kr = Keyring()
        kr.add_key(KeyEntry.from_generated(key_id="kid-1"))
        signed = sign_seal(seal, keyring=kr)
        # The signature must verify with the keyring's active key.
        assert verify_seal(signed, key=kr.active_key().secret) is True

    def test_sign_without_keyring_key_id_is_none(self) -> None:
        """Backward compat: sign_seal(seal, key=<hex>) leaves key_id=None.

        This is the legacy path used by 001/002/003 seals — they have
        no key_id in their SealedSeal.
        """
        seal = _make_unsigned_seal()
        signed = sign_seal(seal, key=FIXTURE_KEY)
        assert signed.key_id is None
        assert verify_seal(signed, key=FIXTURE_KEY) is True

    def test_keyring_overrides_key_arg(self) -> None:
        """When both are passed, keyring wins (precedence: keyring > key)."""
        seal = _make_unsigned_seal()
        kr = Keyring()
        kr.add_key(KeyEntry.from_generated(key_id="kr-wins"))
        # Pass a bogus key, but the keyring should override.
        signed = sign_seal(seal, key="ff" * 32, keyring=kr)
        assert signed.key_id == "kr-wins"
        # The signature was made with the keyring's active key, not the bogus one.
        assert verify_seal(signed, key=kr.active_key().secret) is True
        assert verify_seal(signed, key="ff" * 32) is False

    def test_hmac_with_and_without_keyring_is_identical(self) -> None:
        """D6: the HMAC is computed over the same canonical body regardless
        of whether sign_seal uses a keyring. Only the key_id metadata
        changes.
        """
        seal = _make_unsigned_seal()
        # Path 1: legacy, no keyring.
        legacy = sign_seal(seal, key=FIXTURE_KEY)
        # Path 2: keyring with the same key.
        entry = KeyEntry(
            key_id="kid-1",
            algorithm="hmac",
            secret=FIXTURE_KEY,
            created_at="2026-09-01T00:00:00Z",
            active=True,
        )
        kr = Keyring(keys=[entry])
        keyring_signed = sign_seal(seal, keyring=kr)
        # Same signature (HMAC over same body with same key).
        assert legacy.signature == keyring_signed.signature
        # Different metadata: key_id.
        assert legacy.key_id is None
        assert keyring_signed.key_id == "kid-1"


class TestVerifySealWithKeyring:
    """T044-3 + T044-4: verify_seal(keyring=...) implements D7."""

    def test_v2_seal_exact_match(self) -> None:
        """v2 seal (with key_id) verifies against the matching key in keyring."""
        seal = _make_unsigned_seal()
        kr = Keyring()
        kr.add_key(KeyEntry.from_generated(key_id="kid-v2"))
        signed = sign_seal(seal, keyring=kr)
        assert signed.key_id == "kid-v2"
        assert verify_seal(signed, keyring=kr) is True

    def test_v2_seal_unknown_key_id_returns_false(self) -> None:
        """v2 seal whose key_id is not in the keyring -> verify returns False.

        D7: exact-match v2. If the key is not present (or was revoked),
        verification fails closed.
        """
        seal = _make_unsigned_seal()
        kr_signed = Keyring()
        kr_signed.add_key(KeyEntry.from_generated(key_id="kid-signed"))
        signed = sign_seal(seal, keyring=kr_signed)
        # Different keyring that doesn't contain kid-signed.
        kr_other = Keyring()
        kr_other.add_key(KeyEntry.from_generated(key_id="kid-other"))
        assert verify_seal(signed, keyring=kr_other) is False

    def test_v2_seal_with_revoked_key_returns_false(self) -> None:
        """v2 seal whose key_id is revoked -> verify returns False."""
        seal = _make_unsigned_seal()
        kr = Keyring()
        kr.add_key(KeyEntry.from_generated(key_id="kid-revoked"))
        signed = sign_seal(seal, keyring=kr)
        # Revoke the key — verification must now fail.
        kr.revoke_key("kid-revoked")
        assert verify_seal(signed, keyring=kr) is False

    def test_v1_seal_try_all_finds_correct_key(self) -> None:
        """v1 seal (no key_id) verifies by trying all non-revoked keys.

        Even with multiple keys in the keyring, v1 verification finds
        the one that signs.
        """
        seal = _make_unsigned_seal()
        # Sign with FIXTURE_KEY (legacy path).
        signed = sign_seal(seal, key=FIXTURE_KEY)
        assert signed.key_id is None
        # Keyring has multiple keys, but only one (with FIXTURE_KEY) signs.
        kr = Keyring()
        kr.add_key(
            KeyEntry(
                key_id="kid-noise-1",
                algorithm="hmac",
                secret="ff" * 32,
                created_at="2026-09-01T00:00:00Z",
                active=True,
            )
        )
        kr.add_key(
            KeyEntry(
                key_id="kid-real",
                algorithm="hmac",
                secret=FIXTURE_KEY,
                created_at="2026-09-01T00:00:00Z",
                active=False,
            )
        )
        kr.add_key(
            KeyEntry(
                key_id="kid-noise-2",
                algorithm="hmac",
                secret="aa" * 32,
                created_at="2026-09-01T00:00:00Z",
                active=True,
            )
        )
        # try-all must find kid-real (the only one with the right key).
        assert verify_seal(signed, keyring=kr) is True

    def test_v1_seal_no_match_returns_false(self) -> None:
        """v1 seal that no key in the keyring can verify -> False."""
        seal = _make_unsigned_seal()
        signed = sign_seal(seal, key=FIXTURE_KEY)
        kr = Keyring()
        kr.add_key(
            KeyEntry(
                key_id="kid-noise",
                algorithm="hmac",
                secret="ff" * 32,
                created_at="2026-09-01T00:00:00Z",
                active=True,
            )
        )
        assert verify_seal(signed, keyring=kr) is False

    def test_v1_fixture_real_dc91ea_verifies_via_keyring(self) -> None:
        """Backward compat: the v1 fixture from 001 verifies via keyring
        with the original key. This is the production D7 path for
        existing fixtures.
        """
        import json
        from pathlib import Path

        from agent_trace_witness.seal import seal_from_dict

        d = json.loads(
            Path("tests/fixtures/seal_without_damaging_tool.json").read_text(encoding="utf-8")
        )
        sealed = seal_from_dict(d)
        # Build a keyring with the v1 key.
        kr = Keyring()
        kr.add_key(
            KeyEntry(
                key_id="v1-original",
                algorithm="hmac",
                secret="0" * 64,
                created_at="2026-08-30T14:33:00+00:00",
                active=True,
            )
        )
        assert verify_seal(sealed, keyring=kr) is True


class TestSignSealKeyringErrorTranslation:
    """Empty keyring must raise a typed WitnessKeyError, not AssertionError.

    Pre-fix: sign_seal(keyring=empty_keyring) leaked an AssertionError
    from keyring.active_key() — the operator got a stack trace pointing
    at internal assertions rather than a clear 'run witness keygen first'
    message. Post-fix: WitnessKeyError is raised with the right hint.
    The exception class is part of the public surface (consumers
    distinguish WitnessKeyError from WitnessSealError) so this test
    pins both the type and the message content.
    """

    def test_empty_keyring_raises_witness_key_error(self) -> None:
        from agent_trace_witness.exceptions import WitnessKeyError

        seal = _make_unsigned_seal()
        kr = Keyring()  # empty
        with pytest.raises(WitnessKeyError) as excinfo:
            sign_seal(seal, keyring=kr)
        # The error message must mention the user-actionable fix.
        assert "witness keygen" in str(excinfo.value).lower()

    def test_keyring_with_only_revoked_raises_witness_key_error(self) -> None:
        """A keyring whose only entries are revoked has no active key —
        same translation must apply (the AssertionError from
        active_key() must become WitnessKeyError)."""
        from agent_trace_witness.exceptions import WitnessKeyError

        seal = _make_unsigned_seal()
        kr = Keyring()
        kr.add_key(
            KeyEntry(
                key_id="only-key",
                algorithm="hmac",
                secret="0" * 64,
                created_at="2026-09-01T00:00:00Z",
                active=True,
            )
        )
        kr.revoke_key("only-key")
        with pytest.raises(WitnessKeyError) as excinfo:
            sign_seal(seal, keyring=kr)
        assert "no active key" in str(excinfo.value).lower()

    def test_keyring_with_no_active_raises_typed_error(self) -> None:
        """Same error translation for the >1 active case: the contract
        is 'at most 1 active non-revoked key', violated here with 2."""
        from agent_trace_witness.exceptions import WitnessKeyError

        seal = _make_unsigned_seal()
        e1 = KeyEntry(
            key_id="k1",
            algorithm="hmac",
            secret="0" * 64,
            created_at="2026-09-01T00:00:00Z",
            active=True,
        )
        e2 = KeyEntry(
            key_id="k2",
            algorithm="hmac",
            secret="0" * 64,
            created_at="2026-09-01T00:00:01Z",
            active=True,
        )
        kr = Keyring(keys=[e1, e2])
        with pytest.raises(WitnessKeyError) as excinfo:
            sign_seal(seal, keyring=kr)
        # The >1 case is internal data corruption, but the message
        # still must be typed (no AssertionError leak).
        assert excinfo.type is WitnessKeyError
