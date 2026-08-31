# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Baseline compatibility test (T044-0b).

Verifies that the v1 fixture on disk (``seal_without_damaging_tool.json``,
produced in 001-mvp) currently verifies correctly and that its canonical
body contains exactly the 4 fields the v1 seal promises.

This test is written BEFORE any 004 code touches ``seal.py``. It must
pass in green against the unmodified module. It is the safety net that
D6 (``key_id`` lives outside the signed body) is measured against: every
change to ``_canonical_bytes`` or ``SealedSeal`` is re-run against this.
"""

from __future__ import annotations

import dataclasses
import hmac
import json
from pathlib import Path

import pytest

from agent_trace_witness.seal import (
    SealedSeal,
    _canonical_bytes,
    _seal_body_to_dict,
    seal_from_dict,
    verify_seal,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "seal_without_damaging_tool.json"

# Same fixed key conftest.py uses (0 * 64 hex chars).
FIXTURE_KEY = "0" * 64

EXPECTED_SIGNATURE_HEX = "dc91ea105843ada26bedb76388116820c12ff4e81f276328ab20a691a182996a"

EXPECTED_BODY_FIELDS = {
    "created_at",
    "system_prompt_sha256",
    "tools",
    "witness_id",
    "signature",  # signature is on the dict (v1 SealedSeal) but NOT part
    # of _canonical_bytes (verify_seal pops it before computing the MAC).
}


@pytest.fixture
def fixture_seal() -> SealedSeal:
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return seal_from_dict(d)


class TestV1FixtureBaseline:
    """Everything here must hold against the UNMODIFIED seal.py."""

    def test_fixture_file_has_no_key_id_field(self) -> None:
        """The v1 fixture on disk must not contain key_id."""
        d = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert "key_id" not in d, "fixture unexpectedly gained key_id — baseline broken"

    def test_fixture_signature_byte_equality(self, fixture_seal: SealedSeal) -> None:
        """The fixture signature must be exactly dc91ea... (literal)."""
        assert fixture_seal.signature == f"hmac-sha256:{EXPECTED_SIGNATURE_HEX}"

    def test_canonical_bytes_has_exactly_5_json_fields(self, fixture_seal: SealedSeal) -> None:
        """_seal_body_to_dict over the SealedSeal must return the 5 v1 fields."""
        body = _seal_body_to_dict(fixture_seal)
        assert set(body.keys()) == EXPECTED_BODY_FIELDS

    def test_canonical_body_excludes_key_id(self, fixture_seal: SealedSeal) -> None:
        """Neither the dict nor the canonical bytes may mention key_id."""
        body = _seal_body_to_dict(fixture_seal)
        assert "key_id" not in body
        canonical = _canonical_bytes(body)
        assert b"key_id" not in canonical, "canonical bytes leaked key_id — breaks v1 compatibility"

    def test_verify_seal_passes_against_fixture(self, fixture_seal: SealedSeal) -> None:
        """The full verify_seal path must return True for the v1 fixture."""
        assert verify_seal(fixture_seal, key=FIXTURE_KEY) is True

    def test_verify_seal_rejects_tampered_body(self, fixture_seal: SealedSeal) -> None:
        """If someone edits system_prompt_sha256, verify must return False."""
        tampered = dataclasses.replace(fixture_seal, witness_id="evil")
        assert verify_seal(tampered, key=FIXTURE_KEY) is False

    def test_manual_hmac_matches_fixture(self, fixture_seal: SealedSeal) -> None:
        """Independent recomputation of the HMAC over the canonical body."""
        body = _seal_body_to_dict(fixture_seal)
        provided = body.pop("signature")
        body_bytes = _canonical_bytes(body)
        recomputed = hmac.new(bytes.fromhex(FIXTURE_KEY), body_bytes, "sha256").hexdigest()
        assert recomputed == EXPECTED_SIGNATURE_HEX
        _, _, provided_hex = provided.partition(":")
        assert hmac.compare_digest(provided_hex, recomputed)
