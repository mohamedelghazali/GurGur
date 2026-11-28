from __future__ import annotations

from app.audit import create_signed_checkpoint, verify_signed_checkpoint
from app.db import ZERO_HASH


def test_hmac_checkpoint_detects_tampering_and_key_mismatch():
    key = "test-only-audit-signing-key-0123456789abcdef"
    checkpoint = create_signed_checkpoint(0, ZERO_HASH, key, "test-v1")

    assert verify_signed_checkpoint(checkpoint, key, "test-v1") is True
    assert verify_signed_checkpoint(checkpoint, key, "other-v1") is False
    assert verify_signed_checkpoint(checkpoint, key + "-changed", "test-v1") is False

    tampered = dict(checkpoint)
    tampered["event_count"] = 1
    assert verify_signed_checkpoint(tampered, key, "test-v1") is False


def test_checkpoint_rejects_weak_signing_key():
    try:
        create_signed_checkpoint(0, ZERO_HASH, "short", "test-v1")
    except ValueError as exc:
        assert "32" in str(exc)
    else:
        raise AssertionError("Weak signing key was accepted.")
