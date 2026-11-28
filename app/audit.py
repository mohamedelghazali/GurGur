from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CHECKPOINT_ALGORITHM = "HMAC-SHA256"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_signing_configuration(key: str | None, key_id: str) -> None:
    if key is not None and len(key.encode("utf-8")) < 32:
        raise ValueError("LAB_AUDIT_SIGNING_KEY must contain at least 32 UTF-8 bytes.")
    if not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError("LAB_AUDIT_SIGNING_KEY_ID must be 1-64 safe ASCII characters.")


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_signed_checkpoint(
    event_count: int, head_hash: str, signing_key: str, key_id: str
) -> dict[str, Any]:
    validate_signing_configuration(signing_key, key_id)
    if event_count < 0 or not _HASH_RE.fullmatch(head_hash):
        raise ValueError("Invalid audit head supplied for checkpoint.")
    payload: dict[str, Any] = {
        "version": 1,
        "algorithm": CHECKPOINT_ALGORITHM,
        "key_id": key_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event_count": event_count,
        "head_hash": head_hash,
    }
    payload["signature"] = hmac.new(
        signing_key.encode("utf-8"), _canonical_payload(payload), hashlib.sha256
    ).hexdigest()
    return payload


def verify_signed_checkpoint(
    checkpoint: dict[str, Any], signing_key: str, expected_key_id: str
) -> bool:
    try:
        validate_signing_configuration(signing_key, expected_key_id)
        required = {
            "version", "algorithm", "key_id", "created_at",
            "event_count", "head_hash", "signature"
        }
        if set(checkpoint) != required:
            return False
        if checkpoint["version"] != 1 or checkpoint["algorithm"] != CHECKPOINT_ALGORITHM:
            return False
        if checkpoint["key_id"] != expected_key_id:
            return False
        if not isinstance(checkpoint["event_count"], int) or isinstance(checkpoint["event_count"], bool):
            return False
        if checkpoint["event_count"] < 0:
            return False
        if not isinstance(checkpoint["head_hash"], str) or not _HASH_RE.fullmatch(checkpoint["head_hash"]):
            return False
        if not isinstance(checkpoint["signature"], str) or not _HASH_RE.fullmatch(checkpoint["signature"]):
            return False
        datetime.fromisoformat(str(checkpoint["created_at"]).replace("Z", "+00:00"))
        expected = hmac.new(
            signing_key.encode("utf-8"),
            _canonical_payload(checkpoint),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(checkpoint["signature"], expected)
    except (KeyError, TypeError, ValueError):
        return False


def write_checkpoint(path: Path, checkpoint: dict[str, Any], overwrite: bool = False) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Checkpoint already exists: {destination}")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, destination)


def read_checkpoint(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Checkpoint JSON must contain an object.")
    return value
