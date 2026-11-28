from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from app.db import Store, backup_database, restore_database, verify_backup


def _target(name: str = "fixture") -> dict:
    return {
        "id": str(uuid4()),
        "name": name,
        "ip": "127.0.0.1",
        "port": 8081,
        "scheme": "http",
        "created_at": "2026-11-28T00:00:00+00:00",
    }


def _run(target_id: str) -> dict:
    return {
        "id": str(uuid4()),
        "target_id": target_id,
        "status": "queued",
        "requests_per_second": 1,
        "duration_seconds": 5,
        "concurrency": 1,
    }


def test_run_claim_is_atomic_and_stale_rows_are_recoverable(tmp_path):
    database = tmp_path / "coordination.sqlite3"
    first = Store(database)
    second = Store(database)
    target = _target()
    first.add_target(target)
    initial = _run(target["id"])

    first.claim_run(initial, "owner-one")
    with pytest.raises(RuntimeError, match="already active"):
        second.claim_run(_run(target["id"]), "owner-two")

    recovered = second.recover_abandoned_runs()
    assert recovered == [initial["id"]]
    assert second.get_run(initial["id"])["status"] == "failed"

    next_run = _run(target["id"])
    second.claim_run(next_run, "owner-two")
    assert second.get_active_run_id() == next_run["id"]
    second.finish_run(
        next_run["id"],
        "owner-two",
        "completed",
        {"requests_started": 0, "requests_completed": 0},
    )
    assert first.get_active_run_id() is None
    assert second.verify_audit_chain()["valid"] is True
    first.close()
    second.close()


def test_online_backup_verify_and_restore_preserve_consistent_state(tmp_path):
    database = tmp_path / "gurgur.sqlite3"
    backup = tmp_path / "backups" / "gurgur.sqlite3"
    store = Store(database)
    store.add_target(_target("original"))
    store.add_audit("test.snapshot", None, {"purpose": "backup-test"})
    store.close()

    created = backup_database(database, backup)
    assert created["sha256"]
    assert verify_backup(backup)["valid"] is True

    changed = Store(database)
    changed.add_target(_target("after-backup"))
    changed.close()

    restored = restore_database(backup, database)
    assert restored["pre_restore_backup"] is not None
    assert Path(restored["pre_restore_backup"]).is_file()
    assert Path(f"{restored['pre_restore_backup']}.sha256").is_file()

    final_store = Store(database)
    assert final_store.count_targets() == 1
    assert final_store.list_targets()[0]["name"] == "original"
    assert final_store.verify_audit_chain()["valid"] is True
    final_store.close()


def test_backup_checksum_detects_modified_artifact(tmp_path):
    database = tmp_path / "source.sqlite3"
    store = Store(database)
    store.add_target(_target())
    store.close()
    backup = tmp_path / "backup.sqlite3"
    backup_database(database, backup)
    backup.write_bytes(backup.read_bytes() + b"tamper")

    with pytest.raises(RuntimeError, match="SHA-256"):
        verify_backup(backup)
