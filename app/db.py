from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ZERO_HASH = "0" * 64
ACTIVE_STATUSES = ("queued", "running")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class Store:
    """SQLite store with transactionally claimed single-run coordination."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()
        self.conn = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._mutex:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    scheme TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL REFERENCES targets(id),
                    status TEXT NOT NULL,
                    requests_per_second INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    concurrency INTEGER NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    result_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    subject_id TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_control (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    run_id TEXT NOT NULL UNIQUE REFERENCES runs(id),
                    owner_token TEXT NOT NULL,
                    acquired_at TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(runs)")}
            if "stop_requested" not in columns:
                self.conn.execute(
                    "ALTER TABLE runs ADD COLUMN stop_requested INTEGER NOT NULL DEFAULT 0"
                )
            self.conn.commit()

    def close(self) -> None:
        with self._mutex:
            self.conn.close()

    def _append_audit_tx(
        self, action: str, subject_id: str | None, details: dict[str, Any]
    ) -> None:
        previous = self.conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else ZERO_HASH
        occurred_at = utc_now()
        details_json = _canonical_json(details)
        canonical = _canonical_json(
            {
                "occurred_at": occurred_at,
                "action": action,
                "subject_id": subject_id,
                "details": json.loads(details_json),
                "previous_hash": previous_hash,
            }
        )
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.conn.execute(
            """INSERT INTO audit_events
               (occurred_at,action,subject_id,details_json,previous_hash,event_hash)
               VALUES(?,?,?,?,?,?)""",
            (occurred_at, action, subject_id, details_json, previous_hash, event_hash),
        )

    def add_audit(
        self, action: str, subject_id: str | None, details: dict[str, Any]
    ) -> None:
        with self._mutex:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self._append_audit_tx(action, subject_id, details)
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def _recover_abandoned_runs_tx(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT id FROM runs WHERE status IN ('queued','running')"
        ).fetchall()
        recovered_ids = [str(row["id"]) for row in rows]
        if recovered_ids:
            finished_at = utc_now()
            for run_id in recovered_ids:
                self.conn.execute(
                    """UPDATE runs SET status='failed', finished_at=?, stop_requested=0,
                       result_json=? WHERE id=? AND status IN ('queued','running')""",
                    (
                        finished_at,
                        _canonical_json(
                            {
                                "reason": "owner_process_terminated",
                                "recovered_at": finished_at,
                            }
                        ),
                        run_id,
                    ),
                )
        control = self.conn.execute(
            "SELECT run_id FROM run_control WHERE singleton=1"
        ).fetchone()
        self.conn.execute("DELETE FROM run_control WHERE singleton=1")
        if recovered_ids or control:
            self._append_audit_tx(
                "runs.recovered_after_owner_exit",
                None,
                {"run_ids": recovered_ids, "orphaned_control_row": bool(control)},
            )
        return recovered_ids

    def recover_abandoned_runs(self) -> list[str]:
        """Recover stale rows only while the caller holds the OS run lock."""
        with self._mutex:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                recovered = self._recover_abandoned_runs_tx()
                self.conn.commit()
                return recovered
            except Exception:
                self.conn.rollback()
                raise

    def claim_run(self, record: dict[str, Any], owner_token: str) -> None:
        """Atomically recover stale state, insert a run, and claim the singleton slot."""
        with self._mutex:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                active = self.conn.execute(
                    "SELECT run_id FROM run_control WHERE singleton=1"
                ).fetchone()
                active_rows = self.conn.execute(
                    "SELECT id FROM runs WHERE status IN ('queued','running')"
                ).fetchall()
                if active or active_rows:
                    raise RuntimeError("A measurement run is already active.")
                self.conn.execute(
                    """INSERT INTO runs
                       (id,target_id,status,requests_per_second,duration_seconds,concurrency)
                       VALUES(?,?,?,?,?,?)""",
                    (
                        record["id"],
                        record["target_id"],
                        "queued",
                        record["requests_per_second"],
                        record["duration_seconds"],
                        record["concurrency"],
                    ),
                )
                acquired_at = utc_now()
                self.conn.execute(
                    """INSERT INTO run_control(singleton,run_id,owner_token,acquired_at)
                       VALUES(1,?,?,?)""",
                    (record["id"], owner_token, acquired_at),
                )
                self._append_audit_tx(
                    "run.created",
                    record["id"],
                    {
                        "target_id": record["target_id"],
                        "requests_per_second": record["requests_per_second"],
                        "duration_seconds": record["duration_seconds"],
                        "concurrency": record["concurrency"],
                    },
                )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def mark_run_running(self, run_id: str, owner_token: str, started_at: str) -> bool:
        with self._mutex:
            cursor = self.conn.execute(
                """UPDATE runs SET status='running', started_at=?
                   WHERE id=? AND status='queued'
                   AND EXISTS (
                     SELECT 1 FROM run_control
                     WHERE singleton=1 AND run_id=? AND owner_token=?
                   )""",
                (started_at, run_id, run_id, owner_token),
            )
            self.conn.commit()
            return cursor.rowcount == 1

    def update_run_progress(
        self, run_id: str, owner_token: str, result: dict[str, Any]
    ) -> bool:
        with self._mutex:
            cursor = self.conn.execute(
                """UPDATE runs SET result_json=?
                   WHERE id=? AND status='running'
                   AND EXISTS (
                     SELECT 1 FROM run_control
                     WHERE singleton=1 AND run_id=? AND owner_token=?
                   )""",
                (_canonical_json(result), run_id, run_id, owner_token),
            )
            self.conn.commit()
            return cursor.rowcount == 1

    def is_stop_requested(self, run_id: str) -> bool:
        with self._mutex:
            row = self.conn.execute(
                "SELECT stop_requested FROM runs WHERE id=?", (run_id,)
            ).fetchone()
            return bool(row["stop_requested"]) if row else True

    def request_stop(self, run_id: str) -> bool:
        with self._mutex:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = self.conn.execute(
                    """UPDATE runs SET stop_requested=1
                       WHERE id=? AND status IN ('queued','running')""",
                    (run_id,),
                )
                if cursor.rowcount:
                    self._append_audit_tx("run.stop_requested", run_id, {})
                self.conn.commit()
                return cursor.rowcount == 1
            except Exception:
                self.conn.rollback()
                raise

    def finish_run(
        self,
        run_id: str,
        owner_token: str,
        status: str,
        result: dict[str, Any],
    ) -> None:
        if status not in {"completed", "stopped", "failed"}:
            raise ValueError("Invalid terminal run status.")
        with self._mutex:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    """UPDATE runs SET status=?, result_json=?, finished_at=?, stop_requested=0
                       WHERE id=?""",
                    (status, _canonical_json(result), utc_now(), run_id),
                )
                self.conn.execute(
                    """DELETE FROM run_control
                       WHERE singleton=1 AND run_id=? AND owner_token=?""",
                    (run_id, owner_token),
                )
                self._append_audit_tx(
                    "run.finished",
                    run_id,
                    {
                        "status": status,
                        "requests_started": int(result.get("requests_started", 0)),
                    },
                )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def get_active_run_id(self) -> str | None:
        with self._mutex:
            row = self.conn.execute(
                "SELECT run_id FROM run_control WHERE singleton=1"
            ).fetchone()
            return str(row["run_id"]) if row else None

    def count_targets(self) -> int:
        with self._mutex:
            row = self.conn.execute("SELECT COUNT(*) AS count FROM targets").fetchone()
            return int(row["count"])

    def add_target(self, record: dict[str, Any]) -> None:
        with self._mutex:
            self.conn.execute(
                """INSERT INTO targets(id,name,ip,port,scheme,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    record["id"],
                    record["name"],
                    record["ip"],
                    record["port"],
                    record["scheme"],
                    record["created_at"],
                ),
            )
            self.conn.commit()

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        with self._mutex:
            row = self.conn.execute(
                "SELECT * FROM targets WHERE id=?", (target_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_targets(self) -> list[dict[str, Any]]:
        with self._mutex:
            rows = self.conn.execute(
                "SELECT * FROM targets ORDER BY created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def create_run(self, record: dict[str, Any]) -> None:
        """Compatibility helper for tests and offline fixtures; use claim_run in the API."""
        with self._mutex:
            self.conn.execute(
                """INSERT INTO runs(id,target_id,status,requests_per_second,duration_seconds,concurrency)
                   VALUES(?,?,?,?,?,?)""",
                (
                    record["id"],
                    record["target_id"],
                    record["status"],
                    record["requests_per_second"],
                    record["duration_seconds"],
                    record["concurrency"],
                ),
            )
            self.conn.commit()

    def update_run(
        self,
        run_id: str,
        status: str,
        result: dict[str, Any],
        started_at: str | None = None,
    ) -> None:
        with self._mutex:
            self.conn.execute(
                """UPDATE runs SET status=?, result_json=?,
                   started_at=COALESCE(?,started_at), finished_at=? WHERE id=?""",
                (
                    status,
                    _canonical_json(result),
                    started_at,
                    utc_now() if status in {"completed", "stopped", "failed"} else None,
                    run_id,
                ),
            )
            self.conn.commit()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._mutex:
            row = self.conn.execute(
                "SELECT * FROM runs WHERE id=?", (run_id,)
            ).fetchone()
            if not row:
                return None
            record = dict(row)
            record.pop("stop_requested", None)
            record["result"] = json.loads(record.pop("result_json"))
            return record

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._mutex:
            rows = self.conn.execute(
                "SELECT * FROM runs ORDER BY rowid DESC LIMIT ?", (limit,)
            ).fetchall()
            output = []
            for row in rows:
                record = dict(row)
                record.pop("stop_requested", None)
                record["result"] = json.loads(record.pop("result_json"))
                output.append(record)
            return output

    def verify_audit_chain(self) -> dict[str, Any]:
        with self._mutex:
            rows = self.conn.execute(
                "SELECT * FROM audit_events ORDER BY seq ASC"
            ).fetchall()
        previous_hash = ZERO_HASH
        for row in rows:
            try:
                details = json.loads(row["details_json"])
                canonical = _canonical_json(
                    {
                        "occurred_at": row["occurred_at"],
                        "action": row["action"],
                        "subject_id": row["subject_id"],
                        "details": details,
                        "previous_hash": previous_hash,
                    }
                )
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            except (TypeError, ValueError, json.JSONDecodeError):
                return {
                    "valid": False,
                    "checked_events": int(row["seq"]),
                    "failed_sequence": int(row["seq"]),
                }
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return {
                    "valid": False,
                    "checked_events": int(row["seq"]),
                    "failed_sequence": int(row["seq"]),
                }
            previous_hash = expected
        return {
            "valid": True,
            "checked_events": len(rows),
            "head_hash": previous_hash,
        }

    def audit_head(self) -> dict[str, Any]:
        with self._mutex:
            row = self.conn.execute(
                "SELECT seq,event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if not row:
                return {"event_count": 0, "head_hash": ZERO_HASH}
            count = self.conn.execute(
                "SELECT COUNT(*) AS count FROM audit_events"
            ).fetchone()["count"]
            return {"event_count": int(count), "head_hash": str(row["event_hash"])}

    def audit_hash_at(self, sequence: int) -> str | None:
        if sequence == 0:
            return ZERO_HASH
        with self._mutex:
            row = self.conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY seq ASC LIMIT 1 OFFSET ?",
                (sequence - 1,),
            ).fetchone()
            return str(row["event_hash"]) if row else None


def _integrity_check(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {result[0] if result else 'no result'}")
    foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_errors:
        raise RuntimeError("SQLite foreign-key integrity check failed.")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksum(path: Path, digest: str) -> None:
    sidecar = Path(f"{path}.sha256")
    temporary = Path(f"{sidecar}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, sidecar)


def verify_backup(backup_path: Path) -> dict[str, Any]:
    source = Path(backup_path)
    sidecar = Path(f"{source}.sha256")
    if not source.is_file() or not sidecar.is_file():
        raise FileNotFoundError("Backup database or its .sha256 sidecar is missing.")
    expected = sidecar.read_text(encoding="utf-8").split()[0]
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise RuntimeError("Backup checksum sidecar is malformed.")
    actual = _sha256_file(source)
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError("Backup SHA-256 verification failed.")
    connection = sqlite3.connect(f"file:{source.resolve().as_posix()}?mode=ro", uri=True)
    try:
        _integrity_check(connection)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"targets", "runs", "audit_events"}.issubset(tables):
            raise RuntimeError("Backup does not contain the required legacy GurGur tables.")
    finally:
        connection.close()
    return {"valid": True, "sha256": actual, "size_bytes": source.stat().st_size}


def backup_database(source_path: Path, destination_path: Path, overwrite: bool = False) -> dict[str, Any]:
    source = Path(source_path)
    destination = Path(destination_path)
    if not source.is_file():
        raise FileNotFoundError(f"Database does not exist: {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("Backup destination must differ from the live database.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite and (destination.exists() or Path(f"{destination}.sha256").exists()):
        raise FileExistsError(f"Backup destination already exists: {destination}")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    source_connection = sqlite3.connect(source, timeout=10.0)
    backup_connection = sqlite3.connect(temporary, timeout=10.0)
    try:
        source_connection.execute("PRAGMA busy_timeout=10000")
        source_connection.backup(backup_connection)
        _integrity_check(backup_connection)
        backup_connection.commit()
    finally:
        backup_connection.close()
        source_connection.close()
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, destination)
    digest = _sha256_file(destination)
    _write_checksum(destination, digest)
    return {"path": str(destination), "sha256": digest, "size_bytes": destination.stat().st_size}


def restore_database(backup_path: Path, database_path: Path) -> dict[str, Any]:
    """Restore an integrity-checked backup. The caller must stop every GurGur process first."""
    backup = Path(backup_path)
    database = Path(database_path)
    verification = verify_backup(backup)
    if backup.resolve() == database.resolve():
        raise ValueError("Restore source and destination must differ.")
    database.parent.mkdir(parents=True, exist_ok=True)
    pre_restore: Path | None = None
    if database.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        pre_restore = database.with_name(
            f"{database.name}.pre-restore-{stamp}-{uuid.uuid4().hex[:8]}"
        )
        backup_database(database, pre_restore)

    temporary = database.with_name(f".{database.name}.{uuid.uuid4().hex}.restore")
    source_connection = sqlite3.connect(
        f"file:{backup.resolve().as_posix()}?mode=ro", uri=True, timeout=10.0
    )
    destination_connection = sqlite3.connect(temporary, timeout=10.0)
    try:
        source_connection.backup(destination_connection)
        _integrity_check(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{database}{suffix}")
        if sidecar.exists():
            sidecar.unlink()
    os.replace(temporary, database)
    return {
        "restored": str(database),
        "sha256": verification["sha256"],
        "pre_restore_backup": str(pre_restore) if pre_restore else None,
    }
