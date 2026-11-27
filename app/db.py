from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        self._recover_incomplete_runs()

    def _init_schema(self) -> None:
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
            """
        )
        self.conn.commit()

    def _recover_incomplete_runs(self) -> None:
        rows = self.conn.execute("SELECT id FROM runs WHERE status IN ('queued','running')").fetchall()
        if not rows:
            return
        recovered_at = utc_now()
        for row in rows:
            self.conn.execute(
                "UPDATE runs SET status='failed', finished_at=?, result_json=? WHERE id=?",
                (recovered_at, json.dumps({"reason": "process_restarted"}), row["id"]),
            )
        self.conn.commit()
        self.add_audit("runs.recovered_after_restart", None, {"count": len(rows)})

    def count_targets(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM targets").fetchone()
        return int(row["count"])

    def close(self) -> None:
        self.conn.close()

    def add_target(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO targets(id,name,ip,port,scheme,created_at) VALUES(?,?,?,?,?,?)",
            (record["id"], record["name"], record["ip"], record["port"], record["scheme"], record["created_at"]),
        )
        self.conn.commit()

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return dict(row) if row else None

    def list_targets(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def create_run(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO runs(id,target_id,status,requests_per_second,duration_seconds,concurrency)
               VALUES(?,?,?,?,?,?)""",
            (record["id"], record["target_id"], record["status"], record["requests_per_second"], record["duration_seconds"], record["concurrency"]),
        )
        self.conn.commit()

    def update_run(self, run_id: str, status: str, result: dict[str, Any], started_at: str | None = None) -> None:
        self.conn.execute(
            "UPDATE runs SET status=?, result_json=?, started_at=COALESCE(?,started_at), finished_at=? WHERE id=?",
            (status, json.dumps(result, separators=(",", ":")), started_at, utc_now() if status in {"completed", "stopped", "failed"} else None, run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        record["result"] = json.loads(record.pop("result_json"))
        return record

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM runs ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        output = []
        for row in rows:
            record = dict(row)
            record["result"] = json.loads(record.pop("result_json"))
            output.append(record)
        return output

    def add_audit(self, action: str, subject_id: str | None, details: dict[str, Any]) -> None:
        previous = self.conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        occurred_at = utc_now()
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        canonical = json.dumps(
            {"occurred_at": occurred_at, "action": action, "subject_id": subject_id, "details": json.loads(details_json), "previous_hash": previous_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO audit_events(occurred_at,action,subject_id,details_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
            (occurred_at, action, subject_id, details_json, previous_hash, event_hash),
        )
        self.conn.commit()

    def verify_audit_chain(self) -> dict[str, Any]:
        rows = self.conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            details = json.loads(row["details_json"])
            canonical = json.dumps(
                {"occurred_at": row["occurred_at"], "action": row["action"], "subject_id": row["subject_id"], "details": details, "previous_hash": previous_hash},
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return {"valid": False, "checked_events": int(row["seq"]), "failed_sequence": int(row["seq"])}
            previous_hash = expected
        return {"valid": True, "checked_events": len(rows), "head_hash": previous_hash}
