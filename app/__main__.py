from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Sequence

import uvicorn

from .audit import (
    create_signed_checkpoint,
    read_checkpoint,
    verify_signed_checkpoint,
    write_checkpoint,
)
from .config import Settings
from .db import Store, backup_database, restore_database, verify_backup


def _database_path() -> Path:
    return Path(os.getenv("LAB_DATABASE_PATH", "./data/zyrax.sqlite3"))


def _audit_key() -> tuple[str, str]:
    key = os.getenv("LAB_AUDIT_SIGNING_KEY", "").strip()
    key_id = os.getenv("LAB_AUDIT_SIGNING_KEY_ID", "local-v1").strip()
    if len(key.encode("utf-8")) < 32:
        raise RuntimeError(
            "Set LAB_AUDIT_SIGNING_KEY to a separate random secret of at least 32 bytes."
        )
    return key, key_id


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app",
        description="ZYRAX local administration and bounded lab service.",
    )
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("keygen", help="Generate a high-entropy API key.")

    backup = commands.add_parser("backup", help="Create, verify, or restore a SQLite backup.")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    create = backup_commands.add_parser("create", help="Create a consistent online SQLite backup.")
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--overwrite", action="store_true")
    verify = backup_commands.add_parser("verify", help="Verify a backup checksum and SQLite integrity.")
    verify.add_argument("--input", required=True, type=Path)
    restore = backup_commands.add_parser("restore", help="Restore a verified backup while ZYRAX is stopped.")
    restore.add_argument("--input", required=True, type=Path)
    restore.add_argument(
        "--confirm-offline",
        action="store_true",
        help="Confirm all ZYRAX server/worker processes have been stopped.",
    )

    audit = commands.add_parser("audit", help="Create and verify detached signed audit checkpoints.")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    checkpoint = audit_commands.add_parser("checkpoint", help="Sign the current verified audit-chain head.")
    checkpoint.add_argument("--output", required=True, type=Path)
    checkpoint.add_argument("--overwrite", action="store_true")
    verify_checkpoint = audit_commands.add_parser(
        "verify-checkpoint", help="Verify a detached checkpoint signature and, optionally, the local chain."
    )
    verify_checkpoint.add_argument("--input", required=True, type=Path)
    verify_checkpoint.add_argument("--database-check", action="store_true")

    return parser


def _run_command(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        print(secrets.token_urlsafe(32))
        return 0

    if args.command == "backup":
        if args.backup_command == "create":
            result = backup_database(_database_path(), args.output, overwrite=args.overwrite)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.backup_command == "verify":
            print(json.dumps(verify_backup(args.input), indent=2, sort_keys=True))
            return 0
        if args.backup_command == "restore":
            if not args.confirm_offline:
                raise RuntimeError(
                    "Restore refused: stop every ZYRAX process and pass --confirm-offline."
                )
            result = restore_database(args.input, _database_path())
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

    if args.command == "audit":
        signing_key, key_id = _audit_key()
        if args.audit_command == "checkpoint":
            store = Store(_database_path())
            try:
                chain = store.verify_audit_chain()
                if not chain["valid"]:
                    raise RuntimeError("Audit chain verification failed; no checkpoint was created.")
                head = store.audit_head()
                checkpoint = create_signed_checkpoint(
                    head["event_count"], head["head_hash"], signing_key, key_id
                )
                write_checkpoint(args.output, checkpoint, overwrite=args.overwrite)
                store.add_audit(
                    "audit.checkpoint.created",
                    None,
                    {
                        "key_id": key_id,
                        "event_count": head["event_count"],
                        "head_hash": head["head_hash"],
                    },
                )
            finally:
                store.close()
            print(
                json.dumps(
                    {"path": str(args.output), "key_id": key_id, "event_count": checkpoint["event_count"]},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.audit_command == "verify-checkpoint":
            checkpoint = read_checkpoint(args.input)
            signature_valid = verify_signed_checkpoint(checkpoint, signing_key, key_id)
            result = {"signature_valid": signature_valid, "key_id": checkpoint.get("key_id")}
            if args.database_check:
                store = Store(_database_path())
                try:
                    chain = store.verify_audit_chain()
                    head_present = (
                        store.audit_hash_at(checkpoint.get("event_count", -1))
                        == checkpoint.get("head_hash")
                    )
                finally:
                    store.close()
                result.update(
                    {
                        "current_chain_valid": chain["valid"],
                        "checkpoint_head_present": head_present,
                    }
                )
                valid = signature_valid and chain["valid"] and head_present
            else:
                valid = signature_valid
            result["valid"] = valid
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if valid else 2

    raise RuntimeError("Unsupported command.")


def main(argv: Sequence[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    if args.command is not None:
        try:
            exit_code = _run_command(args)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"ZYRAX administration error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        raise SystemExit(exit_code)

    settings = Settings.from_env()
    uvicorn.run(
        "app.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
        access_log=False,
        server_header=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
