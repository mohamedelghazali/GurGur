# ZYRAX — Operations Runbook (0.2.0.dev0)

This runbook covers only the current local single-operator profile.

## 1. Generate the API key

After installing the project:

```powershell
python -m app keygen
```

The command prints a high-entropy token. Store it in protected environment or secret configuration; do not commit it or paste it into logs/screenshots.

## 2. Configure the service

Minimum environment:

```text
LAB_API_KEY=<generated value>
LAB_DATABASE_PATH=./data/zyrax.sqlite3
LAB_BIND_HOST=127.0.0.1
LAB_BIND_PORT=8000
```

Optional detached audit checkpoint configuration:

```text
LAB_AUDIT_SIGNING_KEY=<separate random secret, at least 32 bytes>
LAB_AUDIT_SIGNING_KEY_ID=local-v1
```

Generate an audit key independently from the API key:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Do not reuse the API key as the audit key. Do not store either secret in the SQLite database, repository, or checkpoint file.

## 3. Start and stop

Start using the supported launcher:

```powershell
python -m app
```

Use the loopback dashboard at `http://127.0.0.1:8000`. Direct Uvicorn commands with a public bind address are unsupported.

To stop cleanly, stop the service process/container. The application requests a stop for its active run and drains under the existing bounded shutdown behavior.

## 4. API-key rotation

The current service has one shared API key loaded at process start.

1. Generate a replacement with `python -m app keygen`.
2. Update the protected `LAB_API_KEY` value for every ZYRAX worker/container.
3. Stop and restart all workers so no process continues using the previous in-memory key.
4. Re-enter the new key in the dashboard. The previous key is rejected after restart.

Changing the shell environment without restarting an already-running process does not rotate its in-memory key.

## 5. Run coordination and recovery

Every measurement run holds `<LAB_DATABASE_PATH>.run.lock` and a singleton row in SQLite. All workers must point to the same canonical database path on the same local host/filesystem.

- A second worker receives HTTP 409 while a run is active.
- A non-owning worker may request a stop; the owner observes the persisted stop flag before scheduling more requests.
- If the owner process exits unexpectedly, the kernel releases the OS lock.
- On startup, a worker recovers stale `queued`/`running` rows only when it can acquire the OS lock.

The run lock is not a multi-host distributed lock. Do not put the database/lock file on a network share or use separate database paths for workers that need coordination. The supported launcher defaults to one worker.

## 6. Online backup

Backups can be created while ZYRAX is running because the command uses SQLite's online backup API:

```powershell
New-Item -ItemType Directory -Force .\backups | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
python -m app backup create --output ".\backups\zyrax-$stamp.sqlite3"
```

The command writes a SQLite backup and a sibling `.sha256` sidecar. Verify before copying or storing the artifact:

```powershell
python -m app backup verify --input ".\backups\zyrax-$stamp.sqlite3"
```

Verification checks the SHA-256 digest, SQLite integrity, foreign-key integrity, and required ZYRAX tables. Store backups away from the live database and restrict access because they contain operational target/run/audit data.

## 7. Offline restore

Restore is not an online operation.

1. Stop all ZYRAX processes and containers that use the target database.
2. Confirm no worker will restart during the maintenance operation.
3. Run:

```powershell
python -m app backup restore --input ".\backups\zyrax-YYYYMMDD-HHMMSS.sqlite3" --confirm-offline
```

The command verifies the source backup, creates a timestamped pre-restore backup if the current database exists, stages a fresh copy, and replaces the database. Re-open ZYRAX only after the command succeeds.

The code cannot reliably enumerate every external process holding the SQLite file. The operator's offline confirmation is mandatory. Never restore while a worker is running.

## 8. Detached HMAC audit checkpoint

Create a checkpoint after configuring `LAB_AUDIT_SIGNING_KEY` and `LAB_AUDIT_SIGNING_KEY_ID`:

```powershell
New-Item -ItemType Directory -Force .\audit-checkpoints | Out-Null
python -m app audit checkpoint --output .\audit-checkpoints\audit-head.json
python -m app audit verify-checkpoint --input .\audit-checkpoints\audit-head.json --database-check
```

The checkpoint command first verifies the current chain, exports the current head to a separate JSON file, then appends an audit event recording checkpoint creation. The checkpoint intentionally anchors the preceding chain prefix.

For an offline signature-only check, omit `--database-check`; for a local prefix check, include it. Keep checkpoint files separate from the SQLite database.

HMAC-SHA256 is symmetric. The verifier needs the same secret and any holder can create a valid checkpoint. This is not a public-key signature, trusted timestamp, or non-repudiation mechanism. Retain old signing keys and key IDs securely if historical checkpoints must remain verifiable after rotation.

## 9. Maintenance limits

- One active run per shared local database and lock file.
- Literal IPv4 loopback/RFC1918 targets only.
- Fixed HTTP `GET /`, no redirects, proxy environment ignored.
- 10 RPS, 30 seconds, 5 concurrent requests, 300 requests per run.
- 2-second request timeout (1-second connect timeout), 16 KiB response cap, bounded drain.
- No public targets, unrestricted stress tests, packet crafting, spoofing, proxy rotation, reflection, amplification, or distributed traffic-generation agents.

Do not raise any traffic ceiling to make a test or demonstration pass.
