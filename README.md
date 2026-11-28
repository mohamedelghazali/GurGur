# ZYRAX

**See Beyond. Defend Smarter.**  
**NETWORK INTELLIGENCE & DEFENSE PLATFORM**

*Understand Every Signal.*  
**Decode. Detect. Defend.**  
*Engineered to See. Built to Defend.*

**Network Intelligence & Defense Platform**  
**Development version:** `0.4.0.dev0` — Explainable Rule-Based Detection Engine candidate  
**Latest baseline:** `0.1.0` — local-first MVP

ZYRAX is a local-first network intelligence, detection, measurement, and defense-research console for authorized private lab environments. It combines a FastAPI control plane, bounded asynchronous HTTP measurements, SQLite persistence, a tamper-evident audit trail, a browser dashboard, and Prometheus-format metrics.

> ZYRAX is a defensive lab tool, not an Internet DDoS generator. Active measurements are limited to explicitly registered loopback and RFC1918 IPv4 targets.

## Product direction

The long-term direction is an **Intelligent Network Threat Detection & Defense Validation Platform** with five connected capabilities:

- Network telemetry ingestion from authorized sensors and service logs.
- Explainable threat detection using tested rules and measured behavioral baselines.
- Defense validation using offline replay and tightly bounded authorized measurements.
- Network forensics with provenance, timelines, and integrity-verifiable evidence.
- Human-controlled incident investigation, response documentation, and recovery verification.

The current development line adds bounded Zeek/Suricata/PCAP ingestion and a deterministic, explainable rule-based detection engine. See [Telemetry Ingestion](docs/TELEMETRY.md) and [Detection Engine](docs/DETECTION.md). Statistical baselines, machine learning, incident management, and forensic acquisition remain deferred until representative reviewed data and explicit operational requirements exist.

## Safety envelope (server-enforced)

| Control | Maximum / behavior |
|---|---|
| Target scope | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Target addressing | IPv4 literal only; no DNS names or IPv6 |
| Port | 1024–65535 |
| Request method/path | Fixed HTTP `GET /` |
| Redirects | Disabled |
| Proxy environment | Ignored (`trust_env=False`) |
| Request rate | 10 requests/second |
| Run duration | 30 seconds |
| Concurrency | 5 |
| Total request budget | 300 per run |
| Per-request timeout | 2 seconds (1 second connect timeout) |
| Response consumption | Capped at 16 KiB per request |
| Registered targets | 100 maximum |
| Active runs | One per shared local database and run-lock file |
| Supported launch bind | Loopback by default; Compose publishes the host port on loopback |

The engine schedules requests for no longer than the configured duration, then allows up to 3 seconds to drain in-flight requests. The operator must own the target or hold explicit written authorization. Keep experiments on an isolated lab VLAN or private test network. Start with the smallest useful measurements; the configured ceilings are hard limits, not recommended default workloads.

### Run coordination boundary

The 0.2 development line combines a non-blocking OS-level lock file with a singleton `run_control` row in SQLite. This prevents another ZYRAX worker on the same host from claiming a run while the active owner holds the OS lock. Run claims and audit events are committed transactionally. A stopped/crashed owner releases the kernel lock; the next worker can then mark stale queued/running rows as failed and recover the control row. Stop requests are persisted so another worker can request a stop for a run it does not own.

This supports multiple ZYRAX processes that share the **same local database path and local filesystem lock semantics**. It does not provide multi-host coordination, NFS/distributed filesystem guarantees, or a multi-tenant execution model. Keep the database and `.run.lock` file on the same trusted local filesystem.

ZYRAX intentionally contains no public-target mode, arbitrary request method/path, proxy/VPN rotation, source spoofing, packet crafting, reflection, amplification, distributed traffic-generation agents, botnet/C2 behavior, or evasion features. Broader detection scenarios should use offline event/PCAP replay rather than higher live traffic rates.

## Current capabilities

### Measurement and control plane

- FastAPI local control plane with Bearer API-key authentication.
- Browser dashboard served by the application.
- SQLite storage for registered targets, run summaries, persistent run coordination, and hash-linked audit events.
- Bounded asynchronous HTTP measurements using the fixed request profile.
- Cross-worker stop requests and stale-run recovery after process exit.
- Prometheus-format metrics endpoint.
- Baseline browser security headers and non-cacheable authenticated API responses.

### Core hardening (0.2 development line)

- Cross-process single-run exclusion using an OS lock file plus an atomic SQLite claim.
- Transactional creation/finish of runs and audit events.
- Consistent online SQLite backups with SHA-256 sidecars and database integrity checks.
- Backup verification and offline restore; restore creates a pre-restore backup where a database already exists.
- API-key generation command and a documented environment-based rotation procedure.
- Optional detached HMAC-SHA256 audit checkpoints using a dedicated key separate from the API key.
- Backward-compatible opening and migration of 0.1 database files.

The current application includes Zeek, Suricata EVE JSON, and offline PCAP/PCAPNG metadata ingestion. It does not yet include a detection engine, behavioral baselines, incident management, or forensic acquisition.

## Requirements

- Python 3.11–3.13.
- Network access only to the explicitly registered local/private lab service.

## Install and run locally

PowerShell:

```powershell
cd path\to\ZYRAX
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[test]"
$env:LAB_API_KEY = (python -m app keygen)
$env:LAB_DATABASE_PATH = ".\data\zyrax.sqlite3"
python -m app
```

Linux/macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[test]'
export LAB_API_KEY="$(python -m app keygen)"
export LAB_DATABASE_PATH="./data/zyrax.sqlite3"
python -m app
```

Open `http://127.0.0.1:8000`, enter the generated API key, and select **Unlock**. Register a target that is listening on a private/loopback address and a port from 1024 to 65535. Start with 1–2 requests/second for 5 seconds.

`LAB_API_KEY` is mandatory and must contain at least 32 characters. Do not commit it or put it in screenshots. The dashboard keeps it in browser `sessionStorage` for the current tab only.

## API-key rotation

ZYRAX currently uses one shared operator API key supplied through `LAB_API_KEY`; there is no multi-key registry or user/RBAC model.

1. Generate a replacement with `python -m app keygen`.
2. Update the protected environment or secret configuration used by every ZYRAX worker.
3. Stop and restart all workers/containers so every process loads the new value.
4. Re-enter the new key in the dashboard. The old key is rejected by the restarted application.

The key is not stored in the SQLite database. Rotation requires a process restart; changing the environment of a running process does not rotate its in-memory key.

## Database backup, verification, and restore

Create an online, WAL-consistent backup while ZYRAX is running:

```bash
python -m app backup create --output ./backups/zyrax-2026-11-28.sqlite3
```

Verify the SHA-256 sidecar, SQLite integrity, foreign-key consistency, and ZYRAX schema:

```bash
python -m app backup verify --input ./backups/zyrax-2026-11-28.sqlite3
```

Restore is an offline maintenance operation. Stop **every** ZYRAX process/container using the database, then explicitly confirm:

```bash
python -m app backup restore --input ./backups/zyrax-2026-11-28.sqlite3 --confirm-offline
```

The restore command rejects execution without `--confirm-offline`, verifies the source backup first, and creates a timestamped pre-restore backup if the current database exists. Protect backups as sensitive operational data: they can include private target IP addresses, run metadata, and audit history.

Backups made with the 0.1 schema remain restorable; opening the restored file with 0.2 code applies the required schema migration. Restore must not be run while any worker is using the database.

## Detached audit checkpoints (optional)

The audit chain is hash-linked and detects ordinary record tampering, but a local administrator able to rewrite the full database can recompute the chain. The 0.2 line can create a detached HMAC-SHA256 checkpoint that anchors the current chain prefix outside the database.

Generate a separate random key (do not reuse `LAB_API_KEY`), then configure:

```bash
export LAB_AUDIT_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export LAB_AUDIT_SIGNING_KEY_ID="local-v1"
```

Create a checkpoint file and verify it later:

```bash
python -m app audit checkpoint --output ./audit-checkpoints/audit-head.json
python -m app audit verify-checkpoint --input ./audit-checkpoints/audit-head.json --database-check
```

Keep the signing key in a protected secret store or protected operator environment and store checkpoint files separately from the database. HMAC is a **symmetric** message-authentication mechanism: a verifier needs the shared secret, and anyone who obtains that secret can create a valid checkpoint. It is not an asymmetric public-key signature and does not provide non-repudiation. Key rotation requires retaining the old key and its key ID in protected offline records to verify old checkpoints.

Authenticated API endpoints are also available:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/audit/checkpoints` | Create a detached HMAC checkpoint |
| POST | `/api/v1/audit/checkpoints/verify` | Verify checkpoint signature and local chain prefix |

These endpoints require `LAB_AUDIT_SIGNING_KEY` to be configured.

## Container run (optional)

Set `LAB_API_KEY` in the shell or a local, uncommitted `.env` file, then run:

```bash
docker compose up --build
```

The supplied Compose mapping publishes `8000` on host loopback only (`127.0.0.1:8000`). Docker is not required for local development. Docker build and Compose validation must be performed on the target host before relying on this path.

## API surface

All `/api/*` routes and `/metrics` require `Authorization: Bearer <LAB_API_KEY>`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Minimal process health |
| GET | `/api/v1/detection/rules` | List versioned explainable detection rules |\n| POST | `/api/v1/detection/evaluate` | Evaluate the latest bounded telemetry slice |\n| GET | `/api/v1/detection/alerts` | List persisted detection alerts |\n| GET | `/api/v1/targets` | List registered targets |
| POST | `/api/v1/targets` | Register a private target |
| POST | `/api/v1/runs` | Atomically claim and start a bounded measurement |
| GET | `/api/v1/runs` | Recent run history |
| GET | `/api/v1/runs/{id}` | Run result and persisted progress |
| POST | `/api/v1/runs/{id}/stop` | Persist a stop request, including across workers |
| GET | `/api/v1/audit/verify` | Verify the stored hash chain |
| POST | `/api/v1/audit/checkpoints` | Create a signed checkpoint |
| POST | `/api/v1/audit/checkpoints/verify` | Verify a checkpoint |
| GET | `/metrics` | Prometheus text metrics |

Interactive OpenAPI documentation remains disabled to reduce exposed surface.

## Development and verification

Run the application tests:

```bash
python -m compileall -q app tests
python -m pytest -q --cov=app --cov-report=term-missing
```

The v0.4 development candidate is undergoing CI verification. See [the v0.4 verification report](docs/VERIFICATION_REPORT_0.4.0_DEV.md) for exact status; no test, coverage, or security result is claimed until it is observed on the candidate commit.

This development iteration is self-contained within ZYRAX. It does not require external governance repositories or policy frameworks to build or run. A test pass is evidence for the tests actually executed, not a comprehensive security audit or production-readiness certification.

## Known limitations

- Single shared operator API key; no multi-user identity, RBAC, or tenant isolation.
- Local database and OS-lock coordination only; no multi-host/distributed locking guarantee.
- Restore requires every process using the database to be stopped by the operator.
- HMAC checkpoints require a shared secret and do not provide public-key non-repudiation.
- No TLS server termination, remote bind profile, SSO, or production secrets manager.
- No live packet capture sensor, flow export collector, IDS/IPS control, or host telemetry ingestion. PCAP parsing is offline and file-based.
- No statistical behavioral baseline, machine-learning model, incident case management, or forensic acquisition workflow. Detection is currently deterministic and rule-based.
- Docker build and Compose validation are not covered by the Python CI workflow.
- No production readiness or comprehensive independent security assurance is claimed.

Use `python -m app` as the local launcher; do not override it with a public Uvicorn bind address. Direct Uvicorn CLI overrides can bypass the launcher-level bind check and are unsupported. Do not expose this build to the public Internet. A production server profile requires a separate security design, independent verification, and human approval.
