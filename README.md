# GurGur

**Network Research & Defense Lab**  
**Version:** 0.1.0 — MVP implementation

GurGur is a local-first, controlled network measurement and DDoS-defense research console. The first release provides a FastAPI control plane, a bounded asynchronous HTTP measurement engine, SQLite persistence, a hash-linked audit trail, a browser dashboard, and Prometheus-format metrics.

> This is a defensive lab measurement tool, not an Internet DDoS generator. It only accepts loopback and RFC1918 IPv4 literals.

## Safety envelope (hard-coded)

| Control | Enforced maximum / behavior |
|---|---|
| Target scope | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Target addressing | IPv4 literal only; no DNS names or IPv6 |
| Port | 1024–65535 |
| Request method/path | fixed `GET /` |
| Redirects | disabled |
| Proxy environment | ignored (`trust_env=False`) |
| Request rate | 10 requests/second |
| Run duration | 30 seconds |
| Concurrency | 5 |
| Total request budget | 300 per run |
| Per-request timeout | 2 seconds (1 second connect timeout) |
| Response consumption | capped at 16 KiB per request |
| Registered targets | 100 maximum |
| Active runs | one per process |
| Supported launch bind | loopback by default; supplied Compose maps the host port to loopback |

The engine schedules requests for no longer than the configured duration, then allows up to 3 seconds to drain in-flight requests. The operator must own the target or hold explicit written authorization. Keep experiments on an isolated lab VLAN or private test network. This release intentionally contains no proxy/VPN rotation, source spoofing, packet crafting, reflection, amplification, distributed agent fleet, or public-target mode.

## Requirements

- Python 3.11–3.13.
- Network access only to the explicitly registered local/private lab service.

## Run locally

PowerShell:

```powershell
cd path\to\GurGur
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[test]"
$env:LAB_API_KEY = (python -c "import secrets; print(secrets.token_urlsafe(32))")
$env:LAB_DATABASE_PATH = ".\data\gurgur.sqlite3"
python -m app
```

Open `http://127.0.0.1:8000`, paste the generated API key into the dashboard, and select **Unlock**. Register a target that is listening on a private/loopback address and a port from 1024 to 65535. Start with 1–2 requests/second for 5 seconds.

Linux/macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
export LAB_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export LAB_DATABASE_PATH="./data/gurgur.sqlite3"
python -m app
```

`LAB_API_KEY` is mandatory and must be at least 32 characters. Do not commit it or put it in screenshots. The dashboard keeps it in browser `sessionStorage` for the current tab session only. The dashboard uses a same-origin Content Security Policy and baseline anti-framing/content-sniffing headers.

## Run tests

```bash
pytest -q
```

The integration test starts a local HTTP fixture on `127.0.0.1` and exercises target registration, the actual request engine, persisted run results, and audit-chain verification.


## Container run (optional)

Set `LAB_API_KEY` in the shell or in a local, uncommitted `.env` file, then run:

```bash
docker compose up --build
```

The supplied Compose mapping publishes `8000` on host loopback only (`127.0.0.1:8000`). Docker is not required for local development. Container build and Compose validation were not available in the environment used to create this release, so validate them on the target host before relying on this path.

## API surface

All `/api/*` routes and `/metrics` require `Authorization: Bearer <LAB_API_KEY>`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | non-sensitive process health |
| GET | `/api/v1/targets` | list registered targets |
| POST | `/api/v1/targets` | register a private target |
| POST | `/api/v1/runs` | start a bounded measurement |
| GET | `/api/v1/runs` | recent run history |
| GET | `/api/v1/runs/{id}` | run result and live counters |
| POST | `/api/v1/runs/{id}/stop` | request stop |
| GET | `/api/v1/audit/verify` | verify the stored hash chain |
| GET | `/metrics` | Prometheus text metrics |

Interactive OpenAPI docs are disabled in this MVP to reduce exposed surface.

## Architecture

```text
Browser dashboard
      │ bearer-authenticated HTTP
      ▼
FastAPI control plane ─── SQLite (targets / runs / audit events)
      │
      ▼
Bounded asynchronous HTTP engine
      │ fixed GET /; <=10 RPS; <=5 concurrent; <=30 s
      ▼
Registered loopback / RFC1918 lab service
```

## Governance and verification status

The implementation follows the applicable workflow from the repository currently served as GENCODE-GOV: inspect → plan → threat model → implement → verify → report. The project includes `docs/THREAT_MODEL.md`, `docs/EXPERIMENT_PROTOCOL.md`, and a scenario-based `.gencode-gov/security-test-matrix.yaml`.

No claim is made that GENCODE-GOV CLI validation, AIGENT-SEC (formerly TSAR), independent security audit, dependency vulnerability review, secret-history scanning, or production deployment review has passed. Those checks have not been run here and remain **NOT VERIFIED**. The presence of the matrix is not evidence of passing controls.

## Known limitations before any remote or production deployment

- Local, single-operator lab profile only; no multi-user authorization or tenant ownership.
- No remote bind, HTTPS server termination, SSO, role model, or production secrets manager.
- No packet capture, flow ingestion, IDS/IPS integration, attribution engine, adaptive detection model, or distributed agents yet.
- Audit chain has no external signed checkpoint; a database administrator able to rewrite the complete database can recompute hashes.
- Run data currently remains in SQLite without automated retention/backup rotation.
- AIGENT-SEC and GENCODE-GOV evidence integration is not configured in this workspace.

Use `python -m app` as the local launcher; do not override it with a public Uvicorn bind address. Direct Uvicorn CLI overrides can bypass the launcher-level bind check and are unsupported. The supplied Docker Compose profile binds the host-side port to `127.0.0.1` and requires an explicit container-mode acknowledgement. Do not expose this build to the public Internet. A production server profile requires a separate security design and review.
