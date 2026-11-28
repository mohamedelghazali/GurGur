# GurGur

**Network Research & Defense Lab**  
**Current version:** 0.1.0 — local-first MVP  
**Next planned milestone:** 0.2.0 — Core Hardening

GurGur is a local-first, controlled network measurement and defense-research console. The current MVP provides a FastAPI control plane, a bounded asynchronous HTTP measurement engine, SQLite persistence, a hash-linked audit trail, a browser dashboard, and Prometheus-format metrics.

> GurGur is a defensive lab tool, not an Internet DDoS generator. Active measurements are limited to registered loopback and RFC1918 IPv4 targets.

## Product direction

The long-term direction is an **Intelligent Network Threat Detection & Defense Validation Platform** with five capabilities:

- Network telemetry ingestion from authorized sensors and service logs.
- Explainable threat detection using tested rules and measured behavioral baselines.
- Defense validation using offline replay and tightly bounded authorized measurements.
- Network forensics with provenance, timelines, and integrity-verifiable evidence.
- Human-controlled incident investigation, response documentation, and recovery verification.

This is the product direction, not a description of features already shipped. The current 0.1.0 release does **not** yet include Zeek or Suricata adapters, PCAP import, flow ingestion, a detection/anomaly engine, incident management, or forensic acquisition. See [Target Architecture](docs/ARCHITECTURE.md) and [Product Roadmap](docs/ROADMAP.md).

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
| Active runs | One per process in the current implementation |
| Supported launch bind | Loopback by default; Compose publishes the host port on loopback |

The engine schedules requests for no longer than the configured duration, then allows up to 3 seconds to drain in-flight requests. The operator must own the target or hold explicit written authorization. Keep experiments on an isolated lab VLAN or private test network. Start with the smallest useful measurements; the configured ceilings are hard limits, not recommended default workloads.

The current active-run lock is process-local. Do not deploy multiple application workers or replicas until durable cross-process run coordination is implemented and verified.

GurGur intentionally contains no public-target mode, arbitrary request method/path, proxy/VPN rotation, source spoofing, packet crafting, reflection, amplification, distributed traffic-generation agents, botnet/C2 behavior, or evasion features. Broader detection scenarios should use offline event/PCAP replay rather than higher live traffic rates.

## Current capabilities (0.1.0)

- FastAPI control plane with bearer-key authentication.
- Browser dashboard served by the application.
- SQLite storage for registered targets, run summaries, and hash-linked audit events.
- Bounded asynchronous HTTP measurements using the fixed request profile.
- Prometheus-format metrics endpoint.
- Local health endpoint and baseline browser security headers.

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
python -m pytest -q --cov=app --cov-report=term-missing
```

The integration test starts a local HTTP fixture on `127.0.0.1` and exercises target registration, the actual request engine, persisted run results, and audit-chain verification.

## Container run (optional)

Set `LAB_API_KEY` in the shell or in a local, uncommitted `.env` file, then run:

```bash
docker compose up --build
```

The supplied Compose mapping publishes `8000` on host loopback only (`127.0.0.1:8000`). Docker is not required for local development. Container build and Compose validation must be performed on the target host before relying on this path; the earlier MVP release report marked those checks as not verified.

## API surface

All `/api/*` routes and `/metrics` require `Authorization: Bearer <LAB_API_KEY>`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Non-sensitive process health |
| GET | `/api/v1/targets` | List registered targets |
| POST | `/api/v1/targets` | Register a private target |
| POST | `/api/v1/runs` | Start a bounded measurement |
| GET | `/api/v1/runs` | Recent run history |
| GET | `/api/v1/runs/{id}` | Run result and live counters |
| POST | `/api/v1/runs/{id}/stop` | Request stop |
| GET | `/api/v1/audit/verify` | Verify the stored hash chain |
| GET | `/metrics` | Prometheus text metrics |

Interactive OpenAPI docs are disabled in this MVP to reduce exposed surface.

## Current architecture

```text
Browser dashboard
      | bearer-authenticated HTTP
      v
FastAPI control plane ------> SQLite (targets / runs / audit events)
      |
      v
Bounded asynchronous HTTP engine
      | fixed GET /; <=10 RPS; <=5 concurrent; <=30 s
      v
Registered loopback / RFC1918 lab service
```

The planned architecture adds passive telemetry adapters (Zeek, Suricata, reverse-proxy logs), normalized event ingestion, explainable detection, incident correlation, forensic evidence workflows, and operator-controlled defense validation. These components are described as future work in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); they are not part of the current application.

## Roadmap

| Release | Focus | Status |
|---|---|---|
| 0.1.0 | Local-first bounded measurement MVP | Implemented baseline |
| 0.2.0 | Core hardening: durable run coordination, key lifecycle, audit checkpoint design, backup/restore, reliability tests | Planned — next |
| 0.3.0 | Zeek/Suricata/reverse-proxy ingestion and offline PCAP replay | Planned |
| 0.4.0 | Explainable rules, baselines, anomaly scoring, detection evaluation | Planned |
| 0.5.0 | Defense validation, incident workflow, forensic reports, recovery metrics | Planned |
| 1.0.0 | Multi-operator/RBAC, PostgreSQL, TLS/SSO, governed sensor operations | Planned, gated |

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestone scope and acceptance criteria. No delivery dates are implied.

## Governance and verification status

GurGur declares GENCODE-GOV and AIGENT-SEC as engineering/security references. This documentation update consulted the repository's agent instructions, engineering charter, applicable GENCODE-GOV security/reliability/testing rules, and AIGENT-SEC v1.2.0 core directives and selected API, application-security, logging, data-handling, testing, detection, and forensics rules.

No GENCODE-GOV CLI assessment, full AIGENT-SEC security audit, independent human security review, production deployment review, or restore drill is claimed for this documentation change. Those items remain **NOT VERIFIED** unless a commit-bound report says otherwise. A green CI run proves only the checks actually executed by that workflow.

## Known limitations

- Local, single-operator lab profile only; no multi-user identity, RBAC, or tenant model.
- No remote bind, HTTPS server termination, SSO, or production secrets manager.
- The current active-run lock is process-local and does not coordinate multiple application workers.
- No packet capture, flow ingestion, Zeek/Suricata integration, IDS/IPS integration, or host telemetry ingestion.
- No detection engine, behavioral baseline, anomaly model, incident case management, or forensic acquisition workflow.
- Audit chain has no external signed checkpoint; an administrator able to rewrite the complete database can recompute hashes.
- Run data currently remains in SQLite without a verified automated backup/restore rotation.
- Docker build and Compose validation are not established by the repository's Python CI workflow.
- No production readiness or comprehensive security assurance is claimed.

Use `python -m app` as the local launcher; do not override it with a public Uvicorn bind address. Direct Uvicorn CLI overrides can bypass the launcher-level bind check and are unsupported. The supplied Docker Compose profile binds the host-side port to `127.0.0.1` and requires an explicit container-mode acknowledgement. Do not expose this build to the public Internet. A production server profile requires a separate security design, independent verification, and human approval.
