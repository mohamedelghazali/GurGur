# GurGur — Network Research & Defense Lab — Threat Model (0.1.0)

## System purpose and security boundary

GurGur — Network Research & Defense Lab is a local-first measurement and defensive telemetry application. It generates a deliberately small, fixed-profile HTTP request stream against an explicitly registered loopback or RFC1918 IPv4 endpoint. It is not a denial-of-service tool and does not provide public-targeting, distributed agent orchestration, proxy/VPN rotation, source spoofing, reflection, amplification, arbitrary payloads, or arbitrary request paths.

The supported launcher binds the API process to loopback by default. The Docker profile binds inside its container but publishes the host port on loopback only. Direct Uvicorn CLI overrides can bypass the launcher-level bind check and are unsupported. The dashboard stores the bearer key in browser `sessionStorage` only. SQLite stores targets, run summaries, and a hash-linked audit event stream.

## Assets

- API bearer key and process environment.
- Registered private target addresses and experiment parameters.
- Availability and integrity of the measured lab service.
- Experiment results and audit event history.
- Host resources used by the control plane and traffic engine.

## Actors

- Authorized local operator.
- Unauthorized local process or browser page attempting to call the API.
- Malicious or mistaken operator entering an out-of-scope address or excessive parameters.
- Compromised dependency or modified project artifact.

## Trust boundaries and entry points

| Boundary / entry point | Untrusted input | Required control |
|---|---|---|
| Browser → API | bearer header, JSON, IDs | constant-time API-key comparison, Pydantic validation, no CORS, no cookie auth |
| Target registration | IP, port, scheme, label | IPv4 literal only; loopback/RFC1918 allow-scope; port 1024–65535; fixed root path |
| Run creation | target ID, RPS, duration, concurrency | server-side hard caps; registered target lookup; one active run |
| Engine → target | network response, redirects, TLS | fixed GET `/`; redirects disabled; `trust_env=False`; TLS verification on; bounded timeout and response read |
| API → SQLite | user-controlled values | parameterized SQL; local database path; WAL; foreign keys |
| Audit history | event data and prior hash | append-style hash-linked events; integrity check endpoint |

## Abuse cases and mitigations

1. **Public Internet target submitted:** rejected by address validation; hostnames and IPv6 are not accepted.
2. **DNS rebinding or proxy environment redirects traffic:** DNS names are rejected; HTTP client ignores proxy environment variables; redirects are disabled.
3. **Attempt to exceed traffic budget:** request model and service enforce at most 10 RPS, 30 seconds, 5 concurrent requests, and 300 intended requests per run. One run can be active at a time.
4. **Slow or oversized responses:** per-request timeout; fixed concurrency; response consumption stops at 16 KiB; run drain is bounded.
5. **Unauthenticated API or metrics access:** bearer key required for all `/api/*` and `/metrics` paths.
6. **SQL injection:** all stored values use SQLite parameter binding; dynamic SQL fragments are not formed from user input.
7. **Audit record alteration:** SHA-256 hash chaining detects an isolated alteration or removal within the stored chain. It is tamper-evident, not tamper-proof; an attacker able to rewrite the whole database can recompute the chain. External signed anchoring is not implemented.
8. **Remote exposure:** the current profile refuses non-loopback application bind configuration; Docker publishes to host loopback only. No production remote-access profile is included.

## Explicit non-goals

- Internet-scale load or denial-of-service testing.
- Botnets, distributed worker fleets, proxy pools, VPN rotation, IP spoofing, packet crafting, reflection or amplification.
- Testing systems without explicit authorization.
- Multi-tenant user accounts, password login, role-based access control, or enterprise SSO.
- Claims of attribution from IP addresses alone.

## Residual risks / release blockers

- Shared bearer key is suitable only for a single-operator local lab; it is not a production identity system.
- SQLite and local filesystem controls depend on host permissions and backups.
- Hash chaining has no external trust anchor.
- The engine is HTTP request-level telemetry, not packet-level capture or a full network IDS.
- No AIGENT-SEC (formerly TSAR) security assessment or GENCODE-GOV independent audit has been executed in this environment. Those gates remain NOT VERIFIED/BLOCKED pending the configured tools and evidence.

## Deployment assumptions

Run under an unprivileged OS account; keep the database on a private local volume; do not publish port 8000 to a public interface; use a dedicated isolated lab VLAN or private test network; retain an operator-owned authorization record for every target; and stop runs when the target shows degradation.
