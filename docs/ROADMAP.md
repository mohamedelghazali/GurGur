# ZYRAX — Product Roadmap

**Latest stable baseline:** `0.1.0`  
**Current development line:** `0.4.0.dev0` — Explainable Rule-Based Detection Engine  
**Status:** v0.4 development candidate; CI and release qualification are pending.

## Product objective

Evolve ZYRAX from a bounded private-network measurement console into an explainable network intelligence, threat detection, defense validation, and investigation platform for authorized environments.

The sequence is deliberate: harden the local control plane before adding telemetry volume, detection complexity, sensors, or additional operators.

## v0.1.0 — Local-first MVP

Implemented baseline:

- FastAPI control plane and browser dashboard.
- Single shared Bearer API key.
- SQLite target, run, and hash-linked audit storage.
- Bounded asynchronous HTTP measurement.
- Literal loopback/RFC1918 IPv4 target validation.
- Fixed `GET /` profile, disabled redirects, ignored proxy environment.
- Prometheus-format metrics and loopback-only launch profile.

Baseline limitation: the active-run lock was process-local; backup/restore and detached audit checkpoints were not provided.

## v0.2.0 — Core Hardening

**Goal:** make the existing local service consistent across same-host workers, recover safely after process exit, and provide operator-controlled recovery and detached audit evidence without widening measurement capability.

### Implemented in the candidate

1. **Same-host run coordination**
   - Non-blocking OS lock file shared by workers using the same local database.
   - Singleton `run_control` row in SQLite and transactional run claim.
   - Run creation and audit append in one transaction.
   - Persisted stop flag for cross-worker stop requests.
   - Stale run recovery only after the OS lock is acquired.
   - Run-progress snapshots persisted for cross-worker reads.

2. **API-key lifecycle**
   - `python -m app keygen` generates a high-entropy Bearer key.
   - Rotation uses protected `LAB_API_KEY` configuration and a restart of all workers.
   - The key remains in process memory and is not stored in SQLite.
   - Multi-key management and user/RBAC remain out of scope.

3. **Detached audit checkpoints**
   - HMAC-SHA256 checkpoints record a verified chain prefix, event count, timestamp, key ID, and MAC.
   - Checkpoint files can be stored outside the database.
   - The key is separate from the API key and remains with the operator.
   - HMAC is symmetric; it is not an asymmetric signature or non-repudiation mechanism.

4. **SQLite backup and restore**
   - Online consistent backup through SQLite's backup API.
   - SHA-256 sidecar, SQLite integrity check, and foreign-key check.
   - Restore requires `--confirm-offline`, validates the source, and creates a pre-restore backup if a destination exists.
   - 0.1 schema backups are accepted and migrated by the 0.2 Store on open.

5. **Regression and negative tests**
   - Cross-process lock exclusivity and kernel lock release after owner termination.
   - Two app instances sharing a database, second-run rejection, and cross-worker stop.
   - Stale-run recovery and atomic claim.
   - Backup integrity, restore, legacy migration, HMAC checkpoint, and tamper tests.

### Candidate verification observed

- Isolated Python 3.11.2 run: **44 tests passed, 0 failed, 77% application line coverage** on candidate commit `67254209572c320968a69db52c64b041b5769701`.
- CLI smoke checks passed for key generation, backup, backup verification, checkpoint creation/verification, and offline restore.
- GitHub Actions Python 3.11/3.12/3.13 and dependency audit remain release gates.
- Docker/Compose validation and independent security review remain NOT VERIFIED.

### v0.2 release gates

- Re-run compileall and the full test suite after the final candidate commit.
- Obtain green GitHub Actions tests for Python 3.11, 3.12, and 3.13.
- Obtain a green dependency vulnerability audit.
- Verify the diff contains no safety-envelope changes.
- Review local filesystem locking assumptions and offline restore instructions.
- Record unsupported platform behavior honestly.
- Do not claim production readiness solely because CI passes.

## v0.3.0 — Network Telemetry and Sensor Ingestion

**Implemented development scope:** authenticated file ingestion for Zeek TSV (`conn`, `dns`, `http`), Suricata EVE JSON Lines (`alert`, `flow`, `dns`, `http`, `tls`), and offline Ethernet PCAP/PCAPNG metadata extraction. Events use a versioned envelope, are persisted in SQLite with source digest and audit provenance, and identical source bytes are idempotent.

**Hard limits:** text imports 16 MiB / 10,000 events; PCAP imports 64 MiB / 100,000 packets. Packet parsing is offline and header-only; no sockets are opened and no captured packet is transmitted. Payload content is not retained. Only Ethernet link type is supported for PCAP/PCAPNG.

**Still deferred:** live sensor agents, Zeek/Suricata process management, reverse-proxy adapters, event retention/deletion controls, ingestion queue/back-pressure, dashboard visualization, and detection rules. These require separate design and testing.

**Exit criteria:** positive/negative fixtures for every adapter; malformed and oversized input rejection; deterministic offline parsing; duplicate batch idempotency; audit-chain continuity; CI and dependency audit green.

## v0.4.0 — Explainable Rule-Based Detection Engine

**Implemented candidate scope:** a deterministic rules engine operating only on normalized, persisted telemetry. Evaluation is explicit and bounded to the latest 5,000 stored events; it does not generate traffic, run sensors, or perform automatic response.

### Initial ruleset 1.0.0

- **SUR-001 — Suricata alert observed:** preserve sensor signature, category, source/destination evidence, and map Suricata severity (1 critical, 2 high, 3 medium, other low).
- **NET-001 — High destination-port diversity:** at least 20 distinct destination ports from one source in a fixed 60-second UTC bucket.
- **NET-002 — High destination-address fan-out:** at least 30 distinct destination IPs from one source in a fixed 60-second UTC bucket.
- **DNS-001 — DNS NXDOMAIN burst:** at least 10 NXDOMAIN responses from one source in a fixed five-minute UTC bucket.
- **DNS-002 — High DNS query-name diversity:** at least 50 distinct query names from one source in a fixed five-minute UTC bucket.

Every rule includes a stable ID/version, severity, threshold, description, rationale, and supported sources. Alerts retain bounded evidence and deterministic fingerprints. Thresholds are conservative starting points, not universal indicators of compromise; benign monitoring, resolvers, proxies, and inventory tools can trigger similar signals.

### API and persistence

- `GET /api/v1/detection/rules` returns the read-only rules catalogue.
- `POST /api/v1/detection/evaluate?limit=5000` explicitly evaluates the latest bounded event slice.
- `GET /api/v1/detection/alerts?limit=100&severity=medium` retrieves persisted alerts.
- Evaluation records and alert upserts are transactional and appended to the existing audit chain.
- Identical rule/subject/time-bucket findings use stable SHA-256 fingerprints to avoid duplicate alert records on repeated evaluation.

### Deferred intentionally

No statistical anomaly scoring, adaptive thresholds, ML model, automatic blocking, containment, or autonomous response. These require representative reviewed datasets, labelled outcomes where possible, measured false-positive rates, model governance, and human approval.

### Exit criteria

- Positive, negative, threshold-boundary, and deterministic-repeat tests for every rule.
- Persistence, idempotent upsert, API authentication, input bounds, and audit-chain tests.
- CI green on Python 3.11, 3.12, and 3.13 plus dependency audit.
- Rule-by-rule review of evidence quality, false-positive limitations, and operator runbooks.
- No changes to the existing active measurement safety envelope.
- Independent review before treating the engine as operationally trusted.

## v0.4.1 — Alert Lifecycle and Investigation Foundation

**Goal:** make each detection alert an auditable, reviewable investigation record.

Implemented candidate scope:
- Alert statuses: new, acknowledged, investigating, resolved, with controlled reopening.
- Analyst classifications: true positive, false positive, benign, undetermined.
- Alert detail with bounded evidence and chronological activity.
- Investigation notes (maximum 2,000 characters).
- Status/classification filters and explicit transition validation.
- Transactional SQLite activity persistence and hash-linked audit events.
- Schema migration for existing detection alert databases.

**Exit criteria:** lifecycle/API tests, migration tests, authentication and invalid-transition tests, audit-chain verification, and green CI across supported Python versions.

## v0.5.0 — Defense Validation and Incident Response

**Goal:** connect detections to safe, human-controlled investigation and defense assessment.

Planned capabilities:

- Incident cases correlating detections and evidence into timelines.
- Investigation notes, evidence references, action history, and reports.
- Offline replay and bounded authorized defense-validation scenarios.
- MTTD, acknowledgement, containment, and recovery measurements where timestamps support them.
- Explicit operator approval for any future response integration.
- Recovery verification and post-incident review.

**Exit criteria:** incident lifecycle is auditable; reports preserve provenance and evidence hashes; no disruptive action executes without operator approval; scenarios have safe teardown and recovery criteria.

## v1.0.0 — Multi-Operator / Enterprise Research Platform

Potential scope after prior gates:

- Multi-user identity, RBAC, ownership boundaries, and audited administrative actions.
- PostgreSQL for concurrent control-plane state after migration and recovery testing.
- HTTPS/TLS and an approved SSO/OIDC integration.
- Passive-only sensor fleet administration.
- Tenant boundaries, data retention, backup/recovery objectives, and operational runbooks.
- SIEM/IDS/IPS adapters.
- Signed release artifacts, SBOM, vulnerability triage, and independent security review.
- Separate deployment threat model and production readiness assessment.

ClickHouse is considered only if measured event volume/query patterns justify it. NATS/Kafka are deferred until a demonstrated delivery/throughput need warrants them. A Go/Rust rewrite is considered only after profiling identifies an actual bottleneck.

## Cross-release non-negotiable safety requirements

- Targets remain literal IPv4 loopback or RFC1918 addresses only; no DNS hostnames or IPv6.
- Requests remain fixed HTTP `GET /`; no arbitrary methods, paths, payloads, or redirects.
- Proxy environment remains ignored.
- Hard ceilings remain 10 requests/second, 30 seconds, 5 concurrent requests, 300 requests per run, existing timeouts, and the 16 KiB response cap.
- One active run per shared local database and OS lock file; multi-host coordination remains unsupported.
- No public-target mode, distributed traffic generation, botnet/C2, proxy/VPN rotation, spoofing, packet crafting, reflection, amplification, evasion, or unrestricted stress testing.
- Prefer offline event/PCAP replay over increasing live traffic.
- Sensors collect authorized telemetry; they do not generate traffic or autonomously modify protected systems.
- No automatic disruptive response; require operator approval, scope preview, and rollback planning.

A change to a safety invariant requires explicit authorization, a threat-model update, negative tests, and human review. A test or benchmark is never a reason to weaken the boundary.

## Project-local verification evidence

For each milestone, record the commit SHA, scope, architecture/threat-model changes, requirement-to-code-to-test traceability, exact runner/version/commands/results, artifact hashes, relevant dependency/secret checks, and unresolved BLOCKED or NOT VERIFIED items.

ZYRAX's development and test process is self-contained. It must not require external governance repositories or policy frameworks. A green CI run alone does not establish complete security or production readiness.
