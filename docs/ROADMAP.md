# GurGur — Product Roadmap

**Latest stable baseline:** `0.1.0`  
**Current development line:** `0.2.0.dev0` — Core Hardening  
**Status:** v0.2 implementation is in the development branch; release qualification is pending.

## Product objective

Evolve GurGur from a bounded private-network measurement console into an explainable network intelligence, threat detection, defense validation, and investigation platform for authorized environments.

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

**Goal:** accept defensive network observations without adding distributed traffic-generation capability.

Planned adapters:

- Zeek structured logs, initially `conn.log`, `dns.log`, and `http.log`.
- Suricata EVE JSON alerts and protocol metadata.
- Reverse-proxy and selected application access/error logs.
- Explicitly supplied PCAP files processed offline.

Planned platform work:

- Versioned normalized event envelope and source provenance.
- Schema validation, bounded ingestion, deduplication, replay, and back-pressure.
- Sensor registration, health/heartbeat, last-seen time, ingestion lag, and error counters.
- Event retention, access control, privacy review, and deletion procedures.
- Offline fixtures and integration tests for supported source formats.

**Exit criteria:** every adapter has positive/negative fixtures; malformed and oversized records are safely rejected; replay is deterministic; duplicate handling is verified; sensor health and ingestion failures are observable.

## v0.4.0 — Explainable Detection Engine

**Goal:** detect measurable behavior deviations with testable, operator-understandable evidence.

Planned capabilities:

- Versioned rules with event dependencies, aggregation windows, thresholds, severity, rationale, owner, and runbook.
- Deterministic rules for traffic-rate deviations, latency/error spikes, connection patterns, and DNS anomalies.
- Per-service or per-network baselines with bounded windows.
- Positive/negative fixtures, regression corpus, tuning, and suppression expiry.
- Evaluation reporting for false positives and, where labelled data exists, precision/recall.

Statistical anomaly scoring may be added only after reliable telemetry and representative labelled/reviewed data exist. An anomaly score is a triage signal, not proof of malicious intent.

**Exit criteria:** each shipped rule has tests, a runbook, measurable false-positive behavior, a stable version, and an accountable owner.

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

GurGur's development and test process is self-contained. It must not require external governance repositories or policy frameworks. A green CI run alone does not establish complete security or production readiness.
