# GurGur — Product Roadmap

**Current release:** `0.1.0` — local-first MVP  
**Next planned release:** `0.2.0` — Core Hardening  
**Roadmap status:** Planned work, not a statement of implemented functionality or a delivery-date commitment.

## Product objective

Evolve GurGur from a bounded private-network measurement console into an explainable network intelligence, threat detection, defense validation, and investigation platform for authorized environments.

The roadmap deliberately prioritizes safety, durable state, evidence integrity, and operational reliability before adding telemetry volume or detection complexity.

## Current baseline — v0.1.0 (implemented)

- FastAPI local control plane and browser dashboard.
- Single bearer API key for a local operator.
- SQLite storage for targets, runs, and hash-linked audit events.
- Bounded asynchronous HTTP measurement against registered loopback/RFC1918 IPv4 literals.
- Fixed `GET /` request profile, disabled redirects, and ignored proxy environment.
- Prometheus-format metrics endpoint.

**Known boundaries:** no multi-user identity/RBAC, no remote deployment profile, no Zeek/Suricata ingestion, no packet capture or flow ingestion, no detection engine, no incident case management, and no forensic acquisition workflow. The process-local active-run lock does not coordinate multiple application workers. The local audit chain has no independent external trust anchor.

## v0.2.0 — Core Hardening (next)

**Goal:** make the existing local service safer to operate and more reliable without widening its traffic-generation capability.

Planned work:

1. **Durable run coordination**
   - Replace process-local-only exclusivity with a database-backed atomic run claim/lease.
   - Persist the owner identity and lease lifecycle; prevent a second worker from starting a run while a valid lease exists.
   - Define stale-lease recovery after a process crash and prove it with multi-process tests.
   - Keep one active run as the supported behavior.

2. **Authentication and authorization hardening**
   - Keep the single-operator profile for this milestone.
   - Add a documented API-key rotation/revocation procedure and avoid credential disclosure in logs, errors, metrics, and evidence.
   - Keep constant-time credential comparison and server-side authorization for every protected route.
   - Defer multi-user accounts, RBAC, and SSO to the enterprise milestone.

3. **Audit integrity**
   - Specify a detached, externally verifiable signed-checkpoint design using a vetted signing implementation and keys held outside the application database.
   - Include key identification, rotation/revocation, checkpoint verification, and recovery behavior.
   - Do not implement custom cryptographic primitives or present an internal hash chain as an external signature.

4. **Backup, restore, and retention**
   - Provide a consistent SQLite backup procedure that accounts for WAL mode.
   - Define backup integrity checks, retention, secure storage, and restore steps.
   - Execute an isolated restore drill and validate application-level data integrity before calling the procedure verified.

5. **Operations and quality**
   - Document service indicators and initial latency objectives.
   - Improve sanitized structured operational/security logging and privacy-safe event fields.
   - Add regression and negative-security tests for run exclusivity, stale leases, authentication, access boundaries, audit verification, backup/restore, and error handling.
   - Keep CI dependency auditing and multi-version Python tests enabled.

**Exit criteria:** no duplicate active run can be created across supported workers; restart/crash behavior is documented and tested; backup restoration is proven in isolation; audit-checkpoint limitations are explicit; applicable security tests and dependency scans are recorded against the release commit. Human security review remains required for authentication and signed-checkpoint design.

## v0.3.0 — Network Telemetry and Sensor Ingestion

**Goal:** accept defensive network observations without adding distributed traffic-generation capability.

Planned source adapters:

- Zeek structured logs, starting with `conn.log`, `dns.log`, and `http.log`.
- Suricata EVE JSON alerts and protocol metadata.
- Reverse-proxy and selected application access/error logs.
- Explicitly supplied PCAP files processed offline.

Planned platform work:

- Versioned normalized event envelope and source provenance.
- Schema validation, bounded ingestion, deduplication, replay, and back-pressure behavior.
- Sensor registration, health/heartbeat, last-seen time, ingestion lag, and error counters.
- Event retention, access control, privacy review, and deletion procedures.
- Offline fixtures and integration tests for each supported source format.

**Exit criteria:** each supported adapter has fixture-based positive/negative tests, malformed and oversized records are safely rejected, replay is deterministic, duplicate handling is verified, and sensor health/ingestion failures are observable.

## v0.4.0 — Explainable Detection Engine

**Goal:** detect measurable behavior deviations with testable, operator-understandable evidence.

Planned capabilities:

- Versioned rule definitions with explicit event dependencies, aggregation windows, thresholds, severity, confidence rationale, owner, and runbook.
- Initial deterministic rules for traffic-rate deviations, latency/error spikes, connection patterns, and DNS anomalies.
- Per-service or per-network baseline support with bounded time windows.
- Positive and negative rule fixtures, regression corpus, tuning, and suppression expiry.
- Evaluation reporting: true/false positives and negatives where labels exist, precision/recall where statistically meaningful, and alert volume.

Statistical anomaly scoring may be added only after reliable telemetry and representative labelled or reviewed data exist. Machine learning is not a substitute for clear detection logic, a tested baseline, or analyst review.

**Exit criteria:** every shipped rule has a tested runbook, measurable false-positive behavior, stable versioning, a documented owner, and a repeatable evaluation report. No rule is treated as proof of malicious attribution.

## v0.5.0 — Defense Validation and Incident Response

**Goal:** connect detection results to safe, human-controlled investigation and defense assessment.

Planned capabilities:

- Incident cases that correlate detections and source evidence into timelines.
- Investigation notes, evidence references, action history, and exportable reports.
- Defense-validation scenarios using offline replay and bounded authorized measurements.
- Measurements for mean time to detect (MTTD), acknowledge, contain, and recover where the workflow provides reliable timestamps.
- Runbooks and explicit operator approval for any future response integration.
- Recovery verification and post-incident review.

**Exit criteria:** incident lifecycle is auditable; reports preserve provenance and evidence hashes; no disruptive action can execute without explicit operator approval; every scenario has defined success criteria and safe teardown/recovery.

## v1.0.0 — Multi-Operator / Enterprise Research Platform

**Goal:** support controlled deployment beyond a single local operator only after the prior gates are met.

Potential scope:

- Multi-user identity, RBAC, ownership boundaries, and audited administrative actions.
- PostgreSQL for concurrent control-plane state after migration and recovery testing.
- HTTPS/TLS and an approved SSO/OIDC integration.
- Sensor fleet administration for **passive telemetry collection only**.
- Defined tenant boundaries, data retention, backup/recovery objectives, and operational runbooks.
- SIEM/IDS/IPS integration through explicit, documented adapters.
- Signed release artifacts, SBOM, vulnerability triage, and independent security review.
- A separate deployment threat model and production readiness assessment.

ClickHouse may be evaluated for high-volume event analytics only when measured ingestion/query patterns justify it. NATS/Kafka should be deferred until a proven queueing, replay, or delivery guarantee cannot be met by a simpler design. A Go/Rust rewrite should be considered only after profiling identifies a real performance constraint.

**Exit criteria:** threat model and privacy review approved; authentication/authorization and tenant-isolation tests pass; operational monitoring and alert delivery are verified; backup restore and rollback drills pass; dependency/supply-chain controls are evidenced; independent security review and human release approval are complete.

## Cross-release non-negotiable safety requirements

All milestones preserve the current measurement safety envelope:

- Targets: literal IPv4 loopback or RFC1918 addresses only; no DNS hostnames or IPv6.
- Request: fixed HTTP `GET /`; no arbitrary methods, paths, payloads, or redirects.
- Proxy environment: ignored.
- Hard ceilings: 10 requests/second, 30 seconds, 5 concurrent requests, 300 requests per run, existing timeouts, and the 16 KiB response cap.
- One active run remains the supported behavior until durable coordination is proven.
- No public-target mode, distributed traffic-generation fleet, botnet/C2, proxy/VPN rotation, source spoofing, packet crafting, reflection, amplification, evasion, or unrestricted stress testing.
- For broader scenario coverage, prefer offline event and PCAP replay over increasing live traffic.
- Sensor integrations collect authorized telemetry; they do not generate traffic or autonomously modify protected systems.
- No automatic disruptive response. Operator approval, scope preview, and rollback planning are required for any future response integration.

A change to one of these invariants is not an ordinary feature request. It requires explicit authorization, a revised threat model, negative-security tests, and human security review; a test or benchmark is never a reason to weaken the boundary.

## Governance and release evidence

For every milestone, record:

- Commit SHA and release scope.
- Architecture and threat-model changes.
- Applicable GENCODE-GOV and AIGENT-SEC rules.
- Requirement-to-test traceability for critical and negative-security scenarios.
- Test runner/version, exact commands, results, timestamps, and artifact hashes.
- Secret scan, dependency audit, and relevant static/security checks.
- Performance, observability, backup, recovery, and migration evidence as applicable.
- Human review and unresolved BLOCKED / NOT VERIFIED items.

Statuses must remain honest: PASS, FAIL, BLOCKED, or NOT VERIFIED. A documentation milestone is not a production release, and a green CI run alone does not establish complete security or production readiness.
