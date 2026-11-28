# GurGur — Target Architecture

**Document status:** Architecture direction for planned releases  
**Current software baseline:** `0.1.0` (MVP)  
**Next planned milestone:** `0.2.0 — Core Hardening`  
**Implementation status:** This document describes both the current implementation and future design. A component marked *planned* is not present in the current release.

## 1. Product vision

GurGur is evolving toward an **Intelligent Network Threat Detection & Defense Validation Platform** for authorized private environments.

The target platform has five connected capabilities:

1. **Network intelligence:** collect and normalize network and service telemetry from authorized sensors and application logs.
2. **Threat detection:** identify suspicious behavior through explainable rules first, then measured behavioral baselines and statistical anomaly methods.
3. **Defense validation:** evaluate the effectiveness of existing controls such as rate limiting, firewalls, WAF policies, and service protections using bounded measurements and offline replay.
4. **Network forensics:** correlate events into timelines and preserve integrity-verifiable evidence with documented custody.
5. **Incident response:** help operators triage, investigate, document, and verify recovery through human-controlled workflows.

The product is a defensive research and validation platform. It is not an Internet-scale traffic generator, botnet controller, or automated disruption tool.

## 2. Current implementation (v0.1.0)

The current release is a local-first, single-operator MVP:

- FastAPI control plane with bearer-key authentication.
- Browser dashboard served by the application.
- SQLite persistence for targets, runs, and hash-linked audit events.
- Bounded asynchronous HTTP measurement engine.
- Fixed request profile: HTTP `GET /`, no redirects, and no proxy-environment inheritance.
- Prometheus-format application metrics.
- Loopback/RFC1918 IPv4 target validation and server-enforced experiment ceilings.

The current release does **not** include Zeek or Suricata ingestion, packet-capture import, network-flow collection, a detection engine, anomaly models, incident management, forensic acquisition, multi-user RBAC, SSO, or a production remote-access profile.

### Current data path

```text
Browser dashboard
       |
       | Bearer-authenticated HTTP
       v
FastAPI control plane ------> SQLite
       |
       v
Bounded HTTP measurement engine
       |
       v
Registered loopback / RFC1918 lab service
```

## 3. Target logical architecture (planned)

```text
   Authorized private environment
   +----------------+  +----------------+  +----------------------+
   | Zeek logs      |  | Suricata EVE   |  | Reverse-proxy logs   |
   | conn/dns/http  |  | alerts/metadata|  | service access data  |
   +-------+--------+  +-------+--------+  +----------+-----------+
           |                   |                      |
           +-------------------+----------------------+
                               |
                       Source adapters
                               |
         Offline PCAP --------+   (offline parsing only)
                               |
                       Schema validation
                               |
                       Event normalization
                               |
                  Bounded, durable ingestion
                               |
             +-----------------+------------------+
             |                                    |
       Event storage                       Detection engine
             |                                    |
             |                          Rules + time windows
             |                          Baselines + scoring
             |                                    |
             +----------------+-------------------+
                              |
                      Incident correlation
                              |
                 Operator review / approvals
                              |
                Dashboard / reports / evidence

  Application and sensor health:
  OpenTelemetry Collector (planned) -> Prometheus / approved log backend
```

This is a logical target, not a claim that these components are already integrated. Each adapter and store must be introduced behind a stable interface and accepted through its own tests and operational evidence.

## 4. Core components

### 4.1 Telemetry ingestion (planned)

Initial source adapters should prioritize structured, locally available records:

- **Zeek:** start with `conn.log`, `dns.log`, and `http.log`; add other logs only when a clear detection or investigation use case requires them.
- **Suricata:** ingest EVE JSON alerts and protocol metadata. Treat sensor alerts as observations requiring correlation, not as unquestionable ground truth.
- **Reverse proxies and application services:** ingest access and error logs with a documented field mapping.
- **Offline PCAP analysis:** accept explicitly supplied capture files for offline parsing and replay. Do not introduce packet injection or an unrestricted live-capture/traffic-generation path as part of this feature.

Adapters must validate input size and format, reject malformed records safely, expose source health and ingestion lag, and support replay without duplicating events.

### 4.2 Normalized event model (planned)

All adapters should map records to a versioned event envelope. The minimum common fields are:

| Field | Purpose |
|---|---|
| `event_id` | Stable event identity for deduplication |
| `schema_version` | Version of the normalized event contract |
| `observed_at` | Source observation time in UTC |
| `ingested_at` | GurGur ingestion time in UTC |
| `source_type` / `sensor_id` | Provenance of the observation |
| `event_type` | Connection, DNS, HTTP, alert, or service event |
| `src` / `dst` | Observed endpoint metadata where available |
| `transport` / `application` | Protocol context when known |
| `duration`, `bytes`, `packets` | Optional measured counters |
| `labels` | Bounded, allow-listed non-sensitive enrichment |

Source-specific attributes may be stored in a versioned extension object. Do not store packet payloads, authentication headers, cookies, access tokens, or full request bodies in the normalized event stream by default. Treat IP addresses and DNS names as potentially sensitive operational data; minimize, protect, and retain them according to a documented policy.

### 4.3 Detection engine (planned)

Build deterministic, explainable detection rules before introducing machine learning. Each rule should define:

- Stable rule ID and version.
- Description, hypothesis, required event types, and data dependencies.
- Window, aggregation, threshold, and allow-listed filters.
- Severity, confidence rationale, and expected false-positive behavior.
- Positive and negative fixtures, regression corpus, and measured evaluation results.
- Investigation guidance and an accountable rule owner.
- Optional ATT&CK mapping only where the mapping is justified by the observed behavior.

Candidate detection families include:

- HTTP request-rate and burst deviations from an approved service baseline.
- Increases in latency, timeout, connection failure, or HTTP error ratios.
- Abnormal connection distributions or protocol-state patterns from sensor metadata.
- DNS query-rate, response-code, or domain-pattern anomalies.
- Correlated signals across sensors and reverse-proxy records.

Behavioral baselines should be scoped per approved service or network segment and should account for seasonality and expected changes. A statistical anomaly score is a triage signal, not proof of malicious intent. Do not make identity or attribution claims from an IP address alone.

A rule must not ship without positive and negative tests, a documented tuning process, and an investigation runbook. Track false-positive rate, precision/recall where labels exist, and alert usefulness over time.

### 4.4 Defense validation (planned)

The validation center should answer measurable questions about existing defenses:

- Was a control present and configured as expected?
- Did it detect the supplied event or bounded experiment?
- How long did detection take?
- Did the service remain healthy?
- How quickly did the service return to its measured baseline?

Prefer offline replay and synthetic event fixtures for broad scenario coverage. Any active measurement must remain inside the current private-target safety envelope and require explicit authorization. GurGur should observe and report control behavior; it must not silently change firewall, WAF, routing, or production settings. Any future response integration requires explicit operator approval, a preview of the action, a bounded scope, and a tested rollback path.

### 4.5 Network forensics and evidence (planned)

The forensic workspace should provide:

- Time-ordered event timelines with source provenance.
- Correlation across sensor IDs, event IDs, and documented time windows.
- A clear distinction between raw source evidence, normalized records, and analyst interpretation.
- SHA-256 digests for acquired files and exported evidence packages.
- An append-only custody record for acquisition, access, transfer, export, and review.
- Exportable investigation reports that preserve timestamps, tool versions, source references, and known limitations.

A hash chain is tamper-evident only relative to the stored chain. It is not proof of authenticity when an administrator can rewrite the complete database and recompute hashes. External signed checkpoints require a separate trusted signer, protected signing keys, key rotation and revocation procedures, and independent verification. Do not invent or implement custom cryptography.

### 4.6 Incident workflow (planned)

A proposed operator workflow is:

```text
Observed -> Triaged -> Investigating -> Containment proposed
         -> Human-approved action (where supported)
         -> Recovery verified -> Resolved -> Closed
```

Incidents should retain linked detections, evidence references, operator decisions, timestamps, and a concise post-incident report. A detection must not automatically trigger a disruptive network action.

## 5. Observability and operational health

Use OpenTelemetry instrumentation and the OpenTelemetry Collector as the planned vendor-neutral collection layer for GurGur service telemetry. Export operational metrics to Prometheus or another explicitly selected backend.

Track at least:

- API availability and endpoint latency (P50, P95, P99).
- Error rates, request volume, and resource saturation.
- Ingestion throughput, queue depth, dropped/invalid events, and source lag.
- Sensor heartbeat and last successful ingestion time.
- Detection counts by rule and severity.
- Rule-level false-positive rate and evaluation quality where labels exist.
- Mean time to detect (MTTD), acknowledge, contain, and recover when the workflow supports those measurements.

Public liveness responses must remain minimal. Detailed diagnostics, sensor inventories, metrics, and operator dashboards must require authentication and appropriate authorization. Never emit secrets, tokens, cookies, or raw sensitive payloads into logs, metrics labels, or traces.

## 6. Storage and scaling decisions

Adopt the simplest store that meets measured requirements:

| Stage | Preferred approach | Reason |
|---|---|---|
| Current MVP | SQLite | Local, single-operator state and bounded run history |
| Early telemetry | SQLite or a small relational store after measurement | Avoid premature distributed infrastructure |
| Multi-user control plane | PostgreSQL | Transactions, concurrent operators, stronger operational separation |
| High-volume event analytics | ClickHouse only when measured volume/query patterns justify it | Efficient large-scale event analytics |
| Queue / event broker | Defer NATS or Kafka until a demonstrated reliability or throughput need | Avoid needless operational complexity |

Keep control-plane state (users, configuration, incidents, audit metadata) conceptually separate from high-volume telemetry. Define retention, deletion, backup, restore, access control, and migration behavior before accumulating sensitive event data. Database selection must follow a measured workload and recovery plan, not anticipated scale alone.

## 7. Security and privacy invariants

The following are product boundaries, not tunable performance settings:

- Active measurement targets remain literal IPv4 addresses in loopback or RFC1918 ranges only.
- The measurement request remains the fixed HTTP `GET /` profile; no arbitrary path or method.
- Redirects remain disabled and proxy environment settings remain ignored by the measurement client.
- Hard limits remain at **10 requests/second, 30 seconds, 5 concurrent requests, and 300 requests per run**, with the existing request-timeout and response-size caps.
- One active experiment remains the supported behavior; coordination must become durable before multi-worker execution is supported.
- Do not add public-target mode, distributed traffic-generation agents, botnet/C2 behavior, proxy/VPN rotation, source spoofing, packet crafting, reflection, amplification, evasion, or unrestricted stress-generation.
- Use offline event/PCAP replay for broad detection testing; do not raise active traffic ceilings to make a demonstration or benchmark pass.
- Sensors are telemetry sources, not remote traffic-generation agents.
- Keep the current local-only deployment boundary until a separate remote deployment design has passed security and operational review.
- Do not collect payloads or personal data by default. Define purpose, lawful authority, retention, access, and deletion before introducing additional data classes.
- Keep detection explainable and human-reviewed. No automatic disruptive response is in scope for the planned milestones.

### Important destination-boundary distinction

GurGur's authorized measurement feature deliberately targets registered loopback/RFC1918 lab services. This is a narrow, operator-controlled destination allow-list, not a general-purpose URL fetcher. Preserve literal-IP validation, fixed `GET /`, port constraints, disabled redirects, and no DNS resolution. Do not broaden it into arbitrary user-supplied URL fetching; generic URL fetchers must apply a separate SSRF-safe destination policy.

## 8. Release and governance gates

Every milestone must have:

1. An updated threat model and architecture impact analysis.
2. A rule-to-code-to-test traceability matrix for applicable security requirements.
3. Positive, negative, regression, and integration tests using the real server boundary.
4. Dependency and secret scanning evidence appropriate to the change.
5. Performance and failure-mode evidence for new ingestion or storage paths.
6. Backup/restore evidence before any release that depends on persistent new data.
7. Independent review of authentication, authorization, data handling, evidence integrity, and active-measurement safety.
8. A release report bound to a commit SHA that distinguishes PASS, FAIL, BLOCKED, and NOT VERIFIED.

A green CI run proves only the checks executed by that workflow. It does not establish production readiness, complete security coverage, or successful recovery.

## 9. Technology references

These are upstream documentation references for future implementation; their inclusion does not mean the integrations are present:

- [Zeek logging framework and log types](https://docs.zeek.org/en/current/logs/index.html)
- [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [OpenTelemetry HTTP metrics semantic conventions](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
