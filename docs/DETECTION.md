# ZYRAX Explainable Detection Engine — v0.4.0.dev0

## Design

The engine evaluates normalized Zeek, Suricata, and offline PCAP metadata already persisted by v0.3. It is deterministic and rule-based. It does not capture traffic, contact sensors, transmit packets, or take response actions.

Each finding contains:
- Stable rule ID and rule version.
- Ruleset version.
- Severity, title, description, and rationale.
- Source and affected subject.
- Fixed UTC time bucket and event count.
- Bounded evidence fields and deterministic SHA-256 fingerprint.

Rules are read-only in this increment. Threshold tuning and custom rules require a separate versioned configuration design and regression corpus.

## Ruleset 1.0.0

| Rule | Severity | Threshold | Supported event sources |
|---|---|---|---|
| SUR-001 — Suricata alert observed | Maps sensor severity | One EVE alert | Suricata |
| NET-001 — High destination-port diversity | Medium | 20 distinct destination ports / source / 60 seconds | Zeek, PCAP |
| NET-002 — High destination-address fan-out | Medium | 30 distinct destination IPs / source / 60 seconds | Zeek, PCAP |
| DNS-001 — DNS NXDOMAIN burst | Medium | 10 NXDOMAIN responses / source / 5 minutes | Zeek, Suricata |
| DNS-002 — High DNS query-name diversity | Low | 50 distinct query names / source / 5 minutes | Zeek, Suricata |

Suricata severity mapping: 1=critical, 2=high, 3=medium, all other or missing values=low.

All aggregation uses fixed UTC epoch-aligned buckets. Repeated evaluation of the same event slice produces the same finding fingerprints. The database upserts an existing alert with that fingerprint instead of adding a duplicate row.

## API

All endpoints require the existing Bearer API key.

- `GET /api/v1/detection/rules` — read-only rules catalogue.
- `POST /api/v1/detection/evaluate?limit=5000` — explicitly evaluate the newest 1–5,000 stored events.
- `GET /api/v1/detection/alerts?limit=100` — list persisted alerts.
- `GET /api/v1/detection/alerts?severity=medium` — filter by severity.

Evaluation is operator-triggered; importing telemetry does not automatically trigger detection. Each evaluation and alert persistence transaction is recorded in the existing audit chain.

## Interpretation and limitations

These are triage rules, not proof of compromise. DNS resolvers, proxies, inventory scanners, monitoring systems, service discovery, and high-volume applications can produce similar patterns. Thresholds are initial conservative defaults and must be reviewed against the local environment.

No statistical baseline, anomaly score, ML inference, automatic blocking, containment, firewall modification, or other disruptive response is implemented. Statistical/ML methods should be considered only after representative, reviewed datasets exist and false-positive behavior can be measured. Any future response integration must require explicit human approval and a documented rollback path.

## Resource bounds

- Maximum input slice per evaluation: 5,000 events.
- Maximum returned alerts: 500 per query.
- No network access or packet transmission during evaluation.
- No arbitrary rule expression, dynamic code, or user-supplied query execution.
- Alert evidence is stored in SQLite and may contain sensitive internal IP addresses and DNS names; protect database and backups.
