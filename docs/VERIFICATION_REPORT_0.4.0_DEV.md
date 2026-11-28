# ZYRAX v0.4.0.dev0 — Verification Report

**Scope:** deterministic, explainable rule-based detection over persisted v0.3 telemetry.  
**Branch:** `feat/v0.4-explainable-detection`  
**Ruleset:** `1.0.0`

## Implemented candidate

- Read-only, versioned rules catalogue.
- SUR-001: preserve Suricata alert and map source severity.
- NET-001: source destination-port diversity (20 unique ports / 60-second UTC bucket).
- NET-002: source destination-address fan-out (30 unique destinations / 60-second UTC bucket).
- DNS-001: NXDOMAIN burst (10 responses / five-minute UTC bucket).
- DNS-002: DNS query-name diversity (50 unique names / five-minute UTC bucket).
- Bounded evaluation of the newest 5,000 persisted telemetry events.
- Stable SHA-256 finding fingerprints and transactional alert upserts.
- Audit-chain entry for every evaluation.
- Authenticated rules, evaluate, and alerts API endpoints.

## Safety properties

- No sensor processes, capture interfaces, or remote sensor connections are started.
- No packet transmission or new network traffic is generated.
- No automatic blocking, containment, or disruptive response.
- Existing active measurement target scope and ceilings are unchanged.
- Detection input is stored normalized telemetry only; maximum 5,000 events per evaluation.

## Test coverage added

- Rule catalogue metadata and version.
- Exact threshold and below-threshold negative boundary for port diversity.
- Destination fan-out threshold.
- DNS NXDOMAIN and distinct-name rules.
- Suricata severity mapping and evidence retention.
- Deterministic evaluation, persistence, API authentication, filters, and audit chain.

## Verification status

- Local compile/test execution: **NOT VERIFIED in this environment**.
- GitHub Actions Python 3.11 / 3.12 / 3.13: **PENDING**.
- Dependency vulnerability audit: **PENDING**.
- Database migration and legacy backup regression: **PENDING CI**.
- Docker / Compose: **NOT VERIFIED**.
- False-positive calibration on representative labelled data: **NOT AVAILABLE / NOT VERIFIED**.
- Production readiness: **NOT CLAIMED**.
