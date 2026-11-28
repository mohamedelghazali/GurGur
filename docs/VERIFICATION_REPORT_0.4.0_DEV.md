# ZYRAX v0.4.0.dev0 — Verification Report

**Scope:** deterministic, explainable rule-based detection over normalized telemetry persisted by v0.3.  
**Branch:** `feat/v0.4-explainable-detection`  
**Application code commit verified:** `3a6957cea2df746c872a95818a86654006d725b1`  
**Ruleset:** `1.0.0`

## Implemented candidate

- Read-only, versioned rules catalogue.
- SUR-001: preserve Suricata alert evidence and map sensor severity (1 critical, 2 high, 3 medium, other/missing low).
- NET-001: source destination-port diversity (20 unique ports / fixed 60-second UTC bucket).
- NET-002: source destination-address fan-out (30 unique destinations / fixed 60-second UTC bucket).
- DNS-001: NXDOMAIN burst (10 responses / fixed five-minute UTC bucket).
- DNS-002: DNS query-name diversity (50 unique names / fixed five-minute UTC bucket).
- Bounded evaluation of the newest 5,000 persisted telemetry events.
- Stable SHA-256 finding fingerprints and transactional alert upserts.
- Audit-chain entry for every evaluation.
- Authenticated rules, evaluate, and alerts API endpoints.

## GitHub Actions verification

**Workflow run:** [46146000510](https://github.com/mohamedelghazali/ZYRAX/actions/runs/46146000510)  
**Result:** all four jobs passed.

| Environment | Tests | Failures | Application line coverage |
|---|---:|---:|---:|
| Python 3.11.18 | 69 passed | 0 | 80% |
| Python 3.12.16 | 69 passed | 0 | 80% |
| Python 3.13.18 | 69 passed | 0 | 80% |
| Dependency vulnerability audit | PASS | — | — |

The test jobs used pytest 9.2.0 and coverage 7.17.5. One existing Starlette/httpx TestClient deprecation warning remains: install `httpx2` instead of using httpx with `starlette.testclient`.

The first CI attempt exposed that the detection routes had not been registered in the application. The route-registration omission was corrected, and the final code commit above passed the full matrix. The earlier failed run was not bypassed.

## Safety properties

- No sensor processes, capture interfaces, or remote sensor connections are started.
- No packet transmission or generated network traffic.
- No automatic blocking, containment, firewall modification, or disruptive response.
- Existing measurement target restrictions and ceilings are unchanged.
- Detection reads stored normalized telemetry only; maximum 5,000 events per evaluation.

## Test coverage added

- Rule catalogue metadata and version.
- Exact port-diversity threshold and below-threshold negative boundary.
- Destination fan-out threshold.
- DNS NXDOMAIN and distinct-name rules.
- Suricata severity mapping and evidence preservation.
- Deterministic evaluation, persistence, API authentication, filters, and audit chain.

## Remaining verification gates

- Local compile/test execution outside GitHub Actions: **NOT VERIFIED**.
- Docker / Compose validation: **NOT VERIFIED**.
- Independent security review: **NOT VERIFIED**.
- False-positive calibration on representative, reviewed and labelled data: **NOT AVAILABLE / NOT VERIFIED**.
- Operational tuning against real environment telemetry: **NOT VERIFIED**.
- Production readiness: **NOT CLAIMED**.

The current rules are triage indicators, not proof of malicious intent. Do not enable automated response based on these findings.
