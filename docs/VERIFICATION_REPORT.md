# ZYRAX 0.1.0 — Historical Verification Snapshot

**Historical test time:** 2026-11-27T21:52:24Z

> Historical record for the 0.1.0 baseline only. This is not the v0.2 verification report and does not impose an external governance dependency on current ZYRAX development. Current development and verification are self-contained in this repository.
**Runtime:** Python 3.13.5 · FastAPI 0.128.2 · httpx 0.28.1 · Pydantic 2.13.5 · Uvicorn 0.48.0 · pytest 9.0.2

## Results

- **34 tests passed, 0 failed, 0 skipped.**
- **87% application line coverage** in the measured `app/` package.
- `python -m compileall -q app tests` completed successfully.
- Live Uvicorn smoke checks passed: health endpoint 200, dashboard 200, static JavaScript 200, unauthenticated API 401, authenticated API 200.
- Integration test used a real local HTTP fixture, exercised the bounded request engine, checked persisted run results, and verified the audit hash chain.
- Negative tests cover missing/invalid bearer keys, public targets, DNS hostnames, invalid labels, excessive run budgets, overlapping runs, unknown run IDs, invalid configuration, container publish acknowledgement, launcher loopback binding, and tampered audit events.
- AIGENT-SEC upstream preflight v1.2.0 passed against pinned commit `e181de2e52cf1ac9ff2300da287c16ac68186e44`: all 175 active policy paths were present; 73 core and applicable policy files were fetched. This validates upstream policy availability/integrity, not this application's security.
- AIGENT-SEC-derived secret-scanner and secure-review heuristics returned no supported findings on this workspace. These checks are heuristic, not exhaustive, and do not replace SAST or independent review.

## Unresolved verification gates

The workspace does not yet have a Git commit SHA bound to this test run. GENCODE-GOV's full CLI validation and independent audit have not been run. A full AIGENT-SEC application security audit and independent human review are also outstanding. Ruff, Bandit, pip-audit, Docker build/Compose validation, SBOM generation, and artifact signing have not been run locally. GitHub Actions includes a `pip-audit` job, but its remote result is pending repository creation and workflow execution. Production deployment, TLS termination, remote access review, backup/restore testing, and operational readiness remain **NOT VERIFIED**.

**Governance outcome: BLOCKED for release/production approval.** This does not negate the observed 34/34 local test result; it records that commit-bound and independent assurance evidence is incomplete.
