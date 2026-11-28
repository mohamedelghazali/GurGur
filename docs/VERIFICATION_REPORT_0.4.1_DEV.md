# ZYRAX v0.4.1 Development Verification Report

**Milestone:** Alert Lifecycle & Investigation Foundation  
**Status:** Development candidate; not a production security certification  
**PR:** https://github.com/mohamedelghazali/ZYRAX/pull/6  
**Base dependency:** PR #5 — v0.4.0 Explainable Rule-Based Detection Engine  
**Final PR head:** `74c228008e0d4c396ebd2abfc7603164544efebc`  
**Code/test commit exercised by CI:** `651c7711e53fbbc8fc50f45666bd621a38444b74`

## Implemented scope

- Alert lifecycle states: `new`, `acknowledged`, `investigating`, `resolved`.
- Controlled reopening from `resolved` to `new`.
- Classifications: `true_positive`, `false_positive`, `benign`, `undetermined`.
- Authenticated alert detail and filtered list endpoints.
- Investigation notes capped at 2,000 characters.
- SQLite activity timeline for status/classification changes and notes.
- Transactional persistence with hash-linked audit events.
- Schema migration adds classification and closed timestamp and normalizes legacy `open` alerts to `new`.
- Existing fingerprint upserts preserve investigation state and classification.
- No network response, packet transmission, live sensor operation, or automatic blocking.

## GitHub Actions evidence

**Workflow run:** [46147463633](https://github.com/mohamedelghazali/ZYRAX/actions/runs/46147463633)

| Job | Result |
|---|---|
| Python 3.11 | PASS — 73 tests, 0 failures, 80% application line coverage |
| Python 3.12 | PASS — 73 tests, 0 failures, 80% application line coverage |
| Python 3.13 | PASS — 73 tests, 0 failures, 80% application line coverage |
| Dependency vulnerability audit | PASS — no known vulnerabilities found |

One Starlette/httpx TestClient deprecation warning remains. The CI run exercised code and tests at commit `651c7711e53fbbc8fc50f45666bd621a38444b74`. Later commits on the PR changed only architecture and threat-model documentation; final PR head is `74c228008e0d4c396ebd2abfc7603164544efebc`.

## Not verified

- Local execution outside GitHub Actions.
- Docker/Compose build and runtime.
- Independent security review.
- Multi-user identity, RBAC, or attribution to distinct humans.
- Production deployment readiness.

## Review and merge order

This is a stacked pull request targeting `feat/v0.4-explainable-detection`. Merge PR #5 first, then retarget PR #6 to `main` and rerun the full required checks against the resulting base.
