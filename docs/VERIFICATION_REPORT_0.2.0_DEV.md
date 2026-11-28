# GurGur 0.2.0.dev0 — Candidate Verification Report

**Candidate commit:** `67254209572c320968a69db52c64b041b5769701`  
**Observed:** 2026-11-28  
**Environment:** isolated Linux execution environment · Python 3.11.2

## Commands executed

```bash
python -m pip install -e '.[test]'
python -m compileall -q app tests
python -m pytest -q --cov=app --cov-report=term-missing
```

## Automated test results

- **44 passed**
- **0 failed**
- **0 skipped**
- **77% total application line coverage**
- `compileall`: PASS

The suite includes tests for process-level file-lock exclusivity and lock release after process termination, atomic run claims, stale-run recovery, cross-worker run conflicts and stop requests, legacy 0.1 database restoration/migration, online backup verification, checksum tampering, detached HMAC checkpoint verification/tampering, and the existing target-scope and request-budget controls.

## CLI smoke checks

The following commands completed successfully against a temporary test database:

- `python -m app keygen`
- `python -m app backup create --output ...`
- `python -m app backup verify --input ...`
- `python -m app audit checkpoint --output ...`
- `python -m app audit verify-checkpoint --input ... --database-check`
- `python -m app backup restore --input ... --confirm-offline`
- Backup verification after restore

Observed filesystem modes on the isolated Linux environment:
- SQLite database: `0600`
- Data directory: `0700`

## Warning and remaining checks

One non-failing warning remains from the test stack:

`StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.`

No dependency was added to silence this warning in the current candidate.

The following have not yet been verified:

- GitHub Actions Python 3.11 / 3.12 / 3.13 matrix on the PR.
- GitHub Actions dependency vulnerability audit.
- Docker image build and Docker Compose validation.
- Independent application security review.
- Multi-host coordination (not supported by design).
- Production deployment or recovery readiness.

This report documents the exact checks run on the candidate commit. It is not a comprehensive security audit or production-readiness approval. No external governance repository or framework is required for GurGur's current development or test process.
