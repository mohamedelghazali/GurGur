# ZYRAX — Agent Instructions

## Project-local source of truth

ZYRAX is developed as a self-contained project. Its engineering procedures, safety rules, threat model, test matrix, and operational requirements must live in this repository.

- Do not require or depend on external governance repositories, policy frameworks, remote agent packs, or externally hosted instructions to build, run, test, or maintain ZYRAX.
- Read and follow this file, `README.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/EXPERIMENT_PROTOCOL.md`, and `docs/SECURITY_TEST_MATRIX.yaml` before changing the application.
- Treat the source code, tests, and project documentation as the project-specific baseline. Record any unresolved requirement as BLOCKED or NOT VERIFIED rather than inventing evidence.

## Non-negotiable safety invariants

- Preserve the loopback/RFC1918 IPv4-only target allow-list.
- Preserve the fixed `GET /` request profile and disabled redirects/proxy environment behavior.
- Preserve server-enforced ceilings: 10 requests/second, 30 seconds, 5 concurrent requests, and 300 requests per run.
- Preserve the 16 KiB response cap and request-timeout limits.
- Keep at most one active measurement run for a given local SQLite database and its shared OS run-lock file.
- Preserve API authentication and loopback-only default bind.
- Do not add public-target mode, arbitrary request methods/paths, distributed traffic-generation agents, botnet/C2 functions, proxy/VPN rotation, source spoofing, reflection, amplification, packet crafting, or evasion features.
- Do not widen a safety limit to make a test, benchmark, or demonstration pass.
- Restore operations require every ZYRAX process using the database to be stopped. The restore command must require an explicit offline confirmation.
- HMAC audit checkpoints are symmetric integrity/authenticity attestations. Never describe them as public-key signatures or non-repudiation.

Any proposed change to a safety invariant requires an explicit threat-model update, negative-security tests, and human review. If safe bounded behavior cannot be demonstrated, stop and report BLOCKED.

## Engineering workflow

Use:

```text
Inspect → Threat Model → Plan → Implement → Test → Independently Verify → Report
```

Run at minimum:

```bash
python -m compileall -q app tests
python -m pytest -q --cov=app --cov-report=term-missing
```

When changing the database, test both fresh and legacy schema migration paths, concurrent access, backup verification, and restore behavior. When changing the run engine, test process-level lock exclusivity, crash recovery, cross-worker stop requests, and all fixed traffic ceilings.

For container changes, validate Docker build and Compose configuration on an environment with Docker. For dependency changes, run the dependency vulnerability audit. Record exact commands, Python/dependency versions, timestamps, test results, commit SHA, and unresolved gates. Never infer production readiness from a green test suite alone.
