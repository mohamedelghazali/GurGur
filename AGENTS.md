# GurGur — Agent Instructions

## Mandatory project context
Before changing this repository, read this file and `README.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/EXPERIMENT_PROTOCOL.md`, and `docs/SECURITY_TEST_MATRIX.yaml`.

Consult the applicable governance source material when available:
- GENCODE-GOV: https://github.com/mohamedelghazali/GENCODE-GOV
- AIGENT-SEC (formerly TSAR): https://github.com/mohamedelghazali/AIGENT-SECURITY

Do not claim either framework was installed, invoked, or passed unless the relevant tool and evidence are actually available and executed. Missing mandatory verification is `BLOCKED` or `NOT VERIFIED`, never `PASS`.

## Non-negotiable safety invariants
- Preserve the loopback/RFC1918 IPv4-only target allow-list.
- Preserve the fixed `GET /` request profile and disabled redirects/proxy environment behavior.
- Preserve server-enforced ceilings: 10 requests/second, 30 seconds, 5 concurrent requests, and 300 requests per run.
- Preserve the response-size and request-timeout limits, single-active-run control, API authentication, and loopback-only default bind.
- Never add public-target mode, arbitrary request methods/paths, distributed traffic agents, botnet/C2 functions, proxy/VPN rotation, source spoofing, reflection, amplification, or evasion features.
- Do not widen a safety limit to make a test, benchmark, or demonstration pass.
- Any proposed change to a safety invariant requires an explicit threat-model update, negative-security tests, and human review. If safe bounded behavior cannot be demonstrated, stop and report `BLOCKED`.

## Engineering workflow
Use `Inspect → Plan → Threat Model → Implement → Test → Independently Verify → Report`.

Run at minimum:
```bash
python -m pytest -q --cov=app --cov-report=term-missing
```
For container changes, validate the Docker build and Compose configuration on an environment with Docker. For dependency changes, run a dependency vulnerability audit. Record exact commands, tool versions, timestamps, results, and unresolved gates. Never infer production readiness from a green test suite alone.
