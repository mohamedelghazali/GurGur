# Security Policy

## Supported versions

Only the latest released version is currently supported for security fixes.

## Reporting a vulnerability

Please do not report exploitable vulnerabilities in public issues. Use GitHub's private vulnerability reporting for this repository when it is enabled, or contact the repository owner through the verified contact details on their GitHub profile.

Include the affected version or commit, impact, reproduction steps, and any relevant logs with secrets and personal data removed. Do not access or disrupt systems you do not own or have explicit permission to test.

## Security scope

ZYRAX is intentionally restricted to loopback and RFC1918 IPv4 targets, a fixed HTTP request profile, and hard-coded low-rate/time/concurrency/request ceilings. Reports concerning bypasses of those controls are in scope. Do not use the software to target public systems.


## v0.2 core-hardening controls

The 0.2 development line adds a non-blocking OS-level run lock and a transactionally maintained SQLite run-control row. This supports one active run across ZYRAX workers that share the same database and local filesystem lock semantics. Multi-host deployments and filesystems without reliable advisory locking are not supported.

SQLite backups use the online backup API, a SHA-256 sidecar, and integrity/foreign-key checks. Restoring is an offline maintenance operation; stop every process that uses the database first. The restore command requires `--confirm-offline` and creates a pre-restore backup when the current database exists.

Detached audit checkpoints use HMAC-SHA256 with a separate `LAB_AUDIT_SIGNING_KEY`. The shared secret must be kept outside the database and protected by the operator. HMAC verification is not a public-key signature and does not provide non-repudiation.
