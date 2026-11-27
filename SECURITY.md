# Security Policy

## Supported versions
Only the latest released version is currently supported for security fixes.

## Reporting a vulnerability
Please do not report exploitable vulnerabilities in public issues. Use GitHub's private vulnerability reporting for this repository when it is enabled, or contact the repository owner through the verified contact details on their GitHub profile.

Include the affected version or commit, impact, reproduction steps, and any relevant logs with secrets and personal data removed. Do not access or disrupt systems you do not own or have explicit permission to test.

## Security scope
GurGur is intentionally restricted to loopback and RFC1918 IPv4 targets, a fixed HTTP request profile, and hard-coded low-rate/time/concurrency/request ceilings. Reports concerning bypasses of those controls are in scope. Do not use the software to target public systems.
