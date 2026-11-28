# ZYRAX — Threat Model (0.4.0.dev0)

**Scope:** Local-first, single-operator network measurement, telemetry ingestion, and explainable detection research service.  
**Status:** Development candidate; this document is not a production security certification.

## 1. Purpose and security boundary

ZYRAX measures the behavior of an authorized loopback or RFC1918 IPv4 lab service using a deliberately small, fixed-profile HTTP request stream. It stores run metadata and a hash-linked audit history, with optional detached HMAC checkpoints and SQLite recovery tools.

ZYRAX is not a denial-of-service generator. It does not provide public targeting, distributed traffic generation, botnet/C2, proxy/VPN rotation, source spoofing, reflection, amplification, packet crafting, evasion, arbitrary HTTP methods or paths, or unrestricted stress testing.

The supported local launcher binds to loopback. The Docker profile publishes the host port on loopback only. Direct Uvicorn bind overrides are unsupported.

## 2. Assets

- API key and optional audit HMAC key, including their key IDs and rotation records.
- Registered target IPv4 addresses, ports, labels, and operator authorization records.
- Run parameters, progress counters, final results, and persistent active-run control row.
- OS lock file and filesystem directory containing it and the SQLite database.
- SQLite database, WAL/SHM files, backup artifacts, and pre-restore backups.
- Hash-linked audit records and detached checkpoint files.
- Availability and integrity of the measured private lab service.
- Host resources used by the control plane and bounded measurement engine.

## 3. Actors and trust boundaries

Actors include the authorized local operator, other ZYRAX workers sharing the same local database, unauthorized local processes or browser pages, mistaken operators, process crashes/restarts, and attackers who gain access to the database directory, backup artifacts, or application environment.

| Boundary | Threat | Control |
|---|---|---|
| Browser → API | Bearer header, JSON, IDs | Constant-time key comparison, strict Pydantic schemas, no CORS, no cookie auth, no-store responses |
| Target registration | IP, port, scheme, label | Literal IPv4 only; loopback/RFC1918 scope; port 1024–65535; fixed root path |
| Run claim | Concurrent calls from different workers | OS non-blocking lock plus singleton SQLite row; atomic transaction |
| Run stop | Stop call goes to non-owning worker | Persisted stop flag checked by run owner before next request |
| Worker exit | Incomplete run and stale control row | Kernel releases lock; next lock owner may recover stale rows |
| Engine → target | Network response, redirects, slow/large body | Fixed GET /; redirects off; proxy env ignored; TLS verification; timeout and size bounds |
| API → SQLite | User values and concurrent writes | Parameterized SQL, busy timeout, WAL, foreign keys, transactions |
| Backup / restore | Corrupt source or restore while active | SHA-256 sidecar, SQLite integrity/FK checks, explicit offline confirmation, pre-restore backup |
| Audit checkpoint | Database rewrite or HMAC key theft | Detached HMAC-SHA256 checkpoint; separate key; key ID and verification |

## 4. Run coordination design

A run owner must hold the OS lock file associated with the configured database path. After acquiring the kernel lock, the worker:

1. Opens an immediate SQLite transaction to recover stale queued/running rows and orphaned control state.
2. Inserts the run, singleton run_control row, and run.created audit event in one transaction.
3. Marks the run running and persists progress snapshots.
4. Checks its local stop event and the database stop flag before scheduling each next request.
5. Finishes the run, appends the completion audit event, and removes its control row in one transaction.
6. Releases the OS lock.

If a process terminates unexpectedly, the operating system releases its lock. A later worker can acquire the lock and mark stale queued/running rows failed before claiming a new run. A worker must not mark active rows failed unless it first acquires the same OS lock.

### Coordination assumptions and residual risk

- All workers must use the same canonical database path and corresponding lock file.
- The lock directory and database directory must be protected from untrusted local users. An actor able to unlink/replace the lock file or modify the database directory may bypass the intended mutual-exclusion boundary.
- The filesystem must correctly implement the host OS advisory locking behavior. Multi-host, network-filesystem, and distributed deployments are unsupported and untested.
- Stop requests are persisted and checked between scheduling steps; requests already in flight complete or drain under existing timeouts.
- SQLite locking is the database serialization layer; the OS lock is the run-lifetime mutual-exclusion layer.
- The supported launcher defaults to one worker. Additional supported processes must share the same local DB path and lock-file semantics.

## 5. Backup and restore model

Online backup uses SQLite's backup API to produce a consistent snapshot while the application is running. The backup is written atomically, protected with owner-only file permissions where supported, accompanied by a SHA-256 sidecar, and checked with SQLite integrity_check and foreign_key_check.

Verification checks the sidecar digest and database integrity. Restore first verifies the source, creates a pre-restore backup if a destination exists, stages a validated copy, removes stale WAL/SHM sidecars, and atomically replaces the database.

Restore cannot reliably detect every application process that might still hold an open database connection. The operator must stop every ZYRAX process/container using the database and explicitly pass --confirm-offline. Running restore against an active database is unsupported and may cause data loss or divergent database files.

0.1 database files and backups are accepted; the 0.2 Store adds run_control and stop_requested schema elements on open.

## 6. Audit-chain and checkpoint model

Each audit event contains a sequence number, timestamp, action, optional subject, canonical details JSON, previous hash, and SHA-256 event hash. Appends run under an immediate transaction so concurrent writers cannot create competing chain heads.

The local hash chain detects record modification, insertion, or removal relative to its stored history. It is not tamper-proof: an administrator who can rewrite the complete database can recompute the chain.

Optional detached checkpoints use HMAC-SHA256 over a canonical payload containing the checkpoint version and algorithm, key ID, creation timestamp, event count, chain-head hash, and HMAC value. The key is supplied by LAB_AUDIT_SIGNING_KEY and must be stored outside the database and separately from LAB_API_KEY. Store checkpoint files separately from the database.

HMAC uses a shared secret. A verifier must possess the secret, and any party holding it can create a valid checkpoint. It is not asymmetric signing, cannot prove non-repudiation, and offers no protection if the signing secret is compromised. Key rotation requires retaining old key material and key IDs securely for historical verification. HSM integration, public-key signatures, and remote timestamping are not part of this release.

## 7. Abuse cases and mitigations

1. Public Internet target submitted: rejected by literal IPv4 loopback/RFC1918 validation.
2. Hostname or DNS rebinding attempt: DNS names and IPv6 are rejected; persisted target URLs are revalidated before each run.
3. Redirect/proxy manipulation: redirects are disabled and HTTPX ignores proxy environment variables.
4. Traffic budget abuse: server enforces 10 RPS, 30 seconds, concurrency 5, 300 requests per run, and existing timeout/response limits.
5. Concurrent run attempts: OS lock acquisition and SQLite singleton state reject a second worker.
6. Owner process crash: OS releases the run lock; next lock owner recovers stale rows.
7. Cross-worker stop request: a stop flag is persisted in SQLite and checked by the run owner before scheduling more requests.
8. Database tampering: hash-chain verification detects ordinary alterations; a detached HMAC checkpoint detects rewriting of its anchored chain prefix if the signing key remains secret.
9. Backup substitution or corruption: SHA-256 sidecar and SQLite integrity checks must pass before restore.
10. Restore while application is active: unsupported; CLI requires explicit operator offline confirmation. Protect the data directory and enforce maintenance procedures.
11. API key exposure: key is not stored in SQLite; it is loaded from environment and compared in constant time. Rotation requires updating all worker environments and restarting all processes.
12. HMAC key exposure: a stolen key permits checkpoint forgery. Keep it out of source, database, logs, backups, and screenshots.

## 8. Explicit non-goals

- Internet-scale load or denial-of-service testing.
- Botnets, distributed traffic generators, proxy pools, VPN rotation, source spoofing, packet crafting, reflection, amplification, or evasion.
- Testing systems without explicit authorization.
- Multi-user accounts, RBAC, SSO, tenant isolation, multi-host coordination, or a remote-access profile.
- Public-key signing, non-repudiation, automatic remote audit anchoring, or HSM-backed keys.
- Claims of person/attacker attribution from IP addresses alone.

## 9. Residual risks and release blockers

- One shared API key remains suitable only for a single-operator lab.
- Local advisory locks do not provide a distributed lock across machines or unsupported filesystems.
- Restore depends on the operator actually stopping every process using the database.
- HMAC checkpoints are only as trustworthy as the shared signing secret and checkpoint storage.
- Application logging is not yet a complete security-event monitoring pipeline.
- The engine measures HTTP request behavior; it is not packet-level capture or a full IDS.
- Live sensor control, detection rules, baseline learning, incident response, and forensic acquisition remain planned. File-based Zeek/Suricata/PCAP metadata ingestion is present; it does not start sensors or transmit captured traffic.
- No production remote-access deployment is supported.
- No comprehensive independent security review, Docker build validation, or production recovery drill is claimed by the current test run.

## 10. Deployment assumptions

Run under a dedicated unprivileged OS account. Keep the database, WAL/SHM files, run-lock file, backups, and checkpoint files in directories inaccessible to untrusted users. Keep secrets in protected environment/secret configuration and never commit them. Bind only to loopback. Use an isolated private lab network, retain operator authorization for every target, and stop experiments if the target shows degradation.


## 11. Telemetry ingestion (v0.3)

- Imports require the existing Bearer API key and accept request bodies only; clients cannot submit arbitrary filesystem paths.
- Text uploads are capped at 16 MiB and 10,000 normalized events. PCAP/PCAPNG uploads are capped at 64 MiB and 100,000 packets.
- PCAP parsing supports Ethernet link type and extracts IPv4/IPv6 packet metadata. It does not retain payload bytes, open sockets, replay packets, or transmit traffic.
- Zeek and Suricata adapters retain only selected metadata fields; raw input files and payload-bearing fields are not persisted.
- Source digest and batch identity provide idempotency for identical source bytes. A different file with the same semantic events is a distinct import.
- Telemetry event records can still contain operationally sensitive IP addresses, DNS names, hostnames, SNI, alert signatures, and flow metadata. Restrict API/database access and define retention before operational deployment.
- There is no automatic deletion/retention policy or sensor heartbeat in this development increment.


## 12. Explainable detection engine (v0.4)

- Detection evaluates only normalized telemetry already stored in the local SQLite database. It does not start capture, connect to sensors, transmit packets, or generate network traffic.
- Each evaluation is explicitly operator-triggered and bounded to at most 5,000 newest stored events. It uses fixed UTC time buckets and a versioned read-only ruleset.
- Rules produce a stable rule ID/version, severity, description, rationale, threshold, source, subject, and bounded evidence. Findings are triage indicators, not proof of malicious intent.
- Initial rules detect imported Suricata alerts, destination-port diversity, destination-address fan-out, DNS NXDOMAIN bursts, and DNS query-name diversity. Benign resolvers, proxies, inventory scanners, monitoring systems, and high-volume applications can trigger these rules.
- Alert fingerprints are deterministic for a rule, subject, and time bucket; repeated evaluations update the existing alert rather than creating an unbounded duplicate stream.
- Rule thresholds are conservative initial defaults and are not universal detection signatures. Operators must review rule output against local traffic patterns before operational use.
- No statistical baseline, machine-learning inference, automated containment, firewall modification, blocking, or disruptive response is included. Future models require representative reviewed data, documented labels/limitations, measured false-positive behavior, and human approval.
- Detection evaluation and alert persistence are transactional and recorded in the existing hash-linked audit history. Protect the database and backups because alert evidence can include sensitive internal addresses and DNS metadata.
