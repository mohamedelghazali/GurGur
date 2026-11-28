# ZYRAX v0.3.0.dev0 — Development Verification Report

**Scope:** Zeek / Suricata file ingestion and offline PCAP metadata parsing.  
**Branch:** feat/v0.3-network-telemetry  
**Status:** Implementation candidate; CI and runtime verification pending.

## Implemented

- Versioned normalized event envelope (schema version 1).
- Zeek TSV adapters for conn, dns, and http.
- Suricata EVE JSON Lines adapters for alert, flow, DNS, HTTP, and TLS metadata.
- Offline classic PCAP / PCAPNG parser for Ethernet link type.
- IPv4/IPv6 metadata extraction; TCP/UDP ports and TCP flags.
- SQLite telemetry batches and event persistence.
- SHA-256 import digest and idempotent repeat-upload handling.
- Audit-chain event for each newly ingested batch.
- Authenticated raw-body API endpoints and bounded upload/query limits.
- Metadata allow-lists; packet payload and HTTP URI/body fields are not persisted.

## Safety properties

- No network socket or packet transmission exists in the PCAP parser.
- No sensor process is started or controlled.
- Existing bounded active measurement limits are unchanged.
- API accepts upload bytes, not arbitrary server-side filesystem paths.
- Text cap: 16 MiB / 10,000 events. PCAP cap: 64 MiB / 100,000 packets.

## Tests added

- Zeek connection, DNS, and HTTP parsing fixtures.
- Invalid Zeek headers and timestamps.
- Suricata alert normalization and payload exclusion.
- Malformed Suricata JSON and timestamps.
- PCAP TCP header parsing and unsupported link type rejection.
- API authentication, content-type validation, persistence, idempotency, and query limits.

## Verification status

- GitHub Actions on package metadata commit 1b7b58fce6027cae6ba627dfbd4565e88c00b4e4 (the same application code merged by this PR): **57 passed on each of Python 3.11, 3.12, and 3.13; 78% application line coverage**.
- Dependency vulnerability audit on that same commit: **PASS**.
- The final documentation-only update does not change application code. Post-merge CI on the squash commit remains a separate confirmation.
- Docker / Compose validation: **NOT VERIFIED**.
- Live sensor interoperability: **NOT IN SCOPE**.
- Production readiness: **NOT CLAIMED**.

A passing CI run is required before treating this branch as merge-ready. Correct and rerun failures; do not bypass failing checks.
