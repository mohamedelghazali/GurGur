# ZYRAX Telemetry Ingestion — v0.3.0.dev0

## Scope

This increment ingests operator-supplied files only. It does not start Zeek or Suricata, run capture interfaces, manage remote sensors, or transmit captured packets.

## Supported inputs

| Adapter | Input | Records |
|---|---|---|
| Zeek | TSV with standard #fields header | conn, dns, http |
| Suricata | EVE JSON Lines | alert, flow, dns, http, tls |
| PCAP | Classic PCAP / PCAPNG, Ethernet link type | IPv4/IPv6 TCP/UDP and other IP metadata |

## Normalized event envelope

Each event uses schema version 1 and includes source, event_type, timestamp, and an allow-listed fields object. Payload-bearing fields are excluded.

## API

All endpoints require the existing Bearer API key.

### Zeek

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/telemetry/zeek?log_type=conn" -H "Authorization: Bearer $env:LAB_API_KEY" -H "Content-Type: text/plain" --data-binary "@conn.log"
```

Use log_type conn, dns, or http.

### Suricata

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/telemetry/suricata -H "Authorization: Bearer $env:LAB_API_KEY" -H "Content-Type: application/x-ndjson" --data-binary "@eve.json"
```

### Offline PCAP / PCAPNG

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/telemetry/pcap -H "Authorization: Bearer $env:LAB_API_KEY" -H "Content-Type: application/vnd.tcpdump.pcap" --data-binary "@capture.pcap"
```

PCAP parsing is offline and metadata-only. It opens no network sockets and never replays packets. Ethernet link type is required. Timestamps, IP addresses, protocol, frame length, TCP/UDP ports, and TCP flags may be retained. Packet payload bytes are never stored.

### Query

- GET /api/v1/telemetry/batches?limit=50
- GET /api/v1/telemetry/events?limit=100&source=zeek

The event source filter accepts zeek, suricata, or pcap. Query limits are 1–100 batches and 1–500 events.

## Resource and integrity limits

- Zeek and Suricata text: 16 MiB and 10,000 normalized events maximum.
- PCAP/PCAPNG: 64 MiB and 100,000 packets maximum.
- Identical bytes for the same adapter are idempotent using SHA-256 source digest.
- Batch and event rows are committed in one SQLite transaction.
- New batches append telemetry.batch.ingested to the existing audit chain.
- Events are retained in SQLite; retention expiry and deletion workflows are not yet implemented.

## Privacy

IP addresses, DNS names, HTTP hostnames, TLS SNI, alert signatures, and flow metadata can be sensitive. Import only authorized data. Restrict database and backup access. Malformed records reject the entire import. Unsupported Suricata event types are skipped. Malformed individual PCAP frames are skipped; malformed capture containers and unsupported link types are rejected.

## Deferred

Live capture, sensor registration/heartbeat, remote sensor management, reverse-proxy adapters, detection rules, behavioral baselines, incident management, retention/deletion controls, and dashboard visualizations.
