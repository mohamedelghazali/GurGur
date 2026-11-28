from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

RULESET_VERSION = "1.0.0"
MAX_EVALUATION_EVENTS = 5_000

RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "SUR-001",
        "version": "1.0.0",
        "title": "Suricata alert observed",
        "severity": "critical",
        "description": "A Suricata EVE alert event was present in the imported telemetry.",
        "rationale": "The source sensor emitted an IDS alert. This rule preserves the sensor severity and signature as evidence; it does not independently validate the signature.",
        "threshold": "One Suricata alert event",
        "sources": ["suricata"],
    },
    {
        "rule_id": "NET-001",
        "version": "1.0.0",
        "title": "High destination-port diversity",
        "severity": "medium",
        "description": "One source address contacted at least 20 distinct destination ports within a fixed 60-second UTC bucket.",
        "rationale": "A high number of destination ports from one source in a short interval can be consistent with service discovery or port scanning. Benign inventory and monitoring tools can produce similar patterns.",
        "threshold": "20 distinct destination ports / source / 60 seconds",
        "sources": ["zeek", "pcap"],
    },
    {
        "rule_id": "NET-002",
        "version": "1.0.0",
        "title": "High destination-address fan-out",
        "severity": "medium",
        "description": "One source address contacted at least 30 distinct destination addresses within a fixed 60-second UTC bucket.",
        "rationale": "Broad destination fan-out may indicate automated discovery or propagation behavior, but can also arise from proxies, resolvers, or service infrastructure.",
        "threshold": "30 distinct destination IPs / source / 60 seconds",
        "sources": ["zeek", "pcap"],
    },
    {
        "rule_id": "DNS-001",
        "version": "1.0.0",
        "title": "DNS NXDOMAIN burst",
        "severity": "medium",
        "description": "One source generated at least 10 NXDOMAIN responses within a fixed five-minute UTC bucket.",
        "rationale": "Repeated negative DNS responses may reflect misconfiguration, DGA-like behavior, stale applications, or user input errors. This signal alone is not proof of malicious activity.",
        "threshold": "10 NXDOMAIN responses / source / 5 minutes",
        "sources": ["zeek", "suricata"],
    },
    {
        "rule_id": "DNS-002",
        "version": "1.0.0",
        "title": "High DNS query-name diversity",
        "severity": "low",
        "description": "One source queried at least 50 distinct DNS names within a fixed five-minute UTC bucket.",
        "rationale": "High query-name diversity can be a triage signal for automated discovery or tunneling investigations, but ordinary clients and recursive resolvers may naturally have high diversity.",
        "threshold": "50 distinct query names / source / 5 minutes",
        "sources": ["zeek", "suricata"],
    },
)

_SURICATA_SEVERITY = {1: "critical", 2: "high", 3: "medium"}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _event_fields(event: dict[str, Any]) -> dict[str, Any]:
    fields = event.get("fields")
    return fields if isinstance(fields, dict) else {}


def _fingerprint(rule_id: str, subject: str, bucket: int, extra: str = "") -> str:
    raw = f"{rule_id}|{subject}|{bucket}|{extra}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _alert(
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    rationale: str,
    source: str,
    subject: str,
    bucket_start: int,
    event_count: int,
    evidence: dict[str, Any],
    extra: str = "",
) -> dict[str, Any]:
    start = datetime.fromtimestamp(bucket_start, timezone.utc).isoformat(timespec="seconds")
    fingerprint = _fingerprint(rule_id, subject, bucket_start, extra)
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "rule_version": "1.0.0",
        "ruleset_version": RULESET_VERSION,
        "title": title,
        "severity": severity,
        "description": description,
        "rationale": rationale,
        "source": source,
        "subject": subject,
        "first_seen": start,
        "last_seen": start,
        "event_count": event_count,
        "evidence": evidence,
    }


def evaluate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate a bounded event set with deterministic, explainable rules only."""
    if len(events) > MAX_EVALUATION_EVENTS:
        raise ValueError(f"Evaluation is limited to {MAX_EVALUATION_EVENTS} events.")

    findings: dict[str, dict[str, Any]] = {}
    port_groups: dict[tuple[str, int], dict[str, Any]] = defaultdict(lambda: {"ports": set(), "count": 0, "sources": set()})
    fanout_groups: dict[tuple[str, int], dict[str, Any]] = defaultdict(lambda: {"destinations": set(), "count": 0, "sources": set()})
    nxdomain_groups: dict[tuple[str, int], dict[str, Any]] = defaultdict(lambda: {"count": 0, "names": set(), "sources": set()})
    dns_groups: dict[tuple[str, int], dict[str, Any]] = defaultdict(lambda: {"names": set(), "count": 0, "sources": set()})

    for event in events:
        if not isinstance(event, dict):
            continue
        fields = _event_fields(event)
        source = str(event.get("source", "unknown"))
        event_type = str(event.get("event_type", ""))
        timestamp = _parse_time(event.get("timestamp"))
        if timestamp is None:
            continue
        epoch = int(timestamp.timestamp())

        if source == "suricata" and event_type == "alert":
            raw_severity = fields.get("severity")
            try:
                severity_number = int(raw_severity)
            except (TypeError, ValueError):
                severity_number = 4
            severity = _SURICATA_SEVERITY.get(severity_number, "low")
            subject = str(fields.get("src_ip") or "unknown-source")
            signature = str(fields.get("signature") or "Unspecified Suricata alert")[:256]
            evidence = {
                "sensor_severity": severity_number,
                "signature": signature,
                "signature_id": fields.get("signature_id"),
                "category": fields.get("category"),
                "action": fields.get("action"),
                "src_ip": fields.get("src_ip"),
                "dest_ip": fields.get("dest_ip"),
                "dest_port": fields.get("dest_port"),
                "proto": fields.get("proto"),
            }
            item = _alert(
                "SUR-001", "Suricata alert observed", severity,
                "A Suricata EVE alert event was present in the imported telemetry.",
                "The source sensor emitted an IDS alert. This rule preserves the sensor severity and signature as evidence; it does not independently validate the signature.",
                source, subject, (epoch // 60) * 60, 1, evidence,
                extra=f"{signature}|{fields.get('signature_id')}",
            )
            findings[item["fingerprint"]] = item

        if event_type in {"connection", "packet_metadata"}:
            src = fields.get("src_ip")
            dst = fields.get("dest_ip")
            port = fields.get("dest_port")
            if isinstance(src, str) and isinstance(dst, str):
                bucket = (epoch // 60) * 60
                if isinstance(port, int) and 0 <= port <= 65535:
                    group = port_groups[(src, bucket)]
                    group["ports"].add(port)
                    group["count"] += 1
                    group["sources"].add(source)
                group = fanout_groups[(src, bucket)]
                group["destinations"].add(dst)
                group["count"] += 1
                group["sources"].add(source)

        if event_type == "dns":
            src = fields.get("src_ip")
            name = fields.get("query") or fields.get("rrname")
            if isinstance(src, str):
                bucket = (epoch // 300) * 300
                if isinstance(name, str) and name:
                    dns_groups[(src, bucket)]["names"].add(name.lower()[:253])
                    dns_groups[(src, bucket)]["count"] += 1
                    dns_groups[(src, bucket)]["sources"].add(source)
                rcode = str(fields.get("rcode_name") or fields.get("rcode") or "").upper()
                if rcode in {"NXDOMAIN", "3"}:
                    group = nxdomain_groups[(src, bucket)]
                    group["count"] += 1
                    if isinstance(name, str) and name:
                        group["names"].add(name.lower()[:253])
                    group["sources"].add(source)

    for (src, bucket), group in port_groups.items():
        ports = sorted(group["ports"])
        if len(ports) >= 20:
            item = _alert(
                "NET-001", "High destination-port diversity", "medium",
                "One source address contacted at least 20 distinct destination ports within a fixed 60-second UTC bucket.",
                "A high number of destination ports from one source in a short interval can be consistent with service discovery or port scanning. Benign inventory and monitoring tools can produce similar patterns.",
                ",".join(sorted(group["sources"])), src, bucket, group["count"],
                {"src_ip": src, "distinct_destination_ports": len(ports), "destination_ports_sample": ports[:50], "observed_connections": group["count"], "window_seconds": 60},
            )
            findings[item["fingerprint"]] = item

    for (src, bucket), group in fanout_groups.items():
        destinations = sorted(group["destinations"])
        if len(destinations) >= 30:
            item = _alert(
                "NET-002", "High destination-address fan-out", "medium",
                "One source address contacted at least 30 distinct destination addresses within a fixed 60-second UTC bucket.",
                "Broad destination fan-out may indicate automated discovery or propagation behavior, but can also arise from proxies, resolvers, or service infrastructure.",
                ",".join(sorted(group["sources"])), src, bucket, group["count"],
                {"src_ip": src, "distinct_destination_ips": len(destinations), "destination_ips_sample": destinations[:50], "observed_connections": group["count"], "window_seconds": 60},
            )
            findings[item["fingerprint"]] = item

    for (src, bucket), group in nxdomain_groups.items():
        if group["count"] >= 10:
            item = _alert(
                "DNS-001", "DNS NXDOMAIN burst", "medium",
                "One source generated at least 10 NXDOMAIN responses within a fixed five-minute UTC bucket.",
                "Repeated negative DNS responses may reflect misconfiguration, DGA-like behavior, stale applications, or user input errors. This signal alone is not proof of malicious activity.",
                ",".join(sorted(group["sources"])), src, bucket, group["count"],
                {"src_ip": src, "nxdomain_count": group["count"], "distinct_query_names": len(group["names"]), "query_names_sample": sorted(group["names"])[:20], "window_seconds": 300},
            )
            findings[item["fingerprint"]] = item

    for (src, bucket), group in dns_groups.items():
        names = sorted(group["names"])
        if len(names) >= 50:
            item = _alert(
                "DNS-002", "High DNS query-name diversity", "low",
                "One source queried at least 50 distinct DNS names within a fixed five-minute UTC bucket.",
                "High query-name diversity can be a triage signal for automated discovery or tunneling investigations, but ordinary clients and recursive resolvers may naturally have high diversity.",
                ",".join(sorted(group["sources"])), src, bucket, group["count"],
                {"src_ip": src, "distinct_query_names": len(names), "query_names_sample": names[:20], "window_seconds": 300},
            )
            findings[item["fingerprint"]] = item

    return sorted(findings.values(), key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item["severity"], 5),
        item["rule_id"], item["subject"], item["first_seen"], item["fingerprint"],
    ))


def rules_catalog() -> list[dict[str, Any]]:
    """Return a JSON-safe copy of the shipped, read-only rule catalogue."""
    return json.loads(json.dumps(RULES))
