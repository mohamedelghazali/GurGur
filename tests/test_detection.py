from __future__ import annotations

import pytest

from app.detection import MAX_EVALUATION_EVENTS, RULESET_VERSION, evaluate_events, rules_catalog


def event(source, kind, timestamp, fields):
    return {
        "schema_version": 1,
        "source": source,
        "event_type": kind,
        "timestamp": timestamp,
        "fields": fields,
    }


def test_rule_catalog_is_versioned_and_explainable():
    rules = rules_catalog()
    assert RULESET_VERSION == "1.0.0"
    assert {item["rule_id"] for item in rules} == {
        "SUR-001", "NET-001", "NET-002", "DNS-001", "DNS-002"
    }
    assert all(item["rationale"] and item["threshold"] and item["sources"] for item in rules)


def test_port_diversity_threshold_is_exact_and_deterministic():
    events = [
        event("zeek", "connection", "2026-11-28T10:00:00+00:00", {
            "src_ip": "10.0.0.10", "dest_ip": "10.0.0.20", "dest_port": port
        })
        for port in range(1000, 1020)
    ]
    first = evaluate_events(events)
    second = evaluate_events(list(reversed(events)))
    finding = next(item for item in first if item["rule_id"] == "NET-001")
    assert finding["event_count"] == 20
    assert finding["evidence"]["distinct_destination_ports"] == 20
    assert finding["fingerprint"] == next(item for item in second if item["rule_id"] == "NET-001")["fingerprint"]
    assert not any(item["rule_id"] == "NET-002" for item in first)


def test_port_diversity_below_threshold_does_not_alert():
    events = [
        event("zeek", "connection", "2026-11-28T10:00:00+00:00", {
            "src_ip": "10.0.0.10", "dest_ip": "10.0.0.20", "dest_port": port
        })
        for port in range(1000, 1019)
    ]
    assert not evaluate_events(events)


def test_destination_fanout_threshold():
    events = [
        event("pcap", "packet_metadata", "2026-11-28T10:00:00+00:00", {
            "src_ip": "10.0.0.10", "dest_ip": f"10.0.1.{index}", "dest_port": 443
        })
        for index in range(1, 31)
    ]
    finding = next(item for item in evaluate_events(events) if item["rule_id"] == "NET-002")
    assert finding["evidence"]["distinct_destination_ips"] == 30
    assert finding["event_count"] == 30


def test_dns_nxdomain_and_name_diversity_rules():
    events = [
        event("suricata", "dns", "2026-11-28T10:00:00+00:00", {
            "src_ip": "10.0.0.10", "rrname": f"host-{index}.example.test", "rcode": "NXDOMAIN"
        })
        for index in range(50)
    ]
    findings = evaluate_events(events)
    assert {item["rule_id"] for item in findings} == {"DNS-001", "DNS-002"}
    nxdomain = next(item for item in findings if item["rule_id"] == "DNS-001")
    diversity = next(item for item in findings if item["rule_id"] == "DNS-002")
    assert nxdomain["evidence"]["nxdomain_count"] == 50
    assert diversity["evidence"]["distinct_query_names"] == 50


def test_suricata_alert_severity_and_evidence_are_preserved():
    item = event("suricata", "alert", "2026-11-28T10:00:00+00:00", {
        "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 443,
        "severity": 2, "signature": "Known test signature", "signature_id": 9001,
    })
    finding = evaluate_events([item])[0]
    assert finding["rule_id"] == "SUR-001"
    assert finding["severity"] == "high"
    assert finding["evidence"]["signature_id"] == 9001


def test_invalid_timestamps_are_ignored_and_event_limit_is_enforced():
    invalid = event("zeek", "connection", "not-a-time", {"src_ip": "10.0.0.1"})
    assert evaluate_events([invalid]) == []
    with pytest.raises(ValueError):
        evaluate_events([{}] * (MAX_EVALUATION_EVENTS + 1))
