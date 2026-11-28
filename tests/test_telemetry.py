from __future__ import annotations

import io
import json
import socket

import dpkt
import pytest

from app.telemetry import TelemetryInputError, parse_pcap, parse_suricata, parse_zeek, source_digest


def test_parse_zeek_conn_tsv_normalizes_connection():
    data = (
        b"#separator \\x09\n"
        b"#set_separator ,\n"
        b"#empty_field (empty)\n"
        b"#unset_field -\n"
        b"#path conn\n"
        b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        b"#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tinterval\tcount\tcount\tstring\n"
        b"1730000000.125\tCabc\t192.168.1.10\t51000\t192.168.1.20\t443\ttcp\tssl\t0.5\t100\t200\tSF\n"
    )
    events = parse_zeek(data, "conn")
    assert len(events) == 1
    assert events[0]["source"] == "zeek"
    assert events[0]["event_type"] == "connection"
    assert events[0]["fields"]["src_ip"] == "192.168.1.10"
    assert events[0]["fields"]["dest_port"] == 443
    assert events[0]["timestamp"].startswith("2024-")


def test_parse_zeek_dns_and_http_metadata_only():
    dns = b"#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\tqtype_name\trcode_name\tanswers\n1.0\tC1\t10.0.0.1\t10.0.0.2\texample.org\tA\tNOERROR\t203.0.113.1\n"
    http = b"#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tmethod\thost\turi\tstatus_code\tstatus_msg\n1.0\tC2\t10.0.0.1\t10.0.0.2\tGET\texample.org\t/private-path\t200\tOK\n"
    assert parse_zeek(dns, "dns")[0]["fields"]["query"] == "example.org"
    http_event = parse_zeek(http, "http")[0]
    assert http_event["fields"]["host"] == "example.org"
    assert "uri" not in http_event["fields"]


def test_zeek_rejects_invalid_header_and_bad_timestamp():
    with pytest.raises(TelemetryInputError):
        parse_zeek(b"not a zeek log\n", "conn")
    bad = b"#fields\tts\tuid\nnot-a-time\tC1\n"
    with pytest.raises(TelemetryInputError):
        parse_zeek(bad, "conn")


def test_suricata_eve_extracts_alert_without_payload():
    row = {
        "timestamp": "2026-11-28T10:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "src_port": 50000,
        "dest_ip": "10.0.0.2",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"signature": "Example alert", "category": "Test", "severity": 2, "signature_id": 123},
        "payload": "must-not-be-retained",
    }
    events = parse_suricata((json.dumps(row) + "\n").encode())
    assert len(events) == 1
    assert events[0]["event_type"] == "alert"
    assert events[0]["fields"]["signature"] == "Example alert"
    assert "payload" not in events[0]["fields"]


def test_suricata_rejects_malformed_json_and_timestamp():
    with pytest.raises(TelemetryInputError):
        parse_suricata(b"{broken}\n")
    with pytest.raises(TelemetryInputError):
        parse_suricata(b'{"timestamp":"bad","event_type":"flow"}\n')


def _one_packet_pcap() -> bytes:
    packet = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.10"),
            dst=socket.inet_aton("192.168.1.20"),
            p=dpkt.ip.IP_PROTO_TCP,
            data=dpkt.tcp.TCP(sport=51515, dport=443, flags=dpkt.tcp.TH_SYN),
        ),
    )
    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    writer.writepkt(packet, ts=1730000000.0)
    return buffer.getvalue()


def test_pcap_offline_extracts_headers_only():
    capture = _one_packet_pcap()
    events = parse_pcap(capture)
    assert len(events) == 1
    assert events[0]["source"] == "pcap"
    assert events[0]["fields"]["src_ip"] == "192.168.1.10"
    assert events[0]["fields"]["dest_port"] == 443
    assert events[0]["fields"]["tcp_flags"] == dpkt.tcp.TH_SYN
    assert "payload" not in events[0]["fields"]


def test_pcap_rejects_truncated_and_unsupported_linktype():
    with pytest.raises(TelemetryInputError):
        parse_pcap(b"bad")
    capture = bytearray(_one_packet_pcap())
    capture[20:24] = (101).to_bytes(4, "little")
    with pytest.raises(TelemetryInputError):
        parse_pcap(bytes(capture))


def test_source_digest_is_stable():
    assert source_digest(b"same") == source_digest(b"same")
    assert source_digest(b"same") != source_digest(b"other")
