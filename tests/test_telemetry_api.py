from __future__ import annotations

import json

from app.telemetry import parse_suricata, parse_zeek


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def test_zeek_upload_persists_batch_and_is_idempotent(client, api_key):
    payload = (
        b"#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        b"1730000000.0\tC1\t10.0.0.1\t50000\t10.0.0.2\t443\ttcp\n"
    )
    url = "/api/v1/telemetry/zeek?log_type=conn"
    first = client.post(url, headers={**auth(api_key), "Content-Type": "text/plain"}, content=payload)
    assert first.status_code == 201
    assert first.json()["event_count"] == 1
    assert first.json()["duplicate"] is False
    second = client.post(url, headers={**auth(api_key), "Content-Type": "text/plain"}, content=payload)
    assert second.status_code == 201
    assert second.json()["duplicate"] is True
    events = client.get("/api/v1/telemetry/events?source=zeek", headers=auth(api_key))
    assert events.status_code == 200
    assert len(events.json()) == 1
    assert client.get("/api/v1/audit/verify", headers=auth(api_key)).json()["valid"] is True


def test_suricata_upload_rejects_malformed_json(client, api_key):
    response = client.post(
        "/api/v1/telemetry/suricata",
        headers={**auth(api_key), "Content-Type": "application/x-ndjson"},
        content=b"{broken}\n",
    )
    assert response.status_code == 422


def test_telemetry_upload_requires_authentication(client):
    response = client.post(
        "/api/v1/telemetry/suricata",
        headers={"Content-Type": "application/x-ndjson"},
        content=b'{"timestamp":"2026-11-28T10:00:00Z","event_type":"flow"}\n',
    )
    assert response.status_code == 401


def test_telemetry_upload_enforces_content_type(client, api_key):
    response = client.post(
        "/api/v1/telemetry/pcap",
        headers={**auth(api_key), "Content-Type": "text/plain"},
        content=b"not pcap",
    )
    assert response.status_code == 415


def test_telemetry_query_limits_are_enforced(client, api_key):
    assert client.get("/api/v1/telemetry/events?limit=501", headers=auth(api_key)).status_code == 422
    assert client.get("/api/v1/telemetry/batches?limit=101", headers=auth(api_key)).status_code == 422
