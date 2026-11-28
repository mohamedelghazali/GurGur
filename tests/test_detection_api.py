from __future__ import annotations


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def test_detection_api_requires_authentication(client):
    assert client.get("/api/v1/detection/rules").status_code == 401
    assert client.post("/api/v1/detection/evaluate").status_code == 401


def test_detection_rules_endpoint_exposes_explanations(client, api_key):
    response = client.get("/api/v1/detection/rules", headers=auth(api_key))
    assert response.status_code == 200
    rules = response.json()
    assert {item["rule_id"] for item in rules} == {
        "SUR-001", "NET-001", "NET-002", "DNS-001", "DNS-002"
    }
    assert all(item["rationale"] for item in rules)


def test_detection_evaluation_persists_deterministic_alerts_and_audit(client, api_key):
    payload = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"]
    for index in range(20):
        payload.append(
            f"1795860000.0\tC{index}\t10.0.0.10\t50000\t10.0.0.20\t{1000 + index}\ttcp"
        )
    upload = client.post(
        "/api/v1/telemetry/zeek?log_type=conn",
        headers={**auth(api_key), "Content-Type": "text/plain"},
        content=("\n".join(payload) + "\n").encode(),
    )
    assert upload.status_code == 201
    first = client.post("/api/v1/detection/evaluate", headers=auth(api_key))
    assert first.status_code == 201
    result = first.json()
    assert result["input_event_count"] == 20
    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule_id"] == "NET-001"
    second = client.post("/api/v1/detection/evaluate", headers=auth(api_key))
    assert second.status_code == 201
    assert second.json()["alerts"][0]["fingerprint"] == result["alerts"][0]["fingerprint"]
    alerts = client.get("/api/v1/detection/alerts?severity=medium", headers=auth(api_key))
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    assert alerts.json()[0]["evidence"]["distinct_destination_ports"] == 20
    assert client.get("/api/v1/audit/verify", headers=auth(api_key)).json()["valid"] is True


def test_detection_evaluation_limit_is_enforced(client, api_key):
    response = client.post(
        "/api/v1/detection/evaluate?limit=5001", headers=auth(api_key)
    )
    assert response.status_code == 422


def test_detection_alert_filter_rejects_unknown_severity(client, api_key):
    response = client.get(
        "/api/v1/detection/alerts?severity=urgent", headers=auth(api_key)
    )
    assert response.status_code == 422
