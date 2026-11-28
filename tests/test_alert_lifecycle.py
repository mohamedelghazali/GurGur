from __future__ import annotations


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def create_alert(client, api_key):
    lines = [
        "#separator \x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto",
    ]
    for index in range(20):
        lines.append(
            f"1795860000.0\tC{index}\t10.0.0.10\t50000\t10.0.0.20\t{1000 + index}\ttcp"
        )
    uploaded = client.post(
        "/api/v1/telemetry/zeek?log_type=conn",
        headers={**auth(api_key), "Content-Type": "text/plain"},
        content=("\n".join(lines) + "\n").encode(),
    )
    assert uploaded.status_code == 201
    evaluated = client.post("/api/v1/detection/evaluate", headers=auth(api_key))
    assert evaluated.status_code == 201
    alert = evaluated.json()["alerts"][0]
    return alert["id"] if "id" in alert else alert["fingerprint"]


def test_alert_lifecycle_notes_and_audit(client, api_key):
    create_alert(client, api_key)
    alerts = client.get(
        "/api/v1/detection/alerts?status=new", headers=auth(api_key)
    )
    assert alerts.status_code == 200
    alert = alerts.json()[0]
    alert_id = alert["id"]

    updated = client.patch(
        f"/api/v1/detection/alerts/{alert_id}",
        headers=auth(api_key),
        json={"status": "acknowledged", "classification": "undetermined"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"

    investigating = client.patch(
        f"/api/v1/detection/alerts/{alert_id}",
        headers=auth(api_key),
        json={"status": "investigating", "classification": "true_positive"},
    )
    assert investigating.status_code == 200
    assert investigating.json()["classification"] == "true_positive"

    noted = client.post(
        f"/api/v1/detection/alerts/{alert_id}/notes",
        headers=auth(api_key),
        json={"note": "Correlated with the lab DNS event timeline."},
    )
    assert noted.status_code == 201
    assert any(
        item["activity_type"] == "note_added" and item["note"]
        for item in noted.json()["activity"]
    )
    assert client.get(
        "/api/v1/audit/verify", headers=auth(api_key)
    ).json()["valid"] is True


def test_alert_resolution_and_reopen(client, api_key):
    create_alert(client, api_key)
    alert = client.get(
        "/api/v1/detection/alerts?status=new", headers=auth(api_key)
    ).json()[0]
    alert_id = alert["id"]
    resolved = client.patch(
        f"/api/v1/detection/alerts/{alert_id}",
        headers=auth(api_key),
        json={"status": "resolved", "classification": "benign"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["closed_at"]
    reopened = client.patch(
        f"/api/v1/detection/alerts/{alert_id}",
        headers=auth(api_key),
        json={"status": "new"},
    )
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "new"
    assert reopened.json()["closed_at"] is None


def test_alert_lifecycle_rejects_invalid_transitions_and_values(client, api_key):
    create_alert(client, api_key)
    alert = client.get(
        "/api/v1/detection/alerts?status=new", headers=auth(api_key)
    ).json()[0]
    alert_id = alert["id"]
    invalid = client.patch(
        f"/api/v1/detection/alerts/{alert_id}",
        headers=auth(api_key),
        json={"status": "resolved", "classification": "malicious"},
    )
    assert invalid.status_code == 422
    bad_note = client.post(
        f"/api/v1/detection/alerts/{alert_id}/notes",
        headers=auth(api_key),
        json={"note": " "},
    )
    assert bad_note.status_code == 422
    assert client.get(
        f"/api/v1/detection/alerts/{alert_id}", headers=auth(api_key)
    ).status_code == 200


def test_alert_investigation_endpoints_require_authentication(client):
    assert client.get("/api/v1/detection/alerts/example").status_code == 401
    assert client.patch(
        "/api/v1/detection/alerts/example", json={"status": "acknowledged"}
    ).status_code == 401
    assert client.post(
        "/api/v1/detection/alerts/example/notes", json={"note": "x"}
    ).status_code == 401
