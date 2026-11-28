from __future__ import annotations

import time


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def register_target(client, key, ip="127.0.0.1", port=8081):
    return client.post(
        "/api/v1/targets",
        headers=auth(key),
        json={"name": "Local fixture", "ip": ip, "port": port, "scheme": "http"},
    )


def test_health_is_available_without_credentials(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_requires_bearer_key(client):
    assert client.get("/api/v1/targets").status_code == 401
    assert client.get("/api/v1/targets", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_public_target_is_rejected(client, api_key):
    response = register_target(client, api_key, ip="8.8.8.8")
    assert response.status_code == 403


def test_dns_hostname_is_rejected(client, api_key):
    response = register_target(client, api_key, ip="example.com")
    assert response.status_code == 422


def test_run_budget_is_validated_server_side(client, api_key):
    target = register_target(client, api_key).json()
    response = client.post(
        "/api/v1/runs",
        headers=auth(api_key),
        json={"target_id": target["id"], "requests_per_second": 11, "duration_seconds": 10, "concurrency": 2},
    )
    assert response.status_code == 422


def test_registered_local_target_can_be_measured_and_audited(client, api_key, target_server):
    target = register_target(client, api_key, port=target_server).json()
    response = client.post(
        "/api/v1/runs",
        headers=auth(api_key),
        json={"target_id": target["id"], "requests_per_second": 2, "duration_seconds": 1, "concurrency": 2},
    )
    assert response.status_code == 202
    run_id = response.json()["id"]

    deadline = time.monotonic() + 5
    record = None
    while time.monotonic() < deadline:
        record = client.get(f"/api/v1/runs/{run_id}", headers=auth(api_key)).json()
        if record["status"] in {"completed", "stopped", "failed"}:
            break
        time.sleep(0.05)

    assert record is not None
    assert record["status"] == "completed"
    assert 1 <= record["result"]["requests_started"] <= 2
    assert record["result"]["successful_responses"] >= 1
    assert record["result"]["status_codes"].get("200", 0) >= 1

    audit = client.get("/api/v1/audit/verify", headers=auth(api_key))
    assert audit.status_code == 200
    assert audit.json()["valid"] is True
    assert audit.json()["checked_events"] >= 3


def test_metrics_endpoint_requires_authentication(client, api_key):
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=auth(api_key)).status_code == 200



def test_second_run_is_rejected_while_a_run_is_active(client, api_key, target_server):
    target = register_target(client, api_key, port=target_server).json()
    payload = {"target_id": target["id"], "requests_per_second": 1, "duration_seconds": 5, "concurrency": 1}
    first = client.post("/api/v1/runs", headers=auth(api_key), json=payload)
    assert first.status_code == 202
    second = client.post("/api/v1/runs", headers=auth(api_key), json=payload)
    assert second.status_code == 409
    stop = client.post(f"/api/v1/runs/{first.json()['id']}/stop", headers=auth(api_key))
    assert stop.status_code == 200

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        record = client.get(f"/api/v1/runs/{first.json()['id']}", headers=auth(api_key)).json()
        if record["status"] in {"stopped", "completed", "failed"}:
            break
        time.sleep(0.03)
    assert record["status"] == "stopped"


def test_audit_chain_detects_modified_event(client, api_key):
    register_target(client, api_key)
    store = client.app.state.store
    store.conn.execute("UPDATE audit_events SET details_json=? WHERE seq=?", ("null", 1))
    store.conn.commit()
    result = client.get("/api/v1/audit/verify", headers=auth(api_key))
    assert result.status_code == 200
    assert result.json()["valid"] is False



def test_dashboard_sends_baseline_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_api_responses_are_not_cacheable(client, api_key):
    response = client.get("/api/v1/targets", headers=auth(api_key))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"



def test_non_ascii_bearer_header_is_rejected_without_server_error(client):
    response = client.get("/api/v1/targets", headers=[(b"authorization", b"Bearer \xff")])
    assert response.status_code == 401



def test_unknown_run_id_is_not_disclosed(client, api_key):
    response = client.get("/api/v1/runs/00000000-0000-0000-0000-000000000000", headers=auth(api_key))
    assert response.status_code == 404


def test_target_label_validation_rejects_markup_and_sql_fragments(client, api_key):
    response = client.post(
        "/api/v1/targets",
        headers=auth(api_key),
        json={"name": "<script>alert(1)</script>", "ip": "127.0.0.1", "port": 8081, "scheme": "http"},
    )
    assert response.status_code == 422


def test_dashboard_uses_text_safe_dom_rendering(client):
    response = client.get("/static/app.js")
    assert response.status_code == 200
    assert ".innerHTML" not in response.text
    assert "textContent" in response.text
    assert "createElement" in response.text


def test_signed_audit_checkpoint_round_trip_and_tamper_detection(client, api_key):
    created = client.post("/api/v1/audit/checkpoints", headers=auth(api_key))
    assert created.status_code == 201
    checkpoint = created.json()

    verified = client.post(
        "/api/v1/audit/checkpoints/verify",
        headers=auth(api_key),
        json=checkpoint,
    )
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["signature_valid"] is True
    assert verified.json()["checkpoint_head_present"] is True

    altered = dict(checkpoint)
    altered["head_hash"] = "0" * 64
    rejected = client.post(
        "/api/v1/audit/checkpoints/verify",
        headers=auth(api_key),
        json=altered,
    )
    assert rejected.status_code == 200
    assert rejected.json()["valid"] is False


def test_run_lock_is_shared_between_app_instances(tmp_path, api_key, target_server):
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    database = tmp_path / "shared-workers.sqlite3"
    settings = Settings(api_key=api_key, database_path=database)
    first_app = create_app(settings)
    second_app = create_app(settings)

    with TestClient(first_app) as first, TestClient(second_app) as second:
        target = register_target(first, api_key, port=target_server).json()
        payload = {
            "target_id": target["id"],
            "requests_per_second": 1,
            "duration_seconds": 5,
            "concurrency": 1,
        }
        started = first.post("/api/v1/runs", headers=auth(api_key), json=payload)
        assert started.status_code == 202

        conflict = second.post("/api/v1/runs", headers=auth(api_key), json=payload)
        assert conflict.status_code == 409

        stopped = second.post(
            f"/api/v1/runs/{started.json()['id']}/stop",
            headers=auth(api_key),
        )
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "stopping"

        deadline = time.monotonic() + 3
        record = None
        while time.monotonic() < deadline:
            record = second.get(
                f"/api/v1/runs/{started.json()['id']}",
                headers=auth(api_key),
            ).json()
            if record["status"] in {"completed", "stopped", "failed"}:
                break
            time.sleep(0.05)
        assert record is not None
        assert record["status"] == "stopped"
