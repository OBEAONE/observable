import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state
from observable.client.sdk import AgentClient


@pytest.fixture()
def client():
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_compliance_report_endpoint_shape(client):
    resp = client.get("/compliance/report")
    assert resp.status_code == 200
    body = resp.json()
    assert "generated_at" in body
    assert body["overall_status"] in {"pass", "fail", "partial", "not_applicable"}
    assert isinstance(body["counts"], dict)
    assert len(body["results"]) >= 10
    control_ids = {r["control_id"] for r in body["results"]}
    assert "deny_by_default_rbac" in control_ids
    assert "immutable_audit_trail" in control_ids


def test_compliance_report_reflects_running_state(client):
    # A fresh default state (no scan run, no threshold set) should have
    # automated_containment PARTIAL (guard exists but no threshold) and
    # shadow/posture N/A (no scan yet).
    body = client.get("/compliance/report").json()
    by_id = {r["control_id"]: r for r in body["results"]}
    assert by_id["automated_containment"]["status"] == "partial"
    assert by_id["no_high_severity_shadow_ai"]["status"] == "not_applicable"

    # Set a threshold and confirm the report picks it up live.
    client.post("/admin/detection/threshold", json={"threshold": 0.6})
    body2 = client.get("/compliance/report").json()
    by_id2 = {r["control_id"]: r for r in body2["results"]}
    assert by_id2["automated_containment"]["status"] == "pass"


def test_compliance_report_reflects_a_scan(client):
    client.post("/inventory/scan", json={})
    body = client.get("/compliance/report").json()
    by_id = {r["control_id"]: r for r in body["results"]}
    assert by_id["no_high_severity_shadow_ai"]["status"] in {"pass", "fail"}
    assert by_id["no_high_severity_posture_findings"]["status"] in {"pass", "fail"}
