import json

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


def _enroll_and_call(client) -> str:
    agent = AgentClient.enroll(
        http=client, display_name="export-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-1")
    return agent.agent_id


def test_export_siem_cef_default_format(client):
    _enroll_and_call(client)
    resp = client.get("/export/siem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    lines = resp.text.splitlines()
    assert len(lines) >= 1
    assert all(line.startswith("CEF:0|Observable|AgentGuard|") for line in lines)


def test_export_siem_json_format(client):
    _enroll_and_call(client)
    resp = client.get("/export/siem", params={"format": "json"})
    assert resp.status_code == 200
    lines = resp.text.splitlines()
    assert len(lines) >= 1
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["vendor"] == "Observable"


def test_export_siem_unknown_format_is_400(client):
    resp = client.get("/export/siem", params={"format": "xml"})
    assert resp.status_code == 400


def test_export_soar_incidents_empty_with_no_containment(client):
    _enroll_and_call(client)
    resp = client.get("/export/soar/incidents")
    assert resp.status_code == 200
    assert resp.json() == []


def test_export_soar_incidents_reflects_containment(client):
    agent_id = _enroll_and_call(client)
    client.post("/admin/contain", json={"agent_id": agent_id, "reason": "manual review"})
    resp = client.get("/export/soar/incidents")
    body = resp.json()
    assert len(body) == 1
    assert body[0]["agent_id"] == agent_id
    assert body[0]["status"] == "open"
    assert body[0]["severity"] == "high"

    client.post("/admin/reinstate", json={"agent_id": agent_id, "reason": "cleared"})
    resp2 = client.get("/export/soar/incidents")
    body2 = resp2.json()
    assert body2[0]["status"] == "closed"
    assert body2[0]["closed_reason"] == "cleared"
