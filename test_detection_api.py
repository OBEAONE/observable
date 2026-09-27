import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state
from observable.client.sdk import AgentClient, AgentClientError


@pytest.fixture()
def client():
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_invoke_response_carries_risk_score_and_signals(client):
    agent = AgentClient.enroll(
        http=client, display_name="det-agent-1", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    result = agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-1")
    assert result["risk_score"] > 0.0
    assert any(s.startswith("new_tool") for s in result["detection_signals"])


def test_baseline_endpoint_unknown_agent(client):
    resp = client.get("/detection/does-not-exist")
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == "does-not-exist"
    assert body["known"] is False
    assert body["n_intervals"] is None


def test_baseline_endpoint_reflects_activity(client):
    agent = AgentClient.enroll(
        http=client, display_name="det-agent-2", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-1")
    agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-2")

    resp = client.get(f"/detection/{agent.agent_id}")
    body = resp.json()
    assert body["known"] is True
    assert body["tools_seen"] == ["crm.read"]
    assert body["distinct_resources_seen"] == 2
    assert body["recent_decision_count"] == 2


def test_setting_and_clearing_auto_contain_threshold(client):
    resp = client.post("/admin/detection/threshold", json={"threshold": 0.05})
    assert resp.status_code == 200
    assert resp.json() == {"auto_contain_threshold": 0.05}

    agent = AgentClient.enroll(
        http=client, display_name="det-agent-3", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    # a very low threshold (0.05) is crossed by the first-ever call's
    # new_tool signal alone, so this should trip auto-containment.
    with pytest.raises(AgentClientError) as exc_info:
        agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-1")
    assert exc_info.value.status_code == 403
    assert "auto-contained" in exc_info.value.detail

    status = client.get(f"/agents/{agent.agent_id}").json()
    assert status["status"] == "suspended"

    # clear the threshold so it doesn't leak into other tests via shared state
    clear_resp = client.post("/admin/detection/threshold", json={"threshold": None})
    assert clear_resp.json() == {"auto_contain_threshold": None}
