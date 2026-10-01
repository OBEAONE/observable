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


def _enroll(client, name="jit-agent"):
    return AgentClient.enroll(
        http=client, display_name=name, role="sales-assistant", tier="foundation", enrolled_by="omar"
    )


def test_role_alone_cannot_mint_an_ungranted_tool(client):
    agent = _enroll(client)
    with pytest.raises(AgentClientError) as exc_info:
        agent.request_token(["tool:ticket.triage"])
    assert exc_info.value.status_code == 403


def test_elevation_grant_then_mint_and_invoke_succeeds(client):
    agent = _enroll(client)
    resp = client.post(
        "/admin/elevation/grant",
        json={
            "agent_id": agent.agent_id,
            "tool": "ticket.triage",
            "reason": "incident-77 follow-up",
            "granted_by": "omar",
            "ttl_seconds": 600,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["resource_ids"] is None

    token = agent.request_token(["tool:ticket.triage"])
    assert token is not None


def test_elevation_grant_resource_scoped(client):
    agent = _enroll(client)
    resp = client.post(
        "/admin/elevation/grant",
        json={
            "agent_id": agent.agent_id,
            "tool": "ticket.triage",
            "resource_ids": ["T-1", "T-2"],
            "reason": "incident-77, tickets T-1/T-2 only",
            "granted_by": "omar",
            "ttl_seconds": 600,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["resource_ids"] == ["T-1", "T-2"]


def test_elevation_grant_unknown_agent_404(client):
    resp = client.post(
        "/admin/elevation/grant",
        json={
            "agent_id": "does-not-exist",
            "tool": "ticket.triage",
            "reason": "x",
            "granted_by": "omar",
            "ttl_seconds": 600,
        },
    )
    assert resp.status_code == 404


def test_elevation_grant_bad_ttl_400(client):
    agent = _enroll(client)
    resp = client.post(
        "/admin/elevation/grant",
        json={
            "agent_id": agent.agent_id,
            "tool": "ticket.triage",
            "reason": "x",
            "granted_by": "omar",
            "ttl_seconds": 0,
        },
    )
    assert resp.status_code == 400


def test_elevation_revoke_then_mint_denied_again(client):
    agent = _enroll(client)
    grant_id = client.post(
        "/admin/elevation/grant",
        json={
            "agent_id": agent.agent_id,
            "tool": "ticket.triage",
            "reason": "x",
            "granted_by": "omar",
            "ttl_seconds": 600,
        },
    ).json()["grant_id"]

    # works while active
    agent.request_token(["tool:ticket.triage"])

    revoke_resp = client.post(f"/admin/elevation/{grant_id}/revoke", json={"reason": "done early"})
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "revoked"

    with pytest.raises(AgentClientError):
        agent.request_token(["tool:ticket.triage"])


def test_elevation_revoke_unknown_grant_404(client):
    resp = client.post("/admin/elevation/does-not-exist/revoke", json={"reason": "x"})
    assert resp.status_code == 404


def test_elevation_list_filters_by_agent(client):
    a1 = _enroll(client, "jit-a1")
    a2 = _enroll(client, "jit-a2")
    client.post(
        "/admin/elevation/grant",
        json={"agent_id": a1.agent_id, "tool": "ticket.triage", "reason": "x", "granted_by": "omar", "ttl_seconds": 600},
    )
    client.post(
        "/admin/elevation/grant",
        json={"agent_id": a2.agent_id, "tool": "email.send", "reason": "y", "granted_by": "omar", "ttl_seconds": 600},
    )

    resp = client.get("/admin/elevation", params={"agent_id": a1.agent_id})
    grants = resp.json()["grants"]
    assert len(grants) == 1
    assert grants[0]["agent_id"] == a1.agent_id

    resp_all = client.get("/admin/elevation")
    assert len(resp_all.json()["grants"]) == 2


def test_elevation_grant_is_audited(client):
    agent = _enroll(client)
    client.post(
        "/admin/elevation/grant",
        json={"agent_id": agent.agent_id, "tool": "ticket.triage", "reason": "x", "granted_by": "omar", "ttl_seconds": 600},
    )
    entries = client.get(f"/audit/{agent.agent_id}").json()
    assert any(e["action"] == "elevation:grant" for e in entries)
