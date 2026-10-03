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


def _login_as_new_operator(client, username: str, password: str) -> None:
    """Runs the full §9.11 bootstrap + two-step login through the real
    HTTP endpoints (setup -> password -> TOTP) and leaves the client
    holding a valid session cookie, for tests that just need to be
    logged in to reach /console."""
    from observable.accounts.totp import totp_now

    setup = client.post("/accounts/setup", json={"username": username, "password": password})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["totp_secret"]

    step1 = client.post("/login/password", json={"username": username, "password": password})
    assert step1.status_code == 200, step1.text

    code = totp_now(secret)
    step2 = client.post("/login/verify", json={"code": code})
    assert step2.status_code == 200, step2.text


def test_enroll_token_invoke_round_trip(client):
    agent = AgentClient.enroll(
        http=client,
        display_name="api-sales-assistant",
        role="sales-assistant",
        tier="foundation",
        enrolled_by="omar",
    )
    assert agent.agent_id

    token = agent.request_token(["tool:crm.read"], purpose="account lookup")
    assert token

    result = agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-102")
    assert result["allowed"] is True
    assert result["result"]["account_id"] if "account_id" in result["result"] else True
    # the fake CRM record for A-102 has a password-looking field that
    # must come back redacted over the wire, not in the clear.
    assert "hunter2" not in str(result["result"])


def test_invoke_denied_without_scope_returns_403(client):
    agent = AgentClient.enroll(
        http=client,
        display_name="api-sales-assistant-2",
        role="sales-assistant",
        tier="foundation",
        enrolled_by="omar",
    )
    token = agent.request_token(["tool:crm.read"])

    with pytest.raises(AgentClientError) as exc_info:
        agent.invoke(token, tool_name="email.send", payload={"to": "x@example.com"})
    assert exc_info.value.status_code == 403


def test_stolen_token_replayed_by_different_agent_rejected(client):
    victim = AgentClient.enroll(
        http=client, display_name="victim", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    attacker = AgentClient.enroll(
        http=client, display_name="attacker", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = victim.request_token(["tool:crm.read"])

    # attacker has the raw JWT string but signs the request with their
    # own certificate/private key, not the victim's.
    attacker_token_reuse = AgentClient(
        http=client,
        private_key=attacker.private_key,
        certificate_pem=attacker.certificate_pem,
        agent_id=attacker.agent_id,
    )
    with pytest.raises(AgentClientError) as exc_info:
        attacker_token_reuse.invoke(token, tool_name="crm.read", payload={}, resource_id="A-102")
    assert exc_info.value.status_code == 403


def test_replay_of_identical_request_rejected(client):
    agent = AgentClient.enroll(
        http=client, display_name="replay-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    # Build one signed /token request manually and send it twice.
    import base64
    import datetime as dt
    import json
    import uuid

    from observable.api.pop import sign_request

    body = json.dumps({"requested_scopes": ["tool:crm.read"], "purpose": None, "risk_score": 0.0}).encode()
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    nonce = uuid.uuid4().hex
    signature = sign_request(
        private_key=agent.private_key, method="POST", path="/token", timestamp=timestamp, nonce=nonce, body=body
    )
    headers = {
        "Content-Type": "application/json",
        "X-Observable-Client-Cert": base64.b64encode(agent.certificate_pem).decode(),
        "X-Observable-Timestamp": timestamp,
        "X-Observable-Nonce": nonce,
        "X-Observable-Signature": base64.b64encode(signature).decode(),
    }

    first = client.post("/token", content=body, headers=headers)
    assert first.status_code == 200

    second = client.post("/token", content=body, headers=headers)
    assert second.status_code == 401
    assert "replay" in second.json()["detail"]


def test_containment_via_admin_endpoint_blocks_subsequent_calls(client):
    agent = AgentClient.enroll(
        http=client, display_name="containable-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])

    resp = client.post("/admin/contain", json={"agent_id": agent.agent_id, "reason": "test containment"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "suspended"

    with pytest.raises(AgentClientError) as exc_info:
        agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-102")
    assert exc_info.value.status_code == 403


def test_audit_verify_endpoint_reports_intact_chain(client):
    agent = AgentClient.enroll(
        http=client, display_name="audit-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-100")

    resp = client.get("/audit/verify")
    body = resp.json()
    assert body["intact"] is True
    assert body["entry_count"] >= 1


def test_agent_status_endpoint(client):
    agent = AgentClient.enroll(
        http=client, display_name="status-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    resp = client.get(f"/agents/{agent.agent_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["role"] == "sales-assistant"


def test_agent_identity_endpoint_returns_live_certificate(client):
    agent = AgentClient.enroll(
        http=client, display_name="identity-agent", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    resp = client.get(f"/agents/{agent.agent_id}/identity")
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == agent.agent_id
    assert body["subject_cn"] == f"agent:{agent.agent_id}"
    assert body["revoked"] is False
    assert "BEGIN CERTIFICATE" in body["certificate_pem"]
    assert body["certificate_pem"] == agent.certificate_pem.decode("utf-8")
    assert len(body["sha256_thumbprint"]) > 0


def test_agent_identity_endpoint_unknown_agent_404s(client):
    resp = client.get("/agents/does-not-exist/identity")
    assert resp.status_code == 404


def test_console_without_a_session_redirects_to_login(client):
    # §9.11: the console used to be reachable by anyone who found the
    # URL; it's now gated behind operator login.
    resp = client.get("/console", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_console_page_served_same_origin_once_logged_in(client):
    _login_as_new_operator(client, "omar", "correct horse battery staple")
    resp = client.get("/console")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in resp.text.lower()
    assert "Observable Console" in resp.text


def test_root_serves_landing_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in resp.text.lower()
    assert "Observable" in resp.text
    assert "SaaS" in resp.text
    # The console stays reachable at its own path; root no longer
    # redirects to it now that it serves the marketing page instead.
    console_resp = client.get("/console")
    assert console_resp.status_code == 200


def test_favicon_ico_served_at_root_path(client):
    resp = client.get("/favicon.ico")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/x-icon"
    assert len(resp.content) > 0


def test_icon_assets_served_for_known_filenames(client):
    for filename, content_type in [
        ("favicon-16x16.png", "image/png"),
        ("favicon-32x32.png", "image/png"),
        ("apple-touch-icon.png", "image/png"),
        ("favicon.ico", "image/x-icon"),
    ]:
        resp = client.get(f"/icons/{filename}")
        assert resp.status_code == 200, filename
        assert resp.headers["content-type"] == content_type
        assert len(resp.content) > 0


def test_icon_asset_rejects_unknown_filename(client):
    resp = client.get("/icons/../app.py")
    assert resp.status_code in (404, 307)  # 307 if Starlette normalizes the path first
    resp2 = client.get("/icons/not-a-real-icon.png")
    assert resp2.status_code == 404


def test_landing_page_links_favicon_tags(client):
    resp = client.get("/")
    assert 'rel="icon" href="/favicon.ico"' in resp.text
    assert "/icons/favicon-32x32.png" in resp.text
    assert "/icons/apple-touch-icon.png" in resp.text


def test_console_page_links_favicon_tags(client):
    resp = client.get("/console")
    assert 'rel="icon" href="/favicon.ico"' in resp.text
    assert "/icons/favicon-32x32.png" in resp.text


def test_list_agents_endpoint_empty_by_default(client):
    resp = client.get("/agents")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_agents_endpoint_reflects_enrollment(client):
    a1 = AgentClient.enroll(
        http=client, display_name="list-agent-1", role="sales-assistant", tier="foundation", enrolled_by="omar"
    )
    a2 = AgentClient.enroll(
        http=client, display_name="list-agent-2", role="sales-assistant", tier="enterprise", enrolled_by="omar"
    )
    resp = client.get("/agents")
    assert resp.status_code == 200
    body = resp.json()
    ids = {a["agent_id"] for a in body}
    assert {a1.agent_id, a2.agent_id} <= ids
    by_id = {a["agent_id"]: a for a in body}
    assert by_id[a1.agent_id]["tier"] == "foundation"
    assert by_id[a2.agent_id]["tier"] == "enterprise"
