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


def test_scan_all_connectors(client):
    resp = client.post("/inventory/scan", json={})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["connector_id"] == "mock:acme-corp"
    assert results[0]["agents"] == 2


def test_scan_unknown_connector_404(client):
    resp = client.post("/inventory/scan", json={"connector_id": "does-not-exist"})
    assert resp.status_code == 404


def test_apps_and_agents_empty_before_first_scan(client):
    assert client.get("/inventory/apps").json() == []
    assert client.get("/inventory/agents").json() == []


def test_agents_endpoint_flags_shadow_after_scan(client):
    client.post("/inventory/scan", json={})
    agents = client.get("/inventory/agents").json()
    by_ref = {a["external_ref"]: a for a in agents}

    assert by_ref["crm-agentforce-sales-1"]["shadow"] is True
    assert by_ref["m365-copilot-ext-42"]["shadow"] is True
    assert by_ref["m365-copilot-ext-42"]["shadow_severity"] == "high"


def test_agents_endpoint_unshadowed_once_enrolled_and_linked(client):
    # enroll an Observable identity linked to the SaaS sales bot's external_ref
    fresh_state = app.dependency_overrides[get_state]()
    from observable.pki.interface import CertificateTier
    from observable.pki.reference_ca import ReferenceCA

    _, pub = ReferenceCA.generate_keypair()
    fresh_state.registry.enroll(
        display_name="linked-sales-bot",
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
        enrolled_by="omar",
        external_ref="crm-agentforce-sales-1",
    )

    client.post("/inventory/scan", json={})
    agents = client.get("/inventory/agents").json()
    by_ref = {a["external_ref"]: a for a in agents}

    assert by_ref["crm-agentforce-sales-1"]["shadow"] is False
    assert by_ref["m365-copilot-ext-42"]["shadow"] is True


def test_shadow_endpoint_lists_findings(client):
    client.post("/inventory/scan", json={})
    findings = client.get("/inventory/shadow").json()
    refs = {f["external_ref"] for f in findings}
    assert "m365-copilot-ext-42" in refs
    assert all(f["reason"] == "unenrolled" for f in findings)


def test_posture_endpoint_lists_findings(client):
    client.post("/inventory/scan", json={})
    findings = client.get("/inventory/posture").json()
    rule_ids = {f["rule_id"] for f in findings}
    assert "stale_privileged_account" in rule_ids
    assert "admin_without_mfa" in rule_ids
    assert "broad_agent_grant" in rule_ids


def test_drift_endpoint_404_before_second_scan(client):
    client.post("/inventory/scan", json={})
    resp = client.get("/inventory/drift/mock:acme-corp")
    assert resp.status_code == 404


def test_drift_endpoint_after_two_scans(client):
    client.post("/inventory/scan", json={})
    client.post("/inventory/scan", json={})
    resp = client.get("/inventory/drift/mock:acme-corp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connector_id"] == "mock:acme-corp"
    assert body["has_changes"] is False  # nothing changed between two identical scans


def test_posture_includes_drift_findings_after_change(client):
    fresh_state = app.dependency_overrides[get_state]()
    client.post("/inventory/scan", json={})

    connector = fresh_state.connectors["mock:acme-corp"]
    from observable.inventory.connector import DiscoveredPermission

    connector.grant_permission(
        DiscoveredPermission(
            app_id="crm", principal_ref="crm-agentforce-sales-1", principal_type="agent",
            permission="crm.delete", scope_level="admin",
        )
    )
    client.post("/inventory/scan", json={})

    findings = client.get("/inventory/posture").json()
    assert any(f["rule_id"] == "drift_new_grant" for f in findings)
