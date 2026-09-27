import pytest

from observable.identity.registry import IdentityRegistry
from observable.inventory.mock_connector import MockConnector
from observable.inventory.shadow import Severity, ShadowReason, detect_shadow_agents
from observable.inventory.store import InventoryStore
from observable.pki.interface import CertificateTier, RevocationReason
from observable.pki.reference_ca import ReferenceCA


@pytest.fixture()
def ca():
    return ReferenceCA(org_name="Test CA")


@pytest.fixture()
def registry(ca):
    return IdentityRegistry(ca)


@pytest.fixture()
def inventory():
    store = InventoryStore()
    store.ingest(MockConnector().scan())
    return store


def _enroll_matching_sales_bot(registry, external_ref="crm-agentforce-sales-1"):
    _, pub = ReferenceCA.generate_keypair()
    return registry.enroll(
        display_name="sales-assistant-linked",
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
        enrolled_by="omar",
        external_ref=external_ref,
    )


def test_unenrolled_agent_flagged_high_for_full_access(registry, inventory):
    # No Observable identities enrolled at all: both mock agents are shadow.
    findings = detect_shadow_agents(inventory=inventory, registry=registry)
    refs = {f.external_ref: f for f in findings}

    assert "crm-agentforce-sales-1" in refs
    assert "m365-copilot-ext-42" in refs
    assert all(f.reason == ShadowReason.UNENROLLED for f in findings)

    # the copilot extension holds a full_access grant -> HIGH
    assert refs["m365-copilot-ext-42"].severity == Severity.HIGH
    # the sales bot only holds read/write -> not HIGH
    assert refs["crm-agentforce-sales-1"].severity != Severity.HIGH


def test_enrolled_and_active_agent_produces_no_finding(registry, inventory):
    _enroll_matching_sales_bot(registry)
    findings = detect_shadow_agents(inventory=inventory, registry=registry)
    refs = {f.external_ref for f in findings}

    assert "crm-agentforce-sales-1" not in refs  # matched + active: no finding
    assert "m365-copilot-ext-42" in refs  # still unenrolled


def test_suspended_identity_still_active_in_saas_flagged_high(registry, inventory):
    enrollment = _enroll_matching_sales_bot(registry)
    registry.suspend(enrollment.record.agent_id, reason="anomalous behavior")

    findings = detect_shadow_agents(inventory=inventory, registry=registry)
    match = next(f for f in findings if f.external_ref == "crm-agentforce-sales-1")

    assert match.reason == ShadowReason.MATCHED_BUT_SUSPENDED
    assert match.severity == Severity.HIGH
    assert match.matched_agent_id == enrollment.record.agent_id


def test_revoked_identity_still_active_in_saas_flagged_high(registry, inventory):
    enrollment = _enroll_matching_sales_bot(registry)
    registry.revoke(enrollment.record.agent_id, reason=RevocationReason.KEY_COMPROMISE)

    findings = detect_shadow_agents(inventory=inventory, registry=registry)
    match = next(f for f in findings if f.external_ref == "crm-agentforce-sales-1")

    assert match.reason == ShadowReason.MATCHED_BUT_REVOKED
    assert match.severity == Severity.HIGH


def test_no_snapshots_yields_no_findings(registry):
    empty_inventory = InventoryStore()
    findings = detect_shadow_agents(inventory=empty_inventory, registry=registry)
    assert findings == []
