import pytest

from observable.compliance.framework import ComplianceContext, ControlStatus, DEFAULT_CONTROLS
from observable.compliance.report import generate_report
from observable.detection.engine import DetectionEngine
from observable.guard.audit import AuditChain
from observable.guard.gateway import AgentGuard
from observable.identity.registry import IdentityRegistry
from observable.inventory.mock_connector import MockConnector
from observable.inventory.store import InventoryStore
from observable.pki.interface import CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import default_bundle
from observable.policy.engine import PolicyEngine
from observable.tokens.service import TokenService


@pytest.fixture()
def ca():
    return ReferenceCA(org_name="Test CA")


@pytest.fixture()
def registry(ca):
    return IdentityRegistry(ca)


@pytest.fixture()
def policy_engine(ca):
    return PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)


@pytest.fixture()
def audit():
    return AuditChain()


def _ctx(registry, policy_engine, audit, *, inventory=None, guard=None):
    return ComplianceContext(
        registry=registry, policy_engine=policy_engine, audit=audit, inventory=inventory, guard=guard
    )


def _enroll(registry, role="sales-assistant", tier=CertificateTier.FOUNDATION, name="agent"):
    _, pub = ReferenceCA.generate_keypair()
    return registry.enroll(
        display_name=name, role=role, tier=tier, public_key_pem=pub, enrolled_by="omar"
    )


# ----------------------------------------------------------------------
# Individual controls
# ----------------------------------------------------------------------
def test_unique_identity_passes_with_no_duplicates(registry, policy_engine, audit):
    _enroll(registry, name="a1")
    _enroll(registry, name="a2")
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "unique_identity")
    assert result.status == ControlStatus.PASS


def test_short_lived_tokens_passes_by_design(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "short_lived_pop_tokens")
    assert result.status == ControlStatus.PASS


def test_deny_by_default_probe_passes_against_real_policy_engine(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "deny_by_default_rbac")
    assert result.status == ControlStatus.PASS
    assert "live probe" in result.evidence[0]


def test_abac_context_aware_passes_with_default_bundle(registry, policy_engine, audit):
    # default_bundle() registers crm.delete (business_hours_only,
    # max_risk_score=0.2) and email.send (max_risk_score=0.5) — so at
    # least one tool is context-aware out of the box.
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "abac_context_aware")
    assert result.status == ControlStatus.PASS


def test_audit_immutability_passes_on_intact_chain(registry, policy_engine, audit):
    audit.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow", reason="ok")
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "immutable_audit_trail")
    assert result.status == ControlStatus.PASS
    assert "1 entries" in result.summary


def test_audit_immutability_fails_on_tampered_chain(registry, policy_engine, audit):
    import dataclasses

    entry = audit.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow", reason="ok")
    tampered = dataclasses.replace(entry, reason="tampered")
    audit._entries[0] = tampered  # simulate a storage-layer tamper
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "immutable_audit_trail")
    assert result.status == ControlStatus.FAIL


def test_sanitization_passes_by_design(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "input_output_sanitization")
    assert result.status == ControlStatus.PASS


def test_automated_containment_not_applicable_without_guard(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "automated_containment")
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_automated_containment_partial_when_no_threshold_set(registry, policy_engine, audit):
    token_service = TokenService(ca=ReferenceCA(org_name="x"), registry=registry, scope_authorizer=policy_engine)
    detection = DetectionEngine()
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine,
        audit=audit, detection=detection,
    )
    report = generate_report(_ctx(registry, policy_engine, audit, guard=guard))
    result = next(r for r in report.results if r.control_id == "automated_containment")
    assert result.status == ControlStatus.PARTIAL


def test_automated_containment_passes_once_threshold_set(registry, policy_engine, audit):
    token_service = TokenService(ca=ReferenceCA(org_name="x"), registry=registry, scope_authorizer=policy_engine)
    detection = DetectionEngine()
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine,
        audit=audit, detection=detection, auto_contain_threshold=0.7,
    )
    report = generate_report(_ctx(registry, policy_engine, audit, guard=guard))
    result = next(r for r in report.results if r.control_id == "automated_containment")
    assert result.status == ControlStatus.PASS
    assert "0.70" in result.summary


def test_signed_policy_partial_for_unsigned_bundle(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "signed_policy_bundle")
    assert result.status == ControlStatus.PARTIAL


def test_shadow_ai_not_applicable_without_scan(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit, inventory=InventoryStore()))
    result = next(r for r in report.results if r.control_id == "no_high_severity_shadow_ai")
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_shadow_ai_fails_when_high_severity_unenrolled_agent_present(registry, policy_engine, audit):
    inventory = InventoryStore()
    inventory.ingest(MockConnector().scan())
    report = generate_report(_ctx(registry, policy_engine, audit, inventory=inventory))
    result = next(r for r in report.results if r.control_id == "no_high_severity_shadow_ai")
    # MockConnector's sample data includes an unenrolled agent with a
    # privileged (admin/full_access) grant, per the inventory tests.
    assert result.status == ControlStatus.FAIL


def test_posture_findings_not_applicable_without_scan(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit, inventory=InventoryStore()))
    result = next(r for r in report.results if r.control_id == "no_high_severity_posture_findings")
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_posture_findings_fails_on_mock_tenant(registry, policy_engine, audit):
    inventory = InventoryStore()
    inventory.ingest(MockConnector().scan())
    report = generate_report(_ctx(registry, policy_engine, audit, inventory=inventory))
    result = next(r for r in report.results if r.control_id == "no_high_severity_posture_findings")
    # MockConnector's sample data includes a stale admin account (rule
    # fires HIGH), per the posture tests.
    assert result.status == ControlStatus.FAIL


def test_continuous_authorization_passes_by_design(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    result = next(r for r in report.results if r.control_id == "continuous_authorization")
    assert result.status == ControlStatus.PASS


# ----------------------------------------------------------------------
# Report roll-up
# ----------------------------------------------------------------------
def test_report_covers_every_default_control(registry, policy_engine, audit):
    report = generate_report(_ctx(registry, policy_engine, audit))
    assert len(report.results) == len(DEFAULT_CONTROLS)
    assert {r.control_id for r in report.results} == {c.control_id for c in DEFAULT_CONTROLS}


def test_overall_status_is_fail_if_any_control_fails(registry, policy_engine, audit):
    inventory = InventoryStore()
    inventory.ingest(MockConnector().scan())
    report = generate_report(_ctx(registry, policy_engine, audit, inventory=inventory))
    assert report.overall_status == ControlStatus.FAIL
    assert len(report.failing()) >= 1


def test_overall_status_is_partial_when_only_partials_present(registry, policy_engine, audit):
    # No inventory scan (shadow/posture -> N/A), no guard (containment
    # -> N/A), unsigned bundle (-> PARTIAL): nothing should FAIL.
    report = generate_report(_ctx(registry, policy_engine, audit))
    assert report.overall_status == ControlStatus.PARTIAL


def test_generate_report_never_mutates_registry_or_audit(registry, policy_engine, audit):
    _enroll(registry, name="a1")
    before_agents = len(registry.list_agents())
    before_entries = len(audit.entries())
    generate_report(_ctx(registry, policy_engine, audit))
    assert len(registry.list_agents()) == before_agents
    assert len(audit.entries()) == before_entries
