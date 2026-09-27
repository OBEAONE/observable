import pytest

from observable.detection.engine import DetectionEngine
from observable.guard.gateway import AgentGuard, GuardDeniedError
from observable.identity.registry import AgentStatus, IdentityRegistry
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
    # Deterministic business-hours check: these tests are about
    # detection/containment wiring, not ABAC's business-hours logic
    # (already covered in test_policy.py / test_guard.py), so don't let
    # them depend on the real wall clock.
    return PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)


@pytest.fixture()
def token_service(ca, registry, policy_engine):
    return TokenService(ca=ca, registry=registry, scope_authorizer=policy_engine)


def _enroll(registry, role="sales-assistant", tier=CertificateTier.FOUNDATION, name="agent"):
    _, pub = ReferenceCA.generate_keypair()
    return registry.enroll(
        display_name=name, role=role, tier=tier, public_key_pem=pub, enrolled_by="omar"
    )


def test_guard_without_detection_still_works(registry, token_service, policy_engine):
    guard = AgentGuard(registry=registry, token_service=token_service, policy_engine=policy_engine)
    guard.register_tool("crm.read", lambda p, r: {"ok": True})
    enrollment = _enroll(registry)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.read"]
    )
    result = guard.invoke(
        client_cert_pem=enrollment.certificate.certificate_pem,
        token=token.jwt,
        tool_name="crm.read",
        payload={},
    )
    assert result.allowed is True
    assert result.risk_score == 0.0
    assert result.detection_signals == []


def test_guard_result_carries_new_tool_signal_on_first_call(registry, token_service, policy_engine):
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine, detection=detection
    )
    guard.register_tool("crm.read", lambda p, r: {"ok": True})
    enrollment = _enroll(registry)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.read"]
    )
    result = guard.invoke(
        client_cert_pem=enrollment.certificate.certificate_pem,
        token=token.jwt,
        tool_name="crm.read",
        payload={},
        resource_id="A-1",
    )
    assert any(s.startswith("new_tool") for s in result.detection_signals)
    assert result.risk_score > 0.0


def test_guard_learns_and_stops_flagging_repeated_normal_calls(registry, token_service, policy_engine):
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine, detection=detection
    )
    guard.register_tool("crm.read", lambda p, r: {"ok": True})
    enrollment = _enroll(registry)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.read"]
    )

    first = guard.invoke(
        client_cert_pem=enrollment.certificate.certificate_pem,
        token=token.jwt,
        tool_name="crm.read",
        payload={},
        resource_id="A-1",
    )
    assert first.detection_signals  # first call to a fresh tool: flagged

    second = guard.invoke(
        client_cert_pem=enrollment.certificate.certificate_pem,
        token=token.jwt,
        tool_name="crm.read",
        payload={},
        resource_id="A-1",
    )
    # same tool, same resource, second time: no longer "new"
    assert not any(s.startswith("new_tool") for s in second.detection_signals)


def test_auto_contain_threshold_blocks_and_suspends_when_crossed(registry, token_service, policy_engine):
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    # crm.delete is HIGH sensitivity -> new_tool risk 0.4, below a 0.3
    # threshold that's easy to cross with one unfamiliar high-sensitivity call.
    guard = AgentGuard(
        registry=registry,
        token_service=token_service,
        policy_engine=policy_engine,
        detection=detection,
        auto_contain_threshold=0.3,
    )
    guard.register_tool("crm.delete", lambda p, r: {"ok": True})
    enrollment = _enroll(registry, role="crm-admin", tier=CertificateTier.ENTERPRISE)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.delete"]
    )

    with pytest.raises(GuardDeniedError, match="auto-contained"):
        guard.invoke(
            client_cert_pem=enrollment.certificate.certificate_pem,
            token=token.jwt,
            tool_name="crm.delete",
            payload={},
            resource_id="A-1",
        )

    assert registry.get(enrollment.record.agent_id).status == AgentStatus.SUSPENDED

    containment_entries = [
        e for e in guard.audit.entries_for_agent(enrollment.record.agent_id) if e.action.startswith("containment")
    ]
    assert containment_entries
    assert "automated containment" in containment_entries[-1].reason


def test_auto_contain_threshold_none_by_default_does_not_suspend(registry, token_service, policy_engine):
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine, detection=detection
    )
    # crm.read is LOW sensitivity (max_risk_score 1.0 in the default
    # bundle), so a first-time-use risk bump (0.1) stays well under its
    # own tool's ABAC ceiling -- isolating "no auto-contain threshold
    # configured" from the (correct, and separately covered below)
    # interaction where a *high*-sensitivity tool's own low risk
    # ceiling denies a risky first call outright.
    guard.register_tool("crm.read", lambda p, r: {"ok": True})
    enrollment = _enroll(registry, role="crm-admin", tier=CertificateTier.ENTERPRISE)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.read"]
    )
    result = guard.invoke(
        client_cert_pem=enrollment.certificate.certificate_pem,
        token=token.jwt,
        tool_name="crm.read",
        payload={},
        resource_id="A-1",
    )
    assert result.allowed is True
    assert registry.get(enrollment.record.agent_id).status == AgentStatus.ACTIVE


def test_live_risk_score_can_trip_a_tools_own_abac_ceiling(registry, token_service, policy_engine):
    # This is the flip side of the test above: crm.delete's own
    # max_risk_score (0.2) is stricter than the first-time-use risk a
    # HIGH-sensitivity new-tool signal contributes (0.4) -- so even with
    # no auto_contain_threshold configured at all, the Detection Engine
    # feeding a real risk_score into ABAC is enough to deny a risky first
    # call on a sensitive tool, purely through the existing policy rule.
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine, detection=detection
    )
    guard.register_tool("crm.delete", lambda p, r: {"ok": True})
    enrollment = _enroll(registry, role="crm-admin", tier=CertificateTier.ENTERPRISE)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.delete"]
    )
    with pytest.raises(GuardDeniedError, match="risk score"):
        guard.invoke(
            client_cert_pem=enrollment.certificate.certificate_pem,
            token=token.jwt,
            tool_name="crm.delete",
            payload={},
            resource_id="A-1",
        )
    # ABAC denial alone, no auto-contain configured: agent stays active.
    assert registry.get(enrollment.record.agent_id).status == AgentStatus.ACTIVE


def test_constructing_guard_with_threshold_but_no_detection_raises(registry, token_service, policy_engine):
    with pytest.raises(ValueError, match="requires a detection engine"):
        AgentGuard(
            registry=registry,
            token_service=token_service,
            policy_engine=policy_engine,
            auto_contain_threshold=0.5,
        )


def test_denied_attempts_feed_deny_rate_signal(registry, token_service, policy_engine):
    detection = DetectionEngine(sensitivity_lookup=policy_engine)
    guard = AgentGuard(
        registry=registry, token_service=token_service, policy_engine=policy_engine, detection=detection
    )
    # no invoker registered for crm.read -> every call denied at the
    # "no registered invoker" step, which still logs (and thus still
    # teaches the baseline) via the centralized _log() hook.
    enrollment = _enroll(registry)
    token = token_service.mint(
        client_cert_pem=enrollment.certificate.certificate_pem, requested_scopes=["tool:crm.read"]
    )

    for _ in range(4):
        with pytest.raises(GuardDeniedError):
            guard.invoke(
                client_cert_pem=enrollment.certificate.certificate_pem,
                token=token.jwt,
                tool_name="crm.read",
                payload={},
            )

    summary = detection.baseline_summary(enrollment.record.agent_id)
    assert summary["recent_deny_count"] == 4
