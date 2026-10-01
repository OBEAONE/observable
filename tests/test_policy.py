import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from observable.pki.interface import AttestationEvidence, CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import PolicyBundle, RoleGrant, Sensitivity, ToolDefinition, default_bundle
from observable.policy.elevation import ElevationStore
from observable.policy.engine import (
    ActionContext,
    BundleSignatureError,
    PolicyEngine,
    sign_bundle,
)
from observable.tokens.scope import Scope


@pytest.fixture()
def ca() -> ReferenceCA:
    return ReferenceCA(org_name="Test CA")


@pytest.fixture()
def engine(ca) -> PolicyEngine:
    return PolicyEngine(ca=ca, bundle=default_bundle())


BUSINESS_HOURS = dt.datetime(2026, 9, 21, 10, 0, tzinfo=dt.timezone.utc)  # Monday 10:00 UTC
AFTER_HOURS = dt.datetime(2026, 9, 21, 23, 0, tzinfo=dt.timezone.utc)  # Monday 23:00 UTC
WEEKEND = dt.datetime(2026, 9, 20, 10, 0, tzinfo=dt.timezone.utc)  # Sunday


def test_authorize_scopes_grants_only_registered_and_role_matched(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:crm.read"), Scope.parse("tool:crm.delete")],
    )
    # crm.delete requires enterprise tier and isn't granted to this role anyway
    assert granted == [Scope(tool="crm.read")]


def test_authorize_scopes_unregistered_tool_never_granted(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="crm-admin",
        tier=CertificateTier.ADVANCED,
        requested=[Scope.parse("tool:does.not.exist")],
    )
    assert granted == []


def test_authorize_scopes_wildcard_role_grant(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="crm-admin",
        tier=CertificateTier.ENTERPRISE,
        requested=[
            Scope.parse("tool:crm.read"),
            Scope.parse("tool:crm.write"),
            Scope.parse("tool:crm.delete"),
        ],
    )
    assert {s.tool for s in granted} == {"crm.read", "crm.write", "crm.delete"}


def test_authorize_scopes_respects_min_tier(engine: PolicyEngine):
    # crm-admin wildcard matches crm.delete, but Foundation tier is below
    # the tool's min_tier=enterprise requirement.
    granted = engine.authorize_scopes(
        role="crm-admin",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:crm.delete")],
    )
    assert granted == []


def test_authorize_action_business_hours(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="crm-admin",
        tier=CertificateTier.ENTERPRISE,
        scope=Scope(tool="crm.write"),
        context=ActionContext(timestamp=AFTER_HOURS, risk_score=0.0),
    )
    assert decision.allowed is False
    assert "business hours" in decision.reason

    decision_ok = engine.authorize_action(
        role="crm-admin",
        tier=CertificateTier.ENTERPRISE,
        scope=Scope(tool="crm.write"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0),
    )
    assert decision_ok.allowed is True


def test_authorize_action_risk_score_threshold(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="email.send"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.9),
    )
    assert decision.allowed is False
    assert "risk score" in decision.reason


def test_authorize_action_resource_scoped_grant_allows_matching_resource(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope.parse("tool:crm.read:resource=A-1,A-2"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, resource_id="A-1"),
    )
    assert decision.allowed is True


def test_authorize_action_resource_scoped_grant_denies_other_resource(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope.parse("tool:crm.read:resource=A-1,A-2"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, resource_id="A-99"),
    )
    assert decision.allowed is False
    assert "granted resource set" in decision.reason


def test_authorize_action_resource_scoped_grant_denies_missing_resource_id(engine: PolicyEngine):
    # The call didn't say *which* resource -- can't confirm it's inside
    # the granted set, so this fails closed rather than assuming it's fine.
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope.parse("tool:crm.read:resource=A-1"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, resource_id=None),
    )
    assert decision.allowed is False
    assert "no resource_id was given" in decision.reason


def test_authorize_action_unrestricted_scope_still_allows_any_resource(engine: PolicyEngine):
    # No "resource=" clause at all -- the pre-existing tool-only
    # granularity is unchanged, not accidentally tightened.
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="crm.read"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, resource_id="anything"),
    )
    assert decision.allowed is True


def test_authorize_action_malformed_constraint_fails_closed(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="crm.read", constraint="resource="),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, resource_id="A-1"),
    )
    assert decision.allowed is False
    assert "malformed scope constraint" in decision.reason


def test_authorize_scopes_drops_malformed_constraint(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope(tool="crm.read", constraint="resource=")],
    )
    assert granted == []


def test_authorize_scopes_keeps_valid_resource_constraint(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:crm.read:resource=A-1")],
    )
    assert granted == [Scope.parse("tool:crm.read:resource=A-1")]


def test_authorize_scopes_elevation_grants_a_tool_the_role_lacks():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    # sales-assistant has no static grant for ticket.triage
    assert engine.authorize_scopes(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:ticket.triage")], agent_id="a1",
    ) == []

    elevation.grant(
        agent_id="a1", scope=Scope(tool="ticket.triage"), reason="incident-88 follow-up",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    granted = engine.authorize_scopes(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:ticket.triage")], agent_id="a1", now=BUSINESS_HOURS,
    )
    assert granted == [Scope(tool="ticket.triage")]


def test_authorize_scopes_elevation_is_per_agent_not_role_wide():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    elevation.grant(
        agent_id="a1", scope=Scope(tool="ticket.triage"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    # a *different* sales-assistant agent gets nothing from a1's grant
    granted = engine.authorize_scopes(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:ticket.triage")], agent_id="a2", now=BUSINESS_HOURS,
    )
    assert granted == []


def test_authorize_scopes_elevation_mints_the_grants_own_narrower_scope():
    # Requesting an unrestricted scope when the elevation itself is
    # resource-scoped must only ever mint the grant's own (narrower)
    # scope, never the broader raw request.
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    elevation.grant(
        agent_id="a1", scope=Scope.parse("tool:ticket.triage:resource=T-1"), reason="x",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    granted = engine.authorize_scopes(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:ticket.triage")], agent_id="a1", now=BUSINESS_HOURS,
    )
    assert granted == [Scope.parse("tool:ticket.triage:resource=T-1")]


def test_authorize_scopes_elevation_does_not_bypass_tier_floor():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    elevation.grant(
        agent_id="a1", scope=Scope(tool="crm.delete"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    # crm.delete requires enterprise tier; elevation can't lower that bar
    granted = engine.authorize_scopes(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:crm.delete")], agent_id="a1", now=BUSINESS_HOURS,
    )
    assert granted == []


def test_authorize_action_elevation_allows_call_while_active():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    elevation.grant(
        agent_id="a1", scope=Scope(tool="ticket.triage"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    decision = engine.authorize_action(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="ticket.triage"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is True


def test_authorize_action_elevation_denies_once_expired():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    elevation.grant(
        agent_id="a1", scope=Scope(tool="ticket.triage"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=BUSINESS_HOURS,
    )
    later = BUSINESS_HOURS + dt.timedelta(minutes=11)
    decision = engine.authorize_action(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="ticket.triage"),
        context=ActionContext(timestamp=later, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is False
    assert "no grant" in decision.reason


def test_authorize_action_elevation_denies_once_revoked():
    elevation = ElevationStore()
    engine = PolicyEngine(ca=ReferenceCA(org_name="Test CA"), bundle=default_bundle(), elevation=elevation)
    grant = elevation.grant(
        agent_id="a1", scope=Scope(tool="ticket.triage"), reason="x", granted_by="omar",
        ttl=dt.timedelta(hours=1), now=BUSINESS_HOURS,
    )
    elevation.revoke(grant.grant_id, reason="task finished early", now=BUSINESS_HOURS)
    decision = engine.authorize_action(
        role="sales-assistant", tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="ticket.triage"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is False


def test_authorize_action_rate_limit_allows_under_limit(engine: PolicyEngine):
    scope = Scope.parse("tool:email.send:rate=2/min")
    for _ in range(2):
        decision = engine.authorize_action(
            role="sales-assistant",
            tier=CertificateTier.FOUNDATION,
            scope=scope,
            context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
        )
        assert decision.allowed is True


def test_authorize_action_rate_limit_denies_over_limit(engine: PolicyEngine):
    scope = Scope.parse("tool:email.send:rate=2/min")
    for _ in range(2):
        engine.authorize_action(
            role="sales-assistant",
            tier=CertificateTier.FOUNDATION,
            scope=scope,
            context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
        )
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=scope,
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is False
    assert "rate limit exceeded" in decision.reason


def test_authorize_action_rate_limit_resets_once_window_elapses(engine: PolicyEngine):
    scope = Scope.parse("tool:email.send:rate=1/min")
    engine.authorize_action(
        role="sales-assistant", tier=CertificateTier.FOUNDATION, scope=scope,
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    later = BUSINESS_HOURS + dt.timedelta(minutes=1, seconds=1)
    decision = engine.authorize_action(
        role="sales-assistant", tier=CertificateTier.FOUNDATION, scope=scope,
        context=ActionContext(timestamp=later, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is True


def test_authorize_action_unrestricted_scope_is_never_rate_limited(engine: PolicyEngine):
    # No "rate=" clause at all -- unlimited calls, exactly the
    # pre-existing behavior, not accidentally throttled.
    scope = Scope(tool="email.send")
    for _ in range(50):
        decision = engine.authorize_action(
            role="sales-assistant", tier=CertificateTier.FOUNDATION, scope=scope,
            context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
        )
        assert decision.allowed is True


def test_authorize_action_rate_limit_requires_agent_id(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope.parse("tool:email.send:rate=1/min"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id=None),
    )
    assert decision.allowed is False
    assert "no agent_id was given" in decision.reason


def test_authorize_action_rate_limit_malformed_constraint_fails_closed(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="email.send", constraint="rate=abc"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert decision.allowed is False
    assert "malformed scope constraint" in decision.reason


def test_authorize_scopes_drops_malformed_rate_constraint(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope(tool="email.send", constraint="rate=0/min")],
    )
    assert granted == []


def test_authorize_scopes_keeps_valid_rate_constraint(engine: PolicyEngine):
    granted = engine.authorize_scopes(
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        requested=[Scope.parse("tool:email.send:rate=10/min")],
    )
    assert granted == [Scope.parse("tool:email.send:rate=10/min")]


def test_authorize_action_denied_for_other_reason_does_not_consume_rate_budget(engine: PolicyEngine):
    # A call denied on business-hours grounds must not itself count
    # against the rate ceiling -- only admitted calls consume budget.
    scope = Scope.parse("tool:crm.write:rate=1/min")
    denied = engine.authorize_action(
        role="crm-admin", tier=CertificateTier.ENTERPRISE, scope=scope,
        context=ActionContext(timestamp=AFTER_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert denied.allowed is False
    assert "business hours" in denied.reason
    allowed = engine.authorize_action(
        role="crm-admin", tier=CertificateTier.ENTERPRISE, scope=scope,
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0, agent_id="a1"),
    )
    assert allowed.allowed is True


def test_authorize_action_denies_role_without_grant(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="support-triage",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="crm.delete"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0),
    )
    assert decision.allowed is False


def test_tool_sandbox_limits_none_for_tool_with_no_override(engine: PolicyEngine):
    assert engine.tool_sandbox_limits("email.send") == (None, None)


def test_tool_sandbox_limits_none_for_unregistered_tool(engine: PolicyEngine):
    assert engine.tool_sandbox_limits("does.not.exist") == (None, None)


def test_tool_sandbox_limits_reads_registered_overrides(ca: ReferenceCA):
    import dataclasses

    base_bundle = default_bundle()
    narrowed = dataclasses.replace(
        base_bundle.tools["email.send"], max_execution_seconds=2.5, max_result_bytes=4096
    )
    custom_bundle = dataclasses.replace(base_bundle, tools={**base_bundle.tools, "email.send": narrowed})
    engine = PolicyEngine(ca=ca, bundle=custom_bundle)
    assert engine.tool_sandbox_limits("email.send") == (2.5, 4096)


def test_signed_bundle_accepted_from_policy_admin(ca: ReferenceCA):
    admin_priv, admin_pub = ReferenceCA.generate_keypair()
    issued = ca.issue(
        agent_id="admin-1",
        role="policy-admin",
        tier=CertificateTier.ENTERPRISE,
        public_key_pem=admin_pub,
    )
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(admin_priv, password=None)

    bundle = default_bundle()
    signature = sign_bundle(bundle, key)

    engine = PolicyEngine.with_signed_bundle(
        ca=ca,
        bundle=bundle,
        signature=signature,
        signer_cert_pem=issued.certificate_pem,
    )
    assert engine.bundle_hash == bundle.content_hash()


def test_signed_bundle_rejected_from_non_admin_role(ca: ReferenceCA):
    priv, pub = ReferenceCA.generate_keypair()
    issued = ca.issue(
        agent_id="not-admin",
        role="sales-assistant",
        tier=CertificateTier.ENTERPRISE,
        public_key_pem=pub,
    )
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(priv, password=None)
    bundle = default_bundle()
    signature = sign_bundle(bundle, key)

    with pytest.raises(BundleSignatureError, match="not authorized"):
        PolicyEngine.with_signed_bundle(
            ca=ca, bundle=bundle, signature=signature, signer_cert_pem=issued.certificate_pem
        )


def test_signed_bundle_rejected_if_tampered_after_signing(ca: ReferenceCA):
    admin_priv, admin_pub = ReferenceCA.generate_keypair()
    issued = ca.issue(
        agent_id="admin-2",
        role="policy-admin",
        tier=CertificateTier.ENTERPRISE,
        public_key_pem=admin_pub,
    )
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(admin_priv, password=None)
    bundle = default_bundle()
    signature = sign_bundle(bundle, key)

    tampered = PolicyBundle(
        version=bundle.version,
        tools={
            **bundle.tools,
            "crm.delete": ToolDefinition(
                name="crm.delete", description="now free for everyone", sensitivity=Sensitivity.LOW
            ),
        },
        role_grants=bundle.role_grants,
        created_at=bundle.created_at,
    )

    with pytest.raises(BundleSignatureError, match="does not verify"):
        PolicyEngine.with_signed_bundle(
            ca=ca, bundle=tampered, signature=signature, signer_cert_pem=issued.certificate_pem
        )


def test_signed_bundle_rejected_if_signer_revoked(ca: ReferenceCA):
    admin_priv, admin_pub = ReferenceCA.generate_keypair()
    issued = ca.issue(
        agent_id="admin-3",
        role="policy-admin",
        tier=CertificateTier.ENTERPRISE,
        public_key_pem=admin_pub,
    )
    ca.revoke(issued.serial_number)
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(admin_priv, password=None)
    bundle = default_bundle()
    signature = sign_bundle(bundle, key)

    with pytest.raises(BundleSignatureError, match="not currently valid"):
        PolicyEngine.with_signed_bundle(
            ca=ca, bundle=bundle, signature=signature, signer_cert_pem=issued.certificate_pem
        )
