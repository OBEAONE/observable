import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from observable.pki.interface import AttestationEvidence, CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import PolicyBundle, RoleGrant, Sensitivity, ToolDefinition, default_bundle
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


def test_authorize_action_denies_role_without_grant(engine: PolicyEngine):
    decision = engine.authorize_action(
        role="support-triage",
        tier=CertificateTier.FOUNDATION,
        scope=Scope(tool="crm.delete"),
        context=ActionContext(timestamp=BUSINESS_HOURS, risk_score=0.0),
    )
    assert decision.allowed is False


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
