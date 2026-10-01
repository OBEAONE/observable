import time

import pytest

from observable.identity.registry import IdentityRegistry
from observable.pki.interface import CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.pki.validate import validate_chain
from observable.tokens.scope import Scope
from observable.tokens.service import (
    AgentNotActiveError,
    ScopeDeniedError,
    TokenInvalidError,
    TokenService,
)


class AllowAllAuthorizer:
    """Test stub: grants every requested scope."""

    def authorize_scopes(self, *, role, tier, requested, agent_id=None):
        return list(requested)


class DenyAllAuthorizer:
    def authorize_scopes(self, *, role, tier, requested, agent_id=None):
        return []


class OnlyReadAuthorizer:
    def authorize_scopes(self, *, role, tier, requested, agent_id=None):
        return [s for s in requested if s.tool == "crm.read"]


@pytest.fixture()
def ca() -> ReferenceCA:
    return ReferenceCA(org_name="Test CA")


@pytest.fixture()
def registry(ca) -> IdentityRegistry:
    return IdentityRegistry(ca)


def _enroll(registry: IdentityRegistry, role="sales-assistant"):
    _, pub = ReferenceCA.generate_keypair()
    result = registry.enroll(
        display_name=f"agent-{role}-{id(pub)}",
        role=role,
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
        enrolled_by="omar",
    )
    return result


def test_mint_and_verify_round_trip(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())

    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read"],
    )
    assert token.scopes == [Scope(tool="crm.read")]

    claims = svc.verify(
        token=token.jwt, presented_cert_thumbprint=result.certificate.sha256_thumbprint
    )
    assert claims.agent_id == result.record.agent_id
    assert claims.role == "sales-assistant"
    assert claims.scopes == [Scope(tool="crm.read")]


def test_pop_mismatch_rejected(ca, registry):
    result = _enroll(registry)
    other = _enroll(registry, role="other")
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())

    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read"],
    )
    # Attacker steals the JWT string but presents a *different* agent's
    # certificate on the connection (or their own unrelated cert).
    with pytest.raises(TokenInvalidError, match="proof-of-possession"):
        svc.verify(
            token=token.jwt,
            presented_cert_thumbprint=other.certificate.sha256_thumbprint,
        )


def test_scope_narrowing_deny_by_default(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=OnlyReadAuthorizer())

    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read", "tool:crm.delete"],
    )
    # only the read scope survives policy narrowing
    assert token.scopes == [Scope(tool="crm.read")]


def test_scope_denied_entirely_raises(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=DenyAllAuthorizer())

    with pytest.raises(ScopeDeniedError):
        svc.mint(
            client_cert_pem=result.certificate.certificate_pem,
            requested_scopes=["tool:crm.read"],
        )


def test_suspended_agent_cannot_mint_or_use_existing_token(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())

    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read"],
    )

    registry.suspend(result.record.agent_id, reason="suspicious behavior")

    with pytest.raises(AgentNotActiveError):
        svc.mint(
            client_cert_pem=result.certificate.certificate_pem,
            requested_scopes=["tool:crm.read"],
        )
    # continuous re-authorization: even the already-minted token stops
    # working immediately, without waiting for its TTL.
    with pytest.raises(AgentNotActiveError):
        svc.verify(
            token=token.jwt,
            presented_cert_thumbprint=result.certificate.sha256_thumbprint,
        )


def test_revoked_certificate_cannot_mint(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())
    registry.revoke(result.record.agent_id)

    from observable.tokens.service import AgentNotActiveError as ANA

    with pytest.raises(ANA):
        svc.mint(
            client_cert_pem=result.certificate.certificate_pem,
            requested_scopes=["tool:crm.read"],
        )


def test_explicit_token_revocation(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())
    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read"],
    )
    svc.revoke_token(token.jti)
    with pytest.raises(TokenInvalidError, match="explicitly revoked"):
        svc.verify(
            token=token.jwt,
            presented_cert_thumbprint=result.certificate.sha256_thumbprint,
        )


def test_tampered_token_rejected(ca, registry):
    result = _enroll(registry)
    svc = TokenService(ca=ca, registry=registry, scope_authorizer=AllowAllAuthorizer())
    token = svc.mint(
        client_cert_pem=result.certificate.certificate_pem,
        requested_scopes=["tool:crm.read"],
    )
    tampered = token.jwt[:-2] + ("aa" if token.jwt[-2:] != "aa" else "bb")
    with pytest.raises(TokenInvalidError):
        svc.verify(
            token=tampered, presented_cert_thumbprint=result.certificate.sha256_thumbprint
        )
