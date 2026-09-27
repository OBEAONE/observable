import pytest

from observable.identity.registry import (
    AgentAlreadyRevokedError,
    AgentStatus,
    DuplicateEnrollmentError,
    IdentityRegistry,
    UnknownAgentError,
)
from observable.pki.interface import CertificateStatus, CertificateTier, RevocationReason
from observable.pki.reference_ca import ReferenceCA


@pytest.fixture()
def registry() -> IdentityRegistry:
    return IdentityRegistry(ReferenceCA(org_name="Test CA"))


def _pub():
    _, pub = ReferenceCA.generate_keypair()
    return pub


def test_enroll_creates_active_agent(registry: IdentityRegistry):
    result = registry.enroll(
        display_name="sales-assistant-1",
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=_pub(),
        enrolled_by="omar",
    )
    assert result.record.status == AgentStatus.ACTIVE
    assert result.certificate.agent_id == result.record.agent_id
    assert registry.is_active(result.record.agent_id) is True


def test_duplicate_display_name_rejected(registry: IdentityRegistry):
    registry.enroll(
        display_name="dup",
        role="reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=_pub(),
        enrolled_by="omar",
    )
    with pytest.raises(DuplicateEnrollmentError):
        registry.enroll(
            display_name="dup",
            role="reader",
            tier=CertificateTier.FOUNDATION,
            public_key_pem=_pub(),
            enrolled_by="omar",
        )


def test_suspend_then_reinstate(registry: IdentityRegistry):
    result = registry.enroll(
        display_name="agent-x",
        role="reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=_pub(),
        enrolled_by="omar",
    )
    agent_id = result.record.agent_id

    registry.suspend(agent_id, reason="anomalous access pattern")
    assert registry.is_active(agent_id) is False
    assert registry.get(agent_id).status == AgentStatus.SUSPENDED

    registry.reinstate(agent_id)
    assert registry.is_active(agent_id) is True
    assert registry.get(agent_id).status == AgentStatus.ACTIVE


def test_revoke_is_terminal(registry: IdentityRegistry):
    result = registry.enroll(
        display_name="agent-y",
        role="reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=_pub(),
        enrolled_by="omar",
    )
    agent_id = result.record.agent_id

    registry.revoke(agent_id, reason=RevocationReason.KEY_COMPROMISE)
    assert registry.is_active(agent_id) is False
    assert registry.get(agent_id).status == AgentStatus.REVOKED

    with pytest.raises(AgentAlreadyRevokedError):
        registry.suspend(agent_id, reason="too late")
    with pytest.raises(AgentAlreadyRevokedError):
        registry.reinstate(agent_id)
    with pytest.raises(AgentAlreadyRevokedError):
        registry.renew(agent_id)


def test_renew_rotates_serial_and_updates_thumbprint(registry: IdentityRegistry):
    result = registry.enroll(
        display_name="agent-z",
        role="reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=_pub(),
        enrolled_by="omar",
    )
    agent_id = result.record.agent_id
    old_serial = result.certificate.serial_number

    renewed = registry.renew(agent_id)
    record = registry.get(agent_id)
    assert renewed.serial_number != old_serial
    assert record.current_serial == renewed.serial_number
    assert record.certificate_history == [old_serial, renewed.serial_number]


def test_unknown_agent_raises(registry: IdentityRegistry):
    with pytest.raises(UnknownAgentError):
        registry.get("does-not-exist")
    assert registry.is_active("does-not-exist") is False
