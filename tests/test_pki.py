import datetime as dt

import pytest

from observable.pki.interface import (
    AttestationEvidence,
    CertificateStatus,
    CertificateTier,
    RevocationReason,
)
from observable.pki.reference_ca import (
    AttestationRequiredError,
    ReferenceCA,
    RevokedCertificateError,
    UnknownSerialError,
)
from observable.pki.validate import CertificateValidationError, validate_chain


@pytest.fixture()
def ca() -> ReferenceCA:
    return ReferenceCA(org_name="Test CA")


def _keypair():
    return ReferenceCA.generate_keypair()


def test_issue_foundation_certificate(ca: ReferenceCA):
    _, pub = _keypair()
    issued = ca.issue(
        agent_id="agent-1",
        role="sales-assistant",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
    )
    assert issued.agent_id == "agent-1"
    assert issued.tier == CertificateTier.FOUNDATION
    assert issued.not_after - issued.not_before <= dt.timedelta(days=91)
    assert ca.status(issued.serial_number).status == CertificateStatus.VALID


def test_advanced_tier_requires_attestation(ca: ReferenceCA):
    _, pub = _keypair()
    with pytest.raises(AttestationRequiredError):
        ca.issue(
            agent_id="agent-2",
            role="finance-bot",
            tier=CertificateTier.ADVANCED,
            public_key_pem=pub,
        )

    # with attestation evidence, it succeeds
    issued = ca.issue(
        agent_id="agent-2",
        role="finance-bot",
        tier=CertificateTier.ADVANCED,
        public_key_pem=pub,
        attestation=AttestationEvidence(device_id="tpm-1", quote=b"fake-quote"),
    )
    assert issued.tier == CertificateTier.ADVANCED
    assert issued.not_after - issued.not_before <= dt.timedelta(hours=25)


def test_revoke_marks_status_and_blocks_renew(ca: ReferenceCA):
    _, pub = _keypair()
    issued = ca.issue(
        agent_id="agent-3",
        role="crm-reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
    )
    ca.revoke(issued.serial_number, reason=RevocationReason.KEY_COMPROMISE)
    status = ca.status(issued.serial_number)
    assert status.status == CertificateStatus.REVOKED
    assert status.reason == RevocationReason.KEY_COMPROMISE

    with pytest.raises(RevokedCertificateError):
        ca.renew(issued.serial_number)


def test_renew_issues_new_serial_same_agent(ca: ReferenceCA):
    _, pub = _keypair()
    issued = ca.issue(
        agent_id="agent-4",
        role="crm-reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
    )
    renewed = ca.renew(issued.serial_number)
    assert renewed.serial_number != issued.serial_number
    assert renewed.agent_id == issued.agent_id
    assert renewed.role == issued.role


def test_unknown_serial_raises(ca: ReferenceCA):
    with pytest.raises(UnknownSerialError):
        ca.revoke("deadbeef")
    assert ca.status("deadbeef").status == CertificateStatus.UNKNOWN


def test_validate_chain_succeeds_for_issued_cert(ca: ReferenceCA):
    _, pub = _keypair()
    issued = ca.issue(
        agent_id="agent-5",
        role="email-drafter",
        tier=CertificateTier.ENTERPRISE,
        public_key_pem=pub,
    )
    identity = validate_chain(issued.certificate_pem, ca.trusted_chain_pem())
    assert identity.agent_id == "agent-5"
    assert identity.role == "email-drafter"
    assert identity.tier == CertificateTier.ENTERPRISE
    assert identity.serial_number == issued.serial_number
    assert identity.sha256_thumbprint == issued.sha256_thumbprint


def test_validate_chain_rejects_foreign_ca(ca: ReferenceCA):
    other_ca = ReferenceCA(org_name="Attacker CA")
    _, pub = _keypair()
    issued = other_ca.issue(
        agent_id="agent-evil",
        role="anything",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
    )
    with pytest.raises(CertificateValidationError):
        validate_chain(issued.certificate_pem, ca.trusted_chain_pem())


def test_validate_chain_rejects_tampered_cert(ca: ReferenceCA):
    _, pub = _keypair()
    issued = ca.issue(
        agent_id="agent-6",
        role="reader",
        tier=CertificateTier.FOUNDATION,
        public_key_pem=pub,
    )
    tampered = issued.certificate_pem.replace(b"A", b"B", 1)
    with pytest.raises(CertificateValidationError):
        validate_chain(tampered, ca.trusted_chain_pem())
