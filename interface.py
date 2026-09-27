"""
Block 1 — PKI foundation.

Defines the pluggable ``CertificateAuthority`` interface that every other
Observable plane depends on. Nothing above this module knows or cares whether
certificates come from an in-process reference CA (dev/test), a
self-operated CA such as EJBCA / step-ca / HashiCorp Vault PKI, or a
qualified Trust Service Provider (QTSP) reached over CMP/EST/REST.

Design intent (see ARCHITECTURE.md §2-3): Observable never holds the Root CA
key. It holds, or calls out to, an Issuing CA. The interface below is
exactly what an Issuing CA needs to expose to the rest of the platform.
"""
from __future__ import annotations

import abc
import dataclasses
import datetime as dt
import enum
from typing import Optional


class CertificateTier(str, enum.Enum):
    """Maps 1:1 to the guide's Foundation / Enterprise / Advanced tiers."""

    FOUNDATION = "foundation"
    ENTERPRISE = "enterprise"
    ADVANCED = "advanced"


# Default certificate validity per tier (ARCHITECTURE.md §4.1).
DEFAULT_VALIDITY: dict[CertificateTier, dt.timedelta] = {
    CertificateTier.FOUNDATION: dt.timedelta(days=90),
    CertificateTier.ENTERPRISE: dt.timedelta(days=7),
    CertificateTier.ADVANCED: dt.timedelta(hours=24),
}


class RevocationReason(str, enum.Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    POLICY_VIOLATION = "policy_violation"


@dataclasses.dataclass(frozen=True)
class AttestationEvidence:
    """Optional hardware-attestation evidence for the Advanced tier.

    The reference CA only checks that this is well-formed; a production
    adapter would validate ``quote`` against a platform attestation
    service (TPM quote verification, HSM key-attestation certificate,
    confidential-computing report, etc.).
    """

    device_id: str
    quote: bytes
    format: str = "tpm2-quote"


@dataclasses.dataclass(frozen=True)
class IssuedCertificate:
    """What the CA hands back after a successful issuance."""

    serial_number: str
    subject_cn: str
    agent_id: str
    role: str
    tier: CertificateTier
    certificate_pem: bytes
    chain_pem: bytes  # issuing + any intermediate certs, PEM-concatenated
    not_before: dt.datetime
    not_after: dt.datetime
    sha256_thumbprint: str  # hex digest of the leaf cert DER, used for PoP `cnf`


class CertificateStatus(str, enum.Enum):
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class CertificateStatusResult:
    status: CertificateStatus
    reason: Optional[RevocationReason] = None
    revoked_at: Optional[dt.datetime] = None


class CertificateAuthority(abc.ABC):
    """The one interface every CA backend (reference, EJBCA, step-ca,
    Vault PKI, or a QTSP adapter) must implement.

    Swapping the backend never requires touching Identity Registry,
    Token Service, Policy Engine or Agent Guard — they only depend on
    this interface.
    """

    @abc.abstractmethod
    def issue(
        self,
        *,
        agent_id: str,
        role: str,
        tier: CertificateTier,
        public_key_pem: bytes,
        san_uris: Optional[list[str]] = None,
        attestation: Optional[AttestationEvidence] = None,
        validity: Optional[dt.timedelta] = None,
    ) -> IssuedCertificate:
        """Issue a new leaf certificate for an agent.

        Implementations MUST refuse to issue an Advanced-tier certificate
        without valid ``attestation`` evidence (ARCHITECTURE.md §5).
        """

    @abc.abstractmethod
    def renew(self, serial_number: str) -> IssuedCertificate:
        """Issue a fresh certificate for the same agent/key, extending
        validity. Implementations should refuse to renew a revoked cert.
        """

    @abc.abstractmethod
    def revoke(
        self, serial_number: str, reason: RevocationReason = RevocationReason.UNSPECIFIED
    ) -> None:
        """Revoke a certificate. Must take effect for both status()
        lookups and any CRL/OCSP responder the backend exposes."""

    @abc.abstractmethod
    def status(self, serial_number: str) -> CertificateStatusResult:
        """Point-in-time status check used by the Guard gateway on every
        PoP validation (not just at token mint time)."""

    @abc.abstractmethod
    def trusted_chain_pem(self) -> bytes:
        """PEM bundle of the Issuing CA (+ intermediates) certificates,
        used by verifiers to validate a presented leaf certificate."""
