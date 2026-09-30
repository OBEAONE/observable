"""
Block 1 — Reference CA implementation.

A software-only, in-process Certificate Authority that implements the
``CertificateAuthority`` interface. This is what Observable runs in dev/test
and in the demo. It is NOT what you point at real agents in production —
for that, write an adapter (EJBCA / step-ca / Vault PKI / QTSP REST-CMP)
against the same interface; everything above the interface is unaffected.

The reference CA still does the real cryptographic work: it generates its
own self-signed root+issuing keypair on first use, signs real X.509
certificates, and enforces the Advanced-tier attestation requirement.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import threading
import uuid
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from observable.pki.interface import (
    AttestationEvidence,
    CertificateAuthority,
    CertificateStatus,
    CertificateStatusResult,
    CertificateTier,
    DEFAULT_VALIDITY,
    IssuedCertificate,
    RevocationReason,
)

# Custom OID (see ARCHITECTURE.md §4.1) carrying role + tier as a UTF-8
# string "role|tier" inside a UTF8String extension. Using a private OID
# under the enterprise-number the platform reserves for this purpose.
OBSERVABLE_ROLE_TIER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1")

OBSERVABLE_URI_SCHEME = "observable:agent:"


class CAError(Exception):
    """Base error for CA operations (issuance refused, unknown serial, ...)."""


class UnknownSerialError(CAError):
    pass


class AttestationRequiredError(CAError):
    pass


class RevokedCertificateError(CAError):
    pass


def _thumbprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class ReferenceCA(CertificateAuthority):
    """Self-contained root+issuing CA for development, testing, and demos.

    Thread-safe: a single ReferenceCA instance can back a multi-worker
    FastAPI process (guarded by a lock around the in-memory issuance
    ledger).
    """

    def __init__(self, *, org_name: str = "Observable Dev CA") -> None:
        self._lock = threading.RLock()
        self._org_name = org_name

        # Root key never "leaves" this object, mirroring how a real
        # deployment keeps the root offline/HSM-held and only exposes the
        # issuing intermediate to the platform.
        self._root_key = ec.generate_private_key(ec.SECP256R1())
        self._root_cert = self._make_root_cert()

        self._issuing_key = ec.generate_private_key(ec.SECP256R1())
        self._issuing_cert = self._make_issuing_cert()

        # serial (hex str) -> record
        self._ledger: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Root / issuing cert bootstrap
    # ------------------------------------------------------------------
    def _make_root_cert(self) -> x509.Certificate:
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_name),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_name} Root"),
            ]
        )
        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._root_key.public_key()),
                critical=False,
            )
        )
        return builder.sign(self._root_key, hashes.SHA256())

    def _make_issuing_cert(self) -> x509.Certificate:
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_name),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_name} Issuing CA"),
            ]
        )
        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_cert.subject)
            .public_key(self._issuing_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._issuing_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._root_key.public_key()
                ),
                critical=False,
            )
        )
        return builder.sign(self._root_key, hashes.SHA256())

    # ------------------------------------------------------------------
    # CertificateAuthority interface
    # ------------------------------------------------------------------
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
        if tier == CertificateTier.ADVANCED and attestation is None:
            raise AttestationRequiredError(
                "Advanced-tier certificates require hardware attestation evidence"
            )

        public_key = serialization.load_pem_public_key(public_key_pem)

        with self._lock:
            now = dt.datetime.now(dt.timezone.utc)
            not_before = now - dt.timedelta(minutes=1)
            not_after = now + (validity or DEFAULT_VALIDITY[tier])

            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_name),
                    x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{agent_id}"),
                ]
            )

            san_list: list[x509.GeneralName] = [
                x509.UniformResourceIdentifier(f"{OBSERVABLE_URI_SCHEME}{agent_id}")
            ]
            for uri in san_uris or []:
                san_list.append(x509.UniformResourceIdentifier(uri))

            role_tier_value = f"{role}|{tier.value}".encode("utf-8")

            serial = x509.random_serial_number()
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._issuing_cert.subject)
                .public_key(public_key)
                .serial_number(serial)
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                    critical=False,
                )
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .add_extension(
                    x509.UnrecognizedExtension(OBSERVABLE_ROLE_TIER_OID, role_tier_value),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        self._issuing_key.public_key()
                    ),
                    critical=False,
                )
            )
            cert = builder.sign(self._issuing_key, hashes.SHA256())

            serial_hex = format(serial, "x")
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            chain_pem = cert_pem + self.trusted_chain_pem()
            thumb = _thumbprint(cert)

            self._ledger[serial_hex] = {
                "agent_id": agent_id,
                "role": role,
                "tier": tier,
                "revoked": False,
                "revoked_reason": None,
                "revoked_at": None,
                "not_after": not_after,
                "public_key_pem": public_key_pem,
                "cert_pem": cert_pem,
                "thumbprint": thumb,
            }

            return IssuedCertificate(
                serial_number=serial_hex,
                subject_cn=f"agent:{agent_id}",
                agent_id=agent_id,
                role=role,
                tier=tier,
                certificate_pem=cert_pem,
                chain_pem=chain_pem,
                not_before=not_before,
                not_after=not_after,
                sha256_thumbprint=thumb,
            )

    def renew(self, serial_number: str) -> IssuedCertificate:
        with self._lock:
            record = self._ledger.get(serial_number)
            if record is None:
                raise UnknownSerialError(serial_number)
            if record["revoked"]:
                raise RevokedCertificateError(
                    f"cannot renew revoked certificate {serial_number}"
                )
            return self.issue(
                agent_id=record["agent_id"],
                role=record["role"],
                tier=record["tier"],
                public_key_pem=record["public_key_pem"],
            )

    def revoke(
        self, serial_number: str, reason: RevocationReason = RevocationReason.UNSPECIFIED
    ) -> None:
        with self._lock:
            record = self._ledger.get(serial_number)
            if record is None:
                raise UnknownSerialError(serial_number)
            record["revoked"] = True
            record["revoked_reason"] = reason
            record["revoked_at"] = dt.datetime.now(dt.timezone.utc)

    def status(self, serial_number: str) -> CertificateStatusResult:
        with self._lock:
            record = self._ledger.get(serial_number)
            if record is None:
                return CertificateStatusResult(status=CertificateStatus.UNKNOWN)
            if record["revoked"]:
                return CertificateStatusResult(
                    status=CertificateStatus.REVOKED,
                    reason=record["revoked_reason"],
                    revoked_at=record["revoked_at"],
                )
            if dt.datetime.now(dt.timezone.utc) > record["not_after"]:
                return CertificateStatusResult(status=CertificateStatus.EXPIRED)
            return CertificateStatusResult(status=CertificateStatus.VALID)

    def trusted_chain_pem(self) -> bytes:
        return self._issuing_cert.public_bytes(
            serialization.Encoding.PEM
        ) + self._root_cert.public_bytes(serialization.Encoding.PEM)

    # ------------------------------------------------------------------
    # Test/demo convenience (not part of the CertificateAuthority interface)
    # ------------------------------------------------------------------
    def record_for(self, serial_number: str) -> Optional[dict]:
        """Expose the internal ledger record for a serial — used by the
        chain validator and by tests. Not part of the abstract interface
        so production adapters are free to omit it."""
        with self._lock:
            return self._ledger.get(serial_number)

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Convenience for callers (agents, tests) that need an EC P-256
        keypair to request a certificate for. Returns (private_pem,
        public_pem)."""
        key = ec.generate_private_key(ec.SECP256R1())
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem
