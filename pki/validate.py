"""
Block 1 — Certificate chain validation and claim extraction.

Used by the Token Service (at mint time) and Agent Guard (at every PoP
check) to verify a presented leaf certificate signs up against the
trusted Issuing CA and to pull the role/tier claims embedded in it. This
module only does cryptographic + structural checks; revocation status is
a separate CA lookup (``CertificateAuthority.status``) because that is a
live, backend-specific call (CRL/OCSP/QTSP API) rather than something you
can verify from the cert bytes alone.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from observable.pki.reference_ca import OBSERVABLE_ROLE_TIER_OID
from observable.pki.interface import CertificateTier


class CertificateValidationError(Exception):
    """Raised for any structural/cryptographic failure: bad signature,
    expired, not-yet-valid, issuer mismatch, or malformed role/tier
    extension. Revocation is checked separately by the caller."""


@dataclasses.dataclass(frozen=True)
class ValidatedIdentity:
    agent_id: str
    role: str
    tier: CertificateTier
    serial_number: str
    sha256_thumbprint: str
    not_after: dt.datetime


def _thumbprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def leaf_thumbprint(cert_pem: bytes) -> str:
    """Public helper: SHA-256 thumbprint of a PEM-encoded leaf
    certificate, in the same form used in a token's ``cnf`` claim. Used
    by Agent Guard to compute the thumbprint of whatever certificate was
    presented on the connection, for comparison against the token."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise CertificateValidationError("malformed certificate") from exc
    return _thumbprint(cert)


def _verify_signed_by(leaf: x509.Certificate, issuer: x509.Certificate) -> None:
    issuer_public_key = issuer.public_key()
    try:
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(leaf.signature_hash_algorithm),
            )
        elif isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf.signature_hash_algorithm,
            )
        else:
            raise CertificateValidationError(
                f"unsupported issuer key type {type(issuer_public_key)!r}"
            )
    except InvalidSignature as exc:
        raise CertificateValidationError("certificate signature does not verify") from exc


def validate_chain(
    leaf_cert_pem: bytes, trusted_chain_pem: bytes
) -> ValidatedIdentity:
    """Verify ``leaf_cert_pem`` was signed by the Issuing CA in
    ``trusted_chain_pem`` and is currently within its validity window,
    then extract the Observable role/tier claim embedded at issuance.

    Does NOT check revocation — callers must additionally call
    ``CertificateAuthority.status(serial_number)``.
    """
    try:
        leaf = x509.load_pem_x509_certificate(leaf_cert_pem)
    except ValueError as exc:
        raise CertificateValidationError("malformed leaf certificate") from exc

    trusted_certs = x509.load_pem_x509_certificates(trusted_chain_pem)
    if not trusted_certs:
        raise CertificateValidationError("empty trusted chain")

    issuing_cert = trusted_certs[0]  # convention: issuing CA is first in the bundle
    if leaf.issuer != issuing_cert.subject:
        raise CertificateValidationError(
            "leaf certificate was not issued by the configured Issuing CA"
        )

    _verify_signed_by(leaf, issuing_cert)

    now = dt.datetime.now(dt.timezone.utc)
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if now < not_before:
        raise CertificateValidationError("certificate is not yet valid")
    if now > not_after:
        raise CertificateValidationError("certificate has expired")

    # --- extract Observable role|tier extension ---
    try:
        ext = leaf.extensions.get_extension_for_oid(OBSERVABLE_ROLE_TIER_OID)
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError(
            "certificate missing Observable role/tier extension"
        ) from exc
    raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
    try:
        role, tier_str = raw.decode("utf-8").split("|", 1)
        tier = CertificateTier(tier_str)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CertificateValidationError("malformed role/tier extension") from exc

    # --- extract agent_id from our observable:agent:<id> SAN URI ---
    agent_id = None
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for uri in san.value.get_values_for_type(x509.UniformResourceIdentifier):
            if uri.startswith("observable:agent:"):
                agent_id = uri.removeprefix("observable:agent:")
                break
    except x509.ExtensionNotFound:
        pass
    if agent_id is None:
        raise CertificateValidationError("certificate missing observable:agent SAN URI")

    serial_hex = format(leaf.serial_number, "x")

    return ValidatedIdentity(
        agent_id=agent_id,
        role=role,
        tier=tier,
        serial_number=serial_hex,
        sha256_thumbprint=_thumbprint(leaf),
        not_after=not_after,
    )
