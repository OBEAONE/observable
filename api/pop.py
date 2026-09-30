"""
Block 6 — Application-layer proof-of-possession for the HTTP API.

ARCHITECTURE.md's trust model calls for mTLS termination in front of
Agent Guard, with the TLS handshake itself proving the caller holds the
private key matching its presented certificate. A real deployment
terminates that mTLS at a gateway/reverse proxy (nginx, Envoy) that
forwards the verified leaf certificate to Observable.

This reference API has no such proxy in front of it (it may be run
behind `uvicorn` directly, including inside test suites with no TLS at
all), so it cannot rely on the transport layer for PoP. Instead every
request that carries a client certificate is *also* required to carry
an application-layer signature over the request, produced with the same
private key, covering the method, path, a fresh timestamp, a single-use
nonce, and the body. Observable verifies that signature against the
certificate's own public key before doing anything else.

This is strictly additional to, not a replacement for, real mTLS: if you
do put a client-cert-verifying proxy in front of this API, keep this
layer too — it protects against a proxy that forwards the wrong header,
and against replay of a captured request.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import threading

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

MAX_CLOCK_SKEW = dt.timedelta(seconds=60)


class SignatureVerificationError(Exception):
    pass


def canonical_string(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, body_hash]).encode("utf-8")


def sign_request(
    *,
    private_key: ec.EllipticCurvePrivateKey,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    message = canonical_string(method=method, path=path, timestamp=timestamp, nonce=nonce, body=body)
    return private_key.sign(message, ec.ECDSA(hashlib_sha256_for_ec()))


def hashlib_sha256_for_ec():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


class NonceCache:
    """Single-use-nonce tracking with a short retention window, so a
    captured (signature, timestamp, nonce, body) tuple cannot be
    replayed even within the freshness window."""

    def __init__(self, retention: dt.timedelta = dt.timedelta(minutes=5)) -> None:
        self._retention = retention
        self._lock = threading.Lock()
        self._seen: dict[str, dt.datetime] = {}

    def check_and_record(self, nonce: str) -> bool:
        """Returns True if this nonce is fresh (and records it),
        False if it has already been used."""
        now = dt.datetime.now(dt.timezone.utc)
        with self._lock:
            self._prune(now)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def _prune(self, now: dt.datetime) -> None:
        expired = [n for n, seen_at in self._seen.items() if now - seen_at > self._retention]
        for n in expired:
            del self._seen[n]


def verify_request_signature(
    *,
    client_cert_pem: bytes,
    signature: bytes,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    nonce_cache: NonceCache,
) -> None:
    """Raises SignatureVerificationError on any failure: stale
    timestamp, reused nonce, or a signature that doesn't verify against
    the presented certificate's public key."""
    try:
        request_time = dt.datetime.fromisoformat(timestamp)
        if request_time.tzinfo is None:
            request_time = request_time.replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise SignatureVerificationError(f"malformed timestamp: {exc}") from exc

    now = dt.datetime.now(dt.timezone.utc)
    if abs(now - request_time) > MAX_CLOCK_SKEW:
        raise SignatureVerificationError("request timestamp is outside the allowed clock skew")

    if not nonce_cache.check_and_record(nonce):
        raise SignatureVerificationError("nonce has already been used (possible replay)")

    try:
        cert = x509.load_pem_x509_certificate(client_cert_pem)
    except ValueError as exc:
        raise SignatureVerificationError(f"malformed client certificate: {exc}") from exc

    message = canonical_string(method=method, path=path, timestamp=timestamp, nonce=nonce, body=body)
    public_key = cert.public_key()
    try:
        public_key.verify(signature, message, ec.ECDSA(hashlib_sha256_for_ec()))
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "request signature does not verify against the presented certificate"
        ) from exc
    except Exception as exc:  # unsupported key type etc.
        raise SignatureVerificationError(f"signature verification failed: {exc}") from exc
