"""
Block 3 — Token Service.

Mints short-lived, certificate-bound (proof-of-possession) access tokens
and verifies them at request time. See ARCHITECTURE.md §4.2 and §6.

Key property this module exists to enforce: a bearer of the JWT string
alone can do nothing with it. The token is only valid when presented
*over the same mTLS connection* as the certificate whose SHA-256
thumbprint is embedded in the token's ``cnf`` claim (RFC 7800/8705-style
PoP binding). Agent Guard (Block 5) is what actually terminates mTLS and
performs that comparison; this module gives it ``verify()`` to do so.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import time
import uuid
from typing import Optional, Protocol

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from observable.identity.registry import IdentityRegistry
from observable.pki.interface import CertificateStatus, CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.pki.validate import CertificateValidationError, validate_chain
from observable.tokens.scope import Scope, format_scopes, parse_scope_string

JWT_ALGORITHM = "ES256"

# Token TTL per tier (ARCHITECTURE.md §4.2). Advanced deliberately uses a
# very short TTL because the guide's Advanced-tier control is continuous
# per-request authorization, not a longer-lived session token.
DEFAULT_TOKEN_TTL: dict[CertificateTier, dt.timedelta] = {
    CertificateTier.FOUNDATION: dt.timedelta(minutes=15),
    CertificateTier.ENTERPRISE: dt.timedelta(minutes=5),
    CertificateTier.ADVANCED: dt.timedelta(seconds=60),
}

TOKEN_AUDIENCE = "observable-gateway"
TOKEN_ISSUER = "observable-token-service"


class TokenError(Exception):
    """Base error for token mint/verify operations."""


class ScopeDeniedError(TokenError):
    """Raised when none of the requested scopes are authorized for the
    agent's role."""


class TokenExpiredError(TokenError):
    pass


class TokenInvalidError(TokenError):
    """Bad signature, malformed claims, wrong audience/issuer, or (most
    importantly) a proof-of-possession mismatch between the token's
    ``cnf`` thumbprint and the certificate actually presented on the
    connection."""


class AgentNotActiveError(TokenError):
    """The presenting agent is suspended, revoked, or unknown to the
    Identity Registry."""


class ScopeAuthorizer(Protocol):
    """What the Token Service needs from a policy engine. Defined here
    (rather than importing Block 4 directly) so Token Service has no
    hard dependency on Policy Engine's implementation — any object
    satisfying this Protocol works, including a stub in tests."""

    def authorize_scopes(
        self, *, role: str, tier: CertificateTier, requested: list[Scope]
    ) -> list[Scope]:
        """Return the subset of ``requested`` scopes this role/tier is
        granted. An empty return means deny-by-default: nothing was
        explicitly granted."""
        ...


@dataclasses.dataclass(frozen=True)
class AccessToken:
    jwt: str
    jti: str
    agent_id: str
    scopes: list[Scope]
    issued_at: dt.datetime
    expires_at: dt.datetime


@dataclasses.dataclass(frozen=True)
class VerifiedTokenClaims:
    jti: str
    agent_id: str
    role: str
    tier: CertificateTier
    scopes: list[Scope]
    cnf_thumbprint: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    risk_score_at_mint: float = 0.0
    purpose: Optional[str] = None


class TokenService:
    def __init__(
        self,
        *,
        ca: ReferenceCA,
        registry: IdentityRegistry,
        scope_authorizer: ScopeAuthorizer,
    ) -> None:
        self._ca = ca
        self._registry = registry
        self._authorizer = scope_authorizer
        self._signing_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key_pem = self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # jti -> revoked flag, so a specific token can be killed early
        # (e.g. by automated containment) without waiting for its TTL.
        self._revoked_jtis: set[str] = set()

    @property
    def public_key_pem(self) -> bytes:
        """Exposed so a separately-deployed Guard instance could verify
        tokens without holding the private key. In this single-process
        reference deployment Guard just calls ``verify()`` directly."""
        return self._public_key_pem

    # ------------------------------------------------------------------
    def mint(
        self,
        *,
        client_cert_pem: bytes,
        requested_scopes: list[str],
        purpose: Optional[str] = None,
        risk_score: float = 0.0,
    ) -> AccessToken:
        """Mint a token for the agent presenting ``client_cert_pem``.

        Steps mirror ARCHITECTURE.md §6 step 2: validate the cert chains
        to our trusted CA and isn't revoked, confirm the agent is active
        in the registry, authorize the requested scopes against policy,
        then mint a PoP-bound JWT with only the granted scopes.
        """
        try:
            identity = validate_chain(client_cert_pem, self._ca.trusted_chain_pem())
        except CertificateValidationError as exc:
            raise TokenInvalidError(f"client certificate rejected: {exc}") from exc

        status = self._ca.status(identity.serial_number)
        if status.status != CertificateStatus.VALID:
            raise AgentNotActiveError(
                f"certificate {identity.serial_number} is {status.status.value}"
            )
        if not self._registry.is_active(identity.agent_id):
            raise AgentNotActiveError(f"agent {identity.agent_id} is not active")

        parsed_requested = [Scope.parse(s) for s in requested_scopes]
        granted = self._authorizer.authorize_scopes(
            role=identity.role, tier=identity.tier, requested=parsed_requested
        )
        if not granted:
            raise ScopeDeniedError(
                f"none of the requested scopes are authorized for role={identity.role!r}"
            )

        now = dt.datetime.now(dt.timezone.utc)
        ttl = DEFAULT_TOKEN_TTL[identity.tier]
        expires_at = now + ttl
        jti = str(uuid.uuid4())

        claims = {
            "iss": TOKEN_ISSUER,
            "sub": f"agent:{identity.agent_id}",
            "aud": TOKEN_AUDIENCE,
            "cnf": {"x5t#S256": identity.sha256_thumbprint},
            "scope": format_scopes(granted),
            "role": identity.role,
            "tier": identity.tier.value,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": jti,
            "req_ctx": {"risk_score": risk_score, "purpose": purpose},
        }
        token_str = pyjwt.encode(claims, self._signing_key, algorithm=JWT_ALGORITHM)

        return AccessToken(
            jwt=token_str,
            jti=jti,
            agent_id=identity.agent_id,
            scopes=granted,
            issued_at=now,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------
    def verify(self, *, token: str, presented_cert_thumbprint: str) -> VerifiedTokenClaims:
        """Verify signature, expiry, audience/issuer, explicit
        early-revocation, and — the control that actually makes a stolen
        token worthless — that the ``cnf`` thumbprint matches the
        certificate presented on *this* connection.
        """
        try:
            payload = pyjwt.decode(
                token,
                self._signing_key.public_key(),
                algorithms=[JWT_ALGORITHM],
                audience=TOKEN_AUDIENCE,
                issuer=TOKEN_ISSUER,
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except pyjwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"token failed verification: {exc}") from exc

        jti = payload.get("jti")
        if not jti:
            raise TokenInvalidError("token missing jti")
        if jti in self._revoked_jtis:
            raise TokenInvalidError(f"token {jti} has been explicitly revoked")

        cnf_thumb = (payload.get("cnf") or {}).get("x5t#S256")
        if not cnf_thumb:
            raise TokenInvalidError("token missing cnf (proof-of-possession) claim")
        if cnf_thumb != presented_cert_thumbprint:
            raise TokenInvalidError(
                "proof-of-possession mismatch: token was not minted for the "
                "certificate presented on this connection"
            )

        agent_id = payload["sub"].removeprefix("agent:")

        # Continuous re-check, not just at mint time (Advanced-tier
        # control from ARCHITECTURE.md §5): if the agent was suspended
        # or revoked *after* this token was minted, it stops working
        # immediately rather than riding out its TTL.
        if not self._registry.is_active(agent_id):
            raise AgentNotActiveError(f"agent {agent_id} is not active")

        req_ctx = payload.get("req_ctx") or {}
        return VerifiedTokenClaims(
            jti=jti,
            agent_id=agent_id,
            role=payload["role"],
            tier=CertificateTier(payload["tier"]),
            scopes=parse_scope_string(payload["scope"]),
            cnf_thumbprint=cnf_thumb,
            issued_at=dt.datetime.fromtimestamp(payload["iat"], tz=dt.timezone.utc),
            expires_at=dt.datetime.fromtimestamp(payload["exp"], tz=dt.timezone.utc),
            risk_score_at_mint=float(req_ctx.get("risk_score") or 0.0),
            purpose=req_ctx.get("purpose"),
        )

    def revoke_token(self, jti: str) -> None:
        """Kill a specific outstanding token before its TTL expires —
        used by automated containment (Block 5) alongside (or instead
        of) suspending the whole agent."""
        self._revoked_jtis.add(jti)
