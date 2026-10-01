"""
Block 4 — Policy Engine.

Two responsibilities, matching the guide's split between the permission
model (RBAC, checked once at token mint) and continuous authorization
(ABAC, re-checked on every action):

1. ``authorize_scopes`` — implements Block 3's ``ScopeAuthorizer``
   protocol. Deny-by-default RBAC: a scope is only granted if the
   agent's role has a matching pattern *and* the tool is registered in
   the loaded policy bundle, *and* the agent's certificate tier meets
   the tool's minimum tier requirement.
2. ``authorize_action`` — ABAC, called by Agent Guard on every request
   (not just at mint time): checks the live context (time of day, risk
   score) against the tool's constraints, so a token minted when
   everything looked fine can still be denied for a specific action if
   context changed since.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from observable.pki.interface import CertificateAuthority, CertificateStatus, CertificateTier
from observable.pki.validate import CertificateValidationError, validate_chain
from observable.policy.bundle import PolicyBundle, Sensitivity
from observable.policy.elevation import ElevationStore
from observable.policy.ratelimit import RateLimiter
from observable.tokens.scope import InvalidScopeError, Scope

TIER_ORDER: dict[CertificateTier, int] = {
    CertificateTier.FOUNDATION: 0,
    CertificateTier.ENTERPRISE: 1,
    CertificateTier.ADVANCED: 2,
}

POLICY_ADMIN_ROLE = "policy-admin"


class PolicyError(Exception):
    pass


class BundleSignatureError(PolicyError):
    """Raised when a policy bundle's signature doesn't verify, or the
    signer isn't a currently-valid, currently-active policy-admin
    certificate. Loading is refused outright — there is no "load
    unsigned and warn" fallback once signing is required."""


@dataclasses.dataclass(frozen=True)
class ActionContext:
    timestamp: dt.datetime
    risk_score: float = 0.0
    resource_id: Optional[str] = None
    agent_id: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _default_is_business_hours(timestamp: dt.datetime) -> bool:
    """Naive Mon-Fri 08:00-18:00 UTC business-hours check. Real
    deployments would inject a org-calendar-aware callable instead."""
    local = timestamp.astimezone(dt.timezone.utc)
    return local.weekday() < 5 and 8 <= local.hour < 18


def sign_bundle(bundle: PolicyBundle, signer_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Convenience for a policy-admin to sign a bundle they authored.
    Not part of PolicyEngine itself — signing happens out of band, by
    whoever holds the policy-admin private key, not by the running
    Observable service."""
    return signer_private_key.sign(bundle.canonical_bytes(), ec.ECDSA(hashes.SHA256()))


class PolicyEngine:
    def __init__(
        self,
        *,
        ca: CertificateAuthority,
        bundle: Optional[PolicyBundle] = None,
        business_hours_check=_default_is_business_hours,
        elevation: Optional[ElevationStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._ca = ca
        self._business_hours_check = business_hours_check
        self._bundle: Optional[PolicyBundle] = None
        self._bundle_hash: Optional[str] = None
        self._bundle_signed: bool = False
        self._elevation = elevation if elevation is not None else ElevationStore()
        self._rate_limiter = rate_limiter if rate_limiter is not None else RateLimiter()
        if bundle is not None:
            self.load_unsigned_bundle(bundle)

    @property
    def elevation(self) -> ElevationStore:
        """The engine's just-in-time elevation store (§4b) — owned here
        (always present, never None) rather than by the caller, so
        ``authorize_scopes``/``authorize_action`` can always consult it
        without a None-check at every call site, and so Agent Guard's
        ``grant_elevation``/``revoke_elevation`` write to the exact same
        store this engine reads from."""
        return self._elevation

    @property
    def rate_limiter(self) -> RateLimiter:
        """The engine's call-rate counter (§9.9) — always present, same
        reasoning as ``elevation`` above."""
        return self._rate_limiter

    @classmethod
    def with_signed_bundle(
        cls,
        *,
        ca: CertificateAuthority,
        bundle: PolicyBundle,
        signature: bytes,
        signer_cert_pem: bytes,
        business_hours_check=_default_is_business_hours,
    ) -> "PolicyEngine":
        """Construct an engine whose *first* loaded bundle must already
        be validly signed by a policy-admin certificate — for
        deployments where an unsigned bundle should never be loadable,
        not even at startup."""
        engine = cls(ca=ca, business_hours_check=business_hours_check)
        engine.load_signed_bundle(bundle=bundle, signature=signature, signer_cert_pem=signer_cert_pem)
        return engine

    # ------------------------------------------------------------------
    def load_signed_bundle(
        self, *, bundle: PolicyBundle, signature: bytes, signer_cert_pem: bytes
    ) -> None:
        """Verify ``signature`` was produced by a valid, non-revoked
        certificate whose role is ``policy-admin``, over exactly
        ``bundle.canonical_bytes()``. Only on success does the engine
        start using the new bundle."""
        try:
            identity = validate_chain(signer_cert_pem, self._ca.trusted_chain_pem())
        except CertificateValidationError as exc:
            raise BundleSignatureError(f"signer certificate invalid: {exc}") from exc

        if self._ca.status(identity.serial_number).status != CertificateStatus.VALID:
            raise BundleSignatureError("signer certificate is not currently valid")
        if identity.role != POLICY_ADMIN_ROLE:
            raise BundleSignatureError(
                f"signer role {identity.role!r} is not authorized to sign policy bundles"
            )

        leaf = x509.load_pem_x509_certificate(signer_cert_pem)
        public_key = leaf.public_key()
        try:
            public_key.verify(signature, bundle.canonical_bytes(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise BundleSignatureError("bundle signature does not verify") from exc

        self._bundle = bundle
        self._bundle_hash = bundle.content_hash()
        self._bundle_signed = True

    def load_unsigned_bundle(self, bundle: PolicyBundle) -> None:
        """Dev/test convenience — loads a bundle with no signature
        check at all. Production deployments should use
        ``load_signed_bundle`` exclusively (ARCHITECTURE.md Enterprise
        row: "signed configurations with deployment verification")."""
        self._bundle = bundle
        self._bundle_hash = bundle.content_hash()
        self._bundle_signed = False

    @property
    def bundle_hash(self) -> str:
        return self._bundle_hash

    @property
    def bundle_version(self) -> str:
        return self._bundle.version

    @property
    def bundle_signed(self) -> bool:
        """Whether the currently loaded bundle came in through
        ``load_signed_bundle`` (verified against a policy-admin
        certificate) rather than ``load_unsigned_bundle``. Read by the
        compliance framework (§9) for the "version-controlled / signed
        policy" control."""
        return self._bundle_signed

    # ------------------------------------------------------------------
    # Block 3's ScopeAuthorizer protocol
    # ------------------------------------------------------------------
    def authorize_scopes(
        self,
        *,
        role: str,
        tier: CertificateTier,
        requested: list[Scope],
        agent_id: Optional[str] = None,
        now: Optional[dt.datetime] = None,
    ) -> list[Scope]:
        now = now or dt.datetime.now(dt.timezone.utc)
        granted: list[Scope] = []
        for scope in requested:
            tool = self._bundle.tools.get(scope.tool)
            if tool is None:
                continue  # unregistered tool: never granted, deny-by-default -- elevation can't create a tool
            if tool.min_tier is not None:
                required = CertificateTier(tool.min_tier)
                if TIER_ORDER[tier] < TIER_ORDER[required]:
                    continue  # tier floor applies equally to a static role grant and an elevated one
            try:
                scope.resource_allowlist()  # validate the constraint parses, fail closed if not
                scope.rate_limit()
            except InvalidScopeError:
                continue  # malformed constraint: never minted into a token, same as an unregistered tool
            if self._bundle.resolve_role(role, scope.tool):
                granted.append(scope)
                continue
            # The static role doesn't carry this tool -- fall back to an
            # active just-in-time elevation grant (§4b) for this specific
            # agent, if one covers it. Mint exactly the grant's own scope
            # (never the raw request) so an elevation can only ever narrow
            # what's minted, never be used to ask for more than what was
            # actually approved.
            elevated = self._elevation.grant_for_token(agent_id=agent_id, tool=scope.tool, now=now)
            if elevated is not None:
                granted.append(elevated.scope)
        return granted

    # ------------------------------------------------------------------
    # ABAC / continuous authorization, called by Agent Guard per request
    # ------------------------------------------------------------------
    def authorize_action(
        self, *, role: str, tier: CertificateTier, scope: Scope, context: ActionContext
    ) -> Decision:
        tool = self._bundle.tools.get(scope.tool)
        if tool is None:
            return Decision(allowed=False, reason=f"tool {scope.tool!r} is not registered")
        if not self._bundle.resolve_role(role, scope.tool):
            # Continuous re-check, same spirit as the revocation/business-
            # hours checks below: a token minted (possibly via elevation)
            # when the grant was active can still be denied here the
            # instant that grant expires or is revoked -- no separate
            # invalidation step needed, this is simply re-evaluated fresh
            # on every single call. Deliberately resource-agnostic here:
            # ``scope`` is exactly what ``authorize_scopes`` minted (the
            # elevation's own scope, verbatim), so any resource
            # restriction is already baked into it and is enforced once,
            # below, by the same resource_allowlist check every scope
            # goes through -- not duplicated here with a less specific
            # denial reason.
            still_elevated = self._elevation.grant_for_token(
                agent_id=context.agent_id, tool=scope.tool, now=context.timestamp
            )
            if still_elevated is None:
                return Decision(allowed=False, reason=f"role {role!r} has no grant for {scope.tool!r}")
        if tool.min_tier is not None:
            required = CertificateTier(tool.min_tier)
            if TIER_ORDER[tier] < TIER_ORDER[required]:
                return Decision(
                    allowed=False,
                    reason=f"tool {scope.tool!r} requires tier >= {tool.min_tier}, agent is {tier.value}",
                )
        if tool.business_hours_only and not self._business_hours_check(context.timestamp):
            return Decision(
                allowed=False, reason=f"tool {scope.tool!r} is restricted to business hours"
            )
        if context.risk_score > tool.max_risk_score:
            return Decision(
                allowed=False,
                reason=(
                    f"risk score {context.risk_score:.2f} exceeds max "
                    f"{tool.max_risk_score:.2f} for tool {scope.tool!r}"
                ),
            )
        # Resource-scoped grants (Least Agency's "which resource", not just
        # "which tool") -- a scope minted with e.g. "resource=A-1,A-2" only
        # authorizes this tool against those specific resource_ids, not
        # every record the tool could otherwise reach.
        try:
            allowlist = scope.resource_allowlist()
        except InvalidScopeError as exc:
            # Shouldn't happen for a scope that made it through
            # authorize_scopes (which already validates this), but a
            # directly-constructed Scope (tests, a future caller) fails
            # closed here rather than being silently treated as unrestricted.
            return Decision(allowed=False, reason=f"malformed scope constraint: {exc}")
        if allowlist is not None:
            if context.resource_id is None:
                return Decision(
                    allowed=False,
                    reason=(
                        f"tool {scope.tool!r} grant is resource-scoped "
                        f"({sorted(allowlist)}) but no resource_id was given"
                    ),
                )
            if context.resource_id not in allowlist:
                return Decision(
                    allowed=False,
                    reason=(
                        f"resource {context.resource_id!r} is not in tool {scope.tool!r}'s "
                        f"granted resource set ({sorted(allowlist)})"
                    ),
                )
        # Call-rate limit (Least Agency's "how often", §9.9) -- checked
        # last, after every other check has already passed, so a call
        # that would be denied anyway (wrong tier, outside business
        # hours, resource not covered, ...) never consumes rate budget.
        # This is also the one check in this method that mutates state:
        # an admitted call is recorded here, atomically, as part of the
        # same decision that allows it.
        try:
            rate = scope.rate_limit()
        except InvalidScopeError as exc:
            return Decision(allowed=False, reason=f"malformed scope constraint: {exc}")
        if rate is not None:
            limit, window = rate
            if context.agent_id is None:
                return Decision(
                    allowed=False,
                    reason=(
                        f"tool {scope.tool!r} grant is rate-limited ({limit}/{window}) "
                        "but no agent_id was given"
                    ),
                )
            rate_decision = self._rate_limiter.check_and_record(
                agent_id=context.agent_id, tool=scope.tool, limit=limit, window=window, now=context.timestamp
            )
            if not rate_decision.allowed:
                return Decision(
                    allowed=False,
                    reason=(
                        f"rate limit exceeded for tool {scope.tool!r}: "
                        f"{rate_decision.count_in_window}/{limit} calls within {window} "
                        f"(retry after {rate_decision.retry_after})"
                    ),
                )
        return Decision(allowed=True, reason="authorized")

    def tool_sensitivity(self, tool_name: str) -> Optional[Sensitivity]:
        tool = self._bundle.tools.get(tool_name)
        return tool.sensitivity if tool else None

    def tool_description(self, tool_name: str) -> Optional[str]:
        """Registered description for a tool, read by the Detection
        Engine's intent-conformance signal (§8.5) — the same registry
        entry that already backs ``tool_sensitivity``, so a tool's
        description used to judge intent is always the one an operator
        actually registered, never a copy that can drift."""
        tool = self._bundle.tools.get(tool_name)
        return tool.description if tool else None

    def tool_sandbox_limits(self, tool_name: str) -> tuple[Optional[float], Optional[int]]:
        """``(max_execution_seconds, max_result_bytes)`` overrides
        registered for this tool (§9.10), or ``(None, None)`` if the
        tool carries no override, or isn't registered at all. Read by
        Agent Guard before each sandboxed invocation; a ``None`` in
        either slot means the caller's own configured default applies,
        the same convention ``min_tier=None`` already uses for "no
        tool-specific override."""
        tool = self._bundle.tools.get(tool_name)
        if tool is None:
            return None, None
        return tool.max_execution_seconds, tool.max_result_bytes

    def registered_tools(self) -> dict:
        """Read-only view of the currently loaded bundle's tool
        registry, keyed by tool name. Used by the compliance framework
        (§9) rather than reaching into ``_bundle`` directly."""
        return dict(self._bundle.tools) if self._bundle else {}
