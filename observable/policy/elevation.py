"""
Block 4b — Just-in-time privilege elevation.

Static RBAC (the Policy Bundle) answers "what can this role always do."
That's the Foundation-tier "static least-privilege roles per agent
function" row in ARCHITECTURE.md §5 — necessary, but not the whole of
Least Agency. The guide's Enterprise/Advanced rows ask for more:

    Enterprise: "elevate permissions only when specific tasks require
    them. Return to baseline permissions after task completion. Log
    all privilege changes."

    Advanced: "grant permissions only at moment of need. Scope access
    to specific resources for specific durations. Automatically revoke
    permissions after task completion or timeout."

This module is that: a time-boxed grant of one specific (tool[,
resource-scoped]) capability to one specific agent, beyond what its
role would otherwise allow, that stops working on its own the moment
its TTL elapses or an operator revokes it early — with no separate
cleanup step, because every check (``active_grant_for``) is evaluated
fresh against the caller's current wall clock, the same way token TTL
and CRL expiry already work elsewhere in this codebase. "Automatic"
here means exactly that: nothing has to notice the clock and go delete
anything: the check that used to say yes simply starts saying no.

The *decision* to elevate is still explicitly human (an operator, or an
upstream approval workflow calling ``AgentGuard.grant_elevation``) —
this module only enforces whatever was granted and lets it lapse; it
never decides on its own that an agent should be elevated, mirroring
the "automate the bookkeeping, not the decisions" rule Guard's
automated-containment path already follows.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import threading
import uuid
from typing import Optional

from observable.tokens.scope import InvalidScopeError, Scope


class ElevationError(Exception):
    pass


class ElevationNotFoundError(ElevationError):
    pass


@dataclasses.dataclass(frozen=True)
class ElevationGrant:
    grant_id: str
    agent_id: str
    scope: Scope
    reason: str
    granted_by: str
    granted_at: dt.datetime
    expires_at: dt.datetime
    revoked_at: Optional[dt.datetime] = None
    revoked_reason: Optional[str] = None

    def is_active(self, now: dt.datetime) -> bool:
        """The single source of truth for "does this grant still apply
        right now" -- always evaluated against a freshly-passed ``now``,
        never cached, so expiry is automatic rather than something a
        caller has to remember to check for separately."""
        return self.revoked_at is None and now < self.expires_at

    def status(self, now: dt.datetime) -> str:
        """Human-readable label for display (API/console), computed
        against ``now`` -- distinct from ``is_active``, which is what
        every authorization decision actually uses."""
        if self.revoked_at is not None:
            return "revoked"
        if now >= self.expires_at:
            return "expired"
        return "active"


class ElevationStore:
    """In-memory, per-process store of elevation grants — same
    durability model as every other piece of live state in this
    reference deployment (Identity Registry, Audit Chain, Detection
    Engine baselines): re-seeded on restart, not a source of truth
    across deploys. A production deployment would back this with
    whatever already durably stores the Policy Bundle."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, ElevationGrant] = {}

    # ------------------------------------------------------------------
    def grant(
        self,
        *,
        agent_id: str,
        scope: Scope,
        reason: str,
        granted_by: str,
        ttl: dt.timedelta,
        now: Optional[dt.datetime] = None,
    ) -> ElevationGrant:
        if ttl <= dt.timedelta(0):
            raise ElevationError("elevation ttl must be positive")
        try:
            scope.resource_allowlist()  # validate the constraint parses, fail closed if not
        except InvalidScopeError as exc:
            raise ElevationError(f"invalid scope for elevation: {exc}") from exc
        now = now or dt.datetime.now(dt.timezone.utc)
        record = ElevationGrant(
            grant_id=uuid.uuid4().hex,
            agent_id=agent_id,
            scope=scope,
            reason=reason,
            granted_by=granted_by,
            granted_at=now,
            expires_at=now + ttl,
        )
        with self._lock:
            self._grants[record.grant_id] = record
        return record

    def revoke(
        self, grant_id: str, *, reason: str, now: Optional[dt.datetime] = None
    ) -> ElevationGrant:
        """Manual early return-to-baseline, before the grant's own TTL
        would have expired it anyway. Idempotent-ish: revoking an
        already-expired or already-revoked grant still records this
        revocation (it just has no further effect on ``is_active``,
        which was already False)."""
        now = now or dt.datetime.now(dt.timezone.utc)
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise ElevationNotFoundError(f"no elevation grant {grant_id!r}")
            revoked = dataclasses.replace(grant, revoked_at=now, revoked_reason=reason)
            self._grants[grant_id] = revoked
            return revoked

    # ------------------------------------------------------------------
    def _active_candidates(self, *, agent_id: str, tool: str, now: dt.datetime) -> list[ElevationGrant]:
        with self._lock:
            candidates = [
                g
                for g in self._grants.values()
                if g.agent_id == agent_id and g.scope.tool == tool and g.is_active(now)
            ]
        candidates.sort(key=lambda g: g.granted_at, reverse=True)
        return candidates

    def grant_for_token(
        self, *, agent_id: Optional[str], tool: str, now: dt.datetime
    ) -> Optional[ElevationGrant]:
        """The most-recently-granted active grant for (agent_id, tool),
        regardless of any resource restriction it carries: "is this agent
        currently elevated for this tool at all." Used in two places: at
        *mint* time (before any specific resource_id is known), and again
        at *action* time as the resource-agnostic half of continuous
        re-authorization -- the resource restriction, if the grant has
        one, was already baked into the scope that got minted, and is
        enforced separately, per call, via that scope's own
        ``resource_allowlist()`` (not duplicated here)."""
        if agent_id is None:
            return None
        candidates = self._active_candidates(agent_id=agent_id, tool=tool, now=now)
        return candidates[0] if candidates else None

    def active_grant_for(
        self, *, agent_id: Optional[str], tool: str, resource_id: Optional[str], now: dt.datetime
    ) -> Optional[ElevationGrant]:
        """The most-recently-granted active grant (not expired, not
        revoked) for this agent covering ``tool``, if any — and, when
        the grant itself is resource-scoped, only when ``resource_id``
        is inside that grant's own allowlist (an unrestricted call
        against a resource-scoped grant, i.e. ``resource_id is None``,
        does not match: can't confirm it's covered, so it fails closed
        for that grant rather than being treated as covered). Ties are
        broken by most-recently-granted, so a newer, narrower grant
        takes precedence without needing the older one revoked first.
        Not called by the Policy Engine itself (which relies on the
        resource-agnostic ``grant_for_token`` plus the minted scope's own
        ``resource_allowlist()`` instead — see that method's docstring
        for why) — kept here as a direct, single-call answer to "can
        this agent act on this resource via elevation right now," for
        admin/API/console use."""
        if agent_id is None:
            return None
        candidates = self._active_candidates(agent_id=agent_id, tool=tool, now=now)
        for g in candidates:
            allowlist = g.scope.resource_allowlist()
            if allowlist is None:
                return g
            if resource_id is not None and resource_id in allowlist:
                return g
        return None

    def for_agent(self, agent_id: str) -> list[ElevationGrant]:
        with self._lock:
            matches = [g for g in self._grants.values() if g.agent_id == agent_id]
        return sorted(matches, key=lambda g: g.granted_at, reverse=True)

    def all_grants(self) -> list[ElevationGrant]:
        with self._lock:
            matches = list(self._grants.values())
        return sorted(matches, key=lambda g: g.granted_at, reverse=True)

    def get(self, grant_id: str) -> ElevationGrant:
        with self._lock:
            grant = self._grants.get(grant_id)
        if grant is None:
            raise ElevationNotFoundError(f"no elevation grant {grant_id!r}")
        return grant
