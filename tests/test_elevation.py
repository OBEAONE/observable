import datetime as dt

import pytest

from observable.policy.elevation import (
    ElevationError,
    ElevationNotFoundError,
    ElevationStore,
)
from observable.tokens.scope import Scope

T0 = dt.datetime(2026, 9, 21, 10, 0, 0, tzinfo=dt.timezone.utc)


def _at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def test_grant_is_active_immediately():
    store = ElevationStore()
    grant = store.grant(
        agent_id="a1",
        scope=Scope(tool="crm.delete"),
        reason="incident-123 cleanup",
        granted_by="omar",
        ttl=dt.timedelta(minutes=10),
        now=T0,
    )
    assert grant.is_active(T0) is True
    assert grant.status(T0) == "active"


def test_grant_expires_automatically_without_any_explicit_revoke():
    store = ElevationStore()
    grant = store.grant(
        agent_id="a1",
        scope=Scope(tool="crm.delete"),
        reason="incident-123 cleanup",
        granted_by="omar",
        ttl=dt.timedelta(minutes=10),
        now=T0,
    )
    just_before = grant.expires_at - dt.timedelta(seconds=1)
    just_after = grant.expires_at + dt.timedelta(seconds=1)
    assert grant.is_active(just_before) is True
    assert grant.is_active(just_after) is False
    assert grant.status(just_after) == "expired"


def test_grant_rejects_non_positive_ttl():
    store = ElevationStore()
    with pytest.raises(ElevationError, match="positive"):
        store.grant(
            agent_id="a1",
            scope=Scope(tool="crm.delete"),
            reason="x",
            granted_by="omar",
            ttl=dt.timedelta(0),
            now=T0,
        )


def test_grant_rejects_malformed_resource_constraint():
    store = ElevationStore()
    with pytest.raises(ElevationError, match="invalid scope"):
        store.grant(
            agent_id="a1",
            scope=Scope(tool="crm.delete", constraint="resource="),
            reason="x",
            granted_by="omar",
            ttl=dt.timedelta(minutes=5),
            now=T0,
        )


def test_revoke_takes_effect_immediately():
    store = ElevationStore()
    grant = store.grant(
        agent_id="a1",
        scope=Scope(tool="crm.delete"),
        reason="x",
        granted_by="omar",
        ttl=dt.timedelta(hours=1),
        now=T0,
    )
    assert grant.is_active(_at(5)) is True
    revoked = store.revoke(grant.grant_id, reason="task finished early", now=_at(5))
    assert revoked.is_active(_at(5)) is False
    assert revoked.status(_at(5)) == "revoked"
    # store's own view is updated, not just the returned copy
    assert store.get(grant.grant_id).is_active(_at(5)) is False


def test_revoke_unknown_grant_raises():
    store = ElevationStore()
    with pytest.raises(ElevationNotFoundError):
        store.revoke("does-not-exist", reason="x")


def test_active_grant_for_unrestricted_scope_matches_any_resource():
    store = ElevationStore()
    store.grant(
        agent_id="a1", scope=Scope(tool="crm.delete"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=T0,
    )
    found = store.active_grant_for(agent_id="a1", tool="crm.delete", resource_id="A-999", now=T0)
    assert found is not None


def test_active_grant_for_resource_scoped_requires_matching_resource():
    store = ElevationStore()
    store.grant(
        agent_id="a1", scope=Scope.parse("tool:crm.delete:resource=A-1"), reason="x",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=T0,
    )
    assert store.active_grant_for(agent_id="a1", tool="crm.delete", resource_id="A-1", now=T0) is not None
    assert store.active_grant_for(agent_id="a1", tool="crm.delete", resource_id="A-2", now=T0) is None
    assert store.active_grant_for(agent_id="a1", tool="crm.delete", resource_id=None, now=T0) is None


def test_active_grant_for_ignores_other_agents_and_tools():
    store = ElevationStore()
    store.grant(
        agent_id="a1", scope=Scope(tool="crm.delete"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=T0,
    )
    assert store.active_grant_for(agent_id="a2", tool="crm.delete", resource_id=None, now=T0) is None
    assert store.active_grant_for(agent_id="a1", tool="email.send", resource_id=None, now=T0) is None


def test_active_grant_for_prefers_most_recent_grant():
    store = ElevationStore()
    store.grant(
        agent_id="a1", scope=Scope.parse("tool:crm.delete:resource=A-1"), reason="first",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=T0,
    )
    newer = store.grant(
        agent_id="a1", scope=Scope.parse("tool:crm.delete:resource=A-1,A-2"), reason="correction",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=_at(1),
    )
    found = store.active_grant_for(agent_id="a1", tool="crm.delete", resource_id="A-2", now=_at(1))
    assert found is not None
    assert found.grant_id == newer.grant_id


def test_grant_for_token_ignores_resource_restriction():
    # Minting doesn't know the call's resource_id yet -- any active grant
    # for (agent, tool) should surface here, restriction or not.
    store = ElevationStore()
    store.grant(
        agent_id="a1", scope=Scope.parse("tool:crm.delete:resource=A-1"), reason="x",
        granted_by="omar", ttl=dt.timedelta(minutes=10), now=T0,
    )
    found = store.grant_for_token(agent_id="a1", tool="crm.delete", now=T0)
    assert found is not None
    assert found.scope.resource_allowlist() == frozenset({"A-1"})


def test_for_agent_and_all_grants_listing():
    store = ElevationStore()
    g1 = store.grant(
        agent_id="a1", scope=Scope(tool="crm.delete"), reason="x", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=T0,
    )
    g2 = store.grant(
        agent_id="a2", scope=Scope(tool="email.send"), reason="y", granted_by="omar",
        ttl=dt.timedelta(minutes=10), now=_at(1),
    )
    assert [g.grant_id for g in store.for_agent("a1")] == [g1.grant_id]
    assert {g.grant_id for g in store.all_grants()} == {g1.grant_id, g2.grant_id}
