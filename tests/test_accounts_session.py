import datetime as dt

from observable.accounts.session import TokenStore

T0 = dt.datetime(2026, 10, 3, 9, 0, tzinfo=dt.timezone.utc)


def test_issued_token_resolves_to_its_payload():
    store = TokenStore(default_ttl=dt.timedelta(minutes=5))
    token = store.issue({"username": "omar"}, now=T0)
    assert store.get(token, now=T0) == {"username": "omar"}


def test_unknown_token_returns_none():
    store = TokenStore(default_ttl=dt.timedelta(minutes=5))
    assert store.get("not-a-real-token", now=T0) is None


def test_token_resolves_up_to_its_expiry_and_not_after():
    store = TokenStore(default_ttl=dt.timedelta(minutes=5))
    token = store.issue({"username": "omar"}, now=T0)
    just_before = T0 + dt.timedelta(minutes=4, seconds=59)
    just_after = T0 + dt.timedelta(minutes=5, seconds=1)
    assert store.get(token, now=just_before) == {"username": "omar"}
    assert store.get(token, now=just_after) is None


def test_revoke_makes_the_token_immediately_unresolvable():
    store = TokenStore(default_ttl=dt.timedelta(minutes=5))
    token = store.issue({"username": "omar"}, now=T0)
    store.revoke(token)
    assert store.get(token, now=T0) is None


def test_per_issue_ttl_overrides_the_default():
    store = TokenStore(default_ttl=dt.timedelta(hours=12))
    token = store.issue({"username": "omar"}, ttl=dt.timedelta(minutes=1), now=T0)
    assert store.get(token, now=T0 + dt.timedelta(minutes=2)) is None


def test_two_issued_tokens_are_distinct_and_independent():
    store = TokenStore(default_ttl=dt.timedelta(minutes=5))
    token_a = store.issue({"username": "a"}, now=T0)
    token_b = store.issue({"username": "b"}, now=T0)
    assert token_a != token_b
    store.revoke(token_a)
    assert store.get(token_a, now=T0) is None
    assert store.get(token_b, now=T0) == {"username": "b"}
