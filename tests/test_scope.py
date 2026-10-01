import datetime as dt

import pytest

from observable.tokens.scope import InvalidScopeError, Scope, parse_constraint


def test_parse_constraint_empty():
    assert parse_constraint(None) == {}
    assert parse_constraint("") == {}


def test_parse_constraint_single_clause():
    assert parse_constraint("resource=A-1") == {"resource": "A-1"}


def test_parse_constraint_multiple_clauses():
    assert parse_constraint("resource=A-1,A-2;rate=10/min") == {
        "resource": "A-1,A-2",
        "rate": "10/min",
    }


def test_parse_constraint_rejects_missing_equals():
    with pytest.raises(InvalidScopeError, match="malformed constraint clause"):
        parse_constraint("not-a-clause")


def test_parse_constraint_rejects_empty_key_or_value():
    with pytest.raises(InvalidScopeError):
        parse_constraint("=A-1")
    with pytest.raises(InvalidScopeError):
        parse_constraint("resource=")


def test_parse_constraint_rejects_duplicate_key():
    with pytest.raises(InvalidScopeError, match="duplicate constraint clause"):
        parse_constraint("resource=A-1;resource=A-2")


def test_resource_allowlist_none_when_no_resource_clause():
    scope = Scope.parse("tool:crm.read")
    assert scope.resource_allowlist() is None

    scope_with_other_constraint = Scope.parse("tool:email.send:rate=10/min")
    assert scope_with_other_constraint.resource_allowlist() is None


def test_resource_allowlist_single_id():
    scope = Scope.parse("tool:crm.read:resource=A-1")
    assert scope.resource_allowlist() == frozenset({"A-1"})


def test_resource_allowlist_multiple_ids():
    scope = Scope.parse("tool:crm.read:resource=A-1,A-2,A-3")
    assert scope.resource_allowlist() == frozenset({"A-1", "A-2", "A-3"})


def test_resource_allowlist_combined_with_other_clause():
    scope = Scope.parse("tool:crm.read:resource=A-1;rate=10/min")
    assert scope.resource_allowlist() == frozenset({"A-1"})


def test_resource_allowlist_rejects_empty_value_after_split():
    scope = Scope.parse("tool:crm.read:resource=, ,")
    with pytest.raises(InvalidScopeError, match="empty resource constraint"):
        scope.resource_allowlist()


def test_str_roundtrips_constraint():
    scope = Scope.parse("tool:crm.read:resource=A-1,A-2")
    assert str(scope) == "tool:crm.read:resource=A-1,A-2"


def test_rate_limit_none_when_no_rate_clause():
    assert Scope.parse("tool:email.send").rate_limit() is None
    assert Scope.parse("tool:email.send:resource=A-1").rate_limit() is None


def test_rate_limit_parses_count_and_unit():
    assert Scope.parse("tool:email.send:rate=10/min").rate_limit() == (10, dt.timedelta(minutes=1))
    assert Scope.parse("tool:email.send:rate=1/s").rate_limit() == (1, dt.timedelta(seconds=1))
    assert Scope.parse("tool:email.send:rate=100/hour").rate_limit() == (100, dt.timedelta(hours=1))
    assert Scope.parse("tool:email.send:rate=5/day").rate_limit() == (5, dt.timedelta(days=1))


def test_rate_limit_combined_with_resource_clause():
    scope = Scope.parse("tool:email.send:resource=A-1;rate=10/min")
    assert scope.resource_allowlist() == frozenset({"A-1"})
    assert scope.rate_limit() == (10, dt.timedelta(minutes=1))


@pytest.mark.parametrize(
    "raw",
    ["rate=abc", "rate=10", "rate=10/", "rate=/min", "rate=10/fortnight", "rate=-1/min"],
)
def test_rate_limit_rejects_malformed_values(raw):
    scope = Scope(tool="email.send", constraint=raw)
    with pytest.raises(InvalidScopeError):
        scope.rate_limit()


def test_rate_limit_rejects_zero_count():
    scope = Scope.parse("tool:email.send:rate=0/min")
    with pytest.raises(InvalidScopeError, match="positive"):
        scope.rate_limit()
