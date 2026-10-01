"""
Block 3 — Scope grammar shared by the Token Service and the Policy Engine.

A scope is ``tool:<name>`` optionally followed by ``:<constraint>``, e.g.
``tool:crm.read`` or ``tool:email.send:rate=10/min``. Keeping this in its
own module (rather than inline string formatting scattered across two
blocks) means Token Service and Policy Engine parse scopes identically.

A constraint is itself a ``;``-separated list of ``key=value`` clauses
(a value may hold a comma-separated list, e.g.
``tool:crm.read:resource=A-1,A-2``). The Policy Engine (§4.2,
ARCHITECTURE.md) enforces two of these: ``resource`` (§9.7, narrowing a
grant to a specific set of resource_ids) and ``rate`` (§9.9, capping how
many times the tool may be called in a trailing time window, e.g.
``rate=10/min``).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re

_SCOPE_RE = re.compile(r"^tool:(?P<name>[a-zA-Z0-9_.\-]+)(:(?P<constraint>.+))?$")
_RATE_RE = re.compile(r"^(?P<count>\d+)/(?P<unit>[a-zA-Z]+)$")

# Accepted units for a "rate=<count>/<unit>" clause, each mapped to its
# window length. Deliberately a small, explicit set rather than a
# free-form duration parser -- a typo'd unit should be rejected at parse
# time, not silently treated as some default window.
_RATE_UNITS: dict[str, dt.timedelta] = {
    "s": dt.timedelta(seconds=1),
    "sec": dt.timedelta(seconds=1),
    "secs": dt.timedelta(seconds=1),
    "second": dt.timedelta(seconds=1),
    "seconds": dt.timedelta(seconds=1),
    "m": dt.timedelta(minutes=1),
    "min": dt.timedelta(minutes=1),
    "mins": dt.timedelta(minutes=1),
    "minute": dt.timedelta(minutes=1),
    "minutes": dt.timedelta(minutes=1),
    "h": dt.timedelta(hours=1),
    "hr": dt.timedelta(hours=1),
    "hour": dt.timedelta(hours=1),
    "hours": dt.timedelta(hours=1),
    "d": dt.timedelta(days=1),
    "day": dt.timedelta(days=1),
    "days": dt.timedelta(days=1),
}


class InvalidScopeError(Exception):
    pass


def parse_constraint(constraint: str | None) -> dict[str, str]:
    """Parse a scope's constraint string into ``{clause: raw_value}``.
    Each clause is read independently by whichever layer cares about it
    (the Policy Engine currently reads only ``resource``). A clause that
    fails to parse (no ``=``, an empty key/value, or a repeated key)
    raises ``InvalidScopeError`` rather than being silently dropped --
    a constraint that fails to parse is exactly the kind of quiet
    misconfiguration Least Agency is supposed to prevent, so callers are
    expected to fail closed on this, not ignore it."""
    if not constraint:
        return {}
    clauses: dict[str, str] = {}
    for part in constraint.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise InvalidScopeError(f"malformed constraint clause: {part!r}")
        key, _, value = part.partition("=")
        key, value = key.strip(), value.strip()
        if not key or not value:
            raise InvalidScopeError(f"malformed constraint clause: {part!r}")
        if key in clauses:
            raise InvalidScopeError(f"duplicate constraint clause {key!r} in {constraint!r}")
        clauses[key] = value
    return clauses


@dataclasses.dataclass(frozen=True)
class Scope:
    tool: str
    constraint: str | None = None

    def __str__(self) -> str:
        return f"tool:{self.tool}" + (f":{self.constraint}" if self.constraint else "")

    @staticmethod
    def parse(raw: str) -> "Scope":
        match = _SCOPE_RE.match(raw.strip())
        if not match:
            raise InvalidScopeError(f"malformed scope string: {raw!r}")
        return Scope(tool=match.group("name"), constraint=match.group("constraint"))

    def resource_allowlist(self) -> frozenset[str] | None:
        """The set of resource_ids this scope is restricted to, or
        ``None`` if it carries no ``resource=`` clause at all (the
        pre-existing, tool-only granularity -- unrestricted). Raises
        ``InvalidScopeError`` if the constraint doesn't parse, or if a
        ``resource=`` clause is present but empty after splitting on
        ``,`` (e.g. ``resource=`` or ``resource=, ,``) -- that's a
        misconfigured grant that should fail closed, not be read as
        "no restriction"."""
        clauses = parse_constraint(self.constraint)
        raw = clauses.get("resource")
        if raw is None:
            return None
        ids = frozenset(v.strip() for v in raw.split(",") if v.strip())
        if not ids:
            raise InvalidScopeError(f"empty resource constraint: {self.constraint!r}")
        return ids

    def rate_limit(self) -> tuple[int, dt.timedelta] | None:
        """``(max_calls, window)`` from this scope's ``rate=`` clause
        (e.g. ``rate=10/min`` -> ``(10, timedelta(minutes=1))``), or
        ``None`` if it carries no ``rate=`` clause at all (unlimited --
        the pre-existing behavior). Raises ``InvalidScopeError`` for a
        zero/negative count or an unrecognized unit, so a typo'd clause
        fails closed at grant time rather than being silently read as
        "no limit"."""
        clauses = parse_constraint(self.constraint)
        raw = clauses.get("rate")
        if raw is None:
            return None
        match = _RATE_RE.match(raw.strip())
        if not match:
            raise InvalidScopeError(f"malformed rate constraint: {raw!r}")
        count = int(match.group("count"))
        if count <= 0:
            raise InvalidScopeError(f"rate constraint count must be positive: {raw!r}")
        unit = match.group("unit").lower()
        window = _RATE_UNITS.get(unit)
        if window is None:
            raise InvalidScopeError(f"unrecognized rate unit {unit!r} in {raw!r}")
        return count, window


def parse_scope_string(scope_str: str) -> list[Scope]:
    """Parse a space-delimited scope string (as carried in the JWT
    ``scope`` claim) into a list of Scope objects. Empty string -> []."""
    scope_str = scope_str.strip()
    if not scope_str:
        return []
    return [Scope.parse(part) for part in scope_str.split()]


def format_scopes(scopes: list[Scope]) -> str:
    return " ".join(str(s) for s in scopes)
