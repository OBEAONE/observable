"""
Block 3 — Scope grammar shared by the Token Service and the Policy Engine.

A scope is ``tool:<name>`` optionally followed by ``:<constraint>``, e.g.
``tool:crm.read`` or ``tool:email.send:rate=10/min``. Keeping this in its
own module (rather than inline string formatting scattered across two
blocks) means Token Service and Policy Engine parse scopes identically.
"""
from __future__ import annotations

import dataclasses
import re

_SCOPE_RE = re.compile(r"^tool:(?P<name>[a-zA-Z0-9_.\-]+)(:(?P<constraint>.+))?$")


class InvalidScopeError(Exception):
    pass


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


def parse_scope_string(scope_str: str) -> list[Scope]:
    """Parse a space-delimited scope string (as carried in the JWT
    ``scope`` claim) into a list of Scope objects. Empty string -> []."""
    scope_str = scope_str.strip()
    if not scope_str:
        return []
    return [Scope.parse(part) for part in scope_str.split()]


def format_scopes(scopes: list[Scope]) -> str:
    return " ".join(str(s) for s in scopes)
