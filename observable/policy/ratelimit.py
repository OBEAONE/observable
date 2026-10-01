"""
Block 4c — per-agent, per-tool call-rate enforcement.

The last unenforced piece of the scope constraint grammar
(``observable/tokens/scope.py``): ``tool:email.send:rate=10/min`` was
always shown in ARCHITECTURE.md §4.2's example JWT as part of what makes
a scope Least Agency rather than plain least privilege — "which tool,
how often, where" — but until now only "where" (§9.7, resource scoping)
and "when/how long" (§9.8, JIT elevation) had real enforcement behind
them. This closes "how often."

A sliding-window counter, per ``(agent_id, tool)`` — not per scope
string or per grant — because what a rate clause actually limits is "how
many times has this agent invoked this tool recently," regardless of
which grant (a static role, or a resource-scoped or elevated one)
happened to authorize any individual call. Two different grants for the
same tool share one ceiling rather than each getting their own budget.
"""
from __future__ import annotations

import collections
import dataclasses
import datetime as dt
import threading
from typing import Optional


@dataclasses.dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    window: dt.timedelta
    count_in_window: int
    retry_after: Optional[dt.timedelta] = None


class RateLimiter:
    """In-memory, per-process — same durability model as every other
    piece of live state in this reference deployment (Identity Registry,
    Audit Chain, Detection Engine baselines, Elevation Store): re-seeded
    on restart, not a source of truth across deploys, and fine for that
    because a rate ceiling resetting to empty on restart is the safe
    direction to fail in."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[tuple[str, str], collections.deque] = collections.defaultdict(collections.deque)

    def check_and_record(
        self, *, agent_id: str, tool: str, limit: int, window: dt.timedelta, now: dt.datetime
    ) -> RateLimitDecision:
        """Atomic check-and-increment. If the agent is under ``limit``
        calls to ``tool`` within the trailing ``window``, *this* call is
        recorded immediately (counting toward the next check) and the
        decision is allowed. If already at the limit, nothing is
        recorded — a denied attempt doesn't itself consume budget, so
        retrying right after a legitimate denial isn't doubly
        penalized, and the caller can't be locked out indefinitely by
        its own denied attempts."""
        key = (agent_id, tool)
        cutoff = now - window
        with self._lock:
            calls = self._calls[key]
            while calls and calls[0] <= cutoff:
                calls.popleft()
            if len(calls) >= limit:
                retry_after = calls[0] + window - now
                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    window=window,
                    count_in_window=len(calls),
                    retry_after=retry_after if retry_after > dt.timedelta(0) else dt.timedelta(0),
                )
            calls.append(now)
            return RateLimitDecision(
                allowed=True, limit=limit, window=window, count_in_window=len(calls)
            )

    def count_in_window(self, *, agent_id: str, tool: str, window: dt.timedelta, now: dt.datetime) -> int:
        """Read-only introspection (admin/API use): how many calls to
        ``tool`` this agent has made within the trailing ``window``,
        as of ``now``. Never mutates state — unlike ``check_and_record``,
        calling this can't itself affect a future decision."""
        cutoff = now - window
        with self._lock:
            calls = self._calls.get((agent_id, tool), ())
            return sum(1 for t in calls if t > cutoff)
