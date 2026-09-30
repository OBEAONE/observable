"""
Detection Block A — per-agent behavior baseline.

Pure state: what "normal" looks like for one agent, built up online (one
event at a time) rather than by batch-training on a fixed dataset — the
guide's Enterprise-tier "automated baseline learning from normal
operations", with the Advanced-tier "continuous baseline refinement"
property falling out naturally, since every event nudges the baseline.

This module only tracks state and mutates it. Turning the state into a
risk score is a separate, read-only concern (``observable.detection.scorer``)
— keeping "what do we remember" and "how anomalous is this" independent
means the scorer can be unit-tested against hand-built baselines without
replaying event sequences, and the baseline can be unit-tested without
caring about scoring thresholds at all.

The inter-arrival-time statistic uses Welford's online algorithm (mean
and variance in one pass, numerically stable, no need to store the full
history of intervals).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import math
from collections import deque
from typing import Optional

# Entries in the bounded history deques older than this are dropped on
# every event, so memory stays flat per agent regardless of how long the
# agent has been active. Generously covers both the resource-burst and
# deny-rate windows the scorer uses (each well under an hour).
_HISTORY_RETENTION = dt.timedelta(hours=1)


@dataclasses.dataclass
class AgentBehaviorBaseline:
    agent_id: str
    n_intervals: int = 0
    _interval_mean: float = 0.0
    _interval_m2: float = 0.0  # Welford's running sum of squared deviations
    last_event_at: Optional[dt.datetime] = None
    tools_seen: set[str] = dataclasses.field(default_factory=set)
    resources_seen: set[str] = dataclasses.field(default_factory=set)
    # (timestamp, resource_id) — only appended the first time a given
    # resource is seen, so this deque's length in a window is exactly
    # "how many *new* resources this agent touched in that window".
    new_resource_events: deque[tuple[dt.datetime, str]] = dataclasses.field(
        default_factory=deque
    )
    # (timestamp, decision) for every event, "allow" | "deny" | "error".
    recent_decisions: deque[tuple[dt.datetime, str]] = dataclasses.field(default_factory=deque)
    # (timestamp, tool, decision) for every event — a superset of
    # recent_decisions that also names the tool, so the intent-
    # conformance signal (§8.5) can ask "what has this agent actually
    # been doing lately" without the scorer needing its own history.
    recent_tool_calls: deque[tuple[dt.datetime, str, str]] = dataclasses.field(default_factory=deque)
    # (timestamp, risk_score) for every *scored* event, regardless of the
    # eventual allow/deny outcome — exists purely so an operator can chart
    # how an agent's live risk_score evolved (the console's "Agents risk
    # score" tab), not to feed any scoring signal itself. Bounded by
    # count rather than the short time-based _prune() window below: a
    # trend chart should keep showing history long after a burst window
    # has expired, so this uses deque's own maxlen instead.
    risk_history: deque[tuple[dt.datetime, float]] = dataclasses.field(
        default_factory=lambda: deque(maxlen=500)
    )

    @property
    def interval_mean(self) -> float:
        return self._interval_mean

    @property
    def interval_std(self) -> float:
        if self.n_intervals < 2:
            return 0.0
        variance = self._interval_m2 / (self.n_intervals - 1)
        return math.sqrt(max(variance, 0.0))

    def record_event(
        self,
        *,
        tool: str,
        resource_id: Optional[str],
        decision: str,
        timestamp: dt.datetime,
    ) -> None:
        """Incorporate one real event into the baseline. Call this only
        once the event's outcome is known — scoring a *hypothetical*
        next event reads this state without calling this method."""
        if self.last_event_at is not None:
            interval = (timestamp - self.last_event_at).total_seconds()
            if interval >= 0:
                self._update_welford(interval)
        self.last_event_at = timestamp

        self.tools_seen.add(tool)

        if resource_id is not None:
            if resource_id not in self.resources_seen:
                self.new_resource_events.append((timestamp, resource_id))
            self.resources_seen.add(resource_id)

        self.recent_decisions.append((timestamp, decision))
        self.recent_tool_calls.append((timestamp, tool, decision))
        self._prune(timestamp)

    def record_risk_score(self, *, timestamp: dt.datetime, risk_score: float) -> None:
        """Append one (timestamp, risk_score) sample for charting.
        Independent of record_event: call this for every *scored* event
        (``DetectionEngine.pre_score``'s result), regardless of whether
        it's later allowed, denied, or auto-contained — a denied burst is
        exactly the kind of spike this chart exists to show."""
        self.risk_history.append((timestamp, risk_score))

    def recent_allowed_tools(self, limit: int = 5) -> list[str]:
        """The last ``limit`` tool names this agent successfully called,
        oldest first — exactly the "recent allowed tool calls" context
        the intent-conformance signal (§8.5) judges a new call against.
        Denied/errored calls are excluded: they were never part of this
        agent's actual observed workflow."""
        allowed = [tool for _, tool, decision in self.recent_tool_calls if decision == "allow"]
        return allowed[-limit:]

    def _update_welford(self, interval: float) -> None:
        self.n_intervals += 1
        delta = interval - self._interval_mean
        self._interval_mean += delta / self.n_intervals
        delta2 = interval - self._interval_mean
        self._interval_m2 += delta * delta2

    def _prune(self, now: dt.datetime) -> None:
        cutoff = now - _HISTORY_RETENTION
        while self.new_resource_events and self.new_resource_events[0][0] < cutoff:
            self.new_resource_events.popleft()
        while self.recent_decisions and self.recent_decisions[0][0] < cutoff:
            self.recent_decisions.popleft()
        while self.recent_tool_calls and self.recent_tool_calls[0][0] < cutoff:
            self.recent_tool_calls.popleft()
