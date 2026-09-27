"""
Detection Block C — Detection Engine.

The one object Agent Guard (and the API) actually talks to: owns one
``AgentBehaviorBaseline`` per agent, exposes ``pre_score`` (read-only —
call before a decision is made) and ``record_event`` (mutating — call
once the decision is known), and can backfill baselines from the Audit
Chain that already exists (Block 5), so a freshly-started Observable process
doesn't start every agent with zero history.

Optionally owns an ``IntentChecker`` (Block D, §8.5) that adds the
``intent_mismatch`` signal. The checker may call out to a model server,
so it runs *outside* the engine lock — a slow scorer must never
serialize every agent's scoring behind it.
"""
from __future__ import annotations

import datetime as dt
import threading
from typing import Optional

from observable.detection.baseline import AgentBehaviorBaseline
from observable.detection.intent import IntentChecker
from observable.detection.scorer import RiskAssessment, SensitivityLookup, score_event
from observable.guard.audit import AuditChain


class DetectionEngine:
    def __init__(
        self,
        *,
        sensitivity_lookup: Optional[SensitivityLookup] = None,
        intent_checker: Optional[IntentChecker] = None,
    ) -> None:
        self._sensitivity_lookup = sensitivity_lookup
        self._intent_checker = intent_checker
        self._lock = threading.RLock()
        self._baselines: dict[str, AgentBehaviorBaseline] = {}

    def _baseline_for(self, agent_id: str) -> AgentBehaviorBaseline:
        with self._lock:
            baseline = self._baselines.get(agent_id)
            if baseline is None:
                baseline = AgentBehaviorBaseline(agent_id=agent_id)
                self._baselines[agent_id] = baseline
            return baseline

    @property
    def intent_checker(self) -> Optional[IntentChecker]:
        return self._intent_checker

    def set_intent_checker(self, checker: Optional[IntentChecker]) -> None:
        self._intent_checker = checker

    def intent_status(self) -> dict:
        checker = self._intent_checker
        if checker is None:
            return {"enabled": False}
        return checker.status()

    def pre_score(
        self,
        *,
        agent_id: str,
        tool: str,
        resource_id: Optional[str],
        timestamp: dt.datetime,
        role: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> RiskAssessment:
        """Read-only: how anomalous would this event be against the
        agent's current baseline? Does not learn from it.

        ``role`` and ``purpose`` (from the verified token) are only used
        by the intent-conformance signal; without an intent checker, or
        without a declared purpose, scoring is exactly the four
        statistical signals."""
        extra: list[tuple[float, Optional[str]]] = []
        degraded: list[str] = []
        checker = self._intent_checker
        if checker is not None:
            with self._lock:
                recent = [t for _, t in self._baseline_for(agent_id).recent_tools]
            result = checker.check(role=role, purpose=purpose, tool=tool, recent_tools=recent)
            if result.label is not None:
                extra.append((result.risk, result.label))
            if result.degraded is not None:
                degraded.append(result.degraded)
        with self._lock:
            baseline = self._baseline_for(agent_id)
            return score_event(
                baseline,
                tool=tool,
                resource_id=resource_id,
                timestamp=timestamp,
                sensitivity_lookup=self._sensitivity_lookup,
                extra_signals=extra,
                degraded=degraded,
            )

    def record_event(
        self,
        *,
        agent_id: str,
        tool: str,
        resource_id: Optional[str],
        decision: str,
        timestamp: dt.datetime,
    ) -> None:
        """Mutating: incorporate a now-decided event into the agent's
        baseline, shaping how future events are scored."""
        with self._lock:
            baseline = self._baseline_for(agent_id)
            baseline.record_event(
                tool=tool, resource_id=resource_id, decision=decision, timestamp=timestamp
            )

    def ingest_from_audit(self, audit: AuditChain, *, agent_id: Optional[str] = None) -> int:
        """Backfill baselines from existing audit history — useful right
        after a restart, or to warm a baseline in a demo without
        replaying real traffic. Returns the number of events ingested.
        Entries are processed in original sequence order so the learned
        inter-arrival statistics are meaningful."""
        entries = audit.entries_for_agent(agent_id) if agent_id else audit.entries()
        count = 0
        for entry in sorted(entries, key=lambda e: e.seq):
            if entry.agent_id is None or not entry.action.startswith("tool:"):
                continue
            if entry.decision not in ("allow", "deny", "error"):
                continue
            tool = entry.action.removeprefix("tool:")
            self.record_event(
                agent_id=entry.agent_id,
                tool=tool,
                resource_id=entry.resource_id,
                decision=entry.decision,
                timestamp=entry.timestamp,
            )
            count += 1
        return count

    def baseline_summary(self, agent_id: str) -> dict:
        """Introspection for the API/demo: a JSON-friendly snapshot of
        what the engine currently believes is normal for this agent."""
        with self._lock:
            baseline = self._baselines.get(agent_id)
            if baseline is None:
                return {
                    "agent_id": agent_id,
                    "known": False,
                }
            recent_denies = sum(1 for _, d in baseline.recent_decisions if d in ("deny", "error"))
            return {
                "agent_id": agent_id,
                "known": True,
                "n_intervals": baseline.n_intervals,
                "interval_mean_seconds": round(baseline.interval_mean, 3),
                "interval_std_seconds": round(baseline.interval_std, 3),
                "tools_seen": sorted(baseline.tools_seen),
                "distinct_resources_seen": len(baseline.resources_seen),
                "recent_decision_count": len(baseline.recent_decisions),
                "recent_deny_count": recent_denies,
                "recent_tools": [t for _, t in baseline.recent_tools],
                "last_event_at": baseline.last_event_at.isoformat() if baseline.last_event_at else None,
            }
