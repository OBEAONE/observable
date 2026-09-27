"""
Detection Block B — anomaly scorer.

Pure, read-only functions: given a baseline and a *hypothetical* next
event, how anomalous is it? Nothing here mutates the baseline — scoring
and learning are different operations on the same state (see the
baseline module's docstring). Four independent statistical/threshold
signals, each individually explainable, combined by a noisy-OR so a
single strong signal dominates but several weak ones still add up:

    combined = 1 - product(1 - signal_i)

This is deliberately not ML (that's the Advanced-tier capability the
roadmap defers): each signal is a plain statistic or threshold check,
which is what the guide's Foundation/Enterprise tiers call for
("threshold-based alerts", "statistical anomaly detection with tunable
sensitivity") and what stays auditable — every risk_score this module
produces comes with the exact reasons that produced it.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Callable, Optional, Protocol

from observable.detection.baseline import AgentBehaviorBaseline

# --- tunable thresholds -------------------------------------------------
RATE_MIN_SAMPLES = 5  # need this many learned intervals before scoring rate at all
RATE_Z_THRESHOLD = 2.0  # z-score below which a fast interval is still "normal"
RATE_Z_SCALE = 3.0  # z-scores above threshold+scale saturate risk at 1.0
RATE_MIN_STD_SECONDS = 0.25  # floor to avoid div-by-tiny-std blowing up z

NEW_TOOL_RISK_HIGH_SENSITIVITY = 0.4
NEW_TOOL_RISK_MEDIUM_SENSITIVITY = 0.25
NEW_TOOL_RISK_LOW_SENSITIVITY = 0.1
NEW_TOOL_RISK_UNKNOWN_SENSITIVITY = 0.2

RESOURCE_BURST_WINDOW = dt.timedelta(seconds=60)
RESOURCE_BURST_THRESHOLD = 5  # distinct *new* resources within the window

DENY_RATE_WINDOW = dt.timedelta(minutes=10)
DENY_RATE_MIN_ATTEMPTS = 4
DENY_RATE_THRESHOLD = 0.5  # fraction of recent attempts denied before this signal fires


class SensitivityLookup(Protocol):
    """What the scorer needs to weight a new-tool signal by how
    sensitive the tool is. ``observable.policy.engine.PolicyEngine`` already
    implements this exact method — see Block 4 — so wiring is a matter
    of passing the existing policy engine in, not building a new one."""

    def tool_sensitivity(self, tool_name: str): ...


@dataclasses.dataclass(frozen=True)
class RiskAssessment:
    risk_score: float
    signals: list[str]
    signal_scores: dict[str, float]


def _score_burst_rate(baseline: AgentBehaviorBaseline, timestamp: dt.datetime) -> tuple[float, Optional[str]]:
    if baseline.last_event_at is None or baseline.n_intervals < RATE_MIN_SAMPLES:
        return 0.0, None
    candidate_interval = (timestamp - baseline.last_event_at).total_seconds()
    if candidate_interval < 0:
        return 0.0, None
    std = max(baseline.interval_std, RATE_MIN_STD_SECONDS)
    # positive z means "faster than usual" (interval below the mean)
    z = (baseline.interval_mean - candidate_interval) / std
    if z <= RATE_Z_THRESHOLD:
        return 0.0, None
    risk = min(1.0, (z - RATE_Z_THRESHOLD) / RATE_Z_SCALE)
    return risk, f"burst_rate(z={z:.2f}, interval={candidate_interval:.2f}s, baseline_mean={baseline.interval_mean:.2f}s)"


def _score_new_tool(
    baseline: AgentBehaviorBaseline, tool: str, sensitivity_lookup: Optional[SensitivityLookup]
) -> tuple[float, Optional[str]]:
    if tool in baseline.tools_seen:
        return 0.0, None
    sensitivity_label = "unknown"
    risk = NEW_TOOL_RISK_UNKNOWN_SENSITIVITY
    if sensitivity_lookup is not None:
        sensitivity = sensitivity_lookup.tool_sensitivity(tool)
        if sensitivity is not None:
            sensitivity_label = sensitivity.value
            risk = {
                "high": NEW_TOOL_RISK_HIGH_SENSITIVITY,
                "medium": NEW_TOOL_RISK_MEDIUM_SENSITIVITY,
                "low": NEW_TOOL_RISK_LOW_SENSITIVITY,
            }.get(sensitivity_label, NEW_TOOL_RISK_UNKNOWN_SENSITIVITY)
    return risk, f"new_tool(tool={tool!r}, sensitivity={sensitivity_label})"


def _score_resource_burst(
    baseline: AgentBehaviorBaseline, resource_id: Optional[str], timestamp: dt.datetime
) -> tuple[float, Optional[str]]:
    if resource_id is None:
        return 0.0, None
    window_start = timestamp - RESOURCE_BURST_WINDOW
    count_in_window = sum(1 for ts, _ in baseline.new_resource_events if ts >= window_start)
    if resource_id not in baseline.resources_seen:
        count_in_window += 1  # this event would itself be a new resource
    if count_in_window < RESOURCE_BURST_THRESHOLD:
        return 0.0, None
    overflow = count_in_window - RESOURCE_BURST_THRESHOLD
    risk = min(1.0, 0.5 + 0.1 * overflow)
    return risk, f"new_resource_burst(count={count_in_window} in {int(RESOURCE_BURST_WINDOW.total_seconds())}s)"


def _score_deny_rate(baseline: AgentBehaviorBaseline, timestamp: dt.datetime) -> tuple[float, Optional[str]]:
    window_start = timestamp - DENY_RATE_WINDOW
    recent = [d for ts, d in baseline.recent_decisions if ts >= window_start]
    if len(recent) < DENY_RATE_MIN_ATTEMPTS:
        return 0.0, None
    deny_fraction = sum(1 for d in recent if d in ("deny", "error")) / len(recent)
    if deny_fraction <= DENY_RATE_THRESHOLD:
        return 0.0, None
    risk = min(1.0, (deny_fraction - DENY_RATE_THRESHOLD) / (1 - DENY_RATE_THRESHOLD))
    return risk, f"deny_rate({deny_fraction:.0%} of {len(recent)} recent attempts)"


def score_event(
    baseline: AgentBehaviorBaseline,
    *,
    tool: str,
    resource_id: Optional[str],
    timestamp: dt.datetime,
    sensitivity_lookup: Optional[SensitivityLookup] = None,
) -> RiskAssessment:
    """Score a hypothetical next event against ``baseline`` without
    mutating it. Call ``baseline.record_event(...)`` separately, after
    the event's outcome is known, to have future scoring reflect it."""
    signal_scores: dict[str, float] = {}
    signals: list[str] = []

    for score, label in (
        _score_burst_rate(baseline, timestamp),
        _score_new_tool(baseline, tool, sensitivity_lookup),
        _score_resource_burst(baseline, resource_id, timestamp),
        _score_deny_rate(baseline, timestamp),
    ):
        if label is not None and score > 0.0:
            signal_scores[label] = score
            signals.append(label)

    combined = 1.0
    for score in signal_scores.values():
        combined *= 1.0 - score
    risk_score = 1.0 - combined

    return RiskAssessment(risk_score=risk_score, signals=signals, signal_scores=signal_scores)
