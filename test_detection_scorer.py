import datetime as dt

from observable.detection.baseline import AgentBehaviorBaseline
from observable.detection.scorer import score_event
from observable.policy.bundle import Sensitivity, ToolDefinition, default_bundle
from observable.policy.engine import PolicyEngine
from observable.pki.reference_ca import ReferenceCA

T0 = dt.datetime(2026, 9, 21, 10, 0, 0, tzinfo=dt.timezone.utc)


def _at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def _steady_baseline(interval_seconds: float = 10.0, n: int = 8) -> AgentBehaviorBaseline:
    b = AgentBehaviorBaseline(agent_id="a1")
    for i in range(n):
        b.record_event(tool="crm.read", resource_id=None, decision="allow", timestamp=_at(i * interval_seconds))
    return b


def test_no_signals_when_baseline_too_young():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id=None, decision="allow", timestamp=T0)
    assessment = score_event(b, tool="crm.read", resource_id=None, timestamp=_at(0.01))
    assert assessment.risk_score == 0.0
    assert assessment.signals == []


def test_burst_rate_signal_fires_for_much_faster_than_usual_call():
    b = _steady_baseline(interval_seconds=10.0, n=8)
    last = b.last_event_at
    # normal-paced next call: no signal
    normal = score_event(b, tool="crm.read", resource_id=None, timestamp=last + dt.timedelta(seconds=10))
    assert normal.risk_score == 0.0

    # a call 0.1s after the last one, against an 8-call baseline of ~10s
    # spacing with near-zero std, is a massive z-score.
    burst = score_event(b, tool="crm.read", resource_id=None, timestamp=last + dt.timedelta(seconds=0.1))
    assert burst.risk_score > 0.5
    assert any(s.startswith("burst_rate") for s in burst.signals)


def test_new_tool_signal_scales_with_sensitivity():
    b = _steady_baseline()
    ca = ReferenceCA(org_name="Test CA")
    engine = PolicyEngine(ca=ca, bundle=default_bundle())

    # crm.delete is HIGH sensitivity in the default bundle and was never
    # called by this agent before.
    high = score_event(
        b, tool="crm.delete", resource_id=None, timestamp=b.last_event_at + dt.timedelta(seconds=10),
        sensitivity_lookup=engine,
    )
    assert any(s.startswith("new_tool") for s in high.signals)
    assert high.signal_scores[next(s for s in high.signals if s.startswith("new_tool"))] == 0.4

    # crm.read was already called -> not new
    not_new = score_event(
        b, tool="crm.read", resource_id=None, timestamp=b.last_event_at + dt.timedelta(seconds=10),
        sensitivity_lookup=engine,
    )
    assert not any(s.startswith("new_tool") for s in not_new.signals)


def test_new_tool_without_sensitivity_lookup_uses_default_weight():
    b = _steady_baseline()
    assessment = score_event(
        b, tool="unknown.tool", resource_id=None, timestamp=b.last_event_at + dt.timedelta(seconds=10)
    )
    label = next(s for s in assessment.signals if s.startswith("new_tool"))
    assert assessment.signal_scores[label] == 0.2


def test_resource_burst_signal_fires_after_threshold_distinct_new_resources():
    b = AgentBehaviorBaseline(agent_id="a1")
    # touch 4 distinct resources quickly -- below threshold (5), no signal
    for i in range(4):
        b.record_event(tool="crm.read", resource_id=f"R-{i}", decision="allow", timestamp=_at(i))
    below = score_event(b, tool="crm.read", resource_id="R-4", timestamp=_at(4.5))
    # R-4 would be the 5th distinct new resource in-window -> should fire
    assert any(s.startswith("new_resource_burst") for s in below.signals)


def test_resource_burst_signal_absent_for_repeated_single_resource():
    b = AgentBehaviorBaseline(agent_id="a1")
    for i in range(10):
        b.record_event(tool="crm.read", resource_id="A-1", decision="allow", timestamp=_at(i))
    assessment = score_event(b, tool="crm.read", resource_id="A-1", timestamp=_at(10))
    assert not any(s.startswith("new_resource_burst") for s in assessment.signals)


def test_deny_rate_signal_fires_after_repeated_recent_denials():
    b = AgentBehaviorBaseline(agent_id="a1")
    decisions = ["deny", "deny", "deny", "allow"]
    for i, d in enumerate(decisions):
        b.record_event(tool="crm.read", resource_id=None, decision=d, timestamp=_at(i * 5))
    assessment = score_event(b, tool="crm.read", resource_id=None, timestamp=_at(25))
    assert any(s.startswith("deny_rate") for s in assessment.signals)


def test_deny_rate_signal_absent_below_min_attempts():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id=None, decision="deny", timestamp=_at(0))
    b.record_event(tool="crm.read", resource_id=None, decision="deny", timestamp=_at(5))
    assessment = score_event(b, tool="crm.read", resource_id=None, timestamp=_at(10))
    assert not any(s.startswith("deny_rate") for s in assessment.signals)


def test_combined_risk_score_from_multiple_signals_exceeds_any_single_one():
    b = AgentBehaviorBaseline(agent_id="a1")
    # 75% deny rate -> a strong but non-saturating deny_rate signal
    # (risk 0.5), leaving room to show a second signal pushes it higher.
    decisions = ["deny", "deny", "deny", "allow"]
    for i, d in enumerate(decisions):
        b.record_event(tool="crm.read", resource_id=None, decision=d, timestamp=_at(i * 5))
    only_deny = score_event(b, tool="crm.read", resource_id=None, timestamp=_at(25))

    # add a new-tool signal on top by scoring a never-seen tool
    combined = score_event(b, tool="crm.delete", resource_id=None, timestamp=_at(25))
    assert combined.risk_score > only_deny.risk_score
    assert combined.risk_score <= 1.0
