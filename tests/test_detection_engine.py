import datetime as dt

import pytest

from observable.detection.engine import DetectionEngine
from observable.guard.audit import AuditChain

T0 = dt.datetime(2026, 9, 21, 10, 0, 0, tzinfo=dt.timezone.utc)


def _at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def test_pre_score_unknown_agent_has_no_history_based_signals():
    # A brand-new agent has an empty baseline, so the only signal that
    # *can* fire is "first time this tool has been seen" (mild, 0.2)
    # -- there's no history yet for burst-rate, resource-burst, or
    # deny-rate to compare against.
    engine = DetectionEngine()
    assessment = engine.pre_score(agent_id="never-seen", tool="crm.read", resource_id=None, timestamp=T0)
    assert assessment.signals == ["new_tool(tool='crm.read', sensitivity=unknown)"]
    assert assessment.risk_score == pytest.approx(0.2)


def test_pre_score_does_not_mutate_state():
    engine = DetectionEngine()
    engine.record_event(agent_id="a1", tool="crm.read", resource_id=None, decision="allow", timestamp=T0)
    before = engine.baseline_summary("a1")
    engine.pre_score(agent_id="a1", tool="crm.read", resource_id=None, timestamp=_at(10))
    after = engine.baseline_summary("a1")
    assert before == after


def test_record_event_then_pre_score_reflects_learned_baseline():
    engine = DetectionEngine()
    for i in range(8):
        engine.record_event(
            agent_id="a1", tool="crm.read", resource_id=None, decision="allow", timestamp=_at(i * 10)
        )
    normal = engine.pre_score(agent_id="a1", tool="crm.read", resource_id=None, timestamp=_at(80))
    assert normal.risk_score == 0.0

    burst = engine.pre_score(agent_id="a1", tool="crm.read", resource_id=None, timestamp=_at(70.1))
    assert burst.risk_score > 0.0


def test_baseline_summary_unknown_agent():
    engine = DetectionEngine()
    summary = engine.baseline_summary("nope")
    assert summary == {"agent_id": "nope", "known": False}


def test_baseline_summary_known_agent_reports_stats():
    engine = DetectionEngine()
    engine.record_event(agent_id="a1", tool="crm.read", resource_id="R-1", decision="allow", timestamp=T0)
    engine.record_event(agent_id="a1", tool="crm.read", resource_id="R-1", decision="deny", timestamp=_at(5))
    summary = engine.baseline_summary("a1")
    assert summary["known"] is True
    assert summary["tools_seen"] == ["crm.read"]
    assert summary["distinct_resources_seen"] == 1
    assert summary["recent_decision_count"] == 2
    assert summary["recent_deny_count"] == 1


def test_ingest_from_audit_backfills_baseline():
    audit = AuditChain()
    audit.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow", reason="ok")
    audit.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow", reason="ok")
    audit.append(agent_id="a2", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    audit.append(agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action", reason="x")

    engine = DetectionEngine()
    count = engine.ingest_from_audit(audit)
    # 3 tool: entries qualify (2 for a1, 1 for a2); the containment entry doesn't.
    assert count == 3
    assert engine.baseline_summary("a1")["known"] is True
    assert engine.baseline_summary("a2")["known"] is True


def test_ingest_from_audit_scoped_to_single_agent():
    audit = AuditChain()
    audit.append(agent_id="a1", role="r", action="tool:crm.read", decision="allow", reason="ok")
    audit.append(agent_id="a2", role="r", action="tool:crm.read", decision="allow", reason="ok")

    engine = DetectionEngine()
    count = engine.ingest_from_audit(audit, agent_id="a1")
    assert count == 1
    assert engine.baseline_summary("a1")["known"] is True
    assert engine.baseline_summary("a2")["known"] is False
