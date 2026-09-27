import datetime as dt

from observable.detection.baseline import AgentBehaviorBaseline

T0 = dt.datetime(2026, 9, 21, 10, 0, 0, tzinfo=dt.timezone.utc)


def _at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def test_first_event_sets_last_event_at_no_interval_yet():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id="A-1", decision="allow", timestamp=T0)
    assert b.last_event_at == T0
    assert b.n_intervals == 0
    assert b.tools_seen == {"crm.read"}
    assert b.resources_seen == {"A-1"}


def test_intervals_accumulate_mean_and_std():
    b = AgentBehaviorBaseline(agent_id="a1")
    # five evenly-spaced calls, 10s apart -> mean should converge to 10, std to ~0
    for i in range(6):
        b.record_event(tool="crm.read", resource_id=None, decision="allow", timestamp=_at(i * 10))
    assert b.n_intervals == 5
    assert abs(b.interval_mean - 10.0) < 1e-9
    assert b.interval_std < 1e-9


def test_variable_intervals_produce_nonzero_std():
    b = AgentBehaviorBaseline(agent_id="a1")
    offsets = [0, 5, 20, 8, 30, 6]
    ts = T0
    times = []
    running = 0
    for off in offsets:
        running += off
        times.append(_at(running))
    for t in times:
        b.record_event(tool="crm.read", resource_id=None, decision="allow", timestamp=t)
    assert b.interval_std > 0


def test_new_resource_events_only_recorded_first_time():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id="A-1", decision="allow", timestamp=_at(0))
    b.record_event(tool="crm.read", resource_id="A-1", decision="allow", timestamp=_at(1))
    b.record_event(tool="crm.read", resource_id="A-2", decision="allow", timestamp=_at(2))
    assert len(b.new_resource_events) == 2  # A-1 once, A-2 once
    assert b.resources_seen == {"A-1", "A-2"}


def test_recent_decisions_recorded_in_order():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id=None, decision="allow", timestamp=_at(0))
    b.record_event(tool="crm.delete", resource_id=None, decision="deny", timestamp=_at(1))
    assert [d for _, d in b.recent_decisions] == ["allow", "deny"]


def test_pruning_drops_events_older_than_retention_window():
    b = AgentBehaviorBaseline(agent_id="a1")
    b.record_event(tool="crm.read", resource_id="A-1", decision="allow", timestamp=T0)
    far_future = T0 + dt.timedelta(hours=2)
    b.record_event(tool="crm.read", resource_id="A-2", decision="allow", timestamp=far_future)
    # the first (very old) new-resource event and decision should be pruned
    assert all(ts >= far_future - dt.timedelta(hours=1) for ts, _ in b.new_resource_events)
    assert all(ts >= far_future - dt.timedelta(hours=1) for ts, _ in b.recent_decisions)
