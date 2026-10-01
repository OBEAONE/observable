import datetime as dt

from observable.policy.ratelimit import RateLimiter

T0 = dt.datetime(2026, 9, 21, 10, 0, 0, tzinfo=dt.timezone.utc)


def _at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def test_allows_calls_under_the_limit():
    rl = RateLimiter()
    for i in range(3):
        decision = rl.check_and_record(
            agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(i)
        )
        assert decision.allowed is True
    assert decision.count_in_window == 3


def test_denies_once_limit_reached_within_window():
    rl = RateLimiter()
    for i in range(3):
        rl.check_and_record(
            agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(i)
        )
    decision = rl.check_and_record(
        agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(3)
    )
    assert decision.allowed is False
    assert decision.count_in_window == 3
    assert decision.retry_after is not None
    assert decision.retry_after > dt.timedelta(0)


def test_denied_attempt_does_not_itself_consume_budget():
    rl = RateLimiter()
    for i in range(3):
        rl.check_and_record(
            agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(i)
        )
    # two denied attempts in a row
    rl.check_and_record(agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(3))
    rl.check_and_record(agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=_at(4))
    # still only 3 recorded -- once the oldest ages out, a new call is allowed
    just_after_window = T0 + dt.timedelta(minutes=1, seconds=0.5)
    decision = rl.check_and_record(
        agent_id="a1", tool="email.send", limit=3, window=dt.timedelta(minutes=1), now=just_after_window
    )
    assert decision.allowed is True


def test_old_calls_age_out_of_the_sliding_window():
    rl = RateLimiter()
    rl.check_and_record(agent_id="a1", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=T0)
    # denied immediately after (still within the window)
    denied = rl.check_and_record(
        agent_id="a1", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=_at(30)
    )
    assert denied.allowed is False
    # allowed again once the first call ages out of the trailing window
    allowed = rl.check_and_record(
        agent_id="a1", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=_at(61)
    )
    assert allowed.allowed is True


def test_limits_are_independent_per_agent():
    rl = RateLimiter()
    rl.check_and_record(agent_id="a1", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=T0)
    decision = rl.check_and_record(
        agent_id="a2", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=T0
    )
    assert decision.allowed is True


def test_limits_are_independent_per_tool():
    rl = RateLimiter()
    rl.check_and_record(agent_id="a1", tool="email.send", limit=1, window=dt.timedelta(minutes=1), now=T0)
    decision = rl.check_and_record(
        agent_id="a1", tool="crm.read", limit=1, window=dt.timedelta(minutes=1), now=T0
    )
    assert decision.allowed is True


def test_count_in_window_is_read_only():
    rl = RateLimiter()
    rl.check_and_record(agent_id="a1", tool="email.send", limit=5, window=dt.timedelta(minutes=1), now=T0)
    rl.check_and_record(agent_id="a1", tool="email.send", limit=5, window=dt.timedelta(minutes=1), now=_at(1))
    before = rl.count_in_window(agent_id="a1", tool="email.send", window=dt.timedelta(minutes=1), now=_at(2))
    assert before == 2
    # calling it again doesn't change anything
    after = rl.count_in_window(agent_id="a1", tool="email.send", window=dt.timedelta(minutes=1), now=_at(2))
    assert after == 2
    # a subsequent real check_and_record still sees exactly 2 prior calls
    decision = rl.check_and_record(
        agent_id="a1", tool="email.send", limit=5, window=dt.timedelta(minutes=1), now=_at(2)
    )
    assert decision.count_in_window == 3
