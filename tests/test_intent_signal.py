"""
Tests for the §8.5 intent-conformance signal: the MockIntentScorer's
deterministic math, IntentChecker's skip rules (off mode, no purpose,
below the sensitivity floor) and fail-open behavior, and an end-to-end
demonstration that it can push an otherwise-allowed call over a tool's
existing risk ceiling — the same scenario ARCHITECTURE.md §8.5 walks
through with the reporting-analyst role.
"""
import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state
from observable.client.sdk import AgentClient, AgentClientError
from observable.detection.intent import (
    IntentChecker,
    IntentScorerError,
    MockIntentScorer,
    build_intent_checker_from_env,
)
from observable.policy.bundle import Sensitivity


# ---------------------------------------------------------------------
# MockIntentScorer
# ---------------------------------------------------------------------
def test_mock_scorer_no_purpose_is_neutral():
    scorer = MockIntentScorer()
    p = scorer.score(
        role="reporting-analyst", purpose=None, recent_tools=[],
        tool_name="reporting.export", tool_description="Export a report",
    )
    assert p == 0.5


def test_mock_scorer_zero_overlap_scores_low():
    scorer = MockIntentScorer()
    p = scorer.score(
        role="reporting-analyst",
        purpose="weekly summary of booking activity",
        recent_tools=["booking.read", "reporting.generate"],
        tool_name="reporting.export",
        tool_description="Export a generated report to an external format/location",
    )
    assert p < 0.5  # no shared words between the purpose and this tool


def test_mock_scorer_one_shared_word_is_borderline_and_does_not_fire():
    scorer = MockIntentScorer()
    p = scorer.score(
        role="reporting-analyst",
        purpose="weekly summary of booking activity",
        recent_tools=[],
        tool_name="booking.read",
        tool_description="Read a booking/reservation record",
    )
    assert p == pytest.approx(0.5)  # "booking" shared -> borderline, signal won't fire


# ---------------------------------------------------------------------
# IntentChecker skip rules
# ---------------------------------------------------------------------
def test_checker_off_mode_is_always_a_noop():
    checker = IntentChecker(mode="off")
    result = checker.check(
        role="booking-agent", purpose="anything", recent_tools=[],
        tool_name="booking.cancel", tool_description="Cancel a booking",
        sensitivity=Sensitivity.HIGH,
    )
    assert result.risk == 0.0
    assert result.label is None
    assert result.degraded is False


def test_checker_no_declared_purpose_is_a_noop():
    checker = IntentChecker(mode="mock", scorer=MockIntentScorer())
    result = checker.check(
        role="booking-agent", purpose=None, recent_tools=[],
        tool_name="booking.cancel", tool_description="Cancel a booking",
        sensitivity=Sensitivity.HIGH,
    )
    assert result.risk == 0.0
    assert result.label is None


def test_checker_below_sensitivity_floor_is_skipped():
    checker = IntentChecker(mode="mock", scorer=MockIntentScorer(), min_sensitivity=Sensitivity.HIGH)
    result = checker.check(
        role="reporting-analyst", purpose="totally unrelated purpose", recent_tools=[],
        tool_name="crm.read", tool_description="Read CRM account/contact records",
        sensitivity=Sensitivity.LOW,
    )
    assert result.risk == 0.0
    assert result.label is None


def test_checker_at_or_above_floor_scores_normally():
    checker = IntentChecker(mode="mock", scorer=MockIntentScorer(), min_sensitivity=Sensitivity.MEDIUM)
    result = checker.check(
        role="reporting-analyst",
        purpose="weekly summary of booking activity",
        recent_tools=["booking.read"],
        tool_name="reporting.export",
        tool_description="Export a generated report to an external format/location",
        sensitivity=Sensitivity.MEDIUM,
    )
    assert result.risk > 0.0
    assert result.label is not None
    assert "intent_mismatch" in result.label
    assert "scorer=mock" in result.label


def test_checker_risk_formula_matches_architecture_doc():
    """ARCHITECTURE.md §8.5: risk = 0.5 * (0.5 - p_consistent) / 0.5,
    which simplifies to 0.5 - p_consistent (clamped to [0, 0.5])."""

    class FixedScorer:
        def score(self, **kwargs):
            return 0.10

    checker = IntentChecker(mode="mock", scorer=FixedScorer())
    result = checker.check(
        role="reporting-analyst", purpose="weekly summary of booking activity",
        recent_tools=[], tool_name="reporting.export", tool_description="Export a report",
        sensitivity=Sensitivity.MEDIUM,
    )
    assert result.risk == pytest.approx(0.40)


def test_checker_fails_open_on_scorer_error():
    class BrokenScorer:
        def score(self, **kwargs):
            raise IntentScorerError("connection refused")

    checker = IntentChecker(mode="clm", scorer=BrokenScorer())
    result = checker.check(
        role="reporting-analyst", purpose="weekly summary of booking activity",
        recent_tools=[], tool_name="reporting.export", tool_description="Export a report",
        sensitivity=Sensitivity.MEDIUM,
    )
    assert result.risk == 0.0  # fail-open: no contribution to risk_score
    assert result.label is None
    assert result.degraded is True
    assert "detection degraded" in result.degraded_reason

    stats = checker.stats()
    assert stats["calls"] == 1
    assert stats["failures"] == 1
    assert "connection refused" in stats["last_error"]


def test_checker_construction_requires_scorer_unless_off():
    with pytest.raises(ValueError):
        IntentChecker(mode="mock", scorer=None)


# ---------------------------------------------------------------------
# build_intent_checker_from_env
# ---------------------------------------------------------------------
def test_build_from_env_defaults_to_off(monkeypatch):
    monkeypatch.delenv("OBSERVABLE_INTENT_SCORER", raising=False)
    checker = build_intent_checker_from_env()
    assert checker.mode == "off"
    assert checker.enabled is False


def test_build_from_env_mock_mode(monkeypatch):
    monkeypatch.setenv("OBSERVABLE_INTENT_SCORER", "mock")
    checker = build_intent_checker_from_env()
    assert checker.mode == "mock"
    assert checker.enabled is True


def test_build_from_env_clm_mode_requires_url(monkeypatch):
    monkeypatch.setenv("OBSERVABLE_INTENT_SCORER", "clm")
    monkeypatch.delenv("OBSERVABLE_CLM_URL", raising=False)
    with pytest.raises(ValueError):
        build_intent_checker_from_env()


def test_build_from_env_clm_mode_with_url(monkeypatch):
    monkeypatch.setenv("OBSERVABLE_INTENT_SCORER", "clm")
    monkeypatch.setenv("OBSERVABLE_CLM_URL", "https://clm.internal:8700")
    checker = build_intent_checker_from_env()
    assert checker.mode == "clm"
    assert checker.enabled is True


# ---------------------------------------------------------------------
# End-to-end: the §8.5 worked example, against a real running instance
# ---------------------------------------------------------------------
@pytest.fixture()
def client_with_mock_intent(monkeypatch):
    monkeypatch.setenv("OBSERVABLE_INTENT_SCORER", "mock")
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_intent_mismatch_denies_export_but_allows_reads(client_with_mock_intent):
    client = client_with_mock_intent
    agent = AgentClient.enroll(
        http=client, display_name="intent-demo-bot", role="reporting-analyst",
        tier="foundation", enrolled_by="omar",
    )
    purpose = "weekly summary of booking activity"

    # In-purpose reads succeed: their tool name/description shares a
    # word with the declared purpose, so the mock scorer keeps
    # p_consistent >= 0.5 and the signal never fires.
    read_token = agent.request_token(["tool:booking.read"], purpose=purpose)
    read = agent.invoke(read_token, tool_name="booking.read", payload={}, resource_id="B-1")
    assert read["allowed"] is True

    gen_token = agent.request_token(["tool:reporting.generate"], purpose=purpose)
    gen = agent.invoke(gen_token, tool_name="reporting.generate", payload={"report_name": "weekly-activity"})
    assert gen["allowed"] is True

    # reporting.export shares no words with the declared purpose ->
    # intent_mismatch fires, pushing risk_score over the tool's own
    # max_risk_score=0.5 ceiling (booking.create.new_tool alone would
    # not have crossed it).
    export_token = agent.request_token(["tool:reporting.export"], purpose=purpose)
    with pytest.raises(AgentClientError) as exc_info:
        agent.invoke(export_token, tool_name="reporting.export", payload={"format": "csv"})
    assert exc_info.value.status_code == 403
    assert "intent_mismatch" in exc_info.value.detail


def test_off_by_default_never_denies_on_intent(monkeypatch):
    """Without OBSERVABLE_INTENT_SCORER set, the same export call that
    gets denied above must succeed exactly as it did before §8.5."""
    monkeypatch.delenv("OBSERVABLE_INTENT_SCORER", raising=False)
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as client:
        agent = AgentClient.enroll(
            http=client, display_name="intent-off-bot", role="reporting-analyst",
            tier="foundation", enrolled_by="omar",
        )
        token = agent.request_token(
            ["tool:reporting.export"], purpose="weekly summary of booking activity"
        )
        result = agent.invoke(token, tool_name="reporting.export", payload={"format": "csv"})
        assert result["allowed"] is True
    app.dependency_overrides.clear()


def test_admin_detection_intent_endpoint_reports_mode_and_counters(client_with_mock_intent):
    client = client_with_mock_intent
    agent = AgentClient.enroll(
        http=client, display_name="intent-status-bot", role="reporting-analyst",
        tier="foundation", enrolled_by="omar",
    )
    token = agent.request_token(
        ["tool:reporting.export"], purpose="weekly summary of booking activity"
    )
    with pytest.raises(AgentClientError):
        agent.invoke(token, tool_name="reporting.export", payload={"format": "csv"})

    status = client.get("/admin/detection/intent").json()
    assert status["mode"] == "mock"
    assert status["enabled"] is True
    assert status["calls"] >= 1
    assert status["failures"] == 0
