"""Detection Block D — intent-conformance signal (§8.5)."""
import datetime as dt
import json

import httpx
import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state, build_intent_checker
from observable.client.sdk import AgentClient, AgentClientError
from observable.detection.engine import DetectionEngine
from observable.detection.intent import (
    INTENT_MAX_RISK,
    CLMIntentScorer,
    IntentChecker,
    IntentQuery,
    IntentScorerError,
    MockIntentScorer,
)
from observable.guard.gateway import AgentGuard, GuardDeniedError
from observable.identity.registry import IdentityRegistry
from observable.pki.interface import CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import Sensitivity, default_bundle
from observable.policy.engine import PolicyEngine
from observable.tokens.service import TokenService

NOW = dt.datetime(2026, 9, 27, 10, 0, tzinfo=dt.timezone.utc)
PURPOSE = "weekly summary of booking activity"


class FixedScorer:
    """Returns a fixed probability and records every query it saw."""

    name = "fixed"

    def __init__(self, p: float):
        self.p = p
        self.queries: list[IntentQuery] = []

    def p_consistent(self, query):
        self.queries.append(query)
        return self.p


class BrokenScorer:
    name = "broken"

    def p_consistent(self, query):
        raise IntentScorerError("connection refused")


@pytest.fixture()
def policy_engine():
    ca = ReferenceCA(org_name="Test CA")
    return PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)


# ----------------------------------------------------------------------
# Checker: signal maths and skip rules
# ----------------------------------------------------------------------
def test_consistent_call_produces_no_signal(policy_engine):
    checker = IntentChecker(FixedScorer(0.8), policy_engine)
    result = checker.check(role="reporting-analyst", purpose=PURPOSE, tool="booking.read", recent_tools=[])
    assert result.label is None and result.risk == 0.0 and result.p_consistent == 0.8


def test_inconsistent_call_fires_and_is_capped(policy_engine):
    checker = IntentChecker(FixedScorer(0.0), policy_engine)
    result = checker.check(role="reporting-analyst", purpose=PURPOSE, tool="reporting.export", recent_tools=[])
    assert result.risk == pytest.approx(INTENT_MAX_RISK)
    assert result.label.startswith("intent_mismatch(tool='reporting.export'")
    assert "scorer=fixed" in result.label and "p_consistent=0.00" in result.label


def test_risk_scales_linearly_below_threshold(policy_engine):
    checker = IntentChecker(FixedScorer(0.25), policy_engine)
    result = checker.check(role="r", purpose=PURPOSE, tool="reporting.export", recent_tools=[])
    assert result.risk == pytest.approx(INTENT_MAX_RISK * 0.5)


def test_no_declared_purpose_skips_scorer(policy_engine):
    scorer = FixedScorer(0.0)
    checker = IntentChecker(scorer, policy_engine)
    result = checker.check(role="r", purpose=None, tool="reporting.export", recent_tools=[])
    assert result.label is None and scorer.queries == []
    assert checker.status()["skipped_no_purpose"] == 1


def test_unregistered_tool_skips_scorer(policy_engine):
    scorer = FixedScorer(0.0)
    checker = IntentChecker(scorer, policy_engine)
    assert checker.check(role="r", purpose=PURPOSE, tool="nope.tool", recent_tools=[]).label is None
    assert scorer.queries == []


def test_min_sensitivity_skips_low_tools(policy_engine):
    scorer = FixedScorer(0.0)
    checker = IntentChecker(scorer, policy_engine, min_sensitivity=Sensitivity.MEDIUM)
    assert checker.check(role="r", purpose=PURPOSE, tool="booking.read", recent_tools=[]).label is None
    assert checker.check(role="r", purpose=PURPOSE, tool="reporting.export", recent_tools=[]).label
    assert checker.status()["skipped_sensitivity"] == 1


def test_query_carries_description_and_recent_tools(policy_engine):
    scorer = FixedScorer(0.9)
    checker = IntentChecker(scorer, policy_engine)
    history = [f"t{i}" for i in range(8)]
    checker.check(role="reporting-analyst", purpose=PURPOSE, tool="reporting.export", recent_tools=history)
    q = scorer.queries[0]
    assert q.tool_description == "Export a generated report to an external format/location"
    assert q.recent_tools == tuple(history[-5:])


def test_scorer_failure_degrades_without_signal(policy_engine):
    checker = IntentChecker(BrokenScorer(), policy_engine)
    result = checker.check(role="r", purpose=PURPOSE, tool="reporting.export", recent_tools=[])
    assert result.label is None and result.risk == 0.0
    assert "intent_scorer_unavailable(broken" in result.degraded
    status = checker.status()
    assert status["failures"] == 1 and "connection refused" in status["last_error"]


def test_long_purpose_is_truncated_in_label(policy_engine):
    checker = IntentChecker(FixedScorer(0.0), policy_engine)
    result = checker.check(role="r", purpose="x" * 500, tool="reporting.export", recent_tools=[])
    assert len(result.label) < 250


# ----------------------------------------------------------------------
# Mock scorer
# ----------------------------------------------------------------------
def _q(tool, description, purpose=PURPOSE):
    return IntentQuery(role="r", purpose=purpose, recent_tools=(), tool_name=tool, tool_description=description)


def test_mock_scorer_is_deterministic_keyword_overlap():
    mock = MockIntentScorer()
    assert mock.p_consistent(_q("booking.read", "Read a booking/reservation record")) >= 0.5
    assert mock.p_consistent(_q("reporting.generate", "Generate a summary report from operational data")) >= 0.5
    assert mock.p_consistent(
        _q("reporting.export", "Export a generated report to an external format/location")
    ) < 0.5


# ----------------------------------------------------------------------
# CLM adapter (HTTP contract, no model needed)
# ----------------------------------------------------------------------
def test_clm_scorer_request_and_response_contract():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"model": "clm-latest", "answers": {"intent": {"type": "noul", "noul": 0.12}}})

    scorer = CLMIntentScorer("http://clm.local:8700/", api_key="k", transport=httpx.MockTransport(handler))
    p = scorer.p_consistent(_q("reporting.export", "Export a report"))
    assert p == pytest.approx(0.12)
    assert seen["path"] == "/v1/systemone"
    assert seen["auth"] == "Bearer k"
    body = seen["body"]
    assert body["state"]["declared_purpose"] == PURPOSE
    assert body["state"]["requested_tool"]["name"] == "reporting.export"
    assert body["questions"]["intent"]["type"] == "noul"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(502, text="embedder down"),
        httpx.Response(200, json={"answers": {}}),
        httpx.Response(200, json={"answers": {"intent": {"noul": 1.7}}}),
    ],
)
def test_clm_scorer_bad_responses_raise(response):
    scorer = CLMIntentScorer(transport=httpx.MockTransport(lambda r: response))
    with pytest.raises(IntentScorerError):
        scorer.p_consistent(_q("reporting.export", "Export a report"))


def test_clm_scorer_network_error_raises():
    def handler(request):
        raise httpx.ConnectError("refused")

    scorer = CLMIntentScorer(transport=httpx.MockTransport(handler))
    with pytest.raises(IntentScorerError):
        scorer.p_consistent(_q("reporting.export", "Export a report"))


# ----------------------------------------------------------------------
# Engine integration
# ----------------------------------------------------------------------
def test_engine_combines_intent_with_statistical_signals(policy_engine):
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine, intent_checker=IntentChecker(FixedScorer(0.0), policy_engine)
    )
    a = engine.pre_score(
        agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
        role="reporting-analyst", purpose=PURPOSE,
    )
    # new_tool (medium, 0.25) and intent_mismatch (0.5) via noisy-OR
    assert a.risk_score == pytest.approx(1 - (1 - 0.25) * (1 - INTENT_MAX_RISK))
    assert any(s.startswith("intent_mismatch") for s in a.signals)


def test_engine_passes_only_allowed_calls_as_history(policy_engine):
    scorer = FixedScorer(0.9)
    engine = DetectionEngine(intent_checker=IntentChecker(scorer, policy_engine))
    engine.record_event(agent_id="a1", tool="booking.read", resource_id=None, decision="allow", timestamp=NOW)
    engine.record_event(agent_id="a1", tool="crm.delete", resource_id=None, decision="deny", timestamp=NOW)
    engine.pre_score(agent_id="a1", tool="reporting.generate", resource_id=None, timestamp=NOW,
                     role="reporting-analyst", purpose=PURPOSE)
    assert scorer.queries[0].recent_tools == ("booking.read",)
    assert engine.baseline_summary("a1")["recent_tools"] == ["booking.read"]


def test_engine_without_checker_reports_disabled(policy_engine):
    assert DetectionEngine().intent_status() == {"enabled": False}


def test_engine_surfaces_degraded(policy_engine):
    engine = DetectionEngine(intent_checker=IntentChecker(BrokenScorer(), policy_engine))
    a = engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
                         role="r", purpose=PURPOSE)
    assert a.degraded and not any(s.startswith("intent_mismatch") for s in a.signals)


# ----------------------------------------------------------------------
# Guard integration: the exfiltration scenario
# ----------------------------------------------------------------------
def _guard_setup(scorer):
    ca = ReferenceCA(org_name="Test CA")
    registry = IdentityRegistry(ca)
    policy = PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)
    tokens = TokenService(ca=ca, registry=registry, scope_authorizer=policy)
    detection = DetectionEngine(sensitivity_lookup=policy, intent_checker=IntentChecker(scorer, policy))
    guard = AgentGuard(registry=registry, token_service=tokens, policy_engine=policy, detection=detection)
    for tool in ("reporting.generate", "reporting.export", "booking.read"):
        guard.register_tool(tool, lambda p, r: {"ok": True})
    _, pub = ReferenceCA.generate_keypair()
    enrollment = registry.enroll(
        display_name="analyst", role="reporting-analyst", tier=CertificateTier.FOUNDATION,
        public_key_pem=pub, enrolled_by="omar",
    )
    cert = enrollment.certificate.certificate_pem
    token = tokens.mint(
        client_cert_pem=cert,
        requested_scopes=["tool:reporting.generate", "tool:reporting.export", "tool:booking.read"],
        purpose=PURPOSE,
    )
    return guard, cert, token.jwt


def test_off_purpose_export_is_denied_by_existing_abac_ceiling():
    guard, cert, token = _guard_setup(MockIntentScorer())
    ok = guard.invoke(client_cert_pem=cert, token=token, tool_name="booking.read", payload={}, resource_id="B-1")
    assert ok.allowed and not any(s.startswith("intent_mismatch") for s in ok.detection_signals)

    # reporting.export has max_risk_score=0.5. new_tool alone (0.25) would
    # pass; with intent_mismatch the combined score crosses the ceiling.
    with pytest.raises(GuardDeniedError) as exc:
        guard.invoke(client_cert_pem=cert, token=token, tool_name="reporting.export", payload={})
    assert "intent_mismatch" in exc.value.reason
    assert "exceeds max 0.50" in exc.value.reason


def test_scorer_outage_does_not_block_and_is_audited():
    guard, cert, token = _guard_setup(BrokenScorer())
    result = guard.invoke(client_cert_pem=cert, token=token, tool_name="booking.read", payload={}, resource_id="B-1")
    assert result.allowed
    assert result.detection_degraded and "intent_scorer_unavailable" in result.detection_degraded[0]
    last = guard.audit.entries()[-1]
    assert "detection degraded" in last.reason


# ----------------------------------------------------------------------
# Configuration and API
# ----------------------------------------------------------------------
def test_env_config(policy_engine):
    assert build_intent_checker(policy_engine, env={}) is None
    mock = build_intent_checker(policy_engine, env={"OBSERVABLE_INTENT_SCORER": "mock"})
    assert mock.scorer.name == "mock" and mock.min_sensitivity is None
    clm = build_intent_checker(
        policy_engine,
        env={"OBSERVABLE_INTENT_SCORER": "clm", "OBSERVABLE_CLM_URL": "http://gpu:8700"},
    )
    assert clm.scorer.name == "clm" and clm.min_sensitivity == Sensitivity.MEDIUM
    high = build_intent_checker(
        policy_engine,
        env={"OBSERVABLE_INTENT_SCORER": "clm", "OBSERVABLE_INTENT_MIN_SENSITIVITY": "high"},
    )
    assert high.min_sensitivity == Sensitivity.HIGH
    with pytest.raises(ValueError):
        build_intent_checker(policy_engine, env={"OBSERVABLE_INTENT_SCORER": "gpt"})


@pytest.fixture()
def mock_client(monkeypatch):
    monkeypatch.setenv("OBSERVABLE_INTENT_SCORER", "mock")
    state = build_default_state()
    state.policy_engine._business_hours_check = lambda ts: True
    app.dependency_overrides[get_state] = lambda: state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_api_intent_status_default_off():
    state = build_default_state()
    app.dependency_overrides[get_state] = lambda: state
    try:
        with TestClient(app) as c:
            assert c.get("/admin/detection/intent").json() == {"enabled": False}
    finally:
        app.dependency_overrides.clear()


def test_api_end_to_end_with_mock_scorer(mock_client):
    agent = AgentClient.enroll(
        http=mock_client, display_name="analyst", role="reporting-analyst", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:booking.read", "tool:reporting.export"], purpose=PURPOSE)
    ok = agent.invoke(token, tool_name="booking.read", payload={}, resource_id="B-1")
    assert ok["detection_degraded"] == []
    with pytest.raises(AgentClientError) as exc:
        agent.invoke(token, tool_name="reporting.export", payload={})
    assert "intent_mismatch" in str(exc.value)
    status = mock_client.get("/admin/detection/intent").json()
    assert status["enabled"] and status["scorer"] == "mock" and status["fired"] == 1
