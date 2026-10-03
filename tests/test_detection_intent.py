"""
Detection Block E — intent-conformance signal (§8.5): integration paths.

``test_intent_signal.py`` covers the scorer maths, IntentChecker's skip
rules, the env factory and the API end to end. This file covers what
sits between them: what the checker hands a scorer, the CLM adapter's
HTTP contract, how DetectionEngine combines the signal with the four
statistical ones, and how AgentGuard surfaces a scorer outage.
"""
import datetime as dt

import httpx
import pytest

from observable.detection.engine import DetectionEngine
from observable.detection.intent import (
    CLMIntentScorer,
    IntentChecker,
    IntentScorerError,
    MockIntentScorer,
)
from observable.detection.scorer import NEW_TOOL_RISK_MEDIUM_SENSITIVITY
from observable.guard.gateway import AgentGuard, GuardDeniedError
from observable.identity.registry import IdentityRegistry
from observable.pki.interface import CertificateTier
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import Sensitivity, default_bundle
from observable.policy.engine import PolicyEngine
from observable.tokens.service import TokenService

NOW = dt.datetime(2026, 9, 27, 10, 0, tzinfo=dt.timezone.utc)
PURPOSE = "weekly summary of booking activity"
INTENT_MAX_RISK = 0.5


class FixedScorer:
    """Returns a fixed probability and records every call it saw."""

    def __init__(self, p: float):
        self.p = p
        self.calls: list[dict] = []

    def score(self, **kwargs):
        self.calls.append(kwargs)
        return self.p


class BrokenScorer:
    def score(self, **kwargs):
        raise IntentScorerError("connection refused")


@pytest.fixture()
def policy_engine():
    ca = ReferenceCA(org_name="Test CA")
    return PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)


def _check(checker, *, tool="reporting.export", recent_tools=(), sensitivity=Sensitivity.MEDIUM):
    return checker.check(
        role="reporting-analyst", purpose=PURPOSE, recent_tools=list(recent_tools),
        tool_name=tool, tool_description="Export a report", sensitivity=sensitivity,
    )


# ----------------------------------------------------------------------
# Checker: what the scorer is given
# ----------------------------------------------------------------------
def test_checker_passes_only_the_last_recent_tools():
    scorer = FixedScorer(0.9)
    history = [f"t{i}" for i in range(8)]
    _check(IntentChecker(mode="mock", scorer=scorer), recent_tools=history)
    call = scorer.calls[0]
    assert call["recent_tools"] == history[-5:]
    assert call["tool_description"] == "Export a report"


def test_checker_treats_unknown_sensitivity_as_low():
    # An unregistered tool has no sensitivity; under the default MEDIUM
    # floor it must never trigger a model call.
    scorer = FixedScorer(0.0)
    result = _check(IntentChecker(mode="mock", scorer=scorer), tool="nope.tool", sensitivity=None)
    assert result.label is None and scorer.calls == []


def test_checker_label_is_capped_and_names_scorer():
    result = _check(IntentChecker(mode="mock", scorer=FixedScorer(0.0)))
    assert result.risk == pytest.approx(INTENT_MAX_RISK)
    assert result.label.startswith("intent_mismatch(tool='reporting.export'")
    assert "p_consistent=0.00" in result.label and "scorer=mock" in result.label


# ----------------------------------------------------------------------
# CLM adapter (HTTP contract, no model needed)
# ----------------------------------------------------------------------
def _clm_score(scorer):
    return scorer.score(
        role="reporting-analyst", purpose=PURPOSE, recent_tools=["booking.read"],
        tool_name="reporting.export", tool_description="Export a report",
    )


def test_clm_scorer_request_and_response_contract(monkeypatch):
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen.update(url=url, json=json, headers=headers, timeout=timeout)
        return httpx.Response(200, json={"probability": 0.12}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    scorer = CLMIntentScorer(base_url="http://clm.local:8700/", api_key="k", timeout=2.0)
    assert _clm_score(scorer) == pytest.approx(0.12)
    assert seen["url"] == "http://clm.local:8700/v1/systemone"
    assert seen["headers"]["Authorization"] == "Bearer k"
    assert seen["timeout"] == 2.0
    question = seen["json"]["question"]
    assert PURPOSE in question and "reporting.export" in question and "booking.read" in question


def test_clm_scorer_omits_auth_header_without_api_key(monkeypatch):
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen["headers"] = headers
        return httpx.Response(200, json={"probability": 0.9}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    _clm_score(CLMIntentScorer(base_url="http://clm.local:8700"))
    assert "Authorization" not in seen["headers"]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(502, text="embedder down"),
        httpx.Response(200, json={}),
        httpx.Response(200, text="not json"),
    ],
)
def test_clm_scorer_bad_responses_raise(monkeypatch, response):
    def fake_post(url, **kwargs):
        response.request = httpx.Request("POST", url)
        return response

    monkeypatch.setattr(httpx, "post", fake_post)
    with pytest.raises(IntentScorerError):
        _clm_score(CLMIntentScorer(base_url="http://clm.local:8700"))


def test_clm_scorer_network_error_raises(monkeypatch):
    def fake_post(url, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", fake_post)
    with pytest.raises(IntentScorerError):
        _clm_score(CLMIntentScorer(base_url="http://clm.local:8700"))


# ----------------------------------------------------------------------
# Engine integration
# ----------------------------------------------------------------------
def test_engine_combines_intent_with_statistical_signals(policy_engine):
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine,
        intent_checker=IntentChecker(mode="mock", scorer=FixedScorer(0.0)),
    )
    a = engine.pre_score(
        agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
        role="reporting-analyst", purpose=PURPOSE,
    )
    # new_tool (medium) and intent_mismatch (capped) combine via noisy-OR
    expected = 1 - (1 - NEW_TOOL_RISK_MEDIUM_SENSITIVITY) * (1 - INTENT_MAX_RISK)
    assert a.risk_score == pytest.approx(expected)
    assert any(s.startswith("intent_mismatch") for s in a.signals)


def test_engine_passes_tool_description_from_policy(policy_engine):
    scorer = FixedScorer(0.9)
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine, intent_checker=IntentChecker(mode="mock", scorer=scorer)
    )
    engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
                     role="reporting-analyst", purpose=PURPOSE)
    assert scorer.calls[0]["tool_description"] == "Export a generated report to an external format/location"


def test_engine_passes_only_allowed_calls_as_history(policy_engine):
    scorer = FixedScorer(0.9)
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine, intent_checker=IntentChecker(mode="mock", scorer=scorer)
    )
    engine.record_event(agent_id="a1", tool="booking.read", resource_id=None, decision="allow", timestamp=NOW)
    engine.record_event(agent_id="a1", tool="crm.delete", resource_id=None, decision="deny", timestamp=NOW)
    engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
                     role="reporting-analyst", purpose=PURPOSE)
    assert scorer.calls[0]["recent_tools"] == ["booking.read"]


def test_engine_without_role_skips_intent(policy_engine):
    scorer = FixedScorer(0.0)
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine, intent_checker=IntentChecker(mode="mock", scorer=scorer)
    )
    a = engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW)
    assert scorer.calls == [] and not any(s.startswith("intent_mismatch") for s in a.signals)


def test_engine_without_checker_reports_none():
    engine = DetectionEngine()
    assert engine.intent_checker is None
    a = engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
                         role="reporting-analyst", purpose=PURPOSE)
    assert not a.detection_degraded


def test_engine_surfaces_degraded(policy_engine):
    engine = DetectionEngine(
        sensitivity_lookup=policy_engine, intent_checker=IntentChecker(mode="clm", scorer=BrokenScorer())
    )
    a = engine.pre_score(agent_id="a1", tool="reporting.export", resource_id=None, timestamp=NOW,
                         role="reporting-analyst", purpose=PURPOSE)
    assert a.detection_degraded and "connection refused" in a.degraded_reason
    assert not any(s.startswith("intent_mismatch") for s in a.signals)


# ----------------------------------------------------------------------
# Guard integration: the exfiltration scenario
# ----------------------------------------------------------------------
def _guard_setup(checker):
    ca = ReferenceCA(org_name="Test CA")
    registry = IdentityRegistry(ca)
    policy = PolicyEngine(ca=ca, bundle=default_bundle(), business_hours_check=lambda ts: True)
    tokens = TokenService(ca=ca, registry=registry, scope_authorizer=policy)
    detection = DetectionEngine(sensitivity_lookup=policy, intent_checker=checker)
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
    guard, cert, token = _guard_setup(IntentChecker(mode="mock", scorer=MockIntentScorer()))
    ok = guard.invoke(client_cert_pem=cert, token=token, tool_name="booking.read", payload={}, resource_id="B-1")
    assert ok.allowed and not any(s.startswith("intent_mismatch") for s in ok.detection_signals)

    # reporting.export has max_risk_score=0.5. new_tool alone (0.25) would
    # pass; with intent_mismatch the combined score crosses the ceiling.
    with pytest.raises(GuardDeniedError) as exc:
        guard.invoke(client_cert_pem=cert, token=token, tool_name="reporting.export", payload={})
    assert "intent_mismatch" in exc.value.reason
    assert "exceeds max 0.50" in exc.value.reason


def test_scorer_outage_does_not_block_and_is_audited():
    guard, cert, token = _guard_setup(IntentChecker(mode="clm", scorer=BrokenScorer()))
    # Same export the mock scorer denies above: with the scorer down the
    # signal fails open, so new_tool alone stays under the 0.5 ceiling.
    result = guard.invoke(client_cert_pem=cert, token=token, tool_name="reporting.export", payload={})
    assert result.allowed and result.detection_degraded
    last = guard.audit.entries()[-1]
    assert "detection degraded" in last.reason
