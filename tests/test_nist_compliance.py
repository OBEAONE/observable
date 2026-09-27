"""
Tests for the NIST AI RMF compliance-report mode (§9.5) and the Impact
Register (MAP 5): the register's math and its coercion/error handling,
the NIST control set's honest-gap behavior (MEASURE 3.3 always fails;
MAP 5.1 tracks the register's actual state), and the HTTP surface
(``?framework=nist-ai-rmf``, the impact-register CRUD endpoints).
"""
import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state
from observable.compliance.framework import ComplianceContext
from observable.compliance.impact_register import (
    ImpactCategory,
    ImpactLikelihood,
    ImpactRegister,
    ImpactRegisterError,
    ImpactSeverity,
    ImpactStatus,
    seed_reflexive_governance_entries,
)
from observable.compliance.nist_ai_rmf import NIST_AI_RMF_CONTROLS
from observable.compliance.report import generate_report


# ---------------------------------------------------------------------
# ImpactRegister
# ---------------------------------------------------------------------
def test_add_and_list_returns_oldest_first():
    register = ImpactRegister()
    first = register.add(
        title="A", category="privacy", affected_parties=["users"], description="d",
        severity="low", likelihood="rare",
    )
    second = register.add(
        title="B", category="security", affected_parties=["ops"], description="d2",
        severity="high", likelihood="likely",
    )
    entries = register.list()
    assert [e.entry_id for e in entries] == [first.entry_id, second.entry_id]
    assert entries[0].category == ImpactCategory.PRIVACY
    assert entries[1].severity == ImpactSeverity.HIGH


def test_invalid_enum_value_raises_impact_register_error():
    register = ImpactRegister()
    with pytest.raises(ImpactRegisterError):
        register.add(
            title="A", category="not-a-real-category", affected_parties=[],
            description="d", severity="low", likelihood="rare",
        )


def test_update_status_and_mitigation():
    register = ImpactRegister()
    entry = register.add(
        title="A", category="safety", affected_parties=["agents"], description="d",
        severity="medium", likelihood="possible",
    )
    assert entry.status == ImpactStatus.OPEN
    updated = register.update_status(entry.entry_id, "mitigated", mitigation="fixed it")
    assert updated.status == ImpactStatus.MITIGATED
    assert updated.mitigation == "fixed it"
    assert updated.updated_at >= updated.created_at


def test_update_status_unknown_entry_raises():
    register = ImpactRegister()
    with pytest.raises(ImpactRegisterError):
        register.update_status("does-not-exist", "mitigated")


def test_open_unmitigated_at_or_above_filters_by_status_and_severity():
    register = ImpactRegister()
    register.add(
        title="open-high", category="security", affected_parties=["x"], description="d",
        severity="high", likelihood="likely", status="open",
    )
    register.add(
        title="mitigated-critical", category="security", affected_parties=["x"], description="d",
        severity="critical", likelihood="likely", status="mitigated",
    )
    register.add(
        title="open-low", category="security", affected_parties=["x"], description="d",
        severity="low", likelihood="rare", status="open",
    )
    flagged = register.open_unmitigated_at_or_above(ImpactSeverity.HIGH)
    assert [e.title for e in flagged] == ["open-high"]


def test_seed_reflexive_governance_entries_populates_register():
    register = ImpactRegister()
    seed_reflexive_governance_entries(register)
    entries = register.list()
    assert len(entries) >= 4
    categories = {e.category for e in entries}
    assert ImpactCategory.FAIRNESS in categories  # the CLM-bias entry
    assert ImpactCategory.THIRD_PARTY in categories


# ---------------------------------------------------------------------
# NIST_AI_RMF_CONTROLS — run directly against a ComplianceContext
# ---------------------------------------------------------------------
def _bare_ctx(**overrides) -> ComplianceContext:
    state = build_default_state()
    ctx = ComplianceContext(
        registry=state.registry,
        policy_engine=state.policy_engine,
        audit=state.guard.audit,
        inventory=state.inventory,
        guard=state.guard,
        impact_register=state.impact_register,
        detection=state.detection,
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


def test_map_5_1_not_applicable_without_a_register():
    ctx = _bare_ctx(impact_register=None)
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    result = next(r for r in report.results if r.control_id == "nist_map_5_1")
    assert result.status.value == "not_applicable"


def test_map_5_1_fails_on_empty_register():
    ctx = _bare_ctx(impact_register=ImpactRegister())
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    result = next(r for r in report.results if r.control_id == "nist_map_5_1")
    assert result.status.value == "fail"


def test_map_5_1_fails_on_open_high_severity_unmitigated():
    register = ImpactRegister()
    register.add(
        title="bad", category="safety", affected_parties=["x"], description="d",
        severity="critical", likelihood="likely", status="open",
    )
    ctx = _bare_ctx(impact_register=register)
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    result = next(r for r in report.results if r.control_id == "nist_map_5_1")
    assert result.status.value == "fail"


def test_map_5_1_passes_on_default_seeded_register():
    """The seeded register (build_default_state's actual startup state)
    has one OPEN item, but at MEDIUM severity, below the HIGH floor
    MAP 5.1 flags — so this should pass, not fail."""
    ctx = _bare_ctx()
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    result = next(r for r in report.results if r.control_id == "nist_map_5_1")
    assert result.status.value == "pass"


def test_measure_3_3_is_always_an_honest_fail():
    """No feedback/appeal channel exists in this reference deployment
    — the control must say so, not report green because a mechanism
    happens to exist somewhere adjacent (SOAR export)."""
    ctx = _bare_ctx()
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    result = next(r for r in report.results if r.control_id == "nist_measure_3_3")
    assert result.status.value == "fail"


def test_nist_report_overall_status_reflects_the_worst_control():
    ctx = _bare_ctx()
    report = generate_report(ctx, controls=NIST_AI_RMF_CONTROLS)
    assert report.overall_status.value == "fail"  # MEASURE 3.3 alone guarantees this
    assert {r.control_id for r in report.results} == {c.control_id for c in NIST_AI_RMF_CONTROLS}


# ---------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------
@pytest.fixture()
def client():
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_compliance_report_defaults_to_zta(client):
    resp = client.get("/compliance/report")
    assert resp.status_code == 200
    assert resp.json()["framework"] == "zta"


def test_compliance_report_nist_framework(client):
    resp = client.get("/compliance/report?framework=nist-ai-rmf")
    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "nist-ai-rmf"
    control_ids = {r["control_id"] for r in body["results"]}
    assert "nist_map_5_1" in control_ids
    assert "nist_measure_3_3" in control_ids
    # guide_tier holds the NIST subcategory label for this framework,
    # not a ZTA GuideTier value.
    map_5_1 = next(r for r in body["results"] if r["control_id"] == "nist_map_5_1")
    assert map_5_1["guide_tier"] == "MAP 5.1"


def test_compliance_report_unknown_framework_is_400(client):
    resp = client.get("/compliance/report?framework=bogus")
    assert resp.status_code == 400


def test_get_impact_register_returns_seeded_entries(client):
    resp = client.get("/compliance/impact-register")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) >= 4
    assert sum(body["counts"].values()) == len(body["entries"])


def test_post_impact_register_adds_entry(client):
    resp = client.post(
        "/compliance/impact-register",
        json={
            "title": "New impact",
            "category": "privacy",
            "affected_parties": ["customers"],
            "description": "something",
            "severity": "low",
            "likelihood": "rare",
        },
    )
    assert resp.status_code == 200
    entry = resp.json()
    assert entry["status"] == "open"
    assert entry["entry_id"]

    listing = client.get("/compliance/impact-register").json()
    assert any(e["entry_id"] == entry["entry_id"] for e in listing["entries"])


def test_post_impact_register_invalid_category_is_400(client):
    resp = client.post(
        "/compliance/impact-register",
        json={
            "title": "Bad",
            "category": "not-real",
            "affected_parties": [],
            "description": "d",
            "severity": "low",
            "likelihood": "rare",
        },
    )
    assert resp.status_code == 400


def test_update_impact_entry_status(client):
    created = client.post(
        "/compliance/impact-register",
        json={
            "title": "To be mitigated",
            "category": "security",
            "affected_parties": ["ops"],
            "description": "d",
            "severity": "high",
            "likelihood": "possible",
        },
    ).json()

    updated = client.post(
        f"/compliance/impact-register/{created['entry_id']}/status",
        json={"status": "mitigated", "mitigation": "patched"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "mitigated"
    assert updated.json()["mitigation"] == "patched"


def test_update_impact_entry_status_unknown_id_is_404(client):
    resp = client.post(
        "/compliance/impact-register/does-not-exist/status",
        json={"status": "mitigated"},
    )
    assert resp.status_code == 404
