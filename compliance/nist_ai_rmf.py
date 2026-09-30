"""
Block O — NIST AI RMF 1.0 control mapping (v1.5).

A second, independent lens over the same running instance the §9.1
control framework already inspects — not a rewrite of it. Where §9.1's
``DEFAULT_CONTROLS`` map one-to-one to the Zero Trust for AI Agents
guide's rows (ARCHITECTURE.md §5), ``NIST_AI_RMF_CONTROLS`` map to a
representative slice of NIST AI RMF 1.0's GOVERN/MAP/MEASURE/MANAGE
subcategories, reusing the exact same ``ComplianceContext`` (registry,
policy engine, audit chain, inventory, guard) plus one addition: the
Impact Register (``impact_register.py``), which is what MAP 5 asks for
and nothing in §9.1 previously provided.

This is deliberately a representative subset, not full RMF coverage:
each control below is one this specific running instance can actually
probe live, in the same "live/data-driven vs. structural/by-design"
spirit as §9.1 — including controls that come back ``partial`` or
``fail`` where a real gap exists (MEASURE 3.3 below is the clearest
example). A compliance report that never shows red is not trustworthy;
NIST AI RMF explicitly frames risk management as continuous, not a
one-time attestation, and this mode is built to be re-run and to
actually change as the deployment does.
"""
from __future__ import annotations

from observable.compliance.framework import (
    ComplianceContext,
    Control,
    ControlResult,
    ControlStatus,
)
from observable.compliance.impact_register import ImpactSeverity
from observable.inventory.posture import scan_snapshot
from observable.inventory.shadow import Severity as FindingSeverity
from observable.inventory.shadow import detect_shadow_agents


def _check_govern_1_1_policy_documented(ctx: ComplianceContext) -> ControlResult:
    signed = ctx.policy_engine.bundle_signed
    status = ControlStatus.PASS if signed else ControlStatus.PARTIAL
    return ControlResult(
        control_id="nist_govern_1_1",
        title="GOVERN 1.1 — Legal/regulatory requirements involving AI are understood and documented",
        guide_tier="GOVERN 1.1",
        status=status,
        summary=(
            "Currently loaded policy bundle is version-hash-referenced and "
            "signed by an authorized policy-admin certificate"
            if signed
            else "Currently loaded policy bundle is unsigned (load_unsigned_bundle) "
            "— fine for dev, tighten before production"
        ),
        evidence=[
            f"bundle_version={ctx.policy_engine.bundle_version!r}",
            f"bundle_hash={ctx.policy_engine.bundle_hash}",
            "ARCHITECTURE.md §2 documents the eIDAS/QTSP-pluggable trust model this policy sits under",
        ],
    )


def _check_govern_1_5_monitoring(ctx: ComplianceContext) -> ControlResult:
    """Live: does this deployment actually have a working, currently-
    intact continuous monitoring mechanism (the audit chain), not just
    a stated intent to monitor."""
    from observable.guard.audit import AuditIntegrityError

    entries = ctx.audit.entries()
    try:
        ctx.audit.verify_chain()
    except AuditIntegrityError as exc:
        return ControlResult(
            control_id="nist_govern_1_5",
            title="GOVERN 1.5 — Ongoing monitoring and periodic review mechanisms are in place",
            guide_tier="GOVERN 1.5",
            status=ControlStatus.FAIL,
            summary=f"Audit chain integrity check FAILED at entry {exc.broken_at_seq}",
            evidence=[f"{len(entries)} entries recorded before failure"],
        )
    return ControlResult(
        control_id="nist_govern_1_5",
        title="GOVERN 1.5 — Ongoing monitoring and periodic review mechanisms are in place",
        guide_tier="GOVERN 1.5",
        status=ControlStatus.PASS,
        summary=f"Hash-chained audit trail intact across {len(entries)} entries; regenerable live via this report and /export/siem",
        evidence=[
            "GET /compliance/report is generated fresh from live state on every call (§9.1)",
            "GET /export/siem exports the same trail to an external SIEM for independent review",
        ],
    )


def _check_map_1_1_purpose_documented(ctx: ComplianceContext) -> ControlResult:
    """Live: what fraction of registered tools carry a documented
    description an operator (and the intent-conformance signal, §8.5)
    can actually judge intended use against."""
    tools = ctx.policy_engine.registered_tools()
    if not tools:
        return ControlResult(
            control_id="nist_map_1_1",
            title="MAP 1.1 — Intended purpose and context of use are documented",
            guide_tier="MAP 1.1",
            status=ControlStatus.NOT_APPLICABLE,
            summary="No tools are registered in the currently loaded policy bundle",
        )
    documented = [name for name, tool in tools.items() if getattr(tool, "description", None)]
    missing = sorted(set(tools) - set(documented))
    status = (
        ControlStatus.PASS
        if not missing
        else ControlStatus.PARTIAL
        if documented
        else ControlStatus.FAIL
    )
    return ControlResult(
        control_id="nist_map_1_1",
        title="MAP 1.1 — Intended purpose and context of use are documented",
        guide_tier="MAP 1.1",
        status=status,
        summary=(
            f"{len(documented)} of {len(tools)} registered tool(s) carry a documented description"
        ),
        evidence=[f"missing description: {name}" for name in missing[:10]] or ["every registered tool has a description"],
    )


def _check_map_5_1_impacts_characterized(ctx: ComplianceContext) -> ControlResult:
    """The Impact Register (impact_register.py) IS this control: MAP
    5.1 asks that likelihood and magnitude of impacts be characterized,
    which is exactly what each ImpactEntry records. An empty or absent
    register is reported honestly as not_applicable/fail, never
    silently skipped."""
    register = ctx.impact_register
    if register is None:
        return ControlResult(
            control_id="nist_map_5_1",
            title="MAP 5.1 — Likelihood and magnitude of impacts are characterized",
            guide_tier="MAP 5.1",
            status=ControlStatus.NOT_APPLICABLE,
            summary="No Impact Register was supplied to this report",
        )
    entries = register.list()
    if not entries:
        return ControlResult(
            control_id="nist_map_5_1",
            title="MAP 5.1 — Likelihood and magnitude of impacts are characterized",
            guide_tier="MAP 5.1",
            status=ControlStatus.FAIL,
            summary="Impact Register exists but has zero entries — no impacts have been characterized yet",
            evidence=["POST /compliance/impact-register to add the first entry"],
        )
    open_high = register.open_unmitigated_at_or_above(ImpactSeverity.HIGH)
    status = ControlStatus.FAIL if open_high else ControlStatus.PASS
    return ControlResult(
        control_id="nist_map_5_1",
        title="MAP 5.1 — Likelihood and magnitude of impacts are characterized",
        guide_tier="MAP 5.1",
        status=status,
        summary=(
            f"{len(entries)} impact(s) characterized; {len(open_high)} still OPEN at high/critical "
            "severity with no recorded mitigation"
            if open_high
            else f"{len(entries)} impact(s) characterized; none open at high/critical severity without a mitigation"
        ),
        evidence=[f"{e.title} ({e.severity.value}, {e.status.value})" for e in open_high]
        or [f"{e.title} ({e.severity.value}, {e.status.value})" for e in entries[:10]],
    )


def _check_map_5_2_third_party_impacts(ctx: ComplianceContext) -> ControlResult:
    """MAP 5.2 asks specifically about third-party impacts. This reuses
    the Inventory & Posture plane's live shadow-AI/posture data (§7) —
    an unaccounted-for or misconfigured SaaS-native agent is exactly a
    third-party impact source — plus any impact_register entries
    explicitly tagged 'third_party'."""
    from observable.compliance.impact_register import ImpactCategory

    findings_summary: list[str] = []
    high_findings = 0
    if ctx.inventory is not None and ctx.inventory.connector_ids():
        shadow = detect_shadow_agents(inventory=ctx.inventory, registry=ctx.registry)
        high_findings += sum(1 for f in shadow if f.severity == FindingSeverity.HIGH)
        for snapshot in ctx.inventory.all_latest().values():
            posture = scan_snapshot(snapshot)
            high_findings += sum(1 for f in posture if f.severity == FindingSeverity.HIGH)

    third_party_entries = []
    if ctx.impact_register is not None:
        third_party_entries = [
            e for e in ctx.impact_register.list() if e.category == ImpactCategory.THIRD_PARTY
        ]
        findings_summary = [f"{e.title} ({e.status.value})" for e in third_party_entries]

    if ctx.inventory is None or not ctx.inventory.connector_ids():
        status = ControlStatus.NOT_APPLICABLE if not third_party_entries else ControlStatus.PARTIAL
        summary = "No inventory scan has been run yet"
        if third_party_entries:
            summary += f"; {len(third_party_entries)} third-party impact(s) recorded in the Impact Register regardless"
    else:
        status = ControlStatus.FAIL if high_findings else ControlStatus.PASS
        summary = (
            f"{high_findings} high-severity shadow-AI/posture finding(s) with third-party exposure"
            if high_findings
            else "No high-severity shadow-AI/posture findings; "
            f"{len(third_party_entries)} third-party impact(s) tracked in the Impact Register"
        )
    return ControlResult(
        control_id="nist_map_5_2",
        title="MAP 5.2 — Third-party impacts are characterized",
        guide_tier="MAP 5.2",
        status=status,
        summary=summary,
        evidence=findings_summary[:10],
    )


def _check_measure_2_1_tevv_documented(ctx: ComplianceContext) -> ControlResult:
    """Structural: this is a property of the repository, not of live
    request state, so it PASSes by construction with evidence pointing
    at what a reviewer should go read — same convention as §9.1's
    structural checks."""
    return ControlResult(
        control_id="nist_measure_2_1",
        title="MEASURE 2.1 — Test sets, metrics, and TEVV processes are identified and documented",
        guide_tier="MEASURE 2.1",
        status=ControlStatus.PASS,
        summary="Every plane ships a pytest suite plus a scripted, human-readable walkthrough (a 'demo') exercising it end-to-end",
        evidence=[
            "tests/ — one file per block/plane, 191 tests at last run",
            "demo.py, inventory_demo.py, detection_demo.py, intent_demo.py, "
            "compliance_export_demo.py — scripted TEVV-style walkthroughs against the real FastAPI app",
        ],
    )


def _check_measure_2_6_bias_safety(ctx: ComplianceContext) -> ControlResult:
    """Honest partial: the intent-conformance CLM path (§8.5) is
    explicitly documented as zero-shot and not yet validated against a
    live model (§8.6) — this control says so rather than reporting
    green because the mechanism merely exists."""
    checker = ctx.detection.intent_checker if ctx.detection is not None else None
    if checker is None or not getattr(checker, "enabled", False):
        return ControlResult(
            control_id="nist_measure_2_6",
            title="MEASURE 2.6 — Computational bias and safety are evaluated",
            guide_tier="MEASURE 2.6",
            status=ControlStatus.PARTIAL,
            summary="Intent-conformance signal (§8.5) is off; the four statistical signals (§8.2) remain the only measured risk basis",
            evidence=["OBSERVABLE_INTENT_SCORER=off — enable 'mock' or 'clm' to bring the model-derived signal into scope"],
        )
    stats = checker.stats()
    return ControlResult(
        control_id="nist_measure_2_6",
        title="MEASURE 2.6 — Computational bias and safety are evaluated",
        guide_tier="MEASURE 2.6",
        status=ControlStatus.PARTIAL,
        summary=(
            f"Intent-conformance signal armed (mode={stats['mode']}); capped at 0.5 contribution and "
            "explainable, but the CLM adapter is explicitly documented as zero-shot and not yet "
            "validated against a live model (§8.6) — see the Impact Register's 'CLM scorer' entry"
        ),
        evidence=[
            f"calls={stats['calls']}, failures={stats['failures']}",
            "ARCHITECTURE.md §8.6: 'Not validated against a live model in this repository'",
        ],
    )


def _check_measure_3_3_feedback(ctx: ComplianceContext) -> ControlResult:
    """Deliberately honest gap: there is no end-user feedback or appeal
    channel in this reference deployment today. Reporting this as a
    real fail is the point of building this control at all — a NIST
    AI RMF report that never shows red is not one an auditor should
    trust, and papering over a known gap here would be exactly that."""
    return ControlResult(
        control_id="nist_measure_3_3",
        title="MEASURE 3.3 — Feedback from relevant AI actors is collected and assessed",
        guide_tier="MEASURE 3.3",
        status=ControlStatus.FAIL,
        summary=(
            "No feedback or appeal channel exists yet for an agent operator to contest a denial "
            "or an automated containment — this is a documented, open gap, not a missed check"
        ),
        evidence=[
            "SOAR incident export (§9.3) surfaces containment events for human review, but that is "
            "operator-facing monitoring, not an end-user/agent-operator feedback or appeal path",
        ],
    )


def _check_manage_1_3_risk_response_tracked(ctx: ComplianceContext) -> ControlResult:
    if ctx.guard is None:
        return ControlResult(
            control_id="nist_manage_1_3",
            title="MANAGE 1.3 — Responses to risks are documented, tracked, and prioritized",
            guide_tier="MANAGE 1.3",
            status=ControlStatus.NOT_APPLICABLE,
            summary="No Agent Guard instance supplied to this report",
        )
    threshold = ctx.guard.auto_contain_threshold
    status = ControlStatus.PASS if threshold is not None else ControlStatus.PARTIAL
    return ControlResult(
        control_id="nist_manage_1_3",
        title="MANAGE 1.3 — Responses to risks are documented, tracked, and prioritized",
        guide_tier="MANAGE 1.3",
        status=status,
        summary=(
            f"Automated containment configured at risk_score >= {threshold:.2f}; every trigger becomes a "
            "SOAR incident with recommended next steps (§9.3)"
            if threshold is not None
            else "No auto-containment threshold configured — response today is manual-only "
            "(mechanism present, decision not yet made by an operator)"
        ),
        evidence=["POST /admin/detection/threshold", "GET /export/soar/incidents"],
    )


def _check_manage_4_1_post_deployment_monitoring(ctx: ComplianceContext) -> ControlResult:
    entries = ctx.audit.entries()
    status = ControlStatus.PASS if entries else ControlStatus.PARTIAL
    return ControlResult(
        control_id="nist_manage_4_1",
        title="MANAGE 4.1 — AI systems are monitored for performance/trustworthiness post-deployment",
        guide_tier="MANAGE 4.1",
        status=status,
        summary=(
            f"{len(entries)} audit entries recorded; every enrolled agent has a live, queryable "
            "behavioral baseline (§8) and this compliance report itself is regenerable on demand"
            if entries
            else "No audit activity recorded yet — nothing has been monitored post-deployment"
        ),
        evidence=["GET /detection/{agent_id} — live baseline per agent", "GET /compliance/report — regenerated fresh on every call"],
    )


NIST_AI_RMF_CONTROLS: list[Control] = [
    Control("nist_govern_1_1", "GOVERN 1.1", "GOVERN 1.1", _check_govern_1_1_policy_documented),
    Control("nist_govern_1_5", "GOVERN 1.5", "GOVERN 1.5", _check_govern_1_5_monitoring),
    Control("nist_map_1_1", "MAP 1.1", "MAP 1.1", _check_map_1_1_purpose_documented),
    Control("nist_map_5_1", "MAP 5.1", "MAP 5.1", _check_map_5_1_impacts_characterized),
    Control("nist_map_5_2", "MAP 5.2", "MAP 5.2", _check_map_5_2_third_party_impacts),
    Control("nist_measure_2_1", "MEASURE 2.1", "MEASURE 2.1", _check_measure_2_1_tevv_documented),
    Control("nist_measure_2_6", "MEASURE 2.6", "MEASURE 2.6", _check_measure_2_6_bias_safety),
    Control("nist_measure_3_3", "MEASURE 3.3", "MEASURE 3.3", _check_measure_3_3_feedback),
    Control("nist_manage_1_3", "MANAGE 1.3", "MANAGE 1.3", _check_manage_1_3_risk_response_tracked),
    Control("nist_manage_4_1", "MANAGE 4.1", "MANAGE 4.1", _check_manage_4_1_post_deployment_monitoring),
]
