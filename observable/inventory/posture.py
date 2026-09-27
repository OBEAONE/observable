"""
Block 10 — Posture findings engine.

A small, explicit rule set scanning what the Inventory Store has
discovered — the AppOmni-style "AppOmni Insights" capability from the
guide's Enterprise-tier observability row: correlate findings and give
step-by-step remediation, not just a raw list of objects. Each rule is
independently testable and returns findings that name the specific
object and the rule that fired (ARCHITECTURE.md §7.3) — never just a
count.

Deliberately not ML-based: these are the cheap, high-value, "obviously
wrong" checks (stale privileged accounts, MFA gaps, overly broad agent
grants, drift that adds a privileged grant) that a mature program
should have covered before reaching for statistical anomaly detection
(v2, per the roadmap).
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from observable.inventory.connector import TenantSnapshot
from observable.inventory.shadow import Severity
from observable.inventory.store import SnapshotDiff

STALE_LOGIN_THRESHOLD = dt.timedelta(days=90)
_PRIVILEGED_SCOPE_LEVELS = {"admin", "full_access"}


@dataclasses.dataclass(frozen=True)
class PostureFinding:
    connector_id: str
    app_id: str
    rule_id: str
    severity: Severity
    object_ref: str
    summary: str
    remediation: str


# ----------------------------------------------------------------------
# Individual rules — each takes a snapshot and yields findings.
# ----------------------------------------------------------------------
def _rule_stale_privileged_account(snapshot: TenantSnapshot) -> list[PostureFinding]:
    findings = []
    now = dt.datetime.now(dt.timezone.utc)
    for user in snapshot.users:
        if not user.is_admin:
            continue
        if user.last_login_at is None or (now - user.last_login_at) > STALE_LOGIN_THRESHOLD:
            days = "never" if user.last_login_at is None else f"{(now - user.last_login_at).days}d ago"
            findings.append(
                PostureFinding(
                    connector_id=snapshot.connector_id,
                    app_id=user.app_id,
                    rule_id="stale_privileged_account",
                    severity=Severity.HIGH,
                    object_ref=user.user_id,
                    summary=f"Admin account {user.display_name!r} last logged in {days}",
                    remediation="Deprovision or downgrade this account; a stale admin "
                    "credential is a standing, unmonitored path to full access.",
                )
            )
    return findings


def _rule_admin_without_mfa(snapshot: TenantSnapshot) -> list[PostureFinding]:
    findings = []
    for user in snapshot.users:
        if user.is_admin and not user.mfa_enabled:
            findings.append(
                PostureFinding(
                    connector_id=snapshot.connector_id,
                    app_id=user.app_id,
                    rule_id="admin_without_mfa",
                    severity=Severity.HIGH,
                    object_ref=user.user_id,
                    summary=f"Admin account {user.display_name!r} has no MFA enrolled",
                    remediation="Require MFA enrollment before the account's next login; "
                    "treat as high priority since it is also a privileged account.",
                )
            )
    return findings


def _rule_broad_agent_grant(snapshot: TenantSnapshot) -> list[PostureFinding]:
    findings = []
    agent_names = {a.external_ref: a.name for a in snapshot.agents}
    for perm in snapshot.permissions:
        if perm.principal_type == "agent" and perm.scope_level in _PRIVILEGED_SCOPE_LEVELS:
            findings.append(
                PostureFinding(
                    connector_id=snapshot.connector_id,
                    app_id=perm.app_id,
                    rule_id="broad_agent_grant",
                    severity=Severity.HIGH,
                    object_ref=perm.principal_ref,
                    summary=(
                        f"Agent {agent_names.get(perm.principal_ref, perm.principal_ref)!r} "
                        f"holds {perm.scope_level} permission {perm.permission!r}"
                    ),
                    remediation="Narrow this grant to the specific action the agent needs "
                    "(Least Agency) — a single wide OAuth scope where several narrow, "
                    "separately-revocable ones would do is the same risk as a static "
                    "admin credential.",
                )
            )
    return findings


def _rule_unused_privileged_agent(snapshot: TenantSnapshot) -> list[PostureFinding]:
    findings = []
    now = dt.datetime.now(dt.timezone.utc)
    privileged_agent_refs = {
        p.principal_ref for p in snapshot.permissions
        if p.principal_type == "agent" and p.scope_level in _PRIVILEGED_SCOPE_LEVELS
    }
    for agent in snapshot.agents:
        if agent.external_ref not in privileged_agent_refs:
            continue
        if agent.last_active_at is None or (now - agent.last_active_at) > STALE_LOGIN_THRESHOLD:
            findings.append(
                PostureFinding(
                    connector_id=snapshot.connector_id,
                    app_id=agent.app_id,
                    rule_id="unused_privileged_agent",
                    severity=Severity.MEDIUM,
                    object_ref=agent.external_ref,
                    summary=f"Agent {agent.name!r} holds a privileged grant but has not been active recently",
                    remediation="Confirm the agent is still needed; if not, revoke its "
                    "grants and deregister it rather than leaving a dormant privileged "
                    "credential in place.",
                )
            )
    return findings


_SNAPSHOT_RULES = [
    _rule_stale_privileged_account,
    _rule_admin_without_mfa,
    _rule_broad_agent_grant,
    _rule_unused_privileged_agent,
]


def scan_snapshot(snapshot: TenantSnapshot) -> list[PostureFinding]:
    findings: list[PostureFinding] = []
    for rule in _SNAPSHOT_RULES:
        findings.extend(rule(snapshot))
    return findings


# ----------------------------------------------------------------------
# Drift-based rule — needs two snapshots, not one.
# ----------------------------------------------------------------------
def scan_drift(diff: SnapshotDiff) -> list[PostureFinding]:
    """Flag configuration drift that adds a privileged grant since the
    previous scan (Enterprise-tier "detect and remediate configuration
    drift" from ARCHITECTURE.md §5). Drift that only *removes* access is
    not flagged — that direction is never the risky one."""
    findings = []
    for app_id, principal_ref, permission in diff.permissions_added:
        findings.append(
            PostureFinding(
                connector_id=diff.connector_id,
                app_id=app_id,
                rule_id="drift_new_grant",
                severity=Severity.MEDIUM,
                object_ref=principal_ref,
                summary=f"New permission {permission!r} granted to {principal_ref!r} since last scan",
                remediation="Confirm this grant was authorized (change ticket, approval "
                "record); if not, revoke it and treat as a possible compromise indicator.",
            )
        )
    for external_ref in diff.agents_added:
        findings.append(
            PostureFinding(
                connector_id=diff.connector_id,
                app_id="",
                rule_id="drift_new_agent",
                severity=Severity.MEDIUM,
                object_ref=external_ref,
                summary=f"New agent {external_ref!r} appeared in the tenant since last scan",
                remediation="Verify who installed/authorized this agent and enroll it in "
                "Observable if it should be operating under Agent Guard.",
            )
        )
    return findings
