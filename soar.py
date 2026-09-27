"""
Block N — SOAR incident export.

The audit chain already records every containment action Agent Guard
takes (§6, `contain_agent`/`revoke_agent`/`reinstate_agent` all log a
`containment:*` entry). This module turns that raw log into the shape a
SOAR platform (Splunk SOAR/Phantom, Palo Alto XSOAR, Tines, or a plain
ticketing webhook) actually wants to ingest to auto-open a case and
kick off a playbook: one incident record per containment event, with a
severity, a plain-language trigger reason, and concrete recommended
next steps — not just "here's a log line, go figure out what happened."

Like `observable/export/cef.py`, this only *formats* — no HTTP call, no
webhook. Which SOAR endpoint an operator points this at is a deployment
decision (ARCHITECTURE.md §5: SIEM/SOAR streaming was explicitly left
for v2/here).

Correlation: a `containment:reinstate` entry for the same agent closes
whatever incident that agent's most recent unclosed `containment:*`
entry opened, so a SOAR case tracker sees the full open->close
lifecycle rather than an unbounded pile of "open" incidents for agents
that were investigated and cleared hours ago.
"""
from __future__ import annotations

import dataclasses
import enum
from typing import Iterable, Optional

from observable.guard.audit import AuditEntry

_AUTOMATED_MARKER = "automated containment"


class IncidentSeverity(str, enum.Enum):
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"


_RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "containment:suspend": [
        "Review the agent's recent audit trail (GET /audit/{agent_id}) for the "
        "specific actions that led to containment",
        "If detection-triggered, review the named signals against the agent's "
        "learned baseline (GET /detection/{agent_id}) to confirm this is not a "
        "false positive before reinstating",
        "Check the Inventory plane for this agent's SaaS-side footprint "
        "(GET /inventory/shadow) — suspending the Observable credential does not "
        "revoke any native SaaS permissions the agent also holds",
        "Reinstate (POST /admin/reinstate) if cleared, or escalate to "
        "revoke_agent() if compromise is confirmed",
    ],
    "containment:revoke": [
        "Treat as confirmed compromise: revocation is terminal and the agent "
        "cannot be reinstated",
        "Rotate any credentials or downstream secrets this agent had access to",
        "Enroll a replacement agent identity if the underlying automation is "
        "still needed",
        "Cross-reference the Inventory plane to disable the agent's native "
        "grant at the SaaS tenant as well",
    ],
    "containment:reinstate": [
        "Confirm the reinstatement decision and reason are recorded for audit",
    ],
}


@dataclasses.dataclass
class SoarIncident:
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    agent_id: str
    role: Optional[str]
    triggered_at: str
    trigger_action: str
    trigger_reason: str
    recommended_actions: list[str]
    related_audit_seqs: list[int]
    closed_at: Optional[str] = None
    closed_reason: Optional[str] = None


def _severity_for(entry: AuditEntry) -> IncidentSeverity:
    if entry.action == "containment:revoke":
        return IncidentSeverity.CRITICAL
    if entry.action == "containment:suspend":
        return IncidentSeverity.CRITICAL if _AUTOMATED_MARKER in entry.reason else IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM


def build_incidents_from_audit(entries: Iterable[AuditEntry]) -> list[SoarIncident]:
    """Read-only: walks the audit chain in order and produces one
    incident per opening containment event (`suspend`/`revoke`),
    closing it out when a later `reinstate` for the same agent_id is
    seen. Entries unrelated to containment are ignored entirely."""
    incidents: list[SoarIncident] = []
    open_by_agent: dict[str, SoarIncident] = {}

    for entry in entries:
        if not entry.action.startswith("containment:") or entry.agent_id is None:
            continue

        if entry.action in ("containment:suspend", "containment:revoke"):
            incident = SoarIncident(
                incident_id=f"observable-{entry.agent_id}-{entry.seq}",
                title=f"Observable containment: agent {entry.agent_id} ({entry.action.split(':')[1]})",
                severity=_severity_for(entry),
                status=IncidentStatus.OPEN,
                agent_id=entry.agent_id,
                role=entry.role,
                triggered_at=entry.timestamp.isoformat(),
                trigger_action=entry.action,
                trigger_reason=entry.reason,
                recommended_actions=list(_RECOMMENDED_ACTIONS.get(entry.action, [])),
                related_audit_seqs=[entry.seq],
            )
            incidents.append(incident)
            if entry.action == "containment:suspend":
                # A subsequent revoke for the same agent supersedes an
                # open suspend incident as the one reinstate could close.
                open_by_agent[entry.agent_id] = incident
            else:
                # Revocation is terminal — nothing left to reinstate.
                open_by_agent.pop(entry.agent_id, None)

        elif entry.action == "containment:reinstate":
            open_incident = open_by_agent.pop(entry.agent_id, None)
            if open_incident is not None:
                open_incident.status = IncidentStatus.CLOSED
                open_incident.closed_at = entry.timestamp.isoformat()
                open_incident.closed_reason = entry.reason
                open_incident.related_audit_seqs.append(entry.seq)

    return incidents


def incident_to_dict(incident: SoarIncident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "agent_id": incident.agent_id,
        "role": incident.role,
        "triggered_at": incident.triggered_at,
        "trigger_action": incident.trigger_action,
        "trigger_reason": incident.trigger_reason,
        "recommended_actions": incident.recommended_actions,
        "related_audit_seqs": incident.related_audit_seqs,
        "closed_at": incident.closed_at,
        "closed_reason": incident.closed_reason,
    }


def export_incidents_json(incidents: Iterable[SoarIncident]) -> list[dict]:
    """JSON-serializable list of incident dicts, ready to hand a SOAR
    platform's case-creation API or write to a file for one."""
    return [incident_to_dict(i) for i in incidents]
