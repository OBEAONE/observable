from observable.export.soar import (
    IncidentSeverity,
    IncidentStatus,
    build_incidents_from_audit,
    export_incidents_json,
)
from observable.guard.audit import AuditChain


def test_no_incidents_for_ordinary_tool_calls():
    chain = AuditChain()
    chain.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="deny", reason="no scope")
    incidents = build_incidents_from_audit(chain.entries())
    assert incidents == []


def test_manual_suspend_produces_high_severity_open_incident():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action",
        reason="operator: suspicious behavior reported by security team",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN
    assert incident.agent_id == "a1"
    assert incident.related_audit_seqs == [0]
    assert len(incident.recommended_actions) >= 2


def test_automated_containment_produces_critical_severity():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action",
        reason="automated containment: risk_score=0.50 >= threshold=0.50; signals=['new_resource_burst']",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert incidents[0].severity == IncidentSeverity.CRITICAL


def test_revoke_is_always_critical():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:revoke", decision="action",
        reason="key_compromise",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert incidents[0].severity == IncidentSeverity.CRITICAL
    assert incidents[0].status == IncidentStatus.OPEN


def test_reinstate_closes_the_matching_open_incident():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action",
        reason="operator: investigating",
    )
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:reinstate", decision="action",
        reason="false positive, cleared by security team",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.status == IncidentStatus.CLOSED
    assert incident.closed_reason == "false positive, cleared by security team"
    assert incident.related_audit_seqs == [0, 1]


def test_reinstate_with_no_open_incident_is_ignored():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:reinstate", decision="action",
        reason="no matching suspend",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert incidents == []


def test_revoke_after_suspend_leaves_suspend_incident_open_and_unreinstatable():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action",
        reason="operator: investigating",
    )
    chain.append(
        agent_id="a1", role="sales-assistant", action="containment:revoke", decision="action",
        reason="key_compromise",
    )
    incidents = build_incidents_from_audit(chain.entries())
    assert len(incidents) == 2
    suspend_incident, revoke_incident = incidents
    assert suspend_incident.status == IncidentStatus.OPEN
    assert revoke_incident.status == IncidentStatus.OPEN
    assert revoke_incident.severity == IncidentSeverity.CRITICAL


def test_incidents_are_scoped_per_agent():
    chain = AuditChain()
    chain.append(agent_id="a1", role="r", action="containment:suspend", decision="action", reason="x")
    chain.append(agent_id="a2", role="r", action="containment:reinstate", decision="action", reason="unrelated")
    incidents = build_incidents_from_audit(chain.entries())
    assert len(incidents) == 1
    assert incidents[0].status == IncidentStatus.OPEN
    assert incidents[0].agent_id == "a1"


def test_export_incidents_json_shape():
    chain = AuditChain()
    chain.append(agent_id="a1", role="sales-assistant", action="containment:suspend", decision="action", reason="x")
    incidents = build_incidents_from_audit(chain.entries())
    docs = export_incidents_json(incidents)
    assert len(docs) == 1
    assert docs[0]["agent_id"] == "a1"
    assert docs[0]["status"] == "open"
    assert "recommended_actions" in docs[0]
