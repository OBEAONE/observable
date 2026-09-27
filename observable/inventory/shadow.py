"""
Block 9 — Shadow AI / Shadow SaaS detector.

Cross-references every AI agent the Inventory Store has discovered
running inside a SaaS tenant against Observable's own Identity Registry
(Block 2), by the agent's ``external_ref``. This is the concrete
version of what the guide calls Shadow AI: automation that exists and
holds real permissions, but that Observable has no enrolled identity for —
so none of Agent Guard's controls (PoP tokens, least-agency scoping,
containment) apply to it at all.

Three distinct findings come out of this, not just one "is it shadow"
boolean, because they call for different remediation:

* **unenrolled** — no Observable identity was ever created for this agent.
  The operator needs to either enroll it (bringing it under Agent
  Guard) or disable it directly in the SaaS tenant.
* **matched_but_suspended** — an Observable identity exists and was
  suspended (e.g. by automated containment), but the agent is *still
  active in the SaaS tenant itself*. This is the sharpest finding:
  suspending an Observable-issued credential does nothing to an agent that
  can still act through the SaaS platform's own native permissions —
  containment has to reach the SaaS tenant too, not just Observable's token
  layer.
* **matched_but_revoked** — same as above but for a revoked identity;
  more severe since revocation implies confirmed compromise.
"""
from __future__ import annotations

import dataclasses
import enum

from observable.identity.registry import AgentStatus, IdentityRegistry
from observable.inventory.connector import DiscoveredAgent
from observable.inventory.store import InventoryStore


class ShadowReason(str, enum.Enum):
    UNENROLLED = "unenrolled"
    MATCHED_BUT_SUSPENDED = "matched_but_suspended"
    MATCHED_BUT_REVOKED = "matched_but_revoked"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_SCOPE_LEVEL_RISK: dict[str, int] = {"read": 0, "write": 1, "admin": 2, "full_access": 2}


@dataclasses.dataclass(frozen=True)
class ShadowFinding:
    connector_id: str
    app_id: str
    external_ref: str
    agent_name: str
    agent_type: str
    scopes: list[str]
    reason: ShadowReason
    severity: Severity
    matched_agent_id: str | None = None  # set for matched_but_{suspended,revoked}


def _agent_severity(agent: DiscoveredAgent, permissions_for_agent: list[str]) -> Severity:
    """Escalate severity based on the highest scope level the agent
    actually holds, not just the fact that it's unenrolled — a
    read-only unenrolled agent is a smaller problem than one holding
    full_access."""
    max_risk = 0
    for scope_level in permissions_for_agent:
        max_risk = max(max_risk, _SCOPE_LEVEL_RISK.get(scope_level, 0))
    if max_risk >= 2:
        return Severity.HIGH
    if max_risk == 1:
        return Severity.MEDIUM
    return Severity.LOW


def detect_shadow_agents(
    *, inventory: InventoryStore, registry: IdentityRegistry
) -> list[ShadowFinding]:
    findings: list[ShadowFinding] = []

    for connector_id, snapshot in inventory.all_latest().items():
        scope_levels_by_agent: dict[str, list[str]] = {}
        for perm in snapshot.permissions:
            if perm.principal_type == "agent":
                scope_levels_by_agent.setdefault(perm.principal_ref, []).append(perm.scope_level)

        for agent in snapshot.agents:
            match = registry.find_by_external_ref(agent.external_ref)
            scope_levels = scope_levels_by_agent.get(agent.external_ref, [])
            severity = _agent_severity(agent, scope_levels)

            if match is None:
                findings.append(
                    ShadowFinding(
                        connector_id=connector_id,
                        app_id=agent.app_id,
                        external_ref=agent.external_ref,
                        agent_name=agent.name,
                        agent_type=agent.agent_type,
                        scopes=list(agent.scopes),
                        reason=ShadowReason.UNENROLLED,
                        severity=severity,
                    )
                )
            elif match.status == AgentStatus.REVOKED:
                findings.append(
                    ShadowFinding(
                        connector_id=connector_id,
                        app_id=agent.app_id,
                        external_ref=agent.external_ref,
                        agent_name=agent.name,
                        agent_type=agent.agent_type,
                        scopes=list(agent.scopes),
                        reason=ShadowReason.MATCHED_BUT_REVOKED,
                        severity=Severity.HIGH,
                        matched_agent_id=match.agent_id,
                    )
                )
            elif match.status == AgentStatus.SUSPENDED:
                findings.append(
                    ShadowFinding(
                        connector_id=connector_id,
                        app_id=agent.app_id,
                        external_ref=agent.external_ref,
                        agent_name=agent.name,
                        agent_type=agent.agent_type,
                        scopes=list(agent.scopes),
                        reason=ShadowReason.MATCHED_BUT_SUSPENDED,
                        severity=Severity.HIGH,
                        matched_agent_id=match.agent_id,
                    )
                )
            # match.status == ACTIVE: fully accounted for, no finding.

    return findings
