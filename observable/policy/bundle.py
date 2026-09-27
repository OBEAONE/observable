"""
Block 4 — Policy bundle: the tool registry + role grants, as a single
version-controlled, hash-referenced, optionally-signed unit.

This is the "Least Agency" source of truth (ARCHITECTURE.md guide
mapping, Enterprise row "signed configurations with deployment
verification"): every tool an agent could ever call must be explicitly
registered here with its sensitivity and constraints, and every role
must be explicitly granted specific tools. A tool absent from the
registry can never be authorized, no matter what a role grant says —
this is what stops a typo or an overly broad role pattern from silently
opening access to something nobody registered.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import fnmatch
import hashlib
import json
from typing import Optional


class Sensitivity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclasses.dataclass(frozen=True)
class ToolDefinition:
    """One callable capability. ``name`` matches the scope's ``tool``
    field exactly (e.g. ``crm.read``, ``email.send``) — verbs are baked
    into the tool name rather than layered on top, so "read" and
    "delete" on the same resource are always two distinct, separately
    grantable tools."""

    name: str
    description: str
    sensitivity: Sensitivity = Sensitivity.LOW
    business_hours_only: bool = False
    max_risk_score: float = 1.0  # requests with a higher risk_score are denied
    min_tier: Optional[str] = None  # e.g. "enterprise" — None means any tier


@dataclasses.dataclass(frozen=True)
class RoleGrant:
    """A role's allowed tool patterns. Patterns support ``fnmatch``
    globs (e.g. ``crm.*``) purely as an authoring convenience — what
    actually gets granted is always intersected against the tool
    registry, so a glob can never grant a tool that was never
    registered."""

    role: str
    tool_patterns: list[str]


@dataclasses.dataclass(frozen=True)
class PolicyBundle:
    version: str
    tools: dict[str, ToolDefinition]
    role_grants: dict[str, RoleGrant]
    created_at: dt.datetime

    def canonical_bytes(self) -> bytes:
        """Deterministic JSON encoding used for hashing/signing. Field
        order is fixed explicitly rather than relying on dict insertion
        order, so re-serializing the same bundle always hashes the
        same way regardless of how it was constructed in memory."""
        payload = {
            "version": self.version,
            "tools": {
                name: {
                    "name": t.name,
                    "description": t.description,
                    "sensitivity": t.sensitivity.value,
                    "business_hours_only": t.business_hours_only,
                    "max_risk_score": t.max_risk_score,
                    "min_tier": t.min_tier,
                }
                for name, t in sorted(self.tools.items())
            },
            "role_grants": {
                role: sorted(grant.tool_patterns)
                for role, grant in sorted(self.role_grants.items())
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def content_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def resolve_role(self, role: str, tool_name: str) -> bool:
        """True if ``role`` has a grant pattern matching ``tool_name``,
        AND ``tool_name`` is present in the registry (deny-by-default:
        an unregistered tool is never matched, whatever the patterns
        say)."""
        if tool_name not in self.tools:
            return False
        grant = self.role_grants.get(role)
        if grant is None:
            return False
        return any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in grant.tool_patterns)


def default_bundle() -> PolicyBundle:
    """A small starter bundle for dev/demo use. Real deployments load a
    bundle authored (and, at Enterprise tier, signed) out of band."""
    tools = {
        "crm.read": ToolDefinition(
            name="crm.read", description="Read CRM account/contact records", sensitivity=Sensitivity.LOW
        ),
        "crm.write": ToolDefinition(
            name="crm.write",
            description="Create/update CRM records",
            sensitivity=Sensitivity.MEDIUM,
            business_hours_only=True,
        ),
        "crm.delete": ToolDefinition(
            name="crm.delete",
            description="Delete CRM records",
            sensitivity=Sensitivity.HIGH,
            business_hours_only=True,
            max_risk_score=0.2,
            min_tier="enterprise",
        ),
        "email.send": ToolDefinition(
            name="email.send",
            description="Send an email as the agent",
            sensitivity=Sensitivity.MEDIUM,
            max_risk_score=0.5,
        ),
        "ticket.triage": ToolDefinition(
            name="ticket.triage", description="Read and categorize support tickets", sensitivity=Sensitivity.LOW
        ),
    }
    role_grants = {
        "sales-assistant": RoleGrant(role="sales-assistant", tool_patterns=["crm.read", "email.send"]),
        "crm-admin": RoleGrant(role="crm-admin", tool_patterns=["crm.*"]),
        "support-triage": RoleGrant(role="support-triage", tool_patterns=["ticket.triage", "crm.read"]),
    }
    return PolicyBundle(
        version="1.0.0",
        tools=tools,
        role_grants=role_grants,
        created_at=dt.datetime.now(dt.timezone.utc),
    )
