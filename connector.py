"""
Block 7 — SaaS connector interface.

Same pattern as ``observable.pki.interface.CertificateAuthority``: one small
abstract interface that everything above it depends on, so a real
OAuth-based Salesforce/Microsoft Graph/ServiceNow adapter is a drop-in
replacement for the reference ``MockConnector`` used in dev/demo. See
ARCHITECTURE.md §7.

A connector is read-only by contract (ARCHITECTURE.md §7.3): it reports
what exists in a SaaS tenant — apps, human users, AI agents/bots/
integrations, and the permissions each principal holds — and never
writes back to the tenant. That agentless, read-only posture is what the
platform description means by "agentless architecture."
"""
from __future__ import annotations

import abc
import dataclasses
import datetime as dt
from typing import Optional


@dataclasses.dataclass(frozen=True)
class DiscoveredApp:
    app_id: str
    name: str
    category: str  # e.g. "crm", "productivity", "itsm"
    vendor: str


@dataclasses.dataclass(frozen=True)
class DiscoveredAgent:
    """An AI agent, bot, or automated integration the connector found
    running inside the SaaS tenant itself — e.g. a Salesforce Agentforce
    bot, a Microsoft 365 Copilot extension, a ServiceNow virtual agent,
    or a plain OAuth app with agent-like scopes. ``external_ref`` is
    whatever stable identifier the SaaS platform uses for it; the
    Shadow AI detector (Block 9) matches this against Observable's own
    Identity Registry."""

    external_ref: str
    app_id: str
    name: str
    agent_type: str
    scopes: list[str]
    created_at: dt.datetime
    last_active_at: Optional[dt.datetime]
    owner: Optional[str]


@dataclasses.dataclass(frozen=True)
class DiscoveredUser:
    user_id: str
    app_id: str
    display_name: str
    email: str
    roles: list[str]
    is_admin: bool
    last_login_at: Optional[dt.datetime]
    mfa_enabled: bool


@dataclasses.dataclass(frozen=True)
class DiscoveredPermission:
    """One grant: a principal (user or agent) holding a specific
    permission/scope on an app. Kept as its own flat record — rather
    than nested under the user/agent — because posture rules (Block 10)
    scan permissions independently of which principal type holds them."""

    app_id: str
    principal_ref: str  # DiscoveredUser.user_id or DiscoveredAgent.external_ref
    principal_type: str  # "user" | "agent"
    permission: str
    scope_level: str  # "read" | "write" | "admin" | "full_access"


@dataclasses.dataclass(frozen=True)
class TenantSnapshot:
    connector_id: str
    taken_at: dt.datetime
    apps: list[DiscoveredApp]
    agents: list[DiscoveredAgent]
    users: list[DiscoveredUser]
    permissions: list[DiscoveredPermission]


class SaaSConnector(abc.ABC):
    @property
    @abc.abstractmethod
    def connector_id(self) -> str:
        """Stable identifier for this connector instance, e.g.
        ``"salesforce:acme-corp-prod"``. Used as the scan's provenance
        and as the snapshot-history key in the Inventory Store."""

    @abc.abstractmethod
    def scan(self) -> TenantSnapshot:
        """Perform one read-only discovery pass and return a fresh,
        fully-populated snapshot. Implementations should not mutate any
        state in the target tenant."""
