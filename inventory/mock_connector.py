"""
Block 7 — Mock connector.

A deterministic, in-memory stand-in for a real SaaS tenant, used for
dev, tests, and the inventory demo. It ships with:

- two apps (a CRM and a productivity suite),
- one AI agent that mirrors the ``sales-assistant`` agent enrolled in
  the Agent Guard demo (so it can be matched, not flagged as shadow),
- one AI agent that was never enrolled anywhere in Observable and holds a
  broad ``full_access`` grant — the shadow-AI case,
- a stale admin account with no MFA — the posture-finding case,
- mutation methods (``grant_permission`` etc.) so tests and the demo
  can simulate a tenant changing between two scans and prove
  configuration-drift detection actually detects something.
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from observable.inventory.connector import (
    DiscoveredAgent,
    DiscoveredApp,
    DiscoveredPermission,
    DiscoveredUser,
    SaaSConnector,
    TenantSnapshot,
)

_NOW = dt.datetime.now(dt.timezone.utc)


class MockConnector(SaaSConnector):
    def __init__(self, connector_id: str = "mock:acme-corp") -> None:
        self._connector_id = connector_id

        self._apps: list[DiscoveredApp] = [
            DiscoveredApp(app_id="crm", name="Acme CRM", category="crm", vendor="MockSalesforce"),
            DiscoveredApp(
                app_id="productivity", name="Acme Workspace", category="productivity", vendor="MockM365"
            ),
        ]

        self._agents: list[DiscoveredAgent] = [
            DiscoveredAgent(
                external_ref="crm-agentforce-sales-1",
                app_id="crm",
                name="Sales Assistant Bot",
                agent_type="agentforce-bot",
                scopes=["crm.read", "email.send"],
                created_at=_NOW - dt.timedelta(days=40),
                last_active_at=_NOW - dt.timedelta(hours=2),
                owner="omar",
            ),
            DiscoveredAgent(
                external_ref="m365-copilot-ext-42",
                app_id="productivity",
                name="Unnamed Copilot Extension",
                agent_type="copilot-extension",
                scopes=["mail.readwrite", "files.readwrite.all"],
                created_at=_NOW - dt.timedelta(days=5),
                last_active_at=_NOW - dt.timedelta(hours=6),
                owner=None,  # nobody on record as having installed it
            ),
        ]

        self._users: list[DiscoveredUser] = [
            DiscoveredUser(
                user_id="u-1",
                app_id="crm",
                display_name="Omar Benaicha",
                email="omar@acme-corp.example",
                roles=["admin"],
                is_admin=True,
                last_login_at=_NOW - dt.timedelta(days=1),
                mfa_enabled=True,
            ),
            DiscoveredUser(
                user_id="u-2",
                app_id="crm",
                display_name="Legacy Service Account",
                email="svc-legacy@acme-corp.example",
                roles=["admin"],
                is_admin=True,
                last_login_at=_NOW - dt.timedelta(days=220),
                mfa_enabled=False,
            ),
        ]

        self._permissions: list[DiscoveredPermission] = [
            DiscoveredPermission(
                app_id="crm", principal_ref="crm-agentforce-sales-1", principal_type="agent",
                permission="crm.read", scope_level="read",
            ),
            DiscoveredPermission(
                app_id="crm", principal_ref="crm-agentforce-sales-1", principal_type="agent",
                permission="email.send", scope_level="write",
            ),
            DiscoveredPermission(
                app_id="productivity", principal_ref="m365-copilot-ext-42", principal_type="agent",
                permission="mail.readwrite", scope_level="write",
            ),
            DiscoveredPermission(
                app_id="productivity", principal_ref="m365-copilot-ext-42", principal_type="agent",
                permission="files.readwrite.all", scope_level="full_access",
            ),
            DiscoveredPermission(
                app_id="crm", principal_ref="u-2", principal_type="user",
                permission="org.admin", scope_level="admin",
            ),
        ]

    @property
    def connector_id(self) -> str:
        return self._connector_id

    def scan(self) -> TenantSnapshot:
        return TenantSnapshot(
            connector_id=self._connector_id,
            taken_at=dt.datetime.now(dt.timezone.utc),
            apps=list(self._apps),
            agents=list(self._agents),
            users=list(self._users),
            permissions=list(self._permissions),
        )

    # ------------------------------------------------------------------
    # Mutation helpers for tests/demo — simulate the tenant changing
    # between two scans so drift detection has something to detect.
    # ------------------------------------------------------------------
    def grant_permission(self, permission: DiscoveredPermission) -> None:
        self._permissions.append(permission)

    def revoke_permission(self, app_id: str, principal_ref: str, permission: str) -> None:
        self._permissions = [
            p
            for p in self._permissions
            if not (p.app_id == app_id and p.principal_ref == principal_ref and p.permission == permission)
        ]

    def add_agent(self, agent: DiscoveredAgent) -> None:
        self._agents.append(agent)
