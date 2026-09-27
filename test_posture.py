import datetime as dt

from observable.inventory.connector import DiscoveredAgent, DiscoveredPermission
from observable.inventory.mock_connector import MockConnector
from observable.inventory.posture import scan_drift, scan_snapshot
from observable.inventory.shadow import Severity
from observable.inventory.store import InventoryStore, diff_snapshots


def test_scan_snapshot_flags_stale_admin_and_no_mfa():
    connector = MockConnector()
    findings = scan_snapshot(connector.scan())

    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    assert "stale_privileged_account" in by_rule
    assert any(f.object_ref == "u-2" for f in by_rule["stale_privileged_account"])

    assert "admin_without_mfa" in by_rule
    assert any(f.object_ref == "u-2" for f in by_rule["admin_without_mfa"])


def test_scan_snapshot_flags_broad_agent_grant():
    connector = MockConnector()
    findings = scan_snapshot(connector.scan())
    broad = [f for f in findings if f.rule_id == "broad_agent_grant"]
    assert any(f.object_ref == "m365-copilot-ext-42" for f in broad)
    assert all(f.severity == Severity.HIGH for f in broad)


def test_well_behaved_agent_and_user_produce_no_findings_for_those_rules():
    connector = MockConnector()
    findings = scan_snapshot(connector.scan())
    # u-1 (Omar) is admin, MFA-on, recent login: must not appear in either rule.
    assert not any(
        f.object_ref == "u-1" and f.rule_id in ("stale_privileged_account", "admin_without_mfa")
        for f in findings
    )
    # crm-agentforce-sales-1 only holds read/write, never admin/full_access.
    assert not any(
        f.object_ref == "crm-agentforce-sales-1" and f.rule_id == "broad_agent_grant"
        for f in findings
    )


def test_unused_privileged_agent_rule():
    connector = MockConnector()
    # give the (already inactive-ish) copilot agent a very old last_active_at
    stale_agent = DiscoveredAgent(
        external_ref="m365-copilot-ext-42",
        app_id="productivity",
        name="Unnamed Copilot Extension",
        agent_type="copilot-extension",
        scopes=["mail.readwrite", "files.readwrite.all"],
        created_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200),
        last_active_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=150),
        owner=None,
    )
    connector._agents = [connector._agents[0], stale_agent]  # test-only direct replace
    findings = scan_snapshot(connector.scan())
    assert any(f.rule_id == "unused_privileged_agent" and f.object_ref == "m365-copilot-ext-42" for f in findings)


def test_scan_drift_flags_new_privileged_grant():
    store = InventoryStore()
    connector = MockConnector()
    store.ingest(connector.scan())

    connector.grant_permission(
        DiscoveredPermission(
            app_id="crm", principal_ref="crm-agentforce-sales-1", principal_type="agent",
            permission="crm.delete", scope_level="admin",
        )
    )
    store.ingest(connector.scan())

    diff = store.drift_since_previous(connector.connector_id)
    findings = scan_drift(diff)
    assert any(f.rule_id == "drift_new_grant" and f.object_ref == "crm-agentforce-sales-1" for f in findings)


def test_scan_drift_flags_new_agent():
    store = InventoryStore()
    connector = MockConnector()
    store.ingest(connector.scan())

    connector.add_agent(
        DiscoveredAgent(
            external_ref="crm-new-rogue-bot",
            app_id="crm",
            name="Rogue Bot",
            agent_type="custom-integration",
            scopes=["crm.read"],
            created_at=dt.datetime.now(dt.timezone.utc),
            last_active_at=None,
            owner=None,
        )
    )
    store.ingest(connector.scan())

    diff = store.drift_since_previous(connector.connector_id)
    findings = scan_drift(diff)
    assert any(f.rule_id == "drift_new_agent" and f.object_ref == "crm-new-rogue-bot" for f in findings)


def test_scan_drift_ignores_removed_access():
    store = InventoryStore()
    connector = MockConnector()
    store.ingest(connector.scan())
    connector.revoke_permission("crm", "u-2", "org.admin")
    store.ingest(connector.scan())

    diff = store.drift_since_previous(connector.connector_id)
    findings = scan_drift(diff)
    assert findings == []
