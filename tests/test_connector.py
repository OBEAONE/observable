from observable.inventory.connector import DiscoveredPermission
from observable.inventory.mock_connector import MockConnector


def test_scan_returns_populated_snapshot():
    connector = MockConnector()
    snapshot = connector.scan()

    assert snapshot.connector_id == "mock:acme-corp"
    assert {a.app_id for a in snapshot.apps} == {"crm", "productivity"}
    assert len(snapshot.agents) == 2
    assert len(snapshot.users) == 2
    assert len(snapshot.permissions) == 5


def test_two_scans_are_independent_snapshots():
    connector = MockConnector()
    first = connector.scan()
    second = connector.scan()
    assert first.taken_at <= second.taken_at
    assert first.permissions == second.permissions


def test_grant_and_revoke_permission_reflected_in_next_scan():
    connector = MockConnector()
    before = connector.scan()
    assert not any(p.permission == "crm.delete" for p in before.permissions)

    connector.grant_permission(
        DiscoveredPermission(
            app_id="crm",
            principal_ref="m365-copilot-ext-42",
            principal_type="agent",
            permission="crm.delete",
            scope_level="admin",
        )
    )
    after = connector.scan()
    assert any(p.permission == "crm.delete" for p in after.permissions)

    connector.revoke_permission("crm", "m365-copilot-ext-42", "crm.delete")
    final = connector.scan()
    assert not any(p.permission == "crm.delete" for p in final.permissions)
