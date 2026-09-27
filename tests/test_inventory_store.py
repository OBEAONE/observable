import pytest

from observable.inventory.connector import DiscoveredPermission
from observable.inventory.mock_connector import MockConnector
from observable.inventory.store import InventoryStore, diff_snapshots


@pytest.fixture()
def connector() -> MockConnector:
    return MockConnector()


@pytest.fixture()
def store() -> InventoryStore:
    return InventoryStore()


def test_ingest_and_latest(store: InventoryStore, connector: MockConnector):
    snapshot = connector.scan()
    store.ingest(snapshot)
    assert store.latest(connector.connector_id) is snapshot
    assert store.latest("nonexistent") is None


def test_history_accumulates(store: InventoryStore, connector: MockConnector):
    store.ingest(connector.scan())
    store.ingest(connector.scan())
    assert len(store.history(connector.connector_id)) == 2


def test_drift_none_with_fewer_than_two_snapshots(store: InventoryStore, connector: MockConnector):
    assert store.drift_since_previous(connector.connector_id) is None
    store.ingest(connector.scan())
    assert store.drift_since_previous(connector.connector_id) is None


def test_drift_detects_new_permission(store: InventoryStore, connector: MockConnector):
    store.ingest(connector.scan())
    connector.grant_permission(
        DiscoveredPermission(
            app_id="crm", principal_ref="m365-copilot-ext-42", principal_type="agent",
            permission="crm.delete", scope_level="admin",
        )
    )
    store.ingest(connector.scan())

    diff = store.drift_since_previous(connector.connector_id)
    assert diff is not None
    assert diff.has_changes is True
    assert ("crm", "m365-copilot-ext-42", "crm.delete") in diff.permissions_added
    assert diff.permissions_removed == []


def test_drift_detects_new_agent(store: InventoryStore, connector: MockConnector):
    from observable.inventory.connector import DiscoveredAgent
    import datetime as dt

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
    assert diff.agents_added == ["crm-new-rogue-bot"]


def test_diff_snapshots_rejects_mismatched_connectors():
    a = MockConnector("mock:a")
    b = MockConnector("mock:b")
    with pytest.raises(ValueError):
        diff_snapshots(a.scan(), b.scan())


def test_all_latest_across_multiple_connectors(store: InventoryStore):
    c1 = MockConnector("mock:tenant-1")
    c2 = MockConnector("mock:tenant-2")
    store.ingest(c1.scan())
    store.ingest(c2.scan())

    latest = store.all_latest()
    assert set(latest.keys()) == {"mock:tenant-1", "mock:tenant-2"}
