"""
Block 8 — Inventory Store.

Ingests snapshots from any number of connectors, keeps their full
history (not just the latest), and computes drift between consecutive
snapshots of the same connector. Storage is in-memory here; a
production deployment swaps this for a durable store without touching
Blocks 9-11, which only depend on the methods below.
"""
from __future__ import annotations

import dataclasses
import threading
from typing import Optional

from observable.inventory.connector import TenantSnapshot


@dataclasses.dataclass(frozen=True)
class SnapshotDiff:
    connector_id: str
    old_taken_at: str
    new_taken_at: str
    apps_added: list[str]
    apps_removed: list[str]
    agents_added: list[str]
    agents_removed: list[str]
    users_added: list[str]
    users_removed: list[str]
    permissions_added: list[tuple[str, str, str]]  # (app_id, principal_ref, permission)
    permissions_removed: list[tuple[str, str, str]]

    @property
    def has_changes(self) -> bool:
        return any(
            [
                self.apps_added,
                self.apps_removed,
                self.agents_added,
                self.agents_removed,
                self.users_added,
                self.users_removed,
                self.permissions_added,
                self.permissions_removed,
            ]
        )


def diff_snapshots(old: TenantSnapshot, new: TenantSnapshot) -> SnapshotDiff:
    if old.connector_id != new.connector_id:
        raise ValueError("cannot diff snapshots from two different connectors")

    old_app_ids = {a.app_id for a in old.apps}
    new_app_ids = {a.app_id for a in new.apps}
    old_agent_refs = {a.external_ref for a in old.agents}
    new_agent_refs = {a.external_ref for a in new.agents}
    old_user_ids = {u.user_id for u in old.users}
    new_user_ids = {u.user_id for u in new.users}
    old_perms = {(p.app_id, p.principal_ref, p.permission) for p in old.permissions}
    new_perms = {(p.app_id, p.principal_ref, p.permission) for p in new.permissions}

    return SnapshotDiff(
        connector_id=old.connector_id,
        old_taken_at=old.taken_at.isoformat(),
        new_taken_at=new.taken_at.isoformat(),
        apps_added=sorted(new_app_ids - old_app_ids),
        apps_removed=sorted(old_app_ids - new_app_ids),
        agents_added=sorted(new_agent_refs - old_agent_refs),
        agents_removed=sorted(old_agent_refs - new_agent_refs),
        users_added=sorted(new_user_ids - old_user_ids),
        users_removed=sorted(old_user_ids - new_user_ids),
        permissions_added=sorted(new_perms - old_perms),
        permissions_removed=sorted(old_perms - new_perms),
    )


class InventoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._history: dict[str, list[TenantSnapshot]] = {}

    def ingest(self, snapshot: TenantSnapshot) -> None:
        with self._lock:
            self._history.setdefault(snapshot.connector_id, []).append(snapshot)

    def latest(self, connector_id: str) -> Optional[TenantSnapshot]:
        with self._lock:
            history = self._history.get(connector_id)
            return history[-1] if history else None

    def history(self, connector_id: str) -> list[TenantSnapshot]:
        with self._lock:
            return list(self._history.get(connector_id, []))

    def all_latest(self) -> dict[str, TenantSnapshot]:
        with self._lock:
            return {
                connector_id: snapshots[-1]
                for connector_id, snapshots in self._history.items()
                if snapshots
            }

    def connector_ids(self) -> list[str]:
        with self._lock:
            return list(self._history.keys())

    def drift_since_previous(self, connector_id: str) -> Optional[SnapshotDiff]:
        with self._lock:
            history = self._history.get(connector_id, [])
            if len(history) < 2:
                return None
            return diff_snapshots(history[-2], history[-1])
