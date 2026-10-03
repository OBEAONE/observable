"""
Block 6 — Wiring: constructs one instance of each plane and registers
the demo tool invokers Agent Guard dispatches to. A production
deployment would replace ``build_default_state`` with something that
constructs a production CA adapter (EJBCA/step-ca/Vault/QTSP), a durable
Identity Registry, and a signed policy bundle loaded from wherever
policy-admins publish it — the rest of the wiring is unchanged.
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from observable.accounts.session import TokenStore
from observable.accounts.store import AccountStore
from observable.api.pop import NonceCache
from observable.compliance.impact_register import ImpactRegister, seed_reflexive_governance_entries
from observable.detection.engine import DetectionEngine
from observable.detection.intent import build_intent_checker_from_env
from observable.guard.gateway import AgentGuard
from observable.identity.registry import IdentityRegistry
from observable.inventory.connector import SaaSConnector
from observable.inventory.mock_connector import MockConnector
from observable.inventory.store import InventoryStore
from observable.pki.reference_ca import ReferenceCA
from observable.policy.bundle import default_bundle
from observable.policy.engine import PolicyEngine
from observable.policy.ratelimit import RateLimiter
from observable.tokens.service import TokenService

# Login flow timing (§9.11) -- a pending-MFA token only needs to survive
# the few seconds between entering a password and entering a 2FA code;
# a session lasts a working day before an operator has to log in again.
PENDING_MFA_TTL = dt.timedelta(minutes=5)
SESSION_TTL = dt.timedelta(hours=12)


@dataclasses.dataclass
class AppState:
    ca: ReferenceCA
    registry: IdentityRegistry
    policy_engine: PolicyEngine
    token_service: TokenService
    guard: AgentGuard
    nonce_cache: NonceCache
    inventory: InventoryStore
    connectors: dict[str, SaaSConnector]
    detection: DetectionEngine
    impact_register: ImpactRegister
    # Human-operator login (§9.11) -- entirely separate from the AI-agent
    # identity system above (registry/token_service/guard): this is who
    # may view the console, not who may call the Gateway.
    accounts: AccountStore
    pending_mfa: TokenStore
    sessions: TokenStore
    login_rate_limiter: RateLimiter

    def run_scan(self, connector_id: str | None = None):
        """Run one or all registered connectors and ingest the
        resulting snapshot(s). Returns the list of snapshots ingested
        by this call."""
        targets = (
            [self.connectors[connector_id]]
            if connector_id
            else list(self.connectors.values())
        )
        snapshots = []
        for connector in targets:
            snapshot = connector.scan()
            self.inventory.ingest(snapshot)
            snapshots.append(snapshot)
        return snapshots


def _fake_crm_backend() -> dict[str, dict]:
    return {
        "A-100": {"name": "Globex Industries", "owner": "omar", "api_key_on_file": "sk-AAAABBBBCCCCDDDDEEEE1111"},
        "A-102": {"name": "Acme Corp", "owner": "omar", "internal_note": "password: hunter2"},
    }


def _fake_booking_backend() -> dict[str, dict]:
    return {
        "B-1": {"resource": "Meeting Room A", "customer": "Acme Corp", "date": "2026-10-02", "status": "confirmed"},
    }


def build_default_state() -> AppState:
    ca = ReferenceCA(org_name="Observable Demo CA")
    registry = IdentityRegistry(ca)
    policy_engine = PolicyEngine(ca=ca, bundle=default_bundle())
    token_service = TokenService(ca=ca, registry=registry, scope_authorizer=policy_engine)
    # Off by default (OBSERVABLE_INTENT_SCORER unset) — see §8.5. Reading
    # the env at process start, not per-request, matches every other
    # operator-facing toggle in this file (auto_contain_threshold, etc.).
    intent_checker = build_intent_checker_from_env()
    detection = DetectionEngine(sensitivity_lookup=policy_engine, intent_checker=intent_checker)
    guard = AgentGuard(
        registry=registry,
        token_service=token_service,
        policy_engine=policy_engine,
        detection=detection,
        # No auto-containment threshold by default: an operator opts in
        # explicitly via POST /admin/detection/threshold. Detection still
        # scores every request and feeds ABAC either way (see Block D).
        auto_contain_threshold=None,
    )

    crm_db = _fake_crm_backend()

    def crm_read(payload: dict, resource_id) -> dict:
        record = crm_db.get(resource_id or "", {"error": "not found"})
        return dict(record)

    def crm_write(payload: dict, resource_id) -> dict:
        if resource_id not in crm_db:
            crm_db[resource_id] = {}
        crm_db[resource_id].update(payload)
        return {"updated": resource_id, "fields": list(payload.keys())}

    def crm_delete(payload: dict, resource_id) -> dict:
        existed = crm_db.pop(resource_id, None) is not None
        return {"deleted": resource_id, "existed": existed}

    def email_send(payload: dict, resource_id) -> dict:
        return {"status": "sent", "to": payload.get("to"), "subject": payload.get("subject")}

    def ticket_triage(payload: dict, resource_id) -> dict:
        return {"ticket": resource_id, "priority": "P3", "category": "billing"}

    booking_db = _fake_booking_backend()
    _booking_seq = {"n": len(booking_db)}

    def booking_read(payload: dict, resource_id) -> dict:
        record = booking_db.get(resource_id or "", {"error": "not found"})
        return dict(record)

    def booking_create(payload: dict, resource_id) -> dict:
        _booking_seq["n"] += 1
        new_id = resource_id or f"B-{_booking_seq['n']}"
        booking_db[new_id] = {
            "resource": payload.get("resource", "unspecified"),
            "customer": payload.get("customer", "unspecified"),
            "date": payload.get("date"),
            "status": "confirmed",
        }
        return {"booking_id": new_id, **booking_db[new_id]}

    def booking_cancel(payload: dict, resource_id) -> dict:
        record = booking_db.get(resource_id or "")
        if record is None:
            return {"error": "not found"}
        record["status"] = "cancelled"
        return {"booking_id": resource_id, "status": "cancelled"}

    def reporting_generate(payload: dict, resource_id) -> dict:
        # A read-only rollup over whatever the demo backends currently
        # hold — nothing here mutates state, matching a real reporting
        # tool's expected blast radius.
        return {
            "report": payload.get("report_name", "activity-summary"),
            "period": payload.get("period", "last_7_days"),
            "crm_accounts": len(crm_db),
            "bookings": len(booking_db),
            "bookings_confirmed": sum(1 for b in booking_db.values() if b["status"] == "confirmed"),
        }

    def reporting_export(payload: dict, resource_id) -> dict:
        fmt = payload.get("format", "csv")
        return {"export_format": fmt, "rows": len(crm_db) + len(booking_db), "status": "generated"}

    guard.register_tool("crm.read", crm_read)
    guard.register_tool("crm.write", crm_write)
    guard.register_tool("crm.delete", crm_delete)
    guard.register_tool("email.send", email_send)
    guard.register_tool("ticket.triage", ticket_triage)
    guard.register_tool("booking.read", booking_read)
    guard.register_tool("booking.create", booking_create)
    guard.register_tool("booking.cancel", booking_cancel)
    guard.register_tool("reporting.generate", reporting_generate)
    guard.register_tool("reporting.export", reporting_export)

    default_connector = MockConnector()

    # Seeded, not empty: an unpopulated Impact Register makes NIST AI
    # RMF's MAP 5.1 check (§9.5) FAIL outright ("no impacts have been
    # characterized yet"), and Observable's own detection/intent
    # components are themselves AI systems under the guide's
    # definition — this is where that reflexive-governance story is
    # recorded rather than left implicit (see impact_register.py).
    impact_register = ImpactRegister()
    seed_reflexive_governance_entries(impact_register)

    return AppState(
        ca=ca,
        registry=registry,
        policy_engine=policy_engine,
        token_service=token_service,
        guard=guard,
        nonce_cache=NonceCache(),
        inventory=InventoryStore(),
        connectors={default_connector.connector_id: default_connector},
        detection=detection,
        impact_register=impact_register,
        accounts=AccountStore(),
        pending_mfa=TokenStore(default_ttl=PENDING_MFA_TTL),
        sessions=TokenStore(default_ttl=SESSION_TTL),
        login_rate_limiter=RateLimiter(),
    )
