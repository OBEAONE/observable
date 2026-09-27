#!/usr/bin/env python3
"""
Observable Inventory & Posture — scripted walkthrough (ARCHITECTURE.md §7).

Runs against the real FastAPI app, in-process. Shows: a discovery scan
of a mock SaaS tenant, the two AI agents it finds (one of which is never
enrolled anywhere in Observable), the shadow-AI findings that come out of
diffing against the Identity Registry, the posture findings from the
rule engine, and configuration-drift detection across a second scan
after the tenant changes.

Run with:  python3 inventory_demo.py
"""
from __future__ import annotations

import json
import textwrap

from starlette.testclient import TestClient

from observable.api.app import app
from observable.inventory.connector import DiscoveredPermission


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show(label: str, obj) -> None:
    print(f"-- {label} --")
    print(textwrap.indent(json.dumps(obj, indent=2, default=str), "  "))


def main() -> None:
    with TestClient(app) as client:
        # No dependency override in this script, so /inventory/scan and
        # friends act on the app's module-level singleton state — pull
        # the same object here to enroll an identity against it in step 3.
        from observable.api.app import _state as state

        banner("1. Discovery scan of the mock SaaS tenant")
        scan_result = client.post("/inventory/scan", json={}).json()
        show("scan result", scan_result)

        banner("2. Discovered agents, with shadow-AI flagging")
        agents = client.get("/inventory/agents").json()
        for a in agents:
            flag = f"SHADOW ({a['shadow_reason']}, {a['shadow_severity']})" if a["shadow"] else "enrolled & active"
            print(f"  {a['external_ref']:<28} scopes={a['scopes']}  -> {flag}")

        banner("3. Link the sales bot to an Observable identity, then re-scan")
        from observable.pki.interface import CertificateTier
        from observable.pki.reference_ca import ReferenceCA

        _, pub = ReferenceCA.generate_keypair()
        state.registry.enroll(
            display_name="sales-assistant-linked",
            role="sales-assistant",
            tier=CertificateTier.FOUNDATION,
            public_key_pem=pub,
            enrolled_by="omar",
            external_ref="crm-agentforce-sales-1",
        )
        print("Enrolled an Observable identity with external_ref='crm-agentforce-sales-1'")
        print("(this is what an operator does after Inventory surfaces an unenrolled agent")
        print("that turns out to be legitimate and should come under Agent Guard).")

        agents = client.get("/inventory/agents").json()
        by_ref = {a["external_ref"]: a for a in agents}
        print(f"crm-agentforce-sales-1 shadow now: {by_ref['crm-agentforce-sales-1']['shadow']}")
        print(f"m365-copilot-ext-42 shadow still: {by_ref['m365-copilot-ext-42']['shadow']}")

        banner("4. Posture findings from the rule engine")
        findings = client.get("/inventory/posture").json()
        for f in findings:
            print(f"  [{f['severity']:<6}] {f['rule_id']:<24} {f['object_ref']:<28} {f['summary']}")

        banner("5. Simulate the tenant changing, then detect drift")
        connector = state.connectors["mock:acme-corp"]
        connector.grant_permission(
            DiscoveredPermission(
                app_id="crm",
                principal_ref="m365-copilot-ext-42",
                principal_type="agent",
                permission="crm.delete",
                scope_level="admin",
            )
        )
        print("Simulated: the (still-shadow) copilot extension was just granted")
        print("crm.delete/admin in the CRM — a privilege escalation an operator")
        print("did not sanction through Observable at all.")

        client.post("/inventory/scan", json={})
        drift = client.get("/inventory/drift/mock:acme-corp").json()
        show("drift since previous scan", drift)

        findings_after = client.get("/inventory/posture").json()
        new_findings = [f for f in findings_after if f["rule_id"].startswith("drift_")]
        print("New drift-based posture findings:")
        for f in new_findings:
            print(f"  [{f['severity']:<6}] {f['rule_id']:<18} {f['object_ref']:<28} {f['summary']}")

        banner("Done")
        print("This is the Inventory & Posture flow from ARCHITECTURE.md §7,")
        print("running against the real Inventory Store, Shadow AI detector,")
        print("and Posture Findings engine (Blocks 7-11).")


if __name__ == "__main__":
    main()
