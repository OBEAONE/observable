#!/usr/bin/env python3
"""
Observable Compliance & SIEM/SOAR Export — scripted walkthrough.

Runs against the real FastAPI app in-process. Shows: a fresh instance's
compliance posture (some controls PARTIAL until an operator makes a
decision, some N/A until a scan has run), an inventory scan turning
two controls live and one of them RED, an operator fixing the gap by
configuring automated containment, a live attack getting caught and
auto-contained (reusing the Detection plane from §8), that containment
event turning into a SIEM-ready audit export and a SOAR-ready incident
record with concrete next steps, and finally the operator clearing the
agent and watching the SOAR incident close itself out.

Run with:  python3 compliance_export_demo.py
"""
from __future__ import annotations

import json
import textwrap

from starlette.testclient import TestClient

from observable.api.app import app
from observable.client.sdk import AgentClient, AgentClientError


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show(label: str, obj) -> None:
    print(f"-- {label} --")
    print(textwrap.indent(json.dumps(obj, indent=2, default=str), "  "))


def print_report_summary(report: dict) -> None:
    print(f"  overall_status = {report['overall_status']}   counts = {report['counts']}")
    for result in report["results"]:
        marker = {"pass": "OK ", "fail": "FAIL", "partial": "~~~", "not_applicable": "n/a "}[result["status"]]
        print(f"  [{marker}] {result['control_id']:<32} {result['summary']}")


def main() -> None:
    with TestClient(app) as client:
        banner("1. Compliance posture of a brand-new Observable instance")
        report = client.get("/compliance/report").json()
        print_report_summary(report)
        print(
            "\nNote: automated_containment is PARTIAL (mechanism exists, no threshold\n"
            "set yet), signed_policy_bundle is PARTIAL (dev bundle loaded unsigned),\n"
            "and the two inventory-backed controls are N/A -- no scan has run yet."
        )

        banner("2. Run an inventory scan: two controls go live")
        client.post("/inventory/scan", json={})
        report = client.get("/compliance/report").json()
        print_report_summary(report)
        print(
            "\nThe mock tenant's stale admin account and unenrolled privileged agent\n"
            "now fail their controls -- this is real, not a canned scenario."
        )

        banner("3. Operator closes the automated-containment gap")
        client.post("/admin/detection/threshold", json={"threshold": 0.5})
        report = client.get("/compliance/report").json()
        by_id = {r["control_id"]: r for r in report["results"]}
        print(f"  automated_containment is now: {by_id['automated_containment']['status']}")
        print(f"  -> {by_id['automated_containment']['summary']}")

        banner("4. An agent triggers automated containment (§8's attack, replayed)")
        agent = AgentClient.enroll(
            http=client, display_name="compliance-demo-agent", role="sales-assistant",
            tier="foundation", enrolled_by="omar",
        )
        token = agent.request_token(["tool:crm.read"], purpose="account review")
        blocked = False
        for resource_id in ["A-900", "A-901", "A-902", "A-903", "A-904", "A-905"]:
            try:
                agent.invoke(token, tool_name="crm.read", payload={}, resource_id=resource_id)
            except AgentClientError as exc:
                print(f"  BLOCKED on {resource_id}: HTTP {exc.status_code} -- {exc.detail}")
                blocked = True
                break
        if not blocked:
            print("  (did not trip the threshold in this run)")

        banner("5. That containment event, exported for a SIEM")
        cef_resp = client.get("/export/siem", params={"format": "cef"})
        print("-- CEF (last 2 lines) --")
        for line in cef_resp.text.splitlines()[-2:]:
            print(f"  {line}")

        banner("6. The same event, exported as a SOAR-ready incident")
        incidents = client.get("/export/soar/incidents").json()
        show("open incident(s)", incidents)

        banner("7. Operator investigates, confirms it, and closes it out")
        for incident in incidents:
            if incident["status"] == "open":
                client.post(
                    "/admin/reinstate",
                    json={"agent_id": incident["agent_id"], "reason": "confirmed and remediated, cleared for reinstatement"},
                )
        incidents_after = client.get("/export/soar/incidents").json()
        show("incident(s) after reinstatement", incidents_after)

        banner("Done")
        print("Compliance report and SIEM/SOAR exports are both generated fresh from")
        print("live state on every call -- registry, policy engine, audit chain,")
        print("inventory store, and Detection Engine. Nothing here is a snapshot that")
        print("can drift from what the platform is actually doing.")


if __name__ == "__main__":
    main()
