#!/usr/bin/env python3
"""
Observable NIST AI RMF alignment (§9.5) — scripted walkthrough.

Runs against the real FastAPI app in-process. Shows the second lens
over the same running instance ``compliance_export_demo.py`` already
reports on: instead of the Zero Trust for AI Agents guide's rows
(ARCHITECTURE.md §5), this walks the NIST AI RMF 1.0 GOVERN/MAP/
MEASURE/MANAGE subcategories §9.5 maps to, including MAP 5's Impact
Register — and it deliberately does NOT show all-green. A compliance
report that never shows a real gap is not one an auditor should trust;
NIST AI RMF frames risk management as continuous, not a one-time
attestation, so this script prints the gaps exactly as the API returns
them.

Run with:  python3 nist_compliance_demo.py
"""
from __future__ import annotations

import json
import textwrap

from starlette.testclient import TestClient

from observable.api.app import app


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
        banner("1. The Impact Register (MAP 5), seeded at startup")
        register = client.get("/compliance/impact-register").json()
        print(f"{len(register['entries'])} impact(s) characterized; status counts: {register['counts']}")
        for entry in register["entries"]:
            print(f"  [{entry['status']:9}] ({entry['severity']:8}) {entry['title']}")
        print()
        print("These include Observable's OWN detection/intent-conformance components")
        print("(§8, §8.5) — the guide's GOVERN/MAP categories apply reflexively to the")
        print("platform's own AI-driven signals, not only to the agents it monitors.")

        banner("2. Add one more impact and mark it resolved")
        added = client.post(
            "/compliance/impact-register",
            json={
                "title": "Demo: new SaaS connector adapter overreaches its read-only scope",
                "category": "third_party",
                "affected_parties": ["Connected SaaS tenant's own admins"],
                "description": (
                    "A hypothetical future non-mock connector could request write "
                    "scopes beyond §7.3's read-only design principle if not reviewed."
                ),
                "severity": "medium",
                "likelihood": "possible",
                "related_component": "observable/inventory/connector.py (§7.3)",
            },
        ).json()
        print(f"Added: {added['title']} (status={added['status']})")
        resolved = client.post(
            f"/compliance/impact-register/{added['entry_id']}/status",
            json={"status": "mitigated", "mitigation": "Code review gate added to the connector interface contract."},
        ).json()
        print(f"Resolved: status={resolved['status']!r}, mitigation={resolved['mitigation']!r}")

        banner("3. NIST AI RMF compliance report — GET /compliance/report?framework=nist-ai-rmf")
        report = client.get("/compliance/report?framework=nist-ai-rmf").json()
        print(f"overall_status: {report['overall_status']}  counts: {report['counts']}")
        for result in report["results"]:
            print(f"  [{result['status']:14}] {result['guide_tier']:12} {result['summary']}")

        banner("4. The honest gap: MEASURE 3.3")
        m33 = next(r for r in report["results"] if r["control_id"] == "nist_measure_3_3")
        print("This control is a deliberate FAIL, not a bug in the demo:")
        print(f"  {m33['summary']}")
        print("SOAR incident export (§9.3) gives operators visibility into containment")
        print("events, but there is still no channel for an agent OPERATOR to contest a")
        print("denial — a real, open gap this report surfaces rather than hiding.")

        banner("5. Same instance, the original ZTA-guide lens still works unchanged")
        zta = client.get("/compliance/report?framework=zta").json()
        print(f"framework={zta['framework']!r}  overall_status={zta['overall_status']}  counts={zta['counts']}")
        print("Both reports read the exact same live state through the same")
        print("ComplianceContext (§9.1) — nist_ai_rmf.py adds a second control set,")
        print("it does not replace or fork the first.")

        banner("Done")
        print("Re-run at any time: both reports regenerate fresh from live state,")
        print("and the Impact Register persists (in-memory, per §9's existing")
        print("no-durable-storage note) for the life of this process.")


if __name__ == "__main__":
    main()
