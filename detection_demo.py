#!/usr/bin/env python3
"""
Observable Detection Plane — scripted walkthrough.

Runs against the real FastAPI app in-process. Shows: a period of normal
activity that lets the Detection Engine learn what "normal" looks like
for an agent, a live risk_score appearing on ordinary calls (the
first-time-use signal), an operator turning on automated containment via
a risk threshold, then a simulated attack — a token being used to
rapid-fire scrape a batch of customer records it has never touched
before — getting caught and the agent auto-contained *before* the burst
finishes, purely from behavior, with no rule anywhere that says
"blocklist these specific resource IDs."

Run with:  python3 detection_demo.py
"""
from __future__ import annotations

import json
import textwrap
import time

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


def main() -> None:
    with TestClient(app) as client:
        banner("1. Enroll an agent and get a broadly-scoped token")
        agent = AgentClient.enroll(
            http=client,
            display_name="sales-assistant-detection-demo",
            role="sales-assistant",
            tier="foundation",
            enrolled_by="omar",
        )
        token = agent.request_token(["tool:crm.read"], purpose="account review")
        print(f"Enrolled agent_id={agent.agent_id}, token minted.")

        banner("2. Normal activity: a human-paced string of lookups")
        for i in range(6):
            result = agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-102")
            print(f"  call {i+1}: risk_score={result['risk_score']:.2f}  signals={result['detection_signals']}")
            time.sleep(0.25)  # a person actually looking things up, not a script

        baseline = client.get(f"/detection/{agent.agent_id}").json()
        show("learned baseline after normal activity", baseline)
        print("Note interval_mean_seconds ~0.25s -- that's now this agent's 'normal pace'.")

        banner("3. Operator turns on automated containment")
        resp = client.post("/admin/detection/threshold", json={"threshold": 0.5})
        show("threshold set", resp.json())
        print("This is the one human decision in this whole flow: 'a risk_score of 0.5")
        print("or higher is unacceptable for this deployment.' Everything from here on")
        print("is Agent Guard mechanically enforcing that decision in real time.")

        banner("4. Attack: the same token used to rapid-fire scrape new records")
        print("Simulating a stolen-token replay pattern: many DIFFERENT customer")
        print("records, back-to-back, far faster than this agent's own baseline pace.")
        print("No rule anywhere lists these specific resource IDs as forbidden --")
        print("this is caught purely because it doesn't look like this agent.")
        blocked = False
        for i, resource_id in enumerate(["A-300", "A-301", "A-302", "A-303", "A-304", "A-305"]):
            try:
                result = agent.invoke(token, tool_name="crm.read", payload={}, resource_id=resource_id)
                print(f"  call {i+1} ({resource_id}): ALLOWED, risk_score={result['risk_score']:.2f}")
            except AgentClientError as exc:
                print(f"  call {i+1} ({resource_id}): BLOCKED -- HTTP {exc.status_code}: {exc.detail}")
                blocked = True
                break

        if not blocked:
            print("  (did not trip the threshold in this run -- see note below)")

        banner("5. Agent status after the attack")
        status = client.get(f"/agents/{agent.agent_id}").json()
        show("agent status", status)

        print("Any further call with the same token now fails immediately, without")
        print("waiting for the token's TTL, because Agent Guard checks the registry's")
        print("live status on every single verify() call:")
        try:
            agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-306")
        except AgentClientError as exc:
            print(f"  Rejected as expected: HTTP {exc.status_code} — {exc.detail}")

        banner("6. Audit trail: the exact moment it happened")
        entries = client.get(f"/audit/{agent.agent_id}").json()
        for e in entries:
            print(f"  [{e['seq']:>3}] {e['decision']:>5} | {e['action']:<22} | {e['reason']}")

        banner("Done")
        print("Detection Engine: pure statistics over this agent's own history --")
        print("burst-rate (Welford z-score on call spacing) and new-resource-burst")
        print("(distinct never-seen resources in a rolling window) combined via")
        print("noisy-OR into one risk_score, feeding both ABAC and, once an operator")
        print("sets a threshold, automated containment.")


if __name__ == "__main__":
    main()
