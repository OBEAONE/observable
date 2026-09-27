#!/usr/bin/env python3
"""
Observable Intent-Conformance Signal — scripted walkthrough (§8.5).

Runs against the real FastAPI app in-process, with the deterministic
MockIntentScorer standing in for a CLM model server (no GPU needed).
Shows: an agent whose token declares a purpose, a sequence of
on-purpose calls that pass, then an off-purpose export attempt that the
four statistical signals alone would let through — denied by the tool's
existing ABAC risk ceiling once intent_mismatch is added — and finally a
simulated model-server outage, which degrades detection loudly instead
of blocking traffic.

To run against a real CLM server instead of the mock:
    OBSERVABLE_INTENT_SCORER=clm OBSERVABLE_CLM_URL=http://<gpu-host>:8700 python3 intent_demo.py

Run with:  python3 intent_demo.py
"""
from __future__ import annotations

import json
import os
import textwrap

os.environ.setdefault("OBSERVABLE_INTENT_SCORER", "mock")

from starlette.testclient import TestClient  # noqa: E402

from observable.api.app import app, get_state  # noqa: E402
from observable.api.state import build_default_state  # noqa: E402
from observable.client.sdk import AgentClient, AgentClientError  # noqa: E402
from observable.detection.intent import IntentChecker, IntentScorerError  # noqa: E402

PURPOSE = "weekly summary of booking activity"


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show(label: str, obj) -> None:
    print(f"-- {label} --")
    print(textwrap.indent(json.dumps(obj, indent=2, default=str), "  "))


class _DownScorer:
    name = "clm"

    def p_consistent(self, query):
        raise IntentScorerError("ConnectError: [Errno 111] Connection refused")


def main() -> None:
    state = build_default_state()
    # Keep the walkthrough independent of the wall clock (business-hours ABAC).
    state.policy_engine._business_hours_check = lambda ts: True
    app.dependency_overrides[get_state] = lambda: state
    try:
        with TestClient(app) as client:
            banner("1. Intent signal configuration")
            show("GET /admin/detection/intent", client.get("/admin/detection/intent").json())

            banner("2. Enroll a reporting agent; its token declares a purpose")
            agent = AgentClient.enroll(
                http=client,
                display_name="reporting-analyst-intent-demo",
                role="reporting-analyst",
                tier="foundation",
                enrolled_by="omar",
            )
            token = agent.request_token(
                ["tool:booking.read", "tool:reporting.generate", "tool:reporting.export"],
                purpose=PURPOSE,
            )
            print(f"agent_id={agent.agent_id}  purpose={PURPOSE!r}")

            banner("3. On-purpose calls: read bookings, generate the summary")
            for tool, resource in (("booking.read", "B-1"), ("reporting.generate", None)):
                r = agent.invoke(token, tool_name=tool, payload={}, resource_id=resource)
                print(f"  {tool:<20} allowed  risk={r['risk_score']:.2f}  signals={r['detection_signals']}")

            banner("4. Off-purpose: export the report to an external location")
            print("  Statistically this is just a first use of a medium-sensitivity tool")
            print("  (new_tool = 0.25, under reporting.export's max_risk_score of 0.50).")
            try:
                agent.invoke(token, tool_name="reporting.export", payload={"destination": "s3://elsewhere"})
                print("  !! unexpectedly allowed")
            except AgentClientError as exc:
                print(f"  DENIED: {exc}")

            banner("5. Model server outage: detection degrades, traffic is not blocked")
            state.detection.set_intent_checker(IntentChecker(_DownScorer(), state.policy_engine))
            r = agent.invoke(token, tool_name="booking.read", payload={}, resource_id="B-1")
            print(f"  booking.read allowed  degraded={r['detection_degraded']}")
            show("GET /admin/detection/intent", client.get("/admin/detection/intent").json())

            banner("6. The audit trail records both the mismatch and the outage")
            audit = state.guard.audit.entries()[-2:]
            for e in audit:
                print(f"  seq={e.seq} {e.action} {e.decision}: {e.reason}")
    finally:
        app.dependency_overrides.clear()


if __name__ == "__main__":
    main()
