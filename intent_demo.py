#!/usr/bin/env python3
"""
Observable Intent-Conformance Signal (§8.5) — scripted walkthrough.

Runs against the real FastAPI app in-process, with the MockIntentScorer
armed (OBSERVABLE_INTENT_SCORER=mock — no GPU, no network call; see
ARCHITECTURE.md §8.5 for the production CLM adapter). Shows the same
scenario the architecture doc walks through: a reporting-analyst agent
declares its purpose at token mint, reads that stay in scope for that
purpose sail through unaffected, and a call whose target tool shares no
vocabulary with the declared purpose gets an intent_mismatch signal
that — stacked on top of the ordinary first-time-tool signal — pushes
the combined risk_score over that tool's own policy ceiling. Nothing
here is a new control: the deny still comes from the pre-existing ABAC
max_risk_score check (§5); intent-conformance only supplies one more
number that feeds it.

Run with:  OBSERVABLE_INTENT_SCORER=mock python3 intent_demo.py
(this script sets that env var itself if it isn't already set, so a
plain `python3 intent_demo.py` also works)
"""
from __future__ import annotations

import json
import os
import textwrap

# Must be set before observable.api.app is imported: the module-level
# AppState (and its DetectionEngine/IntentChecker) is built once at
# import time, exactly like every other OBSERVABLE_* env toggle.
os.environ.setdefault("OBSERVABLE_INTENT_SCORER", "mock")

from starlette.testclient import TestClient  # noqa: E402

from observable.api.app import app  # noqa: E402
from observable.client.sdk import AgentClient, AgentClientError  # noqa: E402


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
        banner("0. Confirm the intent-conformance signal is armed")
        status = client.get("/admin/detection/intent").json()
        show("GET /admin/detection/intent", status)
        if status["mode"] == "off":
            print("OBSERVABLE_INTENT_SCORER is 'off' in this process -- re-run with")
            print("OBSERVABLE_INTENT_SCORER=mock python3 intent_demo.py")
            return

        banner("1. Enroll a reporting-analyst and declare its purpose at mint")
        agent = AgentClient.enroll(
            http=client,
            display_name="intent-demo-reporting-bot",
            role="reporting-analyst",
            tier="foundation",
            enrolled_by="omar",
        )
        purpose = "weekly summary of booking activity"
        print(f"Enrolled agent_id={agent.agent_id}")
        print(f"Declared purpose (signed into every token's req_ctx): {purpose!r}")

        banner("2. In-scope reads: purpose and tool share vocabulary -> no signal")
        for tool, resource_id, payload in (
            ("booking.read", "B-1", {}),
            ("reporting.generate", None, {"report_name": "weekly-activity"}),
        ):
            token = agent.request_token([f"tool:{tool}"], purpose=purpose)
            result = agent.invoke(token, tool_name=tool, payload=payload, resource_id=resource_id)
            signals = result["detection_signals"]
            intent_signals = [s for s in signals if s.startswith("intent_mismatch")]
            print(f"  {tool}: allowed={result['allowed']}  risk_score={result['risk_score']:.2f}")
            print(f"    all signals: {signals or '(none)'}")
            print(f"    intent_mismatch fired: {bool(intent_signals)}")

        banner("3. Out-of-scope call: reporting.export shares no words with the purpose")
        print("'weekly summary of booking activity' vs. reporting.export ('Export a")
        print("generated report to an external format/location') -- no shared vocabulary,")
        print("so the mock scorer's p_consistent comes out low and intent_mismatch fires.")
        export_token = agent.request_token(["tool:reporting.export"], purpose=purpose)
        try:
            agent.invoke(export_token, tool_name="reporting.export", payload={"format": "csv"})
            print("  UNEXPECTEDLY allowed -- mock scorer's overlap heuristic may need retuning")
        except AgentClientError as exc:
            print(f"  DENIED as expected: HTTP {exc.status_code}")
            print(f"  reason: {exc.detail}")

        banner("4. What actually denied it: the existing ABAC ceiling, not a new control")
        print("reporting.export's policy definition caps max_risk_score at 0.5. The")
        print("first-time-tool signal alone (0.25, medium sensitivity) would not have")
        print("crossed that. intent_mismatch's contribution stacked on top of it did --")
        print("intent-conformance only ever supplies evidence to a ceiling that already")
        print("existed; it can never deny a tool whose ceiling is above 0.5 on its own")
        print("(its contribution is capped there by design, ARCHITECTURE.md §8.5).")

        banner("5. Operator-facing failure counters")
        status = client.get("/admin/detection/intent").json()
        show("GET /admin/detection/intent (after this run)", status)
        print("A CLM outage would show up here as failures > 0 with the last error --")
        print("never as a silently-missing signal.")

        banner("Done")
        print("Turn this off again with OBSERVABLE_INTENT_SCORER=off (or unset it) --")
        print("it stays off by default in every deployment that hasn't explicitly armed it.")


if __name__ == "__main__":
    main()
