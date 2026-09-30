"""
Enrolls three fresh test agents against your LIVE deployed Observable
backend and exercises a range of features, so /console has real, varied
data to show instead of an empty/example state:

  1. sales-assistant-<run>  (role: sales-assistant)
     - one allowed crm.read call

  2. booking-bot-<run>  (role: booking-agent)
     - creates a booking, reads it back, attempts to cancel it
       (business-hours-only tool -- may be allowed or denied depending
       on what time it is when you run this; either outcome is a real,
       useful demonstration of the platform's ABAC policy in action)
     - one deliberately DENIED call (email.send, which booking-agent
       was never granted) -- shows up in the audit trail as a policy
       denial, not an error
     - several repeated booking.read calls, to give the Detection
       plane enough history to establish a behavioral baseline for
       this agent (visible under Detection in the console)

  3. reporting-bot-<run>  (role: reporting-analyst)
     - reads CRM + booking data (read-only cross-plane access) and
       generates + exports a report
     - one deliberately DENIED call (booking.cancel, read-only roles
       don't get it)

Each run tags its three display names with a short unique suffix (the
current time, HHMMSS), so re-running this script -- to "refresh" the
demo data, or after Render redeploys and wipes the in-memory state --
always enrolls 3 brand-new agents instead of colliding with whatever
identities are already on the backend (that collision is what silently
skips an agent's tool calls: this script has no saved private key for
an agent enrolled by an earlier run, so a 409 means it can authenticate
as nothing and has to skip it entirely). If you want a clean slate with
exactly 3 agents total, redeploy on Render first (wipes all in-memory
state), then run this once.

Run this from inside your unzipped `observable` project folder (the one
containing the `observable/` package -- check with `dir`/`ls` that you
see requirements.txt right there before running), after
`pip install -r requirements.txt`:

    python seed_live_demo.py https://observable-41zw.onrender.com

(pass your own Render URL as the one argument; defaults to the URL
below if you don't pass one)
"""
import sys
import time

import httpx

from observable.client.sdk import AgentClient, AgentClientError

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "https://observable-41zw.onrender.com"
RUN_TAG = time.strftime("%H%M%S")

print(f"Connecting to {BASE_URL} ...")
print(f"Run tag: {RUN_TAG} (each agent below is named with this suffix so this run never collides "
      f"with agents from an earlier run)\n")
http = httpx.Client(base_url=BASE_URL, timeout=30.0)


def enroll(display_name, role, tier="foundation"):
    try:
        agent = AgentClient.enroll(
            http=http, display_name=display_name, role=role, tier=tier, enrolled_by="omar"
        )
        print(f"  enrolled {display_name} ({agent.agent_id})")
        return agent
    except AgentClientError as exc:
        if exc.status_code == 409:
            print(f"  {display_name} already enrolled on this backend -- skipping enrollment, "
                  f"reusing is not possible from this script (no saved private key), "
                  f"so its tool calls below are skipped too. This shouldn't happen with the "
                  f"run-tag suffix unless you ran this script twice in the same second.")
            return None
        raise


# ---------------------------------------------------------------------
print("1. sales-assistant")
sales = enroll(f"sales-assistant-{RUN_TAG}", "sales-assistant")
if sales:
    token = sales.request_token(["tool:crm.read"], purpose="live demo seed")
    result = sales.invoke(token, tool_name="crm.read", payload={}, resource_id="A-102")
    print("   crm.read ->", result["allowed"])

# ---------------------------------------------------------------------
print("\n2. booking-agent")
booking_bot = enroll(f"booking-bot-{RUN_TAG}", "booking-agent")
if booking_bot:
    create_token = booking_bot.request_token(["tool:booking.create"])
    created = booking_bot.invoke(
        create_token,
        tool_name="booking.create",
        payload={"resource": "Meeting Room A", "customer": "Acme Corp", "date": "2026-11-05"},
    )
    booking_id = created["result"]["booking_id"]
    print(f"   booking.create -> {booking_id}")

    # A few repeated reads (with tiny pauses) so the Detection plane has
    # enough spacing data to learn a baseline for this agent.
    for i in range(6):
        read_token = booking_bot.request_token(["tool:booking.read"])
        booking_bot.invoke(read_token, tool_name="booking.read", payload={}, resource_id=booking_id)
        time.sleep(0.3)
    print("   booking.read x6 -> baseline data recorded")

    try:
        cancel_token = booking_bot.request_token(["tool:booking.cancel"])
        cancel_result = booking_bot.invoke(cancel_token, tool_name="booking.cancel", payload={}, resource_id=booking_id)
        print("   booking.cancel -> allowed (you're calling this during business hours)")
    except AgentClientError as exc:
        print(f"   booking.cancel -> denied ({exc.detail}) -- this is expected outside business hours")

    try:
        booking_bot.request_token(["tool:email.send"])
        print("   email.send -> UNEXPECTEDLY allowed (should have been denied!)")
    except AgentClientError as exc:
        print(f"   email.send -> denied as expected (HTTP {exc.status_code}): booking-agent was never granted this tool")

# ---------------------------------------------------------------------
print("\n3. reporting-analyst")
reporting_bot = enroll(f"reporting-bot-{RUN_TAG}", "reporting-analyst")
if reporting_bot:
    crm_token = reporting_bot.request_token(["tool:crm.read"])
    reporting_bot.invoke(crm_token, tool_name="crm.read", payload={}, resource_id="A-100")
    print("   crm.read -> ok (read-only cross-plane access)")

    gen_token = reporting_bot.request_token(["tool:reporting.generate"])
    report = reporting_bot.invoke(gen_token, tool_name="reporting.generate", payload={"report_name": "weekly-activity"})
    print("   reporting.generate ->", report["result"])

    export_token = reporting_bot.request_token(["tool:reporting.export"])
    exported = reporting_bot.invoke(export_token, tool_name="reporting.export", payload={"format": "csv"})
    print("   reporting.export ->", exported["result"])

    try:
        reporting_bot.request_token(["tool:booking.cancel"])
        print("   booking.cancel -> UNEXPECTEDLY allowed (should have been denied!)")
    except AgentClientError as exc:
        print(f"   booking.cancel -> denied as expected (HTTP {exc.status_code}): reporting-analyst is read-only")

print(f"\nDone. Refresh your /console page:")
print(f"  - Agents: 3 new identities tagged '-{RUN_TAG}', each with a real PKI certificate (click View)")
print(f"  - Overview: the new Agent activity map should show each agent linked to the tools it called")
print(f"  - Detection: booking-bot-{RUN_TAG} should show a learned baseline")
print(f"  - Compliance: report reflects live registry/policy/audit state")
print(f"  - the two DENIED calls are in the audit trail as policy denials, not errors")
