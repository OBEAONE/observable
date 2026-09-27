"""New-role smoke tests for the booking.* and reporting.* tools added
alongside the demo `booking-agent` and `reporting-analyst` identities
(ARCHITECTURE.md §5 role-grant table). These follow the same
enroll -> token -> invoke round trip as test_api.py's sales-assistant
tests, just against the new tool surface, plus the deny-by-default
cross-role checks that matter most: a role never implicitly gets a
tool it wasn't granted, even one that "sounds" related.
"""
import pytest
from starlette.testclient import TestClient

from observable.api.app import app, get_state
from observable.api.state import build_default_state
from observable.client.sdk import AgentClient, AgentClientError


@pytest.fixture()
def client():
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_booking_agent_can_create_read_and_cancel(client):
    agent = AgentClient.enroll(
        http=client, display_name="booking-bot", role="booking-agent", tier="foundation", enrolled_by="omar"
    )

    create_token = agent.request_token(["tool:booking.create"])
    created = agent.invoke(
        create_token,
        tool_name="booking.create",
        payload={"resource": "Meeting Room B", "customer": "Globex Industries", "date": "2026-11-01"},
    )["result"]
    assert created["status"] == "confirmed"
    booking_id = created["booking_id"]

    read_token = agent.request_token(["tool:booking.read"])
    fetched = agent.invoke(read_token, tool_name="booking.read", payload={}, resource_id=booking_id)["result"]
    assert fetched["customer"] == "Globex Industries"


def test_booking_agent_cannot_send_email(client):
    """A role only gets what it was explicitly granted — 'booking' and
    'email' sound unrelated, but this also guards against an overly
    broad glob accidentally covering something it shouldn't."""
    agent = AgentClient.enroll(
        http=client, display_name="booking-bot-2", role="booking-agent", tier="foundation", enrolled_by="omar"
    )
    with pytest.raises(AgentClientError) as exc_info:
        agent.request_token(["tool:email.send"])
    assert exc_info.value.status_code == 403


def test_reporting_analyst_can_generate_and_export(client):
    agent = AgentClient.enroll(
        http=client, display_name="reporting-bot", role="reporting-analyst", tier="foundation", enrolled_by="omar"
    )

    gen_token = agent.request_token(["tool:reporting.generate"])
    report = agent.invoke(
        gen_token, tool_name="reporting.generate", payload={"report_name": "weekly-activity"}
    )["result"]
    assert "crm_accounts" in report
    assert "bookings" in report

    export_token = agent.request_token(["tool:reporting.export"])
    exported = agent.invoke(export_token, tool_name="reporting.export", payload={"format": "csv"})["result"]
    assert exported["export_format"] == "csv"
    assert exported["status"] == "generated"


def test_reporting_analyst_can_read_crm_and_bookings_readonly(client):
    """reporting-analyst is granted crm.read and booking.read (to pull
    source data into a report) but not crm.write/booking.create/
    booking.cancel — read-only access to other planes' data."""
    agent = AgentClient.enroll(
        http=client, display_name="reporting-bot-2", role="reporting-analyst", tier="foundation", enrolled_by="omar"
    )
    token = agent.request_token(["tool:crm.read"])
    result = agent.invoke(token, tool_name="crm.read", payload={}, resource_id="A-100")["result"]
    assert result["name"] == "Globex Industries"

    with pytest.raises(AgentClientError) as exc_info:
        agent.request_token(["tool:booking.create"])
    assert exc_info.value.status_code == 403


def test_reporting_analyst_cannot_cancel_bookings(client):
    agent = AgentClient.enroll(
        http=client, display_name="reporting-bot-3", role="reporting-analyst", tier="foundation", enrolled_by="omar"
    )
    with pytest.raises(AgentClientError) as exc_info:
        agent.request_token(["tool:booking.cancel"])
    assert exc_info.value.status_code == 403
