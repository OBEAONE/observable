import json

from observable.export.cef import (
    export_audit_cef,
    export_audit_json_lines,
    format_entry_cef,
    format_entry_json,
)
from observable.guard.audit import AuditChain


def _chain_with_entries():
    chain = AuditChain()
    chain.append(
        agent_id="a1", role="sales-assistant", action="tool:crm.read", decision="allow",
        reason="authorized", resource_id="A-1", request_jti="jti-1",
    )
    chain.append(
        agent_id="a1", role="sales-assistant", action="tool:crm.delete", decision="deny",
        reason="risk score 0.30 exceeds max 0.20 for tool 'crm.delete'", resource_id="A-2",
        request_jti="jti-2",
    )
    chain.append(
        agent_id="a1", role=None, action="containment:suspend", decision="action",
        reason="automated containment: risk_score=0.50 >= threshold=0.50",
    )
    return chain


def test_format_entry_cef_has_expected_header_shape():
    chain = _chain_with_entries()
    line = format_entry_cef(chain.entries()[0])
    parts = line.split("|")
    assert parts[0] == "CEF:0"
    assert parts[1] == "Observable"
    assert parts[2] == "AgentGuard"
    assert parts[4] == "allow.tool:crm.read"
    assert "suser=a1" in line
    assert "outcome=allow" in line


def test_cef_severity_escalates_for_deny_and_containment():
    chain = _chain_with_entries()
    allow_line, deny_line, action_line = (format_entry_cef(e) for e in chain.entries())
    allow_severity = int(allow_line.split("|")[6])
    deny_severity = int(deny_line.split("|")[6])
    action_severity = int(action_line.split("|")[6])
    assert allow_severity < deny_severity < action_severity


def test_cef_header_escapes_pipe_and_backslash_in_action_derived_fields():
    # `action` feeds both the Signature ID and Name header fields (via
    # entry.action), so a pipe or backslash inside it must come out
    # backslash-escaped in the header, matching what the escape helper
    # itself produces (backslash first, then pipe).
    from observable.export.cef import _cef_escape_header

    chain = AuditChain()
    raw_action = r"tool:weird\|name"
    chain.append(agent_id="a1", role="sales-assistant", action=raw_action, decision="allow", reason="ok")
    line = format_entry_cef(chain.entries()[0])
    expected_signature_id = _cef_escape_header(f"allow.{raw_action}")
    assert expected_signature_id in line
    # the unescaped raw pipe must not appear on its own in the header
    # portion (everything before the extension's first key=value pair)
    header_portion = line.split(" rt=")[0]
    assert raw_action not in header_portion


def test_export_audit_cef_joins_all_entries():
    chain = _chain_with_entries()
    text = export_audit_cef(chain.entries())
    lines = text.splitlines()
    assert len(lines) == 3
    assert all(line.startswith("CEF:0|Observable|AgentGuard|") for line in lines)


def test_format_entry_json_round_trips_key_fields():
    chain = _chain_with_entries()
    entry = chain.entries()[1]
    obj = format_entry_json(entry)
    assert obj["seq"] == entry.seq
    assert obj["agent_id"] == "a1"
    assert obj["decision"] == "deny"
    assert obj["action"] == "tool:crm.delete"
    assert obj["entry_hash"] == entry.entry_hash
    assert obj["prev_hash"] == entry.prev_hash


def test_export_audit_json_lines_is_valid_ndjson():
    chain = _chain_with_entries()
    text = export_audit_json_lines(chain.entries())
    lines = text.splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["seq"] for p in parsed] == [0, 1, 2]


def test_export_empty_chain_produces_empty_string():
    assert export_audit_cef([]) == ""
    assert export_audit_json_lines([]) == ""
