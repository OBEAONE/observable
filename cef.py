"""
Block N — SIEM export (CEF + JSON Lines).

Turns the audit chain (§6, `observable/guard/audit.py`) into two
industry-standard formats a SIEM already knows how to ingest, closing
the "streaming to a SIEM" row ARCHITECTURE.md §5 explicitly left for
v2. This module only *formats* — it does not open a socket or make an
HTTP call, deliberately: which collector a customer points at (Splunk
HEC, a syslog relay, Elastic's Filebeat, Sentinel's Log Analytics
agent) is a deployment decision, not something a reference
implementation should hardcode. `GET /export/siem` (§9.3) hands back
one of these bodies for the operator's own log shipper to pick up.

* **CEF** (Common Event Format, ArcSight/Micro Focus's format but
  understood natively by most SIEMs including Splunk and Sentinel) —
  one line per audit entry, the format a security analyst already has
  dashboards built against.
* **JSON Lines** — one compact JSON object per line, the format
  Splunk's HTTP Event Collector, Elastic Filebeat, and most log
  shippers ingest directly with no parsing rules to write.

Both are pure functions of `AuditEntry` — no state, no I/O, so they're
trivial to unit test and safe to call as often as an operator wants
without touching the chain itself.
"""
from __future__ import annotations

import json
from typing import Iterable

from observable.guard.audit import AuditEntry

CEF_VERSION = 0
DEVICE_VENDOR = "Observable"
DEVICE_PRODUCT = "AgentGuard"
DEVICE_VERSION = "1.3"

# CEF severity is 0-10. Deny/error/containment events should stand out
# in a SIEM's default views; routine allows should not.
_SEVERITY_BY_DECISION: dict[str, int] = {
    "allow": 1,
    "deny": 6,
    "error": 7,
    "action": 8,  # containment:suspend / containment:reinstate etc.
}
_DEFAULT_SEVERITY = 3


def _cef_escape_header(value: str) -> str:
    """CEF header fields: backslash and pipe are the only characters
    that must be escaped, in that order (escaping pipe first would
    double-escape the backslash it introduces)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value: str) -> str:
    """CEF extension values: backslash, equals sign, and embedded
    newlines must be escaped."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _cef_extension(entry: AuditEntry) -> str:
    fields: list[tuple[str, str]] = [
        ("rt", str(int(entry.timestamp.timestamp() * 1000))),
        ("act", entry.action),
        ("outcome", entry.decision),
        ("msg", entry.reason),
    ]
    if entry.agent_id:
        fields.append(("suser", entry.agent_id))
    if entry.role:
        fields.append(("cs1Label", "Role"))
        fields.append(("cs1", entry.role))
    if entry.resource_id:
        fields.append(("cs2Label", "ResourceId"))
        fields.append(("cs2", entry.resource_id))
    if entry.request_jti:
        fields.append(("cs3Label", "RequestJti"))
        fields.append(("cs3", entry.request_jti))
    fields.append(("cs4Label", "AuditSeq"))
    fields.append(("cs4", str(entry.seq)))
    return " ".join(f"{key}={_cef_escape_extension(value)}" for key, value in fields)


def format_entry_cef(entry: AuditEntry) -> str:
    """One CEF-formatted line for a single audit entry."""
    severity = _SEVERITY_BY_DECISION.get(entry.decision, _DEFAULT_SEVERITY)
    signature_id = f"{entry.decision}.{entry.action}"
    name = f"Observable Guard: {entry.action} -> {entry.decision}"
    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            _cef_escape_header(DEVICE_VENDOR),
            _cef_escape_header(DEVICE_PRODUCT),
            _cef_escape_header(DEVICE_VERSION),
            _cef_escape_header(signature_id),
            _cef_escape_header(name),
            str(severity),
        ]
    )
    return f"{header}|{_cef_extension(entry)}"


def export_audit_cef(entries: Iterable[AuditEntry]) -> str:
    """Newline-joined CEF lines, ready to hand a syslog relay or write
    to a file a SIEM's log shipper tails."""
    return "\n".join(format_entry_cef(e) for e in entries)


def format_entry_json(entry: AuditEntry) -> dict:
    """One JSON-serializable dict per audit entry — the shape used by
    `export_audit_json_lines` and by ``GET /export/siem?format=json``."""
    return {
        "seq": entry.seq,
        "timestamp": entry.timestamp.isoformat(),
        "vendor": DEVICE_VENDOR,
        "product": DEVICE_PRODUCT,
        "agent_id": entry.agent_id,
        "role": entry.role,
        "action": entry.action,
        "decision": entry.decision,
        "severity": _SEVERITY_BY_DECISION.get(entry.decision, _DEFAULT_SEVERITY),
        "reason": entry.reason,
        "resource_id": entry.resource_id,
        "request_jti": entry.request_jti,
        "entry_hash": entry.entry_hash,
        "prev_hash": entry.prev_hash,
    }


def export_audit_json_lines(entries: Iterable[AuditEntry]) -> str:
    """Newline-delimited JSON (JSON Lines / NDJSON), one compact object
    per audit entry — the format Splunk HEC, Elastic Filebeat, and most
    log shippers ingest with no custom parsing rules."""
    return "\n".join(json.dumps(format_entry_json(e), separators=(",", ":")) for e in entries)
