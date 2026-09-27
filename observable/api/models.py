"""Block 6 — HTTP request/response schemas."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class EnrollRequest(BaseModel):
    display_name: str
    role: str
    tier: str = Field(description="foundation | enterprise | advanced")
    public_key_pem: str
    enrolled_by: str
    attestation_device_id: Optional[str] = None
    attestation_quote_b64: Optional[str] = None


class EnrollResponse(BaseModel):
    agent_id: str
    serial_number: str
    certificate_pem: str
    chain_pem: str
    not_after: str


class TokenRequest(BaseModel):
    requested_scopes: list[str]
    purpose: Optional[str] = None
    risk_score: float = 0.0


class TokenResponse(BaseModel):
    access_token: str
    jti: str
    scopes: list[str]
    expires_at: str


class InvokeRequest(BaseModel):
    tool_name: str
    payload: dict
    resource_id: Optional[str] = None


class InvokeResponse(BaseModel):
    allowed: bool
    tool: str
    result: Optional[dict]
    reason: str
    audit_seq: int
    redactions: list[str]
    risk_score: float = 0.0
    detection_signals: list[str] = []


class ContainRequest(BaseModel):
    agent_id: str
    reason: str


class AgentStatusResponse(BaseModel):
    agent_id: str
    display_name: str
    role: str
    tier: str
    status: str
    current_serial: str
    current_not_after: str


class AgentIdentityResponse(BaseModel):
    agent_id: str
    subject_cn: str
    role: str
    tier: str
    status: str
    serial_number: str
    sha256_thumbprint: str
    not_after: str
    revoked: bool
    certificate_pem: str


class AuditVerifyResponse(BaseModel):
    intact: bool
    entry_count: int
    detail: Optional[str] = None


class AuditEntryResponse(BaseModel):
    seq: int
    timestamp: str
    agent_id: Optional[str]
    role: Optional[str]
    action: str
    decision: str
    reason: str
    resource_id: Optional[str]
    request_jti: Optional[str]


# ----------------------------------------------------------------------
# Inventory & Posture (Blocks 7-11)
# ----------------------------------------------------------------------
class ScanRequest(BaseModel):
    connector_id: Optional[str] = None


class ScanResultItem(BaseModel):
    connector_id: str
    taken_at: str
    apps: int
    agents: int
    users: int
    permissions: int


class AppSummary(BaseModel):
    connector_id: str
    app_id: str
    name: str
    category: str
    vendor: str


class AgentSummary(BaseModel):
    connector_id: str
    app_id: str
    external_ref: str
    name: str
    agent_type: str
    scopes: list[str]
    owner: Optional[str]
    last_active_at: Optional[str]
    shadow: bool
    shadow_reason: Optional[str] = None
    shadow_severity: Optional[str] = None


class ShadowFindingResponse(BaseModel):
    connector_id: str
    app_id: str
    external_ref: str
    agent_name: str
    agent_type: str
    scopes: list[str]
    reason: str
    severity: str
    matched_agent_id: Optional[str]


class PostureFindingResponse(BaseModel):
    connector_id: str
    app_id: str
    rule_id: str
    severity: str
    object_ref: str
    summary: str
    remediation: str


class DetectionThresholdRequest(BaseModel):
    threshold: Optional[float] = None


class BaselineSummaryResponse(BaseModel):
    agent_id: str
    known: bool
    n_intervals: Optional[int] = None
    interval_mean_seconds: Optional[float] = None
    interval_std_seconds: Optional[float] = None
    tools_seen: Optional[list[str]] = None
    distinct_resources_seen: Optional[int] = None
    recent_decision_count: Optional[int] = None
    recent_deny_count: Optional[int] = None
    last_event_at: Optional[str] = None


class ControlResultResponse(BaseModel):
    control_id: str
    title: str
    guide_tier: str
    status: str
    summary: str
    evidence: list[str]


class ComplianceReportResponse(BaseModel):
    generated_at: str
    overall_status: str
    counts: dict[str, int]
    results: list[ControlResultResponse]


class SoarIncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    agent_id: str
    role: Optional[str]
    triggered_at: str
    trigger_action: str
    trigger_reason: str
    recommended_actions: list[str]
    related_audit_seqs: list[int]
    closed_at: Optional[str] = None
    closed_reason: Optional[str] = None


class DriftResponse(BaseModel):
    connector_id: str
    old_taken_at: str
    new_taken_at: str
    has_changes: bool
    apps_added: list[str]
    apps_removed: list[str]
    agents_added: list[str]
    agents_removed: list[str]
    users_added: list[str]
    users_removed: list[str]
    permissions_added: list[list[str]]
    permissions_removed: list[list[str]]
