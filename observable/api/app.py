"""
Block 6 — FastAPI application.

Exposes the Agent Guard core over HTTP. Endpoints:

  POST /enroll             one-time agent enrollment (operator-approved
                            out of band in a real deployment; unauthenticated
                            here for the reference implementation — see
                            the module docstring note below)
  POST /token               mint a scoped, PoP-bound access token
  POST /gateway/invoke      the one door every tool call goes through
  POST /admin/contain       automated/operator containment (suspend)
  POST /admin/reinstate     lift a suspension
  POST /admin/elevation/grant         grant a time-boxed, just-in-time permission
  POST /admin/elevation/{id}/revoke   revoke one early, before it would expire
  GET  /admin/elevation               list elevation grants (optionally by agent_id)
  GET  /audit/verify        tamper-evidence check over the whole chain
  GET  /audit/{agent_id}    an agent's own audit trail
  GET  /agents              list all enrolled agents
  GET  /agents/{agent_id}   registry status lookup
  GET  /agents/{agent_id}/identity   live certificate (PEM) + thumbprint

Every endpoint except /enroll requires the application-layer
proof-of-possession headers described in observable.api.pop. /enroll has no
certificate to check a signature against yet (that's the point of
enrollment) — in production, put it behind separate operator
authentication (SSO + approval workflow), which is out of scope for
this reference core.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from observable.api.models import (
    AgentIdentityResponse,
    AgentRiskHistoryResponse,
    AgentStatusResponse,
    AgentSummary,
    AppSummary,
    AuditEntryResponse,
    AuditVerifyResponse,
    BaselineSummaryResponse,
    IntentStatusResponse,
    ComplianceReportResponse,
    ContainRequest,
    ControlResultResponse,
    DetectionThresholdRequest,
    DriftResponse,
    ElevationGrantRequest,
    ElevationGrantResponse,
    ElevationListResponse,
    ElevationRevokeRequest,
    EnrollRequest,
    EnrollResponse,
    ImpactEntryRequest,
    ImpactEntryResponse,
    ImpactRegisterResponse,
    ImpactStatusUpdateRequest,
    InvokeRequest,
    InvokeResponse,
    PostureFindingResponse,
    RiskHistoryResponse,
    ScanRequest,
    ScanResultItem,
    ShadowFindingResponse,
    SoarIncidentResponse,
    TokenRequest,
    TokenResponse,
)
from observable.api.pop import SignatureVerificationError, verify_request_signature
from observable.api.state import AppState, build_default_state
from observable.compliance.framework import ComplianceContext
from observable.compliance.impact_register import ImpactRegisterError
from observable.compliance.nist_ai_rmf import NIST_AI_RMF_CONTROLS
from observable.compliance.report import generate_report
from observable.export.cef import export_audit_cef, export_audit_json_lines
from observable.export.soar import build_incidents_from_audit, export_incidents_json
from observable.guard.audit import AuditIntegrityError
from observable.guard.gateway import GuardDeniedError, ToolExecutionError
from observable.identity.registry import (
    AgentAlreadyRevokedError,
    DuplicateEnrollmentError,
    IdentityError,
    UnknownAgentError,
)
from observable.inventory.posture import scan_drift, scan_snapshot
from observable.inventory.shadow import detect_shadow_agents
from observable.pki.interface import AttestationEvidence, CertificateTier
from observable.policy.elevation import ElevationError, ElevationGrant, ElevationNotFoundError
from observable.pki.reference_ca import AttestationRequiredError
from observable.tokens.service import AgentNotActiveError, ScopeDeniedError, TokenError

app = FastAPI(title="Observable Guard", version="0.1.0")

# Allows a browser-hosted dashboard (e.g. the read-only console served as
# a separate static page) to call this API cross-origin. Wide open here
# because this is a reference deployment with no cookie-based auth to
# protect (every write endpoint that matters is behind PoP or an
# operator's own network access) — a production deployment should
# restrict allow_origins to the dashboard's actual origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_state: AppState = build_default_state()


def get_state() -> AppState:
    return _state


# ----------------------------------------------------------------------
# Console — a small self-hosted read-only dashboard (agents, compliance,
# inventory, detection, SOAR incidents) over this same API. Served
# same-origin deliberately: a Claude-published Artifact page cannot
# fetch an arbitrary external API at all (its Content-Security-Policy
# blocks it by platform design, no matter what CORS headers this API
# sends), so the dashboard has to be served by the API itself rather
# than hosted separately.
# ----------------------------------------------------------------------
_CONSOLE_HTML_PATH = Path(__file__).parent / "static" / "console.html"
_LANDING_HTML_PATH = Path(__file__).parent / "static" / "landing.html"
_ICONS_DIR = Path(__file__).parent / "static" / "icons"
_ICON_MEDIA_TYPES = {
    "favicon.ico": "image/x-icon",
    "favicon-16x16.png": "image/png",
    "favicon-32x32.png": "image/png",
    "apple-touch-icon.png": "image/png",
}


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    # Browsers request this exact root-level path by default, independent
    # of any <link rel="icon"> tag in the served HTML.
    data = (_ICONS_DIR / "favicon.ico").read_bytes()
    return Response(content=data, media_type="image/x-icon")


@app.get("/icons/{filename}", include_in_schema=False)
def icon_asset(filename: str) -> Response:
    # Allowlisted by exact filename (no path traversal via user input).
    media_type = _ICON_MEDIA_TYPES.get(filename)
    if media_type is None:
        raise HTTPException(status_code=404, detail="unknown icon asset")
    data = (_ICONS_DIR / filename).read_bytes()
    return Response(content=data, media_type=media_type)


@app.get("/console", response_class=HTMLResponse)
def console_page() -> HTMLResponse:
    raw = _CONSOLE_HTML_PATH.read_text(encoding="utf-8")
    # The file itself is just a <title>/<style>/body-markup/<script>
    # fragment (no <!doctype>/<html>/<head> of its own); browsers hoist
    # the stray head-level tags into an implicit <head> regardless of
    # where they land relative to this wrapper, per the HTML5 parsing
    # algorithm, so no manual split between head and body is needed.
    wrapped = (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<link rel="icon" href="/favicon.ico" sizes="any">\n'
        '<link rel="icon" type="image/png" sizes="32x32" href="/icons/favicon-32x32.png">\n'
        '<link rel="icon" type="image/png" sizes="16x16" href="/icons/favicon-16x16.png">\n'
        '<link rel="apple-touch-icon" sizes="180x180" href="/icons/apple-touch-icon.png">\n'
        "</head>\n<body>\n" + raw + "\n</body>\n</html>\n"
    )
    return HTMLResponse(content=wrapped)


# ----------------------------------------------------------------------
# Marketing landing page — served same-origin at the root path, so the
# same Render deployment (and, once DNS is pointed at it, the same
# observable24.com domain) carries both the public-facing page and the
# read-only console below it. landing.html is a complete, self-contained
# document (own <!doctype>/<head>), unlike console.html's fragment above.
# ----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page() -> HTMLResponse:
    raw = _LANDING_HTML_PATH.read_text(encoding="utf-8")
    return HTMLResponse(content=raw)


@dataclasses.dataclass(frozen=True)
class PoPContext:
    client_cert_pem: bytes
    raw_body: bytes


async def pop_context(request: Request, state: AppState = Depends(get_state)) -> PoPContext:
    raw_body = await request.body()
    cert_b64 = request.headers.get("X-Observable-Client-Cert")
    timestamp = request.headers.get("X-Observable-Timestamp")
    nonce = request.headers.get("X-Observable-Nonce")
    sig_b64 = request.headers.get("X-Observable-Signature")

    missing = [
        name
        for name, value in [
            ("X-Observable-Client-Cert", cert_b64),
            ("X-Observable-Timestamp", timestamp),
            ("X-Observable-Nonce", nonce),
            ("X-Observable-Signature", sig_b64),
        ]
        if not value
    ]
    if missing:
        raise HTTPException(status_code=401, detail=f"missing required headers: {missing}")

    try:
        cert_pem = base64.b64decode(cert_b64)
        signature = base64.b64decode(sig_b64)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"malformed header encoding: {exc}") from exc

    try:
        verify_request_signature(
            client_cert_pem=cert_pem,
            signature=signature,
            method=request.method,
            path=request.url.path,
            timestamp=timestamp,
            nonce=nonce,
            body=raw_body,
            nonce_cache=state.nonce_cache,
        )
    except SignatureVerificationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return PoPContext(client_cert_pem=cert_pem, raw_body=raw_body)


# ----------------------------------------------------------------------
# Enrollment
# ----------------------------------------------------------------------
@app.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, state: AppState = Depends(get_state)) -> EnrollResponse:
    try:
        tier = CertificateTier(body.tier)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown tier {body.tier!r}")

    attestation = None
    if body.attestation_device_id:
        quote = base64.b64decode(body.attestation_quote_b64 or "")
        attestation = AttestationEvidence(device_id=body.attestation_device_id, quote=quote)

    try:
        result = state.registry.enroll(
            display_name=body.display_name,
            role=body.role,
            tier=tier,
            public_key_pem=body.public_key_pem.encode("utf-8"),
            enrolled_by=body.enrolled_by,
            attestation=attestation,
        )
    except DuplicateEnrollmentError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AttestationRequiredError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return EnrollResponse(
        agent_id=result.record.agent_id,
        serial_number=result.certificate.serial_number,
        certificate_pem=result.certificate.certificate_pem.decode("utf-8"),
        chain_pem=result.certificate.chain_pem.decode("utf-8"),
        not_after=result.certificate.not_after.isoformat(),
    )


# ----------------------------------------------------------------------
# Token issuance
# ----------------------------------------------------------------------
@app.post("/token", response_model=TokenResponse)
def issue_token(
    body: TokenRequest, ctx: PoPContext = Depends(pop_context), state: AppState = Depends(get_state)
) -> TokenResponse:
    try:
        token = state.token_service.mint(
            client_cert_pem=ctx.client_cert_pem,
            requested_scopes=body.requested_scopes,
            purpose=body.purpose,
            risk_score=body.risk_score,
        )
    except ScopeDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AgentNotActiveError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return TokenResponse(
        access_token=token.jwt,
        jti=token.jti,
        scopes=[str(s) for s in token.scopes],
        expires_at=token.expires_at.isoformat(),
    )


# ----------------------------------------------------------------------
# Gateway invocation
# ----------------------------------------------------------------------
@app.post("/gateway/invoke", response_model=InvokeResponse)
def gateway_invoke(
    body: InvokeRequest,
    request: Request,
    ctx: PoPContext = Depends(pop_context),
    state: AppState = Depends(get_state),
) -> InvokeResponse:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing Authorization: Bearer <token> header")
    token = auth_header.removeprefix("Bearer ").strip()

    try:
        result = state.guard.invoke(
            client_cert_pem=ctx.client_cert_pem,
            token=token,
            tool_name=body.tool_name,
            payload=body.payload,
            resource_id=body.resource_id,
        )
    except GuardDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.reason) from exc
    except ToolExecutionError as exc:
        raise HTTPException(status_code=502, detail=exc.reason) from exc

    return InvokeResponse(
        allowed=result.allowed,
        tool=result.tool,
        result=result.result,
        reason=result.reason,
        audit_seq=result.audit_seq,
        redactions=result.redactions,
        risk_score=result.risk_score,
        detection_signals=result.detection_signals,
        detection_degraded=result.detection_degraded,
    )


# ----------------------------------------------------------------------
# Containment / admin
# ----------------------------------------------------------------------
@app.post("/admin/contain")
def admin_contain(body: ContainRequest, state: AppState = Depends(get_state)) -> dict:
    try:
        record = state.guard.contain_agent(body.agent_id, reason=body.reason)
    except UnknownAgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AgentAlreadyRevokedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"agent_id": record.agent_id, "status": record.status.value}


@app.post("/admin/reinstate")
def admin_reinstate(body: ContainRequest, state: AppState = Depends(get_state)) -> dict:
    try:
        record = state.guard.reinstate_agent(body.agent_id, reason=body.reason)
    except (UnknownAgentError, AgentAlreadyRevokedError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"agent_id": record.agent_id, "status": record.status.value}


# ----------------------------------------------------------------------
# Just-in-time privilege elevation (§4b / §9.8) -- dynamic privilege
# scoping: grant one agent one tool it wouldn't otherwise have, for a
# bounded time, with no separate step to revert it -- it just stops
# working once expired or explicitly revoked.
# ----------------------------------------------------------------------
def _elevation_response(grant: ElevationGrant, *, now: dt.datetime) -> ElevationGrantResponse:
    allowlist = grant.scope.resource_allowlist()
    return ElevationGrantResponse(
        grant_id=grant.grant_id,
        agent_id=grant.agent_id,
        tool=grant.scope.tool,
        resource_ids=sorted(allowlist) if allowlist is not None else None,
        reason=grant.reason,
        granted_by=grant.granted_by,
        granted_at=grant.granted_at.isoformat(),
        expires_at=grant.expires_at.isoformat(),
        revoked_at=grant.revoked_at.isoformat() if grant.revoked_at else None,
        revoked_reason=grant.revoked_reason,
        status=grant.status(now),
    )


@app.post("/admin/elevation/grant", response_model=ElevationGrantResponse)
def admin_grant_elevation(
    body: ElevationGrantRequest, state: AppState = Depends(get_state)
) -> ElevationGrantResponse:
    try:
        grant = state.guard.grant_elevation(
            agent_id=body.agent_id,
            tool=body.tool,
            resource_ids=body.resource_ids,
            reason=body.reason,
            granted_by=body.granted_by,
            ttl=dt.timedelta(seconds=body.ttl_seconds),
        )
    except UnknownAgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, ElevationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _elevation_response(grant, now=dt.datetime.now(dt.timezone.utc))


@app.post("/admin/elevation/{grant_id}/revoke", response_model=ElevationGrantResponse)
def admin_revoke_elevation(
    grant_id: str, body: ElevationRevokeRequest, state: AppState = Depends(get_state)
) -> ElevationGrantResponse:
    try:
        grant = state.guard.revoke_elevation(grant_id, reason=body.reason)
    except ElevationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _elevation_response(grant, now=dt.datetime.now(dt.timezone.utc))


@app.get("/admin/elevation", response_model=ElevationListResponse)
def admin_list_elevations(
    agent_id: Optional[str] = None, state: AppState = Depends(get_state)
) -> ElevationListResponse:
    now = dt.datetime.now(dt.timezone.utc)
    store = state.guard.elevation
    grants = store.for_agent(agent_id) if agent_id else store.all_grants()
    return ElevationListResponse(grants=[_elevation_response(g, now=now) for g in grants])


# ----------------------------------------------------------------------
# Audit and status
# ----------------------------------------------------------------------
@app.get("/audit/verify", response_model=AuditVerifyResponse)
def audit_verify(state: AppState = Depends(get_state)) -> AuditVerifyResponse:
    entries = state.guard.audit.entries()
    try:
        state.guard.audit.verify_chain()
    except AuditIntegrityError as exc:
        return AuditVerifyResponse(intact=False, entry_count=len(entries), detail=str(exc))
    return AuditVerifyResponse(intact=True, entry_count=len(entries))


@app.get("/audit/{agent_id}", response_model=list[AuditEntryResponse])
def audit_for_agent(agent_id: str, state: AppState = Depends(get_state)) -> list[AuditEntryResponse]:
    entries = state.guard.audit.entries_for_agent(agent_id)
    return [
        AuditEntryResponse(
            seq=e.seq,
            timestamp=e.timestamp.isoformat(),
            agent_id=e.agent_id,
            role=e.role,
            action=e.action,
            decision=e.decision,
            reason=e.reason,
            resource_id=e.resource_id,
            request_jti=e.request_jti,
        )
        for e in entries
    ]


@app.get("/agents", response_model=list[AgentStatusResponse])
def list_agents(state: AppState = Depends(get_state)) -> list[AgentStatusResponse]:
    return [
        AgentStatusResponse(
            agent_id=r.agent_id,
            display_name=r.display_name,
            role=r.role,
            tier=r.tier.value,
            status=r.status.value,
            current_serial=r.current_serial,
            current_not_after=r.current_not_after.isoformat(),
        )
        for r in state.registry.list_agents()
    ]


@app.get("/agents/{agent_id}", response_model=AgentStatusResponse)
def agent_status(agent_id: str, state: AppState = Depends(get_state)) -> AgentStatusResponse:
    try:
        record = state.registry.get(agent_id)
    except UnknownAgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return AgentStatusResponse(
        agent_id=record.agent_id,
        display_name=record.display_name,
        role=record.role,
        tier=record.tier.value,
        status=record.status.value,
        current_serial=record.current_serial,
        current_not_after=record.current_not_after.isoformat(),
    )


@app.get("/agents/{agent_id}/identity", response_model=AgentIdentityResponse)
def agent_identity(agent_id: str, state: AppState = Depends(get_state)) -> AgentIdentityResponse:
    """Return an agent's current PKI identity: its live certificate (PEM),
    thumbprint, and serial, straight from the CA's own ledger — not a
    copy the registry might drift from. This is the operator-facing
    counterpart to what the agent itself already received back from
    ``POST /enroll``: a way to look an already-enrolled agent's identity
    up later (e.g. to hand a re-deployed agent process its certificate
    again, or to confirm what a specific agent_id is actually presenting
    on the wire) without re-enrolling it, which would mint a new identity.
    """
    try:
        record = state.registry.get(agent_id)
    except UnknownAgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    cert_record = state.ca.record_for(record.current_serial)
    if cert_record is None:
        raise HTTPException(
            status_code=404,
            detail=f"no CA ledger entry for serial {record.current_serial}",
        )

    return AgentIdentityResponse(
        agent_id=record.agent_id,
        subject_cn=f"agent:{record.agent_id}",
        role=record.role,
        tier=record.tier.value,
        status=record.status.value,
        serial_number=record.current_serial,
        sha256_thumbprint=cert_record["thumbprint"],
        not_after=record.current_not_after.isoformat(),
        revoked=cert_record["revoked"],
        certificate_pem=cert_record["cert_pem"].decode("utf-8")
        if isinstance(cert_record["cert_pem"], bytes)
        else cert_record["cert_pem"],
    )


# ----------------------------------------------------------------------
# Inventory & Posture (Blocks 7-11)
# ----------------------------------------------------------------------
@app.post("/inventory/scan", response_model=list[ScanResultItem])
def inventory_scan(body: ScanRequest, state: AppState = Depends(get_state)) -> list[ScanResultItem]:
    try:
        snapshots = state.run_scan(body.connector_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown connector_id {exc}") from exc
    return [
        ScanResultItem(
            connector_id=s.connector_id,
            taken_at=s.taken_at.isoformat(),
            apps=len(s.apps),
            agents=len(s.agents),
            users=len(s.users),
            permissions=len(s.permissions),
        )
        for s in snapshots
    ]


@app.get("/inventory/apps", response_model=list[AppSummary])
def inventory_apps(state: AppState = Depends(get_state)) -> list[AppSummary]:
    out = []
    for connector_id, snapshot in state.inventory.all_latest().items():
        for app_ in snapshot.apps:
            out.append(
                AppSummary(
                    connector_id=connector_id,
                    app_id=app_.app_id,
                    name=app_.name,
                    category=app_.category,
                    vendor=app_.vendor,
                )
            )
    return out


@app.get("/inventory/agents", response_model=list[AgentSummary])
def inventory_agents(state: AppState = Depends(get_state)) -> list[AgentSummary]:
    shadow_by_key = {
        (f.connector_id, f.external_ref): f
        for f in detect_shadow_agents(inventory=state.inventory, registry=state.registry)
    }
    out = []
    for connector_id, snapshot in state.inventory.all_latest().items():
        for agent in snapshot.agents:
            shadow_finding = shadow_by_key.get((connector_id, agent.external_ref))
            out.append(
                AgentSummary(
                    connector_id=connector_id,
                    app_id=agent.app_id,
                    external_ref=agent.external_ref,
                    name=agent.name,
                    agent_type=agent.agent_type,
                    scopes=list(agent.scopes),
                    owner=agent.owner,
                    last_active_at=agent.last_active_at.isoformat() if agent.last_active_at else None,
                    shadow=shadow_finding is not None,
                    shadow_reason=shadow_finding.reason.value if shadow_finding else None,
                    shadow_severity=shadow_finding.severity.value if shadow_finding else None,
                )
            )
    return out


@app.get("/inventory/shadow", response_model=list[ShadowFindingResponse])
def inventory_shadow(state: AppState = Depends(get_state)) -> list[ShadowFindingResponse]:
    findings = detect_shadow_agents(inventory=state.inventory, registry=state.registry)
    return [
        ShadowFindingResponse(
            connector_id=f.connector_id,
            app_id=f.app_id,
            external_ref=f.external_ref,
            agent_name=f.agent_name,
            agent_type=f.agent_type,
            scopes=f.scopes,
            reason=f.reason.value,
            severity=f.severity.value,
            matched_agent_id=f.matched_agent_id,
        )
        for f in findings
    ]


@app.get("/inventory/posture", response_model=list[PostureFindingResponse])
def inventory_posture(state: AppState = Depends(get_state)) -> list[PostureFindingResponse]:
    findings = []
    for connector_id, snapshot in state.inventory.all_latest().items():
        findings.extend(scan_snapshot(snapshot))
        diff = state.inventory.drift_since_previous(connector_id)
        if diff is not None:
            findings.extend(scan_drift(diff))
    return [
        PostureFindingResponse(
            connector_id=f.connector_id,
            app_id=f.app_id,
            rule_id=f.rule_id,
            severity=f.severity.value,
            object_ref=f.object_ref,
            summary=f.summary,
            remediation=f.remediation,
        )
        for f in findings
    ]


@app.get("/detection/risk-history", response_model=RiskHistoryResponse)
def detection_risk_history(state: AppState = Depends(get_state)) -> RiskHistoryResponse:
    """Every enrolled agent's (timestamp, risk_score) series, oldest
    first per agent — one call for the console's "Agents risk score"
    chart (§8) instead of one round trip per agent. Only agents the
    Detection Engine has actually scored at least once appear; a
    just-enrolled agent that has never called a tool is omitted rather
    than shown with an empty series.

    Registered ABOVE the "/detection/{agent_id}" route below: a
    parameterized path segment matches "risk-history" just like any
    other agent_id, so the more specific literal route has to come
    first or this endpoint is unreachable."""
    histories = state.detection.all_risk_histories()
    agents_by_id = {r.agent_id: r for r in state.registry.list_agents()}
    agents = []
    for agent_id, points in histories.items():
        if not points:
            continue
        record = agents_by_id.get(agent_id)
        agents.append(
            AgentRiskHistoryResponse(
                agent_id=agent_id,
                display_name=record.display_name if record else agent_id,
                role=record.role if record else "unknown",
                status=record.status.value if record else "unknown",
                points=points,
            )
        )
    return RiskHistoryResponse(agents=agents)


@app.get("/detection/{agent_id}", response_model=BaselineSummaryResponse)
def detection_baseline(agent_id: str, state: AppState = Depends(get_state)) -> BaselineSummaryResponse:
    return BaselineSummaryResponse(**state.detection.baseline_summary(agent_id))


@app.post("/admin/detection/threshold")
def set_detection_threshold(
    body: DetectionThresholdRequest, state: AppState = Depends(get_state)
) -> dict:
    try:
        state.guard.set_auto_contain_threshold(body.threshold)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"auto_contain_threshold": body.threshold}


@app.get("/admin/detection/intent", response_model=IntentStatusResponse)
def detection_intent_status(state: AppState = Depends(get_state)) -> IntentStatusResponse:
    """Operator-facing status for the §8.5 intent-conformance signal:
    which mode is armed (off/mock/clm), the sensitivity floor, and
    failure counters — so a scorer that's silently fail-opening on
    every call (bad OBSERVABLE_CLM_URL, expired key) is visible instead
    of just quietly contributing nothing to every risk_score."""
    checker = state.detection.intent_checker
    if checker is None:
        return IntentStatusResponse(
            mode="off", enabled=False, min_sensitivity="medium", calls=0, failures=0, last_error=None
        )
    return IntentStatusResponse(**checker.stats())


@app.get("/compliance/report", response_model=ComplianceReportResponse)
def compliance_report(
    framework: str = "zta", state: AppState = Depends(get_state)
) -> ComplianceReportResponse:
    """``framework=zta`` (default) runs the §9.1 control set mapped to
    ARCHITECTURE.md §5's Zero Trust for AI Agents guide rows.
    ``framework=nist-ai-rmf`` runs the §9.5 control set mapped to NIST
    AI RMF 1.0 GOVERN/MAP/MEASURE/MANAGE subcategories instead — same
    live instance, same ComplianceContext, a different lens over it."""
    if framework not in ("zta", "nist-ai-rmf"):
        raise HTTPException(
            status_code=400,
            detail=f"unknown framework {framework!r}; expected 'zta' or 'nist-ai-rmf'",
        )
    ctx = ComplianceContext(
        registry=state.registry,
        policy_engine=state.policy_engine,
        audit=state.guard.audit,
        inventory=state.inventory,
        guard=state.guard,
        impact_register=state.impact_register,
        detection=state.detection,
    )
    controls = NIST_AI_RMF_CONTROLS if framework == "nist-ai-rmf" else None
    report = generate_report(ctx) if controls is None else generate_report(ctx, controls=controls)
    return ComplianceReportResponse(
        framework=framework,
        generated_at=report.generated_at.isoformat(),
        overall_status=report.overall_status.value,
        counts=report.counts,
        results=[
            ControlResultResponse(
                control_id=r.control_id,
                title=r.title,
                guide_tier=getattr(r.guide_tier, "value", r.guide_tier),
                status=r.status.value,
                summary=r.summary,
                evidence=r.evidence,
            )
            for r in report.results
        ],
    )


def _impact_entry_response(entry) -> ImpactEntryResponse:
    return ImpactEntryResponse(
        entry_id=entry.entry_id,
        title=entry.title,
        category=entry.category.value,
        affected_parties=entry.affected_parties,
        description=entry.description,
        severity=entry.severity.value,
        likelihood=entry.likelihood.value,
        status=entry.status.value,
        mitigation=entry.mitigation,
        related_component=entry.related_component,
        created_at=entry.created_at.isoformat(),
        updated_at=entry.updated_at.isoformat(),
    )


@app.get("/compliance/impact-register", response_model=ImpactRegisterResponse)
def get_impact_register(state: AppState = Depends(get_state)) -> ImpactRegisterResponse:
    """NIST AI RMF MAP 5 (§9.5): every impact to individuals, groups,
    organizations, or society this deployment has characterized so
    far — including the reflexive entries for Observable's own
    detection/intent-conformance components, seeded at startup."""
    entries = state.impact_register.list()
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.status.value] = counts.get(entry.status.value, 0) + 1
    return ImpactRegisterResponse(
        counts=counts, entries=[_impact_entry_response(e) for e in entries]
    )


@app.post("/compliance/impact-register", response_model=ImpactEntryResponse)
def add_impact_entry(
    body: ImpactEntryRequest, state: AppState = Depends(get_state)
) -> ImpactEntryResponse:
    try:
        entry = state.impact_register.add(
            title=body.title,
            category=body.category,
            affected_parties=body.affected_parties,
            description=body.description,
            severity=body.severity,
            likelihood=body.likelihood,
            mitigation=body.mitigation,
            related_component=body.related_component,
            status=body.status,
        )
    except ImpactRegisterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _impact_entry_response(entry)


@app.post("/compliance/impact-register/{entry_id}/status", response_model=ImpactEntryResponse)
def update_impact_entry_status(
    entry_id: str, body: ImpactStatusUpdateRequest, state: AppState = Depends(get_state)
) -> ImpactEntryResponse:
    try:
        entry = state.impact_register.update_status(
            entry_id, body.status, mitigation=body.mitigation
        )
    except ImpactRegisterError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _impact_entry_response(entry)


@app.get("/export/siem")
def export_siem(format: str = "cef", state: AppState = Depends(get_state)) -> PlainTextResponse:
    entries = state.guard.audit.entries()
    if format == "cef":
        return PlainTextResponse(export_audit_cef(entries), media_type="text/plain")
    if format == "json":
        return PlainTextResponse(export_audit_json_lines(entries), media_type="application/x-ndjson")
    raise HTTPException(status_code=400, detail=f"unknown format {format!r}; expected 'cef' or 'json'")


@app.get("/export/soar/incidents", response_model=list[SoarIncidentResponse])
def export_soar_incidents(state: AppState = Depends(get_state)) -> list[SoarIncidentResponse]:
    incidents = build_incidents_from_audit(state.guard.audit.entries())
    return [SoarIncidentResponse(**doc) for doc in export_incidents_json(incidents)]


@app.get("/inventory/drift/{connector_id}", response_model=DriftResponse)
def inventory_drift(connector_id: str, state: AppState = Depends(get_state)) -> DriftResponse:
    diff = state.inventory.drift_since_previous(connector_id)
    if diff is None:
        raise HTTPException(
            status_code=404,
            detail=f"no drift available for {connector_id!r} (need at least two scans)",
        )
    return DriftResponse(
        connector_id=diff.connector_id,
        old_taken_at=diff.old_taken_at,
        new_taken_at=diff.new_taken_at,
        has_changes=diff.has_changes,
        apps_added=diff.apps_added,
        apps_removed=diff.apps_removed,
        agents_added=diff.agents_added,
        agents_removed=diff.agents_removed,
        users_added=diff.users_added,
        users_removed=diff.users_removed,
        permissions_added=[list(p) for p in diff.permissions_added],
        permissions_removed=[list(p) for p in diff.permissions_removed],
    )
