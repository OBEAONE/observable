"""
Block 5 — Agent Guard gateway.

This is the single door every agent action goes through
(ARCHITECTURE.md §6): PoP verification -> scope check -> input
sanitization -> ABAC re-authorization -> tool invocation -> output
filtering -> audit. Every one of those steps writes to the audit chain,
allow or deny, so "what did this agent try to do" is always answerable
even for denied attempts.

Automated containment (suspend an agent, killing every outstanding
token within one verify() call) is exposed here two ways: an explicit
call (from an operator, or from an upstream system) via
``contain_agent``, and an optional ``auto_contain_threshold`` that, once
set, executes containment the instant the Detection Engine's live
risk_score for an agent crosses it. That threshold is itself an explicit
decision an operator makes when configuring Observable — Agent Guard never
picks the threshold or decides an agent is malicious on its own
judgment. This is exactly the guide's rule: "automate the bookkeeping
around incidents, not the decisions" — the decision (what risk level is
intolerable) is human and made in advance; crossing it is mechanically
enforced.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Callable, Optional

from observable.detection.engine import DetectionEngine
from observable.detection.scorer import RiskAssessment
from observable.guard.audit import AuditChain, AuditEntry
from observable.guard.sanitize import filter_output, sanitize_input
from observable.identity.registry import AgentRecord, IdentityRegistry
from observable.pki.interface import RevocationReason
from observable.pki.validate import CertificateValidationError, leaf_thumbprint
from observable.policy.engine import ActionContext, PolicyEngine
from observable.tokens.scope import Scope
from observable.tokens.service import TokenError, TokenService

# A tool invoker takes the sanitized payload and an optional resource id
# and returns a JSON-serializable result dict. Registered per tool name
# by whoever wires up Observable (see Block 6's demo for examples).
ToolInvoker = Callable[[dict, Optional[str]], dict]


class GuardError(Exception):
    pass


class GuardDeniedError(GuardError):
    """Raised for any denial — invalid credential, PoP mismatch, scope
    not granted, sanitization failure, ABAC denial, or unregistered
    tool. ``audit_seq`` points at the audit entry that recorded the
    denial, so callers (e.g. the API layer) can surface it."""

    def __init__(self, reason: str, audit_seq: Optional[int] = None):
        super().__init__(reason)
        self.reason = reason
        self.audit_seq = audit_seq


class ToolExecutionError(GuardError):
    """The request was authorized, but the tool invoker itself raised."""

    def __init__(self, reason: str, audit_seq: Optional[int] = None):
        super().__init__(reason)
        self.reason = reason
        self.audit_seq = audit_seq


@dataclasses.dataclass(frozen=True)
class GuardResult:
    allowed: bool
    tool: str
    result: Optional[dict]
    reason: str
    audit_seq: int
    redactions: list[str] = dataclasses.field(default_factory=list)
    risk_score: float = 0.0
    detection_signals: list[str] = dataclasses.field(default_factory=list)
    detection_degraded: bool = False


class AgentGuard:
    def __init__(
        self,
        *,
        registry: IdentityRegistry,
        token_service: TokenService,
        policy_engine: PolicyEngine,
        audit: Optional[AuditChain] = None,
        detection: Optional[DetectionEngine] = None,
        auto_contain_threshold: Optional[float] = None,
    ) -> None:
        self._registry = registry
        self._token_service = token_service
        self._policy_engine = policy_engine
        self.audit = audit or AuditChain()
        self._tools: dict[str, ToolInvoker] = {}
        self._detection = detection
        self._auto_contain_threshold = auto_contain_threshold
        if auto_contain_threshold is not None and detection is None:
            raise ValueError("auto_contain_threshold requires a detection engine")

    def register_tool(self, tool_name: str, invoker: ToolInvoker) -> None:
        self._tools[tool_name] = invoker

    @property
    def auto_contain_threshold(self) -> Optional[float]:
        """Read-only view of the current threshold, for reporting
        (compliance framework, §9) — use ``set_auto_contain_threshold``
        to change it."""
        return self._auto_contain_threshold

    def set_auto_contain_threshold(self, threshold: Optional[float]) -> None:
        """Let an operator turn automated containment on/off, or retune
        it, without rebuilding the whole Guard instance. ``None``
        disables it. This is exactly the "explicit, human-set decision"
        the module docstring describes — changing the number is the
        decision; Guard just keeps enforcing whatever it's currently set
        to."""
        if threshold is not None and self._detection is None:
            raise ValueError("auto_contain_threshold requires a detection engine")
        self._auto_contain_threshold = threshold

    # ------------------------------------------------------------------
    def invoke(
        self,
        *,
        client_cert_pem: bytes,
        token: str,
        tool_name: str,
        payload: dict,
        resource_id: Optional[str] = None,
        extra_risk_score: float = 0.0,
    ) -> GuardResult:
        # 1. Compute the thumbprint of whatever certificate was actually
        #    presented on this connection.
        try:
            presented_thumbprint = leaf_thumbprint(client_cert_pem)
        except CertificateValidationError as exc:
            entry = self._log(
                agent_id=None,
                role=None,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=f"invalid client certificate: {exc}",
                resource_id=resource_id,
                request_jti=None,
            )
            raise GuardDeniedError(str(exc), audit_seq=entry.seq) from exc

        # 2. Verify the token: signature, expiry, PoP binding to the
        #    presented certificate, and that the agent is still active.
        try:
            claims = self._token_service.verify(
                token=token, presented_cert_thumbprint=presented_thumbprint
            )
        except TokenError as exc:
            entry = self._log(
                agent_id=None,
                role=None,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=str(exc),
                resource_id=resource_id,
                request_jti=None,
            )
            raise GuardDeniedError(str(exc), audit_seq=entry.seq) from exc

        # 2.5. Score this event against the agent's live behavioral
        #      baseline, before deciding anything else about it. This is
        #      read-only (doesn't teach the baseline anything yet) so
        #      scoring never depends on the outcome of this same event.
        now = dt.datetime.now(dt.timezone.utc)
        assessment: Optional[RiskAssessment] = None
        if self._detection is not None:
            assessment = self._detection.pre_score(
                agent_id=claims.agent_id,
                tool=tool_name,
                resource_id=resource_id,
                timestamp=now,
                role=claims.role,
                purpose=claims.purpose,
            )
            # Record this sample for the risk-history chart regardless of
            # what happens next (allow, deny, or auto-contain below) — a
            # denied/contained event is exactly the spike that chart
            # exists to surface, not something to skip.
            self._detection.record_risk_score(
                agent_id=claims.agent_id, risk_score=assessment.risk_score, timestamp=now
            )

        # 2.6. Automated containment: if this agent's live risk score has
        #      already crossed the operator-configured threshold, contain
        #      it now and deny this request too, rather than letting it
        #      through and only blocking the *next* one.
        if (
            self._auto_contain_threshold is not None
            and assessment is not None
            and assessment.risk_score >= self._auto_contain_threshold
            and self._registry.is_active(claims.agent_id)
        ):
            self.contain_agent(
                claims.agent_id,
                reason=(
                    f"automated containment: risk_score={assessment.risk_score:.2f} "
                    f">= threshold={self._auto_contain_threshold:.2f}; signals={assessment.signals}"
                ),
            )
            deny_reason = (
                f"agent auto-contained: risk_score {assessment.risk_score:.2f} "
                f"exceeded threshold {self._auto_contain_threshold:.2f}"
            )
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=deny_reason,
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise GuardDeniedError(deny_reason, audit_seq=entry.seq)

        # 3. The token must actually carry a scope for this exact tool.
        matched_scope = next((s for s in claims.scopes if s.tool == tool_name), None)
        if matched_scope is None:
            reason = f"token does not carry a scope for tool {tool_name!r}"
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=reason,
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise GuardDeniedError(reason, audit_seq=entry.seq)

        # 4. Input sanitization, before the payload reaches policy
        #    evaluation or the tool itself.
        sanitization = sanitize_input(payload)
        if not sanitization.clean:
            deny_reason = f"input rejected: {sanitization.reason}"
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=deny_reason,
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise GuardDeniedError(deny_reason, audit_seq=entry.seq)

        # 5. Continuous (ABAC) authorization against live context — this
        #    can deny even a request whose token was validly minted, if
        #    context (time, risk score) has moved since then.
        live_risk_score = max(
            claims.risk_score_at_mint, extra_risk_score, assessment.risk_score if assessment else 0.0
        )
        context = ActionContext(timestamp=now, risk_score=live_risk_score, resource_id=resource_id)
        decision = self._policy_engine.authorize_action(
            role=claims.role, tier=claims.tier, scope=matched_scope, context=context
        )
        if not decision.allowed:
            deny_reason = decision.reason
            if assessment and assessment.signals:
                deny_reason += f"; detection signals: {', '.join(assessment.signals)}"
            if assessment and assessment.detection_degraded:
                deny_reason += f"; {assessment.degraded_reason}"
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=deny_reason,
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise GuardDeniedError(deny_reason, audit_seq=entry.seq)

        # 6. Dispatch to the registered tool invoker.
        invoker = self._tools.get(tool_name)
        if invoker is None:
            reason = f"tool {tool_name!r} has no registered invoker"
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="deny",
                reason=reason,
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise GuardDeniedError(reason, audit_seq=entry.seq)

        try:
            raw_result = invoker(payload, resource_id)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, tool code is untrusted
            entry = self._log(
                agent_id=claims.agent_id,
                role=claims.role,
                action=f"tool:{tool_name}",
                decision="error",
                reason=f"tool invocation raised: {exc}",
                resource_id=resource_id,
                request_jti=claims.jti,
            )
            raise ToolExecutionError(str(exc), audit_seq=entry.seq) from exc

        # 7. Output filtering before the result ever reaches the agent.
        filtered_result, redactions = filter_output(raw_result)

        reason = "authorized"
        if redactions:
            reason += f"; redacted {len(redactions)} sensitive field(s): {', '.join(redactions)}"
        if assessment and assessment.detection_degraded:
            reason += f"; {assessment.degraded_reason}"

        entry = self._log(
            agent_id=claims.agent_id,
            role=claims.role,
            action=f"tool:{tool_name}",
            decision="allow",
            reason=reason,
            resource_id=resource_id,
            request_jti=claims.jti,
        )

        return GuardResult(
            allowed=True,
            tool=tool_name,
            result=filtered_result,
            reason=reason,
            audit_seq=entry.seq,
            redactions=redactions,
            risk_score=live_risk_score,
            detection_signals=assessment.signals if assessment else [],
            detection_degraded=bool(assessment.detection_degraded) if assessment else False,
        )

    # ------------------------------------------------------------------
    # Automated containment (decision stays with the caller; execution
    # is instantaneous and total — see module docstring).
    # ------------------------------------------------------------------
    def contain_agent(self, agent_id: str, reason: str) -> AgentRecord:
        """Suspend the agent immediately. Because Token Service checks
        registry.is_active() on every verify() call (not just at mint),
        this invalidates every outstanding token for the agent within
        this single call — there is no window where a suspended agent's
        existing token keeps working."""
        record = self._registry.suspend(agent_id, reason=reason)
        self._log(
            agent_id=agent_id,
            role=record.role,
            action="containment:suspend",
            decision="action",
            reason=reason,
            resource_id=None,
            request_jti=None,
        )
        return record

    def revoke_agent(self, agent_id: str, reason: RevocationReason) -> AgentRecord:
        """Terminal containment: revokes the certificate at the CA in
        addition to suspending in the registry. Use when compromise is
        confirmed, not just suspected."""
        record = self._registry.revoke(agent_id, reason=reason)
        self._log(
            agent_id=agent_id,
            role=record.role,
            action="containment:revoke",
            decision="action",
            reason=reason.value,
            resource_id=None,
            request_jti=None,
        )
        return record

    def reinstate_agent(self, agent_id: str, reason: str) -> AgentRecord:
        record = self._registry.reinstate(agent_id)
        self._log(
            agent_id=agent_id,
            role=record.role,
            action="containment:reinstate",
            decision="action",
            reason=reason,
            resource_id=None,
            request_jti=None,
        )
        return record

    # ------------------------------------------------------------------
    def _log(
        self,
        *,
        agent_id: Optional[str],
        role: Optional[str],
        action: str,
        decision: str,
        reason: str,
        resource_id: Optional[str],
        request_jti: Optional[str],
    ) -> AuditEntry:
        entry = self.audit.append(
            agent_id=agent_id,
            role=role,
            action=action,
            decision=decision,
            reason=reason,
            resource_id=resource_id,
            request_jti=request_jti,
        )
        # Every tool-call outcome (allow/deny/error) feeds the Detection
        # Engine's baseline for this agent, regardless of which step in
        # invoke() produced it — centralizing this here means every new
        # exit path added to invoke() learns automatically, with nothing
        # to remember to wire up at each call site. Containment actions
        # (action starting with "containment:") are not tool calls and
        # are deliberately excluded from the behavioral baseline.
        if (
            self._detection is not None
            and agent_id is not None
            and action.startswith("tool:")
            and decision in ("allow", "deny", "error")
        ):
            self._detection.record_event(
                agent_id=agent_id,
                tool=action.removeprefix("tool:"),
                resource_id=resource_id,
                decision=decision,
                timestamp=entry.timestamp,
            )
        return entry
