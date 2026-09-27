"""
Block 2 — Identity Registry.

Owns the agent lifecycle: enrollment (one-time, operator-approved),
certificate issuance/renewal via the pluggable CA, and the
active/suspended/revoked state machine that Agent Guard consults on
every request in addition to raw certificate validity.

Why a registry state *in addition to* certificate status: revoking a
certificate is the hard stop (new mTLS handshakes fail outright), but
suspension is the fast, reversible lever — an operator (or an automated
containment trigger, see Block 5) can suspend an agent in milliseconds
without going through the CA at all, and reinstate it just as fast if the
trigger turns out to be a false positive. Revocation is for confirmed
compromise; suspension is for "stop this agent while we look."
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import threading
import uuid
from typing import Optional

from observable.pki.interface import (
    AttestationEvidence,
    CertificateAuthority,
    CertificateStatus,
    CertificateTier,
    IssuedCertificate,
    RevocationReason,
)


class AgentStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class IdentityError(Exception):
    """Base error for identity registry operations."""


class UnknownAgentError(IdentityError):
    pass


class AgentAlreadyRevokedError(IdentityError):
    pass


class DuplicateEnrollmentError(IdentityError):
    pass


@dataclasses.dataclass
class AgentRecord:
    agent_id: str
    display_name: str
    role: str
    tier: CertificateTier
    enrolled_by: str
    status: AgentStatus
    created_at: dt.datetime
    current_serial: str
    current_thumbprint: str
    current_not_after: dt.datetime
    certificate_history: list[str] = dataclasses.field(default_factory=list)
    suspended_reason: Optional[str] = None
    revoked_reason: Optional[RevocationReason] = None
    external_ref: Optional[str] = None
    """Stable identifier of this agent as it appears in a SaaS tenant
    (e.g. a Salesforce Agentforce bot ID). Optional: most agents are
    Observable-native and have no SaaS-side counterpart. Set at enrollment
    when an operator is linking Observable identity to a SaaS-discovered
    agent found by the Inventory plane (Block 9)."""


@dataclasses.dataclass(frozen=True)
class EnrollmentResult:
    record: AgentRecord
    certificate: IssuedCertificate


class IdentityRegistry:
    """In-memory identity registry backed by a pluggable
    ``CertificateAuthority``. A production deployment would back
    ``_agents`` with a durable store (Postgres, etc.); the interface here
    is what the rest of Observable depends on, so swapping storage is a
    contained change.
    """

    def __init__(self, ca: CertificateAuthority) -> None:
        self._ca = ca
        self._lock = threading.RLock()
        self._agents: dict[str, AgentRecord] = {}
        self._names_in_use: set[str] = set()

    # ------------------------------------------------------------------
    def enroll(
        self,
        *,
        display_name: str,
        role: str,
        tier: CertificateTier,
        public_key_pem: bytes,
        enrolled_by: str,
        attestation: Optional[AttestationEvidence] = None,
        san_uris: Optional[list[str]] = None,
        external_ref: Optional[str] = None,
    ) -> EnrollmentResult:
        """One-time enrollment of a new agent instance. Always mints a
        fresh UUID — identities are never recycled, so a retired agent's
        ID can never be reassigned to a different piece of software
        later (ARCHITECTURE.md: "unique agent IDs, never reused")."""
        with self._lock:
            if display_name in self._names_in_use:
                raise DuplicateEnrollmentError(
                    f"display name {display_name!r} is already enrolled; "
                    "enroll a distinct instance name or renew the existing agent"
                )

            agent_id = str(uuid.uuid4())
            issued = self._ca.issue(
                agent_id=agent_id,
                role=role,
                tier=tier,
                public_key_pem=public_key_pem,
                san_uris=san_uris,
                attestation=attestation,
            )
            record = AgentRecord(
                agent_id=agent_id,
                display_name=display_name,
                role=role,
                tier=tier,
                enrolled_by=enrolled_by,
                status=AgentStatus.ACTIVE,
                created_at=dt.datetime.now(dt.timezone.utc),
                current_serial=issued.serial_number,
                current_thumbprint=issued.sha256_thumbprint,
                current_not_after=issued.not_after,
                certificate_history=[issued.serial_number],
                external_ref=external_ref,
            )
            self._agents[agent_id] = record
            self._names_in_use.add(display_name)
            return EnrollmentResult(record=record, certificate=issued)

    def renew(self, agent_id: str) -> IssuedCertificate:
        with self._lock:
            record = self._require(agent_id)
            if record.status == AgentStatus.REVOKED:
                raise AgentAlreadyRevokedError(agent_id)
            issued = self._ca.renew(record.current_serial)
            record.current_serial = issued.serial_number
            record.current_thumbprint = issued.sha256_thumbprint
            record.current_not_after = issued.not_after
            record.certificate_history.append(issued.serial_number)
            return issued

    def suspend(self, agent_id: str, reason: str) -> AgentRecord:
        """Fast, reversible block. Does not touch the CA."""
        with self._lock:
            record = self._require(agent_id)
            if record.status == AgentStatus.REVOKED:
                raise AgentAlreadyRevokedError(agent_id)
            record.status = AgentStatus.SUSPENDED
            record.suspended_reason = reason
            return record

    def reinstate(self, agent_id: str) -> AgentRecord:
        with self._lock:
            record = self._require(agent_id)
            if record.status == AgentStatus.REVOKED:
                raise AgentAlreadyRevokedError(agent_id)
            record.status = AgentStatus.ACTIVE
            record.suspended_reason = None
            return record

    def revoke(
        self,
        agent_id: str,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ) -> AgentRecord:
        """Terminal. Revokes the current certificate at the CA and marks
        the agent permanently revoked. A revoked agent can never be
        reinstated; re-enroll a new agent identity instead."""
        with self._lock:
            record = self._require(agent_id)
            if record.status == AgentStatus.REVOKED:
                return record
            self._ca.revoke(record.current_serial, reason=reason)
            record.status = AgentStatus.REVOKED
            record.revoked_reason = reason
            return record

    # ------------------------------------------------------------------
    def get(self, agent_id: str) -> AgentRecord:
        with self._lock:
            return self._require(agent_id)

    def is_active(self, agent_id: str) -> bool:
        """True only if the registry considers the agent ACTIVE *and*
        the CA still considers its current certificate valid. Guard
        should still separately check the specific certificate serial
        presented on the connection (see Block 5) — this is the coarse,
        registry-level check."""
        with self._lock:
            try:
                record = self._require(agent_id)
            except UnknownAgentError:
                return False
            if record.status != AgentStatus.ACTIVE:
                return False
            return self._ca.status(record.current_serial).status == CertificateStatus.VALID

    def list_agents(self) -> list[AgentRecord]:
        with self._lock:
            return list(self._agents.values())

    def find_by_external_ref(self, external_ref: str) -> Optional[AgentRecord]:
        """Used by the Shadow AI detector (Block 9) to check whether a
        SaaS-discovered agent has a matching Observable identity at all."""
        with self._lock:
            for record in self._agents.values():
                if record.external_ref == external_ref:
                    return record
            return None

    # ------------------------------------------------------------------
    def _require(self, agent_id: str) -> AgentRecord:
        record = self._agents.get(agent_id)
        if record is None:
            raise UnknownAgentError(agent_id)
        return record
