"""
Block 5 — Audit chain.

Every decision Agent Guard makes (allow or deny) is appended here.
Entries are hash-linked (each entry's hash covers the previous entry's
hash) and individually signed with Observable's audit-signing key, so:

* an attacker who gets write access to wherever entries are persisted
  cannot edit or delete a past entry without breaking the hash chain
  from that point forward (tamper-evidence), and
* an attacker who *also* somehow forges new-looking entries still can't
  produce a valid signature without the audit-signing private key.

This satisfies the guide's Enterprise-tier "immutable audit trails with
integrity verification" capability. Streaming to a SIEM and true
append-only storage (Advanced tier) are v2 (ARCHITECTURE.md §7) — this
module gives you the tamper-evidence property in-process, storage-
backend-agnostic (swap ``_entries: list`` for an append-only store without
changing the hashing/signing logic).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import threading
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

GENESIS_HASH = "0" * 64


class AuditError(Exception):
    pass


class AuditIntegrityError(AuditError):
    """Raised by verify_chain() when a hash link or signature doesn't
    check out. Carries the sequence number where the chain first breaks."""

    def __init__(self, message: str, broken_at_seq: int):
        super().__init__(message)
        self.broken_at_seq = broken_at_seq


@dataclasses.dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: dt.datetime
    agent_id: Optional[str]
    role: Optional[str]
    action: str  # e.g. "tool:crm.read" or "containment:suspend"
    decision: str  # "allow" | "deny" | "action"
    reason: str
    resource_id: Optional[str]
    request_jti: Optional[str]
    prev_hash: str
    entry_hash: str
    signature: bytes

    def canonical_body(self) -> bytes:
        """Deterministic bytes covering everything except the hash and
        signature themselves — this is what gets hashed and signed."""
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "role": self.role,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "resource_id": self.resource_id,
            "request_jti": self.request_jti,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditChain:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[AuditEntry] = []
        self._signing_key = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_key_pem(self) -> bytes:
        return self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def append(
        self,
        *,
        agent_id: Optional[str],
        role: Optional[str],
        action: str,
        decision: str,
        reason: str,
        resource_id: Optional[str] = None,
        request_jti: Optional[str] = None,
    ) -> AuditEntry:
        with self._lock:
            seq = len(self._entries)
            prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH

            provisional = AuditEntry(
                seq=seq,
                timestamp=dt.datetime.now(dt.timezone.utc),
                agent_id=agent_id,
                role=role,
                action=action,
                decision=decision,
                reason=reason,
                resource_id=resource_id,
                request_jti=request_jti,
                prev_hash=prev_hash,
                entry_hash="",
                signature=b"",
            )
            entry_hash = hashlib.sha256(provisional.canonical_body()).hexdigest()
            signature = self._signing_key.sign(
                bytes.fromhex(entry_hash), ec.ECDSA(hashes.SHA256())
            )
            final = dataclasses.replace(provisional, entry_hash=entry_hash, signature=signature)
            self._entries.append(final)
            return final

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def entries_for_agent(self, agent_id: str) -> list[AuditEntry]:
        with self._lock:
            return [e for e in self._entries if e.agent_id == agent_id]

    def verify_chain(self) -> None:
        """Walk the whole chain, recomputing each hash and verifying
        each signature and the prev_hash linkage. Raises
        AuditIntegrityError at the first entry that doesn't check out;
        returns None (silently) if the whole chain is intact."""
        with self._lock:
            public_key = self._signing_key.public_key()
            expected_prev = GENESIS_HASH
            for entry in self._entries:
                if entry.prev_hash != expected_prev:
                    raise AuditIntegrityError(
                        f"entry {entry.seq} prev_hash does not match preceding entry",
                        broken_at_seq=entry.seq,
                    )
                recomputed = hashlib.sha256(entry.canonical_body()).hexdigest()
                if recomputed != entry.entry_hash:
                    raise AuditIntegrityError(
                        f"entry {entry.seq} content hash does not match stored hash "
                        "(entry was altered after being written)",
                        broken_at_seq=entry.seq,
                    )
                try:
                    public_key.verify(
                        entry.signature, bytes.fromhex(entry.entry_hash), ec.ECDSA(hashes.SHA256())
                    )
                except InvalidSignature as exc:
                    raise AuditIntegrityError(
                        f"entry {entry.seq} signature does not verify", broken_at_seq=entry.seq
                    ) from exc
                expected_prev = entry.entry_hash
