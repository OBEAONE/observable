"""
Block N — Impact Register (NIST AI RMF MAP 5).

NIST AI RMF 1.0's MAP function asks that "impacts to individuals,
groups, communities, organizations, and society" be characterized
(MAP 5.1) and that third-party impacts get the same treatment
(MAP 5.2) — not once, in a document that goes stale, but as something
an operator actually keeps current. This is a small, structured,
queryable register for exactly that: who could be affected, how
severely, how likely, what mitigates it, and whether that mitigation
is actually in place today or still an open gap.

Two things this register is deliberately built to make visible rather
than paper over:

* **Reflexive governance.** Observable's own Detection Engine (§8) and
  its intent-conformance signal (§8.5) are themselves statistical/AI
  components making decisions that feed an authorization boundary —
  they are "AI systems" under the guide's own definition, not just
  the agents Observable monitors. ``seed_reflexive_governance_entries``
  records the impacts of Observable's own detection plane, so this
  register documents the platform's own footprint, not only its
  customers' agents.
* **Honesty over a green checklist.** An entry left ``OPEN`` with no
  mitigation is not a bug in this module — it is the register doing
  its job. The NIST AI RMF compliance-report mode (§9.5) reads this
  register's actual state rather than assuming every listed impact has
  been handled.

This is in-memory, like ``InventoryStore`` and the audit chain in this
reference deployment — re-seeded on restart, with a durable backing
store an additive change for a production deployment (see
ARCHITECTURE.md §9.5 and the "no persistence layer yet" note in
README.md).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import uuid
from typing import Optional, Union


class ImpactCategory(str, enum.Enum):
    PRIVACY = "privacy"
    FAIRNESS = "fairness"
    SECURITY = "security"
    SAFETY = "safety"
    THIRD_PARTY = "third_party"
    TRANSPARENCY = "transparency"


class ImpactSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    ImpactSeverity.LOW: 0,
    ImpactSeverity.MEDIUM: 1,
    ImpactSeverity.HIGH: 2,
    ImpactSeverity.CRITICAL: 3,
}


class ImpactLikelihood(str, enum.Enum):
    RARE = "rare"
    POSSIBLE = "possible"
    LIKELY = "likely"


class ImpactStatus(str, enum.Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


class ImpactRegisterError(Exception):
    pass


@dataclasses.dataclass
class ImpactEntry:
    entry_id: str
    title: str
    category: ImpactCategory
    affected_parties: list[str]
    description: str
    severity: ImpactSeverity
    likelihood: ImpactLikelihood
    status: ImpactStatus
    mitigation: Optional[str]
    related_component: Optional[str]
    created_at: dt.datetime
    updated_at: dt.datetime


def _coerce(enum_cls, value):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in enum_cls)
        raise ImpactRegisterError(f"invalid {enum_cls.__name__}: {value!r} (allowed: {allowed})") from exc


class ImpactRegister:
    """One process-wide register of characterized impacts. Read
    methods never mutate; ``add``/``update_status`` are the only
    writers, matching the same read/write separation the Detection
    Engine (§8.1) and Inventory Store (§7) already use."""

    def __init__(self) -> None:
        self._entries: dict[str, ImpactEntry] = {}

    def add(
        self,
        *,
        title: str,
        category: Union[ImpactCategory, str],
        affected_parties: list[str],
        description: str,
        severity: Union[ImpactSeverity, str],
        likelihood: Union[ImpactLikelihood, str],
        mitigation: Optional[str] = None,
        related_component: Optional[str] = None,
        status: Union[ImpactStatus, str] = ImpactStatus.OPEN,
    ) -> ImpactEntry:
        now = dt.datetime.now(dt.timezone.utc)
        entry = ImpactEntry(
            entry_id=str(uuid.uuid4()),
            title=title,
            category=_coerce(ImpactCategory, category),
            affected_parties=list(affected_parties),
            description=description,
            severity=_coerce(ImpactSeverity, severity),
            likelihood=_coerce(ImpactLikelihood, likelihood),
            status=_coerce(ImpactStatus, status),
            mitigation=mitigation,
            related_component=related_component,
            created_at=now,
            updated_at=now,
        )
        self._entries[entry.entry_id] = entry
        return entry

    def get(self, entry_id: str) -> Optional[ImpactEntry]:
        return self._entries.get(entry_id)

    def list(self) -> list[ImpactEntry]:
        return sorted(self._entries.values(), key=lambda e: e.created_at)

    def update_status(
        self,
        entry_id: str,
        status: Union[ImpactStatus, str],
        *,
        mitigation: Optional[str] = None,
    ) -> ImpactEntry:
        entry = self._entries.get(entry_id)
        if entry is None:
            raise ImpactRegisterError(f"no impact entry with id {entry_id!r}")
        entry.status = _coerce(ImpactStatus, status)
        if mitigation is not None:
            entry.mitigation = mitigation
        entry.updated_at = dt.datetime.now(dt.timezone.utc)
        return entry

    def open_unmitigated_at_or_above(self, min_severity: ImpactSeverity) -> list[ImpactEntry]:
        """Entries a NIST AI RMF MAP 5.1 check should flag: still
        ``OPEN`` (neither mitigated nor knowingly accepted) and at or
        above the given severity."""
        floor = _SEVERITY_ORDER[min_severity]
        return [
            e
            for e in self.list()
            if e.status == ImpactStatus.OPEN and _SEVERITY_ORDER[e.severity] >= floor
        ]


def seed_reflexive_governance_entries(register: ImpactRegister) -> None:
    """Populates the register with impacts identified while aligning
    this codebase with the NIST AI RMF (see ARCHITECTURE.md §9.5):
    Observable's own detection/intent-conformance components are
    "AI systems" under the guide's definition too, so their impacts are
    characterized here rather than left implicit."""
    register.add(
        title="Detection Engine false positive blocks legitimate agent work",
        category=ImpactCategory.SAFETY,
        affected_parties=["Enrolled agents", "Business teams relying on agent output"],
        description=(
            "The statistical detection signals (§8.2) or the intent-conformance "
            "signal (§8.5) can push a legitimate call's risk_score over a "
            "tool's ABAC ceiling, denying a real business action or, if an "
            "auto-containment threshold is configured, suspending a compliant "
            "agent mid-task."
        ),
        severity=ImpactSeverity.MEDIUM,
        likelihood=ImpactLikelihood.LIKELY,
        mitigation=(
            "Every signal is capped and named in the audit reason (never an "
            "opaque denial); SOAR incident export (§9.3) surfaces every "
            "automated containment for human review; an operator can "
            "reinstate immediately via /admin/agents/{id}/reinstate."
        ),
        related_component="observable/detection (§8, §8.5)",
        status=ImpactStatus.MITIGATED,
    )
    register.add(
        title="Intent-conformance CLM scorer may reflect training-data bias or blind spots",
        category=ImpactCategory.FAIRNESS,
        affected_parties=[
            "Agents whose declared purpose uses uncommon phrasing",
            "Non-English-first teams",
        ],
        description=(
            "CLMIntentScorer (§8.5) judges purpose-to-tool fit with a frozen "
            "language model. An agent whose operator writes purposes in a "
            "style or language distant from the model's training "
            "distribution may accumulate more intent_mismatch signals than "
            "an equivalent agent using more \"typical\" phrasing — a "
            "consistency/fairness risk MAP 5.1 asks to be named, not just "
            "accepted by default."
        ),
        severity=ImpactSeverity.MEDIUM,
        likelihood=ImpactLikelihood.POSSIBLE,
        mitigation=(
            "Capped at 0.5 contribution so it alone can never deny a tool "
            "above that ceiling; off by default; explicitly flagged in "
            "§8.6 as zero-shot and not yet validated against a live model, "
            "pending fine-tuning on Observable's own labelled audit history."
        ),
        related_component="observable/detection/intent.py (§8.5, §8.6)",
        status=ImpactStatus.OPEN,
    )
    register.add(
        title="Observable's own detection plane is an AI system under the guide's definition",
        category=ImpactCategory.TRANSPARENCY,
        affected_parties=["Security operators", "Auditors", "Enrolled agents' own stakeholders"],
        description=(
            "The Detection Engine (§8) and intent-conformance signal (§8.5) "
            "make statistical/model-derived decisions that feed an "
            "authorization boundary. NIST AI RMF's GOVERN/MAP categories "
            "apply reflexively to Observable's own detection plane, not "
            "only to the agents it monitors — a governance point this "
            "architecture document did not previously state explicitly."
        ),
        severity=ImpactSeverity.LOW,
        likelihood=ImpactLikelihood.LIKELY,
        mitigation=(
            "This register and the NIST AI RMF compliance-report mode "
            "(§9.5) are the explicit acknowledgement: every detection/"
            "intent control is itself listed and checked, and every "
            "signal is capped, explainable, and independently auditable."
        ),
        related_component="observable/detection (§8, §8.5); observable/compliance (§9.1, §9.5)",
        status=ImpactStatus.MITIGATED,
    )
    register.add(
        title="Downstream SaaS tenant is not notified when a connected agent is contained",
        category=ImpactCategory.THIRD_PARTY,
        affected_parties=[
            "End customers of the monitored SaaS tenant",
            "The tenant's own support/operations teams",
        ],
        description=(
            "Automated containment (§8.1) suspends the agent's Observable "
            "identity and tokens, but nothing in this reference deployment "
            "notifies the SaaS tenant's own operators that one of its AI "
            "agents just stopped working mid-task — a third-party impact "
            "MAP 5.2 calls out separately from the direct-agent case above."
        ),
        severity=ImpactSeverity.MEDIUM,
        likelihood=ImpactLikelihood.POSSIBLE,
        mitigation=None,
        related_component="observable/guard/gateway.py (contain_agent); observable/export/soar.py",
        status=ImpactStatus.OPEN,
    )
