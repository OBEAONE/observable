"""
Detection Block D — intent-conformance signal (``intent_mismatch``).

The four statistical signals in ``observable.detection.scorer`` see *how*
an agent behaves (pace, novelty, denials) but not *whether an action
makes sense for what the agent is supposed to be doing*. That blind spot
is where the guide's hardest threats live — tool chaining, confused-deputy
relays, indirect prompt injection — because every individual call there
is authorized and statistically unremarkable; only its fit with the
agent's purpose is wrong.

This module asks one question per request: *given this agent's role, its
declared purpose (``req_ctx.purpose``, signed into its token at mint) and
its recent tool calls, is calling this tool consistent with that
purpose?* The answer is a probability ``p_consistent``; a low value
becomes a fifth, noisy-OR-combined detection signal.

Design rules (ARCHITECTURE.md §8.5):

* **Pluggable scorer**, same pattern as ``CertificateAuthority`` and
  ``SaaSConnector``: ``IntentScorer`` is the interface,
  ``MockIntentScorer`` a deterministic keyword stand-in for tests/demos,
  ``CLMIntentScorer`` the adapter for a self-hosted Contrastive Language
  Model server (``clm-serve``, CLM-v0.1-8B on Qwen3-8B). Nothing above the
  interface changes when one is swapped for another.
* **A signal, never a control.** The contribution is capped at
  ``INTENT_MAX_RISK`` so this signal alone can never reach 1.0; it can
  only push an already-suspicious request over a tool's ABAC
  ``max_risk_score`` or an operator's containment threshold. Deny-by-
  default policy, PoP tokens and scopes are unaffected by it.
* **Fail-open, but loudly.** If the scorer is unreachable or errors, the
  request is scored without this signal (the hard controls still apply)
  and the outage is reported as a ``degraded`` note on the assessment,
  the Guard result and ``GET /admin/detection/intent`` — never silently.
* **Explainable output.** The signal label carries the tool, the
  probability, the scorer name and the purpose it was judged against, so
  it can be read in the audit trail like the statistical signals.
"""
from __future__ import annotations

import dataclasses
import re
import threading
import time
from typing import Optional, Protocol, Sequence

import httpx

from observable.policy.bundle import Sensitivity

# --- tunable thresholds -------------------------------------------------
INTENT_CONSISTENT_THRESHOLD = 0.5  # p_consistent at/above this -> no signal
INTENT_MAX_RISK = 0.5  # cap: this signal alone can never exceed this
PURPOSE_LABEL_MAX_CHARS = 60  # purpose is agent-supplied; keep labels short
RECENT_TOOLS_IN_STATE = 5

_SENSITIVITY_ORDER = {Sensitivity.LOW: 0, Sensitivity.MEDIUM: 1, Sensitivity.HIGH: 2}


class IntentScorerError(Exception):
    """Raised by a scorer when it cannot produce an answer (network
    failure, bad response). The checker turns this into a ``degraded``
    note rather than a signal."""


@dataclasses.dataclass(frozen=True)
class IntentQuery:
    """Everything a scorer is allowed to see. Deliberately excludes the
    request payload: this signal judges *which tool* for *which
    purpose*; payload-level analysis (injection, leakage) is a separate
    concern."""

    role: str
    purpose: str
    recent_tools: tuple[str, ...]
    tool_name: str
    tool_description: str


class IntentScorer(Protocol):
    name: str

    def p_consistent(self, query: IntentQuery) -> float:
        """Probability in [0, 1] that calling ``query.tool_name`` is
        consistent with the declared purpose. Raises
        ``IntentScorerError`` if it cannot answer."""
        ...


class ToolCatalog(Protocol):
    """What the checker needs from the policy plane.
    ``observable.policy.engine.PolicyEngine`` implements both methods."""

    def registered_tools(self) -> dict: ...

    def tool_sensitivity(self, tool_name: str): ...


# ----------------------------------------------------------------------
# Scorers
# ----------------------------------------------------------------------
_STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "this", "that", "our", "your",
    "all", "any", "new", "existing", "agent", "record", "records", "data",
}


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3 and t not in _STOPWORDS}


class MockIntentScorer:
    """Deterministic keyword-overlap stand-in for dev, tests and demos.
    It has no semantic understanding: it only checks whether the tool's
    name/description shares words with the declared purpose. It exists
    so the full signal path can be exercised without a GPU, exactly like
    ``ReferenceCA`` and ``MockConnector``. Never use it in production."""

    name = "mock"

    def p_consistent(self, query: IntentQuery) -> float:
        purpose = _tokens(query.purpose)
        tool = _tokens(f"{query.tool_name} {query.tool_description}")
        overlap = len(purpose & tool)
        if overlap == 0:
            return 0.1
        if overlap == 1:
            return 0.6
        return 0.9


class CLMIntentScorer:
    """Adapter for a self-hosted CLM server (``clm-serve`` from the
    ``contrastive-lm`` package, default port 8700). Uses the typed
    ``/v1/systemone`` endpoint with a single yes/no question, which
    returns an absolute probability rather than one relative to a
    candidate set — so legitimate multi-tool workflows are not penalised
    for every tool that isn't the single "best" next move.

    Only standard-library-plus-httpx; no dependency on the CLM package
    or on torch in the Observable process."""

    name = "clm"

    QUESTION_KEY = "intent"
    INSTRUCTIONS = (
        "Is the requested tool call consistent with the agent's role and declared "
        "purpose, given its recent tool calls?"
    )
    CRITERIA = {
        "true": "The requested tool call plausibly serves the declared purpose.",
        "false": (
            "The requested tool call does not fit the declared purpose, for example "
            "moving data to an unrelated or external destination."
        ),
    }

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8700",
        *,
        api_key: Optional[str] = None,
        timeout: float = 2.0,
        model: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._model = model
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def build_request(self, query: IntentQuery) -> dict:
        body: dict = {
            "state": {
                "agent_role": query.role,
                "declared_purpose": query.purpose,
                "recent_tool_calls": list(query.recent_tools),
                "requested_tool": {"name": query.tool_name, "description": query.tool_description},
            },
            "questions": {
                self.QUESTION_KEY: {
                    "type": "noul",
                    "instructions": self.INSTRUCTIONS,
                    "criteria": dict(self.CRITERIA),
                }
            },
        }
        if self._model:
            body["model"] = self._model
        return body

    def p_consistent(self, query: IntentQuery) -> float:
        try:
            response = self._client.post("/v1/systemone", json=self.build_request(query))
        except httpx.HTTPError as exc:
            raise IntentScorerError(f"{type(exc).__name__}: {exc}") from exc
        if response.status_code != 200:
            raise IntentScorerError(f"HTTP {response.status_code}: {response.text[:200]}")
        try:
            value = float(response.json()["answers"][self.QUESTION_KEY]["noul"])
        except (ValueError, KeyError, TypeError) as exc:
            raise IntentScorerError(f"unexpected response shape: {exc}") from exc
        if not 0.0 <= value <= 1.0:
            raise IntentScorerError(f"probability out of range: {value}")
        return value

    def close(self) -> None:
        self._client.close()


# ----------------------------------------------------------------------
# Checker: decides when to ask, turns the answer into a signal
# ----------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class IntentResult:
    risk: float  # 0.0 when no signal
    label: Optional[str]  # set only when the signal fires
    degraded: Optional[str] = None  # set when the scorer could not answer
    p_consistent: Optional[float] = None


_NO_SIGNAL = IntentResult(risk=0.0, label=None)


class IntentChecker:
    def __init__(
        self,
        scorer: IntentScorer,
        catalog: ToolCatalog,
        *,
        min_sensitivity: Optional[Sensitivity] = None,
    ) -> None:
        """``min_sensitivity`` limits which tools are checked (e.g.
        ``Sensitivity.MEDIUM`` skips low-sensitivity reads so a model
        call is only on the hot path where it matters). ``None`` checks
        every registered tool."""
        self.scorer = scorer
        self._catalog = catalog
        self.min_sensitivity = min_sensitivity
        self._lock = threading.Lock()
        self._stats = {
            "checked": 0,
            "fired": 0,
            "skipped_no_purpose": 0,
            "skipped_sensitivity": 0,
            "failures": 0,
        }
        self._last_error: Optional[str] = None
        self._last_latency_ms: Optional[float] = None

    def _bump(self, key: str) -> None:
        with self._lock:
            self._stats[key] += 1

    def check(
        self,
        *,
        role: Optional[str],
        purpose: Optional[str],
        tool: str,
        recent_tools: Sequence[str],
    ) -> IntentResult:
        if not purpose or not role:
            self._bump("skipped_no_purpose")
            return _NO_SIGNAL
        definition = self._catalog.registered_tools().get(tool)
        if definition is None:
            # Unregistered tool: policy denies it anyway (deny-by-default),
            # and there is no description to judge.
            return _NO_SIGNAL
        if self.min_sensitivity is not None:
            sensitivity = definition.sensitivity
            if _SENSITIVITY_ORDER[sensitivity] < _SENSITIVITY_ORDER[self.min_sensitivity]:
                self._bump("skipped_sensitivity")
                return _NO_SIGNAL

        query = IntentQuery(
            role=role,
            purpose=purpose,
            recent_tools=tuple(recent_tools[-RECENT_TOOLS_IN_STATE:]),
            tool_name=tool,
            tool_description=definition.description,
        )
        started = time.perf_counter()
        try:
            p = self.scorer.p_consistent(query)
        except Exception as exc:  # noqa: BLE001 - any scorer failure degrades, never blocks
            message = f"intent_scorer_unavailable({self.scorer.name}: {exc})"
            with self._lock:
                self._stats["failures"] += 1
                self._last_error = str(exc)
            return IntentResult(risk=0.0, label=None, degraded=message)
        with self._lock:
            self._stats["checked"] += 1
            self._last_latency_ms = round((time.perf_counter() - started) * 1000, 1)

        if p >= INTENT_CONSISTENT_THRESHOLD:
            return IntentResult(risk=0.0, label=None, p_consistent=p)

        risk = INTENT_MAX_RISK * (INTENT_CONSISTENT_THRESHOLD - p) / INTENT_CONSISTENT_THRESHOLD
        short_purpose = purpose if len(purpose) <= PURPOSE_LABEL_MAX_CHARS else purpose[: PURPOSE_LABEL_MAX_CHARS - 1] + "…"
        label = (
            f"intent_mismatch(tool={tool!r}, p_consistent={p:.2f}, "
            f"purpose={short_purpose!r}, scorer={self.scorer.name})"
        )
        self._bump("fired")
        return IntentResult(risk=risk, label=label, p_consistent=p)

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": True,
                "scorer": self.scorer.name,
                "min_sensitivity": self.min_sensitivity.value if self.min_sensitivity else None,
                "consistent_threshold": INTENT_CONSISTENT_THRESHOLD,
                "max_risk": INTENT_MAX_RISK,
                **self._stats,
                "last_error": self._last_error,
                "last_latency_ms": self._last_latency_ms,
            }
