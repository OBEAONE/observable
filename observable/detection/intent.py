"""
Detection Block E — intent-conformance signal (ARCHITECTURE.md §8.5).

The four signals in ``scorer.py`` see *how* an agent behaves — its pace,
what's new to it, how often it is denied — but not *whether an action
makes sense for what the agent is supposed to be doing*. This module
adds one optional fifth signal, ``intent_mismatch``: given an agent's
role, its declared purpose (signed into its token at mint, §4.2) and
its recent allowed tool calls, is calling this tool consistent with
that purpose?

Design principles carried over verbatim from the architecture doc:

* **Pluggable scorer**, same pattern as ``CertificateAuthority`` and
  ``SaaSConnector`` — ``IntentScorer`` is the interface, nothing above
  it changes when an implementation is swapped.
* **A signal, never a control.** Its contribution to the combined risk
  score is capped at 0.5, so it alone can never deny a tool whose
  ceiling is above 0.5, nor trip an auto-containment threshold set
  above 0.5. Deny-by-default policy, PoP tokens and scopes are
  untouched — this only adds evidence to an already-suspicious request.
* **Fail-open, but loudly.** A scorer timeout or error never blocks the
  request; the hard controls still apply. The outage is never silent:
  it's surfaced as ``degraded`` on the assessment, propagated to
  ``GuardResult.detection_degraded`` and the audit entry's reason, and
  counted in failure counters exposed at ``GET /admin/detection/intent``.
* **Off by default.** Turning this on (and choosing mock vs. a real
  model) is an explicit operator decision via ``OBSERVABLE_INTENT_SCORER``,
  never an implicit side effect of upgrading Observable.
"""
from __future__ import annotations

import dataclasses
import os
import re
from typing import Optional, Protocol

from observable.policy.bundle import Sensitivity

# --- tunables (all overridable via env, see build_intent_checker_from_env) -
DEFAULT_MIN_SENSITIVITY = Sensitivity.MEDIUM
DEFAULT_CLM_TIMEOUT_SECONDS = 5.0
DEFAULT_RECENT_TOOLS_LIMIT = 5

_SENSITIVITY_ORDER: dict[Sensitivity, int] = {
    Sensitivity.LOW: 0,
    Sensitivity.MEDIUM: 1,
    Sensitivity.HIGH: 2,
}

_STOPWORDS = {
    "a", "an", "the", "of", "to", "from", "and", "or", "for", "on", "in",
    "at", "is", "with", "this", "that", "about", "into", "as", "by",
}


def _words(text: Optional[str]) -> set[str]:
    if not text:
        return set()
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return {t for t in tokens if t not in _STOPWORDS and len(t) > 1}


class IntentScorerError(Exception):
    """Raised by an ``IntentScorer`` on any failure (timeout, transport
    error, malformed response). Caught by ``IntentChecker``, which fails
    open — see module docstring."""


class IntentScorer(Protocol):
    """What ``IntentChecker`` needs from a scorer implementation. Returns
    ``p_consistent`` in [0, 1]: the scorer's estimate that calling
    ``tool_name`` is consistent with ``purpose``, given ``role`` and the
    agent's ``recent_tools``. Never sees the request payload — only
    role, purpose, recent tool names, and the candidate tool's own
    registered name/description (§8.5 "what the scorer sees")."""

    def score(
        self,
        *,
        role: str,
        purpose: Optional[str],
        recent_tools: list[str],
        tool_name: str,
        tool_description: str,
    ) -> float: ...


class MockIntentScorer:
    """Deterministic keyword overlap between the declared purpose and
    the candidate tool's name/description. No semantic understanding —
    it exists so the full path runs in tests and demos without a GPU.
    Never for production (see ``CLMIntentScorer``).

    ``p_consistent = 0.15 + 0.35 * min(overlap, 2)``: zero shared words
    scores 0.15 (a clear mismatch — this signal will fire), one shared
    word scores 0.50 (borderline, does not fire), two or more shared
    words scores 0.85 (clearly consistent)."""

    def score(
        self,
        *,
        role: str,
        purpose: Optional[str],
        recent_tools: list[str],
        tool_name: str,
        tool_description: str,
    ) -> float:
        purpose_words = _words(purpose)
        if not purpose_words:
            return 0.5  # nothing declared to judge against: stay neutral
        tool_words = _words(tool_name.replace(".", " ")) | _words(tool_description)
        overlap = len(purpose_words & tool_words)
        return min(1.0, 0.15 + 0.35 * min(overlap, 2))


class CLMIntentScorer:
    """Adapter for a self-hosted Contrastive Language Model server
    (``clm-serve``, CLM-v0.1-8B on a frozen Qwen3-8B encoder). Calls
    ``POST /v1/systemone`` with one yes/no question and reads back the
    probability — deliberately not CLM's ranking endpoint, which scores
    relative to a candidate set and would penalise every legitimate step
    of a multi-tool workflow that isn't the single "best" next move.

    Depends only on ``httpx``; no torch or CLM package runs inside the
    Observable process. The CLM server itself runs outside Observable, on
    a GPU host the customer controls (see ARCHITECTURE.md §8.5
    Deployment)."""

    def __init__(self, *, base_url: str, api_key: Optional[str] = None, timeout: float = DEFAULT_CLM_TIMEOUT_SECONDS) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def score(
        self,
        *,
        role: str,
        purpose: Optional[str],
        recent_tools: list[str],
        tool_name: str,
        tool_description: str,
    ) -> float:
        import httpx

        question = (
            f"An AI agent with role '{role}' has declared its purpose as: "
            f"'{purpose}'. Its recent tool calls were: {recent_tools or 'none yet'}. "
            f"Is calling the tool '{tool_name}' ({tool_description}) "
            f"consistent with that declared purpose? Answer yes or no."
        )
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            response = httpx.post(
                f"{self._base_url}/v1/systemone",
                json={"question": question},
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            return float(data["probability"])
        except Exception as exc:  # noqa: BLE001 - any failure here fails open, see IntentChecker
            raise IntentScorerError(f"CLM scorer request failed: {exc}") from exc


@dataclasses.dataclass(frozen=True)
class IntentCheckResult:
    risk: float
    label: Optional[str]
    degraded: bool
    degraded_reason: Optional[str]


class IntentChecker:
    """Orchestrates the intent-conformance signal: skip rules (mode,
    sensitivity floor, no declared purpose), the capped risk formula,
    and fail-open error handling with failure counters for
    ``GET /admin/detection/intent``.

    ``mode`` is one of ``"off"``, ``"mock"``, ``"clm"`` — construct via
    ``build_intent_checker_from_env()`` in normal operation rather than
    picking a scorer by hand."""

    def __init__(
        self,
        *,
        mode: str = "off",
        scorer: Optional[IntentScorer] = None,
        min_sensitivity: Sensitivity = DEFAULT_MIN_SENSITIVITY,
        recent_tools_limit: int = DEFAULT_RECENT_TOOLS_LIMIT,
    ) -> None:
        if mode not in ("off", "mock", "clm"):
            raise ValueError(f"unknown intent scorer mode {mode!r}")
        if mode != "off" and scorer is None:
            raise ValueError(f"mode {mode!r} requires a scorer instance")
        self.mode = mode
        self._scorer = scorer if mode != "off" else None
        self._min_sensitivity = min_sensitivity
        self._recent_tools_limit = recent_tools_limit
        self._calls = 0
        self._failures = 0
        self._last_error: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self._scorer is not None

    def check(
        self,
        *,
        role: str,
        purpose: Optional[str],
        recent_tools: list[str],
        tool_name: str,
        tool_description: Optional[str],
        sensitivity: Optional[Sensitivity],
    ) -> IntentCheckResult:
        if self._scorer is None:
            return IntentCheckResult(risk=0.0, label=None, degraded=False, degraded_reason=None)
        if not purpose:
            # Nothing declared to judge the call against — no evidence
            # either way, so this is a no-op rather than a neutral 0.5
            # that would otherwise never actually contribute (0.5 - 0.5
            # = 0 risk), which is the same outcome without a model call.
            return IntentCheckResult(risk=0.0, label=None, degraded=False, degraded_reason=None)
        floor = _SENSITIVITY_ORDER.get(sensitivity, _SENSITIVITY_ORDER[Sensitivity.LOW])
        if floor < _SENSITIVITY_ORDER[self._min_sensitivity]:
            return IntentCheckResult(risk=0.0, label=None, degraded=False, degraded_reason=None)

        self._calls += 1
        try:
            p_consistent = self._scorer.score(
                role=role,
                purpose=purpose,
                recent_tools=recent_tools[-self._recent_tools_limit :],
                tool_name=tool_name,
                tool_description=tool_description or "",
            )
        except Exception as exc:  # noqa: BLE001 - fail open, see module docstring
            self._failures += 1
            self._last_error = str(exc)
            return IntentCheckResult(
                risk=0.0,
                label=None,
                degraded=True,
                degraded_reason=f"detection degraded: intent scorer ({self.mode}) failed: {exc}",
            )

        if p_consistent >= 0.5:
            return IntentCheckResult(risk=0.0, label=None, degraded=False, degraded_reason=None)

        risk = min(0.5, max(0.0, 0.5 - p_consistent))
        label = (
            f"intent_mismatch(tool={tool_name!r}, p_consistent={p_consistent:.2f}, "
            f"purpose={purpose!r}, scorer={self.mode})"
        )
        return IntentCheckResult(risk=risk, label=label, degraded=False, degraded_reason=None)

    def stats(self) -> dict:
        """JSON-friendly snapshot for ``GET /admin/detection/intent``."""
        return {
            "mode": self.mode,
            "enabled": self.enabled,
            "min_sensitivity": self._min_sensitivity.value,
            "calls": self._calls,
            "failures": self._failures,
            "last_error": self._last_error,
        }


def build_intent_checker_from_env() -> IntentChecker:
    """Factory reading the operator-facing env vars from ARCHITECTURE.md
    §8.5:

    * ``OBSERVABLE_INTENT_SCORER`` — ``off`` (default) | ``mock`` | ``clm``
    * ``OBSERVABLE_INTENT_MIN_SENSITIVITY`` — ``low`` | ``medium``
      (default) | ``high``: tools below this sensitivity never trigger a
      model call, so low-risk reads never wait on one.
    * ``OBSERVABLE_CLM_URL`` — base URL of a self-hosted ``clm-serve``
      instance, required when mode is ``clm``.
    * ``OBSERVABLE_CLM_API_KEY`` — optional bearer token for that server.

    Adding an ML-derived input to authorization should never happen
    implicitly, so an unset or ``off`` mode is the default and this
    factory never reaches out over the network at construction time —
    only ``check()`` calls do, and only once armed."""
    mode = os.environ.get("OBSERVABLE_INTENT_SCORER", "off").strip().lower()
    min_sensitivity_raw = os.environ.get("OBSERVABLE_INTENT_MIN_SENSITIVITY", "medium").strip().lower()
    try:
        min_sensitivity = Sensitivity(min_sensitivity_raw)
    except ValueError:
        min_sensitivity = DEFAULT_MIN_SENSITIVITY

    if mode == "off":
        return IntentChecker(mode="off", scorer=None, min_sensitivity=min_sensitivity)
    if mode == "mock":
        return IntentChecker(mode="mock", scorer=MockIntentScorer(), min_sensitivity=min_sensitivity)
    if mode == "clm":
        base_url = os.environ.get("OBSERVABLE_CLM_URL")
        if not base_url:
            raise ValueError("OBSERVABLE_INTENT_SCORER=clm requires OBSERVABLE_CLM_URL to be set")
        api_key = os.environ.get("OBSERVABLE_CLM_API_KEY")
        scorer = CLMIntentScorer(base_url=base_url, api_key=api_key)
        return IntentChecker(mode="clm", scorer=scorer, min_sensitivity=min_sensitivity)
    raise ValueError(
        f"unknown OBSERVABLE_INTENT_SCORER={mode!r}; expected off, mock, or clm"
    )
