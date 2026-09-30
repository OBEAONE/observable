"""
Block 5 — Input sanitization and output filtering.

Foundation/Enterprise-tier controls from the guide: reject obviously
malformed or oversized input before an agent (or the tool it's about to
call) ever sees it, and scan tool responses for sensitive-data patterns
before they go back to the agent. Neither of these claims to catch a
sophisticated prompt injection — the guide is explicit that pattern
matching alone is insufficient against that (Advanced tier calls for
constitutional classifiers and spotlighting instead, v2 here) — but they
do close the cheap, high-volume cases: oversized payloads, obvious
instruction-override strings, and secrets echoed back in a tool result.
"""
from __future__ import annotations

import dataclasses
import re

MAX_PAYLOAD_BYTES = 32_768
MAX_STRING_FIELD_LENGTH = 8_192

# Known-bad instruction-override / injection phrasing. Enterprise-tier
# "content filtering with known attack pattern detection" — a floor, not
# a ceiling; see docstring above.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\b.{0,25}\binstructions\b", re.IGNORECASE),
    re.compile(r"disregard\b.{0,25}\b(system|prompt)\b", re.IGNORECASE),
    re.compile(r"you are now (in )?(developer|debug|admin) mode", re.IGNORECASE),
    re.compile(r"reveal (your|the) (system prompt|instructions)", re.IGNORECASE),
    re.compile(r"act as (if you have|an unrestricted)", re.IGNORECASE),
]

# Sensitive-data patterns for output filtering.
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("openai_style_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("generic_password_field", re.compile(r"(?i)\"?password\"?\s*[:=]\s*\"?[^\s\"]{4,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{16,}")),
]


class SanitizationError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class SanitizationResult:
    clean: bool
    reason: str = ""


def sanitize_input(payload: dict) -> SanitizationResult:
    """Structural + pattern checks on an inbound tool-call payload.
    Returns a result rather than raising, so Agent Guard can log the
    specific reason in the audit trail before denying."""
    try:
        import json

        encoded = json.dumps(payload)
    except (TypeError, ValueError):
        return SanitizationResult(clean=False, reason="payload is not JSON-serializable")

    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return SanitizationResult(
            clean=False, reason=f"payload exceeds {MAX_PAYLOAD_BYTES} byte limit"
        )

    for value in _iter_string_values(payload):
        if len(value) > MAX_STRING_FIELD_LENGTH:
            return SanitizationResult(
                clean=False, reason=f"a field exceeds {MAX_STRING_FIELD_LENGTH} characters"
            )
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(value):
                return SanitizationResult(
                    clean=False, reason=f"input matches known injection pattern: {pattern.pattern!r}"
                )

    return SanitizationResult(clean=True)


def filter_output(result: dict) -> tuple[dict, list[str]]:
    """Redact sensitive-looking values in a tool's response before it
    goes back to the agent. Returns (filtered_result,
    list_of_redaction_labels) so the caller can log what was redacted
    without logging the secret itself."""
    redacted_labels: list[str] = []

    def _redact_value(value):
        if isinstance(value, str):
            new_value = value
            for label, pattern in _SENSITIVE_PATTERNS:
                if pattern.search(new_value):
                    redacted_labels.append(label)
                    new_value = pattern.sub("[REDACTED]", new_value)
            return new_value
        if isinstance(value, dict):
            return {k: _redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_redact_value(v) for v in value]
        return value

    filtered = _redact_value(result)
    return filtered, redacted_labels


def _iter_string_values(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_string_values(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_string_values(v)
