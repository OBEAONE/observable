"""
Block M — Compliance report generation.

Runs every control in ``DEFAULT_CONTROLS`` (or a caller-supplied subset)
against a ``ComplianceContext`` and rolls the results up into one
``ComplianceReport`` — the thing an operator actually hands to an
auditor or pastes into a customer security questionnaire.
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from observable.compliance.framework import (
    DEFAULT_CONTROLS,
    Control,
    ComplianceContext,
    ControlResult,
    ControlStatus,
)


@dataclasses.dataclass(frozen=True)
class ComplianceReport:
    generated_at: dt.datetime
    results: list[ControlResult]

    @property
    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in ControlStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def overall_status(self) -> ControlStatus:
        """PASS only if nothing failed. A PARTIAL anywhere (but no
        FAIL) rolls up to PARTIAL rather than PASS — an operator should
        have to notice a partial control, not have it hidden inside an
        overall green light."""
        statuses = {r.status for r in self.results}
        if ControlStatus.FAIL in statuses:
            return ControlStatus.FAIL
        if ControlStatus.PARTIAL in statuses:
            return ControlStatus.PARTIAL
        return ControlStatus.PASS

    def failing(self) -> list[ControlResult]:
        return [r for r in self.results if r.status == ControlStatus.FAIL]


def generate_report(
    ctx: ComplianceContext, controls: list[Control] = DEFAULT_CONTROLS
) -> ComplianceReport:
    results = [control.check(ctx) for control in controls]
    return ComplianceReport(generated_at=dt.datetime.now(dt.timezone.utc), results=results)
