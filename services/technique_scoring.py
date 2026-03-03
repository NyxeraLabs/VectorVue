# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0
#
# You may:
# Study
# Modify
# Use for internal security testing
#
# You may NOT:
# Offer as a commercial service
# Sell derived competing products

"""Technique coverage and confidence scoring service (Phase 2 Sprint 2.2)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


class TechniqueScoringError(ValueError):
    """Raised when technique scoring operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


@dataclass(frozen=True, slots=True)
class TechniqueCoverage:
    """Technique coverage model."""

    technique_id: str
    detection_present: bool = False
    detection_latency_seconds: int | None = None
    alert_quality_weight: float = 0.0
    false_negative_count: int = 0
    execution_count: int = 0
    response_observed: bool = False
    containment_observed: bool = False
    confidence_score: float = 0.0
    maturity_index: float = 0.0

    def __post_init__(self) -> None:
        if self.detection_latency_seconds is not None and self.detection_latency_seconds < 0:
            raise TechniqueScoringError("detection_latency_seconds must be >= 0")
        if self.false_negative_count < 0:
            raise TechniqueScoringError("false_negative_count must be >= 0")
        if self.execution_count < 0:
            raise TechniqueScoringError("execution_count must be >= 0")
        if not (0.0 <= self.alert_quality_weight <= 1.0):
            raise TechniqueScoringError("alert_quality_weight must be between 0 and 1")
        if not (0.0 <= self.confidence_score <= 1.0):
            raise TechniqueScoringError("confidence_score must be between 0 and 1")
        if not (0.0 <= self.maturity_index <= 1.0):
            raise TechniqueScoringError("maturity_index must be between 0 and 1")


class TechniqueCoverageService:
    """In-memory technique coverage and scoring calculator."""

    def __init__(self) -> None:
        self._rows: dict[str, TechniqueCoverage] = {}

    def ensure_technique(self, technique_id: str) -> TechniqueCoverage:
        tid = technique_id.strip().upper()
        if not tid:
            raise TechniqueScoringError("technique_id is required")
        if tid not in self._rows:
            self._rows[tid] = TechniqueCoverage(technique_id=tid)
        return self._rows[tid]

    def record_execution(
        self,
        *,
        technique_id: str,
        detection_present: bool,
        detection_latency_seconds: int | None,
        alert_quality_weight: float,
        response_observed: bool,
        containment_observed: bool,
    ) -> TechniqueCoverage:
        row = self.ensure_technique(technique_id)
        execution_count = row.execution_count + 1
        false_negative_count = row.false_negative_count + (
            1 if (not detection_present and row.detection_present) else 0
        )
        next_latency = detection_latency_seconds
        if row.detection_latency_seconds is not None and detection_latency_seconds is not None:
            next_latency = int((row.detection_latency_seconds + detection_latency_seconds) / 2)
        elif row.detection_latency_seconds is not None and detection_latency_seconds is None:
            next_latency = row.detection_latency_seconds

        updated = replace(
            row,
            detection_present=row.detection_present or detection_present,
            detection_latency_seconds=next_latency,
            alert_quality_weight=_clamp(
                (row.alert_quality_weight * row.execution_count + alert_quality_weight) / execution_count,
                0.0,
                1.0,
            ),
            false_negative_count=false_negative_count,
            execution_count=execution_count,
            response_observed=row.response_observed or response_observed,
            containment_observed=row.containment_observed or containment_observed,
        )
        scored = self._recalculate(updated)
        self._rows[scored.technique_id] = scored
        return scored

    def update_false_negative_count(self, *, technique_id: str, false_negative_count: int) -> TechniqueCoverage:
        row = self.ensure_technique(technique_id)
        updated = replace(row, false_negative_count=false_negative_count)
        scored = self._recalculate(updated)
        self._rows[scored.technique_id] = scored
        return scored

    def _recalculate(self, row: TechniqueCoverage) -> TechniqueCoverage:
        # Detection latency score: 1.0 at <=5s, linearly decays to 0.0 at 300s.
        if row.detection_latency_seconds is None:
            latency_score = 0.0
        else:
            latency_score = _clamp(1.0 - (float(row.detection_latency_seconds) - 5.0) / 295.0, 0.0, 1.0)

        fn_rate = (
            float(row.false_negative_count) / float(row.execution_count)
            if row.execution_count > 0
            else 0.0
        )
        false_negative_score = 1.0 - _clamp(fn_rate, 0.0, 1.0)

        detection_presence_score = 1.0 if row.detection_present else 0.0
        response_score = 1.0 if row.response_observed else 0.0
        containment_score = 1.0 if row.containment_observed else 0.0

        # Technique confidence scoring formula (0..1).
        confidence = (
            detection_presence_score * 0.22
            + latency_score * 0.20
            + row.alert_quality_weight * 0.20
            + false_negative_score * 0.18
            + response_score * 0.10
            + containment_score * 0.10
        )
        confidence = _clamp(confidence, 0.0, 1.0)

        # Technique maturity index favors sustained quality and low FN behavior.
        maturity = (
            confidence * 0.55
            + false_negative_score * 0.25
            + row.alert_quality_weight * 0.10
            + (0.10 if row.execution_count >= 3 else 0.0)
        )
        maturity = _clamp(maturity, 0.0, 1.0)

        return replace(
            row,
            confidence_score=round(confidence, 4),
            maturity_index=round(maturity, 4),
        )

    def get(self, technique_id: str) -> TechniqueCoverage:
        tid = technique_id.strip().upper()
        if tid not in self._rows:
            raise TechniqueScoringError("technique not found")
        return self._rows[tid]

    def summary(self) -> list[dict[str, Any]]:
        return [
            {
                "technique_id": row.technique_id,
                "detection_present": row.detection_present,
                "detection_latency_seconds": row.detection_latency_seconds,
                "alert_quality_weight": row.alert_quality_weight,
                "false_negative_count": row.false_negative_count,
                "execution_count": row.execution_count,
                "response_observed": row.response_observed,
                "containment_observed": row.containment_observed,
                "confidence_score": row.confidence_score,
                "maturity_index": row.maturity_index,
            }
            for row in sorted(self._rows.values(), key=lambda item: item.technique_id)
        ]
