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

"""Coverage analytics engine (Phase 6 Sprint 6.1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from services.attack_backbone import infer_default_tactic_ids


class CoverageAnalyticsError(ValueError):
    """Raised when coverage analytics operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


@dataclass(frozen=True, slots=True)
class TechniqueCoverageMetric:
    technique_id: str
    coverage_score: float
    confidence_score: float
    maturity_index: float
    detected: bool
    tactic_ids: tuple[str, ...]


class CoverageAnalyticsService:
    """Coverage analytics service for ATT&CK-native executive reporting."""

    def build_technique_metrics(
        self,
        *,
        technique_rows: list[dict[str, Any]],
        technique_to_tactic: dict[str, list[str]] | None = None,
    ) -> list[TechniqueCoverageMetric]:
        mappings = {k.strip().upper(): [i.strip().upper() for i in v] for k, v in (technique_to_tactic or {}).items()}
        metrics: list[TechniqueCoverageMetric] = []
        for row in technique_rows:
            tid = str(row.get("technique_id", "")).strip().upper()
            if not tid:
                raise CoverageAnalyticsError("technique_id is required in technique_rows")
            confidence = float(row.get("confidence_score", 0.0))
            maturity = float(row.get("maturity_index", 0.0))
            detected = bool(row.get("detection_present", False))
            execution_count = max(0, int(row.get("execution_count", 0)))
            execution_bonus = min(0.10, execution_count * 0.02)
            score = _clamp((confidence * 0.50) + (maturity * 0.35) + (0.05 if detected else 0.0) + execution_bonus, 0.0, 1.0)
            tactic_ids = tuple(mappings.get(tid, list(infer_default_tactic_ids(tid))))
            metrics.append(
                TechniqueCoverageMetric(
                    technique_id=tid,
                    coverage_score=round(score, 4),
                    confidence_score=round(_clamp(confidence, 0.0, 1.0), 4),
                    maturity_index=round(_clamp(maturity, 0.0, 1.0), 4),
                    detected=detected,
                    tactic_ids=tactic_ids,
                )
            )
        return sorted(metrics, key=lambda item: item.technique_id)

    def generate_attack_heatmap(
        self,
        *,
        technique_metrics: list[TechniqueCoverageMetric],
    ) -> dict[str, dict[str, float]]:
        heatmap: dict[str, dict[str, float]] = {}
        for metric in technique_metrics:
            if not metric.tactic_ids:
                heatmap.setdefault("UNMAPPED", {})[metric.technique_id] = metric.coverage_score
                continue
            for tactic in metric.tactic_ids:
                bucket = heatmap.setdefault(tactic, {})
                bucket[metric.technique_id] = metric.coverage_score
        return {
            tactic: dict(sorted(techniques.items(), key=lambda item: item[0]))
            for tactic, techniques in sorted(heatmap.items(), key=lambda item: item[0])
        }

    def technique_level_coverage_score(
        self,
        *,
        technique_metrics: list[TechniqueCoverageMetric],
    ) -> dict[str, float]:
        return {row.technique_id: row.coverage_score for row in technique_metrics}

    def tactic_level_coverage_score(
        self,
        *,
        technique_metrics: list[TechniqueCoverageMetric],
    ) -> dict[str, float]:
        buckets: dict[str, list[float]] = {}
        for row in technique_metrics:
            tactic_ids = row.tactic_ids or ("UNMAPPED",)
            for tactic in tactic_ids:
                buckets.setdefault(tactic, []).append(row.coverage_score)
        return {
            tactic: round(sum(values) / float(len(values)), 4)
            for tactic, values in sorted(buckets.items(), key=lambda item: item[0])
        }

    def detection_effectiveness_index(
        self,
        *,
        technique_metrics: list[TechniqueCoverageMetric],
    ) -> float:
        if not technique_metrics:
            return 0.0
        weighted = [
            row.confidence_score * (1.0 if row.detected else 0.35)
            for row in technique_metrics
        ]
        return round(_clamp(sum(weighted) / float(len(weighted)), 0.0, 1.0), 4)

    def control_reliability_score(
        self,
        *,
        control_state_rows: list[dict[str, Any]],
    ) -> float:
        if not control_state_rows:
            return 0.0
        normalized: list[float] = []
        for row in control_state_rows:
            state = str(row.get("state", "")).strip().lower()
            failure_rate = _clamp(float(row.get("failure_rate", 0.0)), 0.0, 1.0)
            coverage_percent = _clamp(float(row.get("coverage_percent", 0.0)), 0.0, 100.0)
            base = {
                "operating": 0.95,
                "degraded": 0.70,
                "failed": 0.35,
                "insufficient_evidence": 0.45,
            }.get(state, 0.50)
            score = base * 0.60 + (1.0 - failure_rate) * 0.25 + (coverage_percent / 100.0) * 0.15
            normalized.append(_clamp(score, 0.0, 1.0))
        return round(sum(normalized) / float(len(normalized)), 4)

    def historical_trend_comparison(
        self,
        *,
        snapshots: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if len(snapshots) < 2:
            return {"trend": "insufficient_data", "delta": 0.0, "series": snapshots}
        ordered = sorted(snapshots, key=lambda item: str(item.get("cycle", "")))
        first = float(ordered[0].get("overall_score", 0.0))
        last = float(ordered[-1].get("overall_score", 0.0))
        delta = round(last - first, 4)
        if delta >= 0.05:
            trend = "improving"
        elif delta <= -0.05:
            trend = "regressing"
        else:
            trend = "stable"
        return {"trend": trend, "delta": delta, "series": ordered}

    def executive_risk_summary(
        self,
        *,
        technique_metrics: list[TechniqueCoverageMetric],
        control_reliability: float,
        trend: dict[str, Any],
    ) -> dict[str, Any]:
        tactic_scores = self.tactic_level_coverage_score(technique_metrics=technique_metrics)
        detection_index = self.detection_effectiveness_index(technique_metrics=technique_metrics)
        mean_coverage = (
            sum(row.coverage_score for row in technique_metrics) / float(len(technique_metrics))
            if technique_metrics
            else 0.0
        )
        overall_assurance = _clamp(
            mean_coverage * 0.45 + detection_index * 0.30 + control_reliability * 0.25,
            0.0,
            1.0,
        )
        residual_risk = round(1.0 - overall_assurance, 4)
        lowest_tactics = sorted(tactic_scores.items(), key=lambda item: item[1])[:3]
        return {
            "overall_assurance_score": round(overall_assurance, 4),
            "residual_risk_score": residual_risk,
            "detection_effectiveness_index": detection_index,
            "control_reliability_score": round(control_reliability, 4),
            "trend": trend,
            "lowest_tactic_coverage": [
                {"tactic_id": tactic, "score": score} for tactic, score in lowest_tactics
            ],
            "technique_count": len(technique_metrics),
        }

