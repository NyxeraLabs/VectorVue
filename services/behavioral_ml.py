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

"""Behavioral and ML anomaly service (Phase 7 Sprint 7.2)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
from typing import Any


class BehavioralMLError(ValueError):
    """Raised when behavioral ML operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


@dataclass(frozen=True, slots=True)
class TechniqueBaseline:
    technique_id: str
    mean_daily_count: float
    std_daily_count: float
    sample_days: int


@dataclass(frozen=True, slots=True)
class TechniqueAnomaly:
    technique_id: str
    observed_count: int
    expected_mean: float
    deviation_score: float
    weighted_anomaly_score: float
    adjusted_confidence: float


class BehavioralMLService:
    """In-memory anomaly correlation and ML-style confidence adjustment."""

    def correlate_anomalies(
        self,
        *,
        events: list[dict[str, Any]],
        correlation_window_minutes: int = 30,
    ) -> list[dict[str, Any]]:
        if correlation_window_minutes < 1:
            raise BehavioralMLError("correlation_window_minutes must be >= 1")
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in events:
            asset = str(row.get("asset_id", "")).strip()
            technique = str(row.get("technique_id", "")).strip().upper()
            if not asset or not technique:
                continue
            grouped[(asset, technique)].append(row)
        correlated: list[dict[str, Any]] = []
        for (asset, technique), rows in grouped.items():
            ordered = sorted(rows, key=lambda item: str(item.get("observed_at", "")))
            if len(ordered) < 2:
                continue
            correlated.append(
                {
                    "asset_id": asset,
                    "technique_id": technique,
                    "events": len(ordered),
                    "window_minutes": correlation_window_minutes,
                    "correlation_score": round(_clamp(len(ordered) / 10.0, 0.0, 1.0), 4),
                }
            )
        return sorted(correlated, key=lambda item: (-item["correlation_score"], item["technique_id"]))

    def compute_baselines(
        self,
        *,
        history_by_technique: dict[str, list[int]],
    ) -> dict[str, TechniqueBaseline]:
        baselines: dict[str, TechniqueBaseline] = {}
        for tid_raw, samples in history_by_technique.items():
            tid = tid_raw.strip().upper()
            if not tid:
                continue
            vals = [max(0, int(v)) for v in samples]
            if not vals:
                mean = 0.0
                std = 0.0
                n = 0
            else:
                n = len(vals)
                mean = float(sum(vals)) / float(n)
                var = sum((float(v) - mean) ** 2 for v in vals) / float(n)
                std = math.sqrt(var)
            baselines[tid] = TechniqueBaseline(
                technique_id=tid,
                mean_daily_count=round(mean, 4),
                std_daily_count=round(std, 4),
                sample_days=n,
            )
        return dict(sorted(baselines.items(), key=lambda item: item[0]))

    def detection_deviation_score(
        self,
        *,
        observed_count: int,
        baseline: TechniqueBaseline,
    ) -> float:
        obs = max(0, int(observed_count))
        mean = baseline.mean_daily_count
        std = baseline.std_daily_count
        if baseline.sample_days < 3:
            # low-trust baseline: use ratio deviation
            ratio = abs(float(obs) - mean) / max(1.0, mean + 1.0)
            return round(_clamp(ratio, 0.0, 1.0), 4)
        if std <= 0.0001:
            return 0.0 if abs(float(obs) - mean) < 0.0001 else 1.0
        z = abs(float(obs) - mean) / std
        return round(_clamp(z / 4.0, 0.0, 1.0), 4)

    def technique_anomaly_weight(
        self,
        *,
        technique_id: str,
        deviation_score: float,
        tactic_weight: float = 1.0,
    ) -> float:
        tid = technique_id.strip().upper()
        if not tid:
            raise BehavioralMLError("technique_id is required")
        critical_prefix = {"T1003", "T1021", "T1078", "T1068", "T1543"}
        prefix = tid.split(".")[0]
        critical_boost = 1.25 if prefix in critical_prefix else 1.0
        weighted = float(deviation_score) * float(tactic_weight) * critical_boost
        return round(_clamp(weighted, 0.0, 1.0), 4)

    def adjust_ml_confidence(
        self,
        *,
        base_confidence: float,
        deviation_score: float,
        sample_days: int,
    ) -> float:
        base = _clamp(float(base_confidence), 0.0, 1.0)
        deviation = _clamp(float(deviation_score), 0.0, 1.0)
        sample_factor = _clamp(float(sample_days) / 30.0, 0.15, 1.0)
        # Increase confidence for strong deviations with stable baselines,
        # decrease confidence when baseline is weak.
        confidence = base + deviation * 0.35 * sample_factor - (1.0 - sample_factor) * 0.20
        return round(_clamp(confidence, 0.0, 1.0), 4)

    def score_current_observations(
        self,
        *,
        observed_by_technique: dict[str, int],
        baselines: dict[str, TechniqueBaseline],
        base_confidence_by_technique: dict[str, float] | None = None,
        tactic_weight_by_technique: dict[str, float] | None = None,
    ) -> list[TechniqueAnomaly]:
        base_conf = {k.strip().upper(): float(v) for k, v in (base_confidence_by_technique or {}).items()}
        tactic_weight = {k.strip().upper(): float(v) for k, v in (tactic_weight_by_technique or {}).items()}
        rows: list[TechniqueAnomaly] = []
        for tid_raw, observed in observed_by_technique.items():
            tid = tid_raw.strip().upper()
            baseline = baselines.get(tid)
            if baseline is None:
                continue
            deviation = self.detection_deviation_score(observed_count=observed, baseline=baseline)
            weighted = self.technique_anomaly_weight(
                technique_id=tid,
                deviation_score=deviation,
                tactic_weight=tactic_weight.get(tid, 1.0),
            )
            adjusted = self.adjust_ml_confidence(
                base_confidence=base_conf.get(tid, 0.5),
                deviation_score=deviation,
                sample_days=baseline.sample_days,
            )
            rows.append(
                TechniqueAnomaly(
                    technique_id=tid,
                    observed_count=max(0, int(observed)),
                    expected_mean=baseline.mean_daily_count,
                    deviation_score=deviation,
                    weighted_anomaly_score=weighted,
                    adjusted_confidence=adjusted,
                )
            )
        return sorted(rows, key=lambda item: (-item.weighted_anomaly_score, item.technique_id))

