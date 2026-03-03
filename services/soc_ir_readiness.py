# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 -> Apache-2.0
#
# You may:
# Study
# Modify
# Use for internal security testing
#
# You may NOT:
# Offer as a commercial service
# Sell derived competing products

"""SOC and IR readiness service (Phase 3 Sprint 3.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SocReadinessError(ValueError):
    """Raised when SOC readiness operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _minutes_between(start: datetime, end: datetime | None) -> float | None:
    if end is None:
        return None
    if end < start:
        raise SocReadinessError("end timestamp cannot be earlier than start timestamp")
    return (end - start).total_seconds() / 60.0


class ResponseStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESPONDED = "responded"
    CONTAINED = "contained"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class ResponseAction:
    """ResponseAction table row."""

    response_action_id: str
    tenant_id: str
    detection_event_id: str
    action_type: str
    owner: str
    status: ResponseStatus
    signal_observed_at: datetime
    detected_at: datetime
    acknowledged_at: datetime | None = None
    responded_at: datetime | None = None
    contained_at: datetime | None = None
    closed_at: datetime | None = None
    sla_target_minutes: int = 30
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.response_action_id.strip():
            raise SocReadinessError("response_action_id is required")
        if not self.tenant_id.strip():
            raise SocReadinessError("tenant_id is required")
        if not self.detection_event_id.strip():
            raise SocReadinessError("detection_event_id is required")
        if not self.action_type.strip():
            raise SocReadinessError("action_type is required")
        if not self.owner.strip():
            raise SocReadinessError("owner is required")
        if self.detected_at < self.signal_observed_at:
            raise SocReadinessError("detected_at cannot be earlier than signal_observed_at")
        _minutes_between(self.detected_at, self.acknowledged_at)
        _minutes_between(self.detected_at, self.responded_at)
        _minutes_between(self.detected_at, self.contained_at)
        _minutes_between(self.detected_at, self.closed_at)
        if self.sla_target_minutes <= 0:
            raise SocReadinessError("sla_target_minutes must be > 0")


class SocIrReadinessService:
    """In-memory response timing analytics for SOC/IR readiness."""

    def __init__(self) -> None:
        self._actions: dict[str, ResponseAction] = {}

    def upsert_response_action(
        self,
        *,
        response_action_id: str,
        tenant_id: str,
        detection_event_id: str,
        action_type: str,
        owner: str,
        status: ResponseStatus | str,
        signal_observed_at: datetime,
        detected_at: datetime,
        acknowledged_at: datetime | None = None,
        responded_at: datetime | None = None,
        contained_at: datetime | None = None,
        closed_at: datetime | None = None,
        sla_target_minutes: int = 30,
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ResponseAction:
        state = status if isinstance(status, ResponseStatus) else ResponseStatus(str(status).strip().lower())
        row = ResponseAction(
            response_action_id=response_action_id,
            tenant_id=tenant_id,
            detection_event_id=detection_event_id,
            action_type=action_type,
            owner=owner,
            status=state,
            signal_observed_at=signal_observed_at,
            detected_at=detected_at,
            acknowledged_at=acknowledged_at,
            responded_at=responded_at,
            contained_at=contained_at,
            closed_at=closed_at,
            sla_target_minutes=sla_target_minutes,
            notes=notes,
            metadata=dict(metadata or {}),
        )
        self._actions[row.response_action_id] = row
        return row

    def escalation_timeline(self, *, response_action_id: str) -> list[dict[str, Any]]:
        if response_action_id not in self._actions:
            raise SocReadinessError("response action not found")
        row = self._actions[response_action_id]
        points = [
            ("signal_observed", row.signal_observed_at, row.signal_observed_at),
            ("detected", row.detected_at, row.detected_at),
            ("acknowledged", row.detected_at, row.acknowledged_at),
            ("responded", row.detected_at, row.responded_at),
            ("contained", row.detected_at, row.contained_at),
            ("closed", row.detected_at, row.closed_at),
        ]
        timeline: list[dict[str, Any]] = []
        for stage, base, ts in points:
            if ts is None:
                continue
            timeline.append(
                {
                    "stage": stage,
                    "timestamp": ts.isoformat(),
                    "minutes_from_detection": round(_minutes_between(base, ts) or 0.0, 4),
                }
            )
        return timeline

    def time_to_detect_minutes(self, *, response_action_id: str) -> float:
        row = self._get(response_action_id)
        return round(_minutes_between(row.signal_observed_at, row.detected_at) or 0.0, 4)

    def time_to_respond_minutes(self, *, response_action_id: str) -> float | None:
        row = self._get(response_action_id)
        val = _minutes_between(row.detected_at, row.responded_at)
        return round(val, 4) if val is not None else None

    def time_to_contain_minutes(self, *, response_action_id: str) -> float | None:
        row = self._get(response_action_id)
        val = _minutes_between(row.detected_at, row.contained_at)
        return round(val, 4) if val is not None else None

    def detect_sla_violation(
        self, *, response_action_id: str, reference_time: datetime | None = None
    ) -> dict[str, Any]:
        row = self._get(response_action_id)
        now = reference_time or datetime.now(timezone.utc)
        ttr = _minutes_between(row.detected_at, row.responded_at)
        elapsed = _minutes_between(row.detected_at, now) or 0.0
        breached = False
        breach_reason = "within_sla"
        measured = ttr if ttr is not None else elapsed
        if measured > float(row.sla_target_minutes):
            breached = True
            breach_reason = "response_timeout" if ttr is not None else "open_timeout"
        return {
            "response_action_id": row.response_action_id,
            "tenant_id": row.tenant_id,
            "sla_target_minutes": row.sla_target_minutes,
            "measured_minutes": round(measured, 4),
            "breached": breached,
            "reason": breach_reason,
        }

    def soc_effectiveness_index(self, *, tenant_id: str) -> float:
        rows = [r for r in self._actions.values() if r.tenant_id == tenant_id]
        if not rows:
            return 0.0
        ttd_values = [(r.detected_at - r.signal_observed_at).total_seconds() / 60.0 for r in rows]
        responded = [r for r in rows if r.responded_at is not None]
        contained = [r for r in rows if r.contained_at is not None]
        sla_ok = [
            1.0
            if not self.detect_sla_violation(response_action_id=r.response_action_id)["breached"]
            else 0.0
            for r in rows
        ]

        avg_ttd = sum(ttd_values) / float(len(ttd_values))
        ttd_score = _clamp(1.0 - (avg_ttd / 120.0), 0.0, 1.0)
        response_rate = len(responded) / float(len(rows))
        containment_rate = len(contained) / float(len(rows))
        sla_rate = sum(sla_ok) / float(len(rows))

        score = (
            ttd_score * 0.30
            + response_rate * 0.30
            + containment_rate * 0.20
            + sla_rate * 0.20
        )
        return round(_clamp(score, 0.0, 1.0), 4)

    def ir_readiness_composite_score(self, *, tenant_id: str) -> float:
        rows = [r for r in self._actions.values() if r.tenant_id == tenant_id]
        if not rows:
            return 0.0
        soc_index = self.soc_effectiveness_index(tenant_id=tenant_id)
        ttr_values = [
            _minutes_between(r.detected_at, r.responded_at) for r in rows if r.responded_at is not None
        ]
        ttc_values = [
            _minutes_between(r.detected_at, r.contained_at) for r in rows if r.contained_at is not None
        ]
        avg_ttr = sum(ttr_values) / float(len(ttr_values)) if ttr_values else 999.0
        avg_ttc = sum(ttc_values) / float(len(ttc_values)) if ttc_values else 999.0
        ttr_score = _clamp(1.0 - (avg_ttr / 180.0), 0.0, 1.0)
        ttc_score = _clamp(1.0 - (avg_ttc / 360.0), 0.0, 1.0)

        score = soc_index * 0.60 + ttr_score * 0.20 + ttc_score * 0.20
        return round(_clamp(score, 0.0, 1.0), 4)

    def list_sla_violations(
        self, *, tenant_id: str, reference_time: datetime | None = None
    ) -> list[dict[str, Any]]:
        rows = [r for r in self._actions.values() if r.tenant_id == tenant_id]
        violations = []
        for row in rows:
            verdict = self.detect_sla_violation(
                response_action_id=row.response_action_id,
                reference_time=reference_time,
            )
            if verdict["breached"]:
                violations.append(verdict)
        return sorted(violations, key=lambda item: item["measured_minutes"], reverse=True)

    def _get(self, response_action_id: str) -> ResponseAction:
        if response_action_id not in self._actions:
            raise SocReadinessError("response action not found")
        return self._actions[response_action_id]

    @property
    def response_actions(self) -> dict[str, ResponseAction]:
        return dict(self._actions)

