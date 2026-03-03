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

"""Control modeling and detection normalization service (Phase 3 Sprint 3.1)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


_TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


class ControlModelingError(ValueError):
    """Raised when control modeling operations fail."""


class ControlType(str, Enum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ControlVendor:
    """ControlVendor table row."""

    vendor_id: str
    name: str
    product_family: str | None = None

    def __post_init__(self) -> None:
        if not self.vendor_id.strip():
            raise ControlModelingError("vendor_id is required")
        if not self.name.strip():
            raise ControlModelingError("vendor name is required")


@dataclass(frozen=True, slots=True)
class ControlInstance:
    """ControlInstance table row."""

    control_instance_id: str
    tenant_id: str
    control_id: str
    vendor_id: str
    control_type: ControlType
    name: str
    version: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.control_instance_id.strip():
            raise ControlModelingError("control_instance_id is required")
        if not self.tenant_id.strip():
            raise ControlModelingError("tenant_id is required")
        if not self.control_id.strip():
            raise ControlModelingError("control_id is required")
        if not self.vendor_id.strip():
            raise ControlModelingError("vendor_id is required")
        if not self.name.strip():
            raise ControlModelingError("control instance name is required")


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """DetectionEvent table row."""

    detection_event_id: str
    tenant_id: str
    control_instance_id: str
    vendor_id: str
    alert_id: str
    alert_title: str
    raw_severity: str
    normalized_severity: AlertSeverity
    observed_at: datetime
    technique_ids: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detection_event_id.strip():
            raise ControlModelingError("detection_event_id is required")
        if not self.tenant_id.strip():
            raise ControlModelingError("tenant_id is required")
        if not self.control_instance_id.strip():
            raise ControlModelingError("control_instance_id is required")
        if not self.vendor_id.strip():
            raise ControlModelingError("vendor_id is required")
        if not self.alert_id.strip():
            raise ControlModelingError("alert_id is required")
        if not self.alert_title.strip():
            raise ControlModelingError("alert_title is required")


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_alert_severity(raw_value: str) -> AlertSeverity:
    normalized = raw_value.strip().lower()
    mapping: dict[str, AlertSeverity] = {
        "informational": AlertSeverity.INFO,
        "info": AlertSeverity.INFO,
        "low": AlertSeverity.LOW,
        "warning": AlertSeverity.MEDIUM,
        "medium": AlertSeverity.MEDIUM,
        "moderate": AlertSeverity.MEDIUM,
        "high": AlertSeverity.HIGH,
        "severe": AlertSeverity.HIGH,
        "critical": AlertSeverity.CRITICAL,
        "urgent": AlertSeverity.CRITICAL,
        "p0": AlertSeverity.CRITICAL,
        "p1": AlertSeverity.HIGH,
        "p2": AlertSeverity.MEDIUM,
        "p3": AlertSeverity.LOW,
        "1": AlertSeverity.INFO,
        "2": AlertSeverity.LOW,
        "3": AlertSeverity.MEDIUM,
        "4": AlertSeverity.HIGH,
        "5": AlertSeverity.CRITICAL,
    }
    return mapping.get(normalized, AlertSeverity.MEDIUM)


def _severity_score(severity: AlertSeverity) -> int:
    scores = {
        AlertSeverity.INFO: 1,
        AlertSeverity.LOW: 2,
        AlertSeverity.MEDIUM: 3,
        AlertSeverity.HIGH: 4,
        AlertSeverity.CRITICAL: 5,
    }
    return scores[severity]


class ControlModelingService:
    """In-memory control model and multi-vendor alert normalization layer."""

    def __init__(self) -> None:
        self._vendors: dict[str, ControlVendor] = {}
        self._instances: dict[str, ControlInstance] = {}
        self._events: dict[str, DetectionEvent] = {}
        self._signature_to_techniques: dict[str, tuple[str, ...]] = {}

    def upsert_control_vendor(self, *, vendor_id: str, name: str, product_family: str | None = None) -> ControlVendor:
        row = ControlVendor(vendor_id=vendor_id.strip().lower(), name=name, product_family=product_family)
        self._vendors[row.vendor_id] = row
        return row

    def upsert_control_instance(
        self,
        *,
        control_instance_id: str,
        tenant_id: str,
        control_id: str,
        vendor_id: str,
        control_type: ControlType | str,
        name: str,
        version: str | None = None,
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> ControlInstance:
        vid = vendor_id.strip().lower()
        if vid not in self._vendors:
            raise ControlModelingError("control vendor not found")
        ctype = control_type if isinstance(control_type, ControlType) else ControlType(str(control_type).strip().lower())
        row = ControlInstance(
            control_instance_id=control_instance_id,
            tenant_id=tenant_id,
            control_id=control_id,
            vendor_id=vid,
            control_type=ctype,
            name=name,
            version=version,
            enabled=enabled,
            metadata=dict(metadata or {}),
        )
        self._instances[row.control_instance_id] = row
        return row

    def register_detection_to_technique_mapping(self, *, signature: str, technique_ids: list[str]) -> None:
        key = signature.strip().lower()
        if not key:
            raise ControlModelingError("signature is required")
        parsed = tuple(sorted({item.strip().upper() for item in technique_ids if _TECHNIQUE_PATTERN.fullmatch(item.strip())}))
        if not parsed:
            raise ControlModelingError("at least one valid technique id is required")
        self._signature_to_techniques[key] = parsed

    def normalize_and_record_detection_event(
        self,
        *,
        detection_event_id: str,
        tenant_id: str,
        control_instance_id: str,
        payload: dict[str, Any],
        observed_at: datetime | None = None,
    ) -> DetectionEvent:
        if control_instance_id not in self._instances:
            raise ControlModelingError("control instance not found")
        instance = self._instances[control_instance_id]

        alert_id = (
            _normalize_text(payload.get("alert_id"))
            or _normalize_text(payload.get("id"))
            or detection_event_id
        )
        alert_title = (
            _normalize_text(payload.get("title"))
            or _normalize_text(payload.get("name"))
            or "unnamed alert"
        )
        raw_severity = (
            _normalize_text(payload.get("severity"))
            or _normalize_text(payload.get("priority"))
            or _normalize_text(payload.get("risk_level"))
            or "medium"
        )
        normalized_severity = normalize_alert_severity(raw_severity)
        technique_ids = self._map_detection_to_techniques(payload=payload, alert_title=alert_title)

        event = DetectionEvent(
            detection_event_id=detection_event_id,
            tenant_id=tenant_id,
            control_instance_id=control_instance_id,
            vendor_id=instance.vendor_id,
            alert_id=alert_id,
            alert_title=alert_title,
            raw_severity=raw_severity,
            normalized_severity=normalized_severity,
            observed_at=observed_at or datetime.now(timezone.utc),
            technique_ids=technique_ids,
            payload=dict(payload),
        )
        self._events[event.detection_event_id] = event
        return event

    def _map_detection_to_techniques(self, *, payload: dict[str, Any], alert_title: str) -> tuple[str, ...]:
        explicit = payload.get("technique_ids")
        extracted: set[str] = set()
        if isinstance(explicit, list):
            for value in explicit:
                token = str(value).strip().upper()
                if _TECHNIQUE_PATTERN.fullmatch(token):
                    extracted.add(token)

        blobs = [
            _normalize_text(payload.get("description")),
            _normalize_text(payload.get("rule")),
            _normalize_text(payload.get("signature")),
            alert_title,
        ]
        for blob in blobs:
            for match in _TECHNIQUE_PATTERN.findall(blob):
                extracted.add(match.upper())

        signature = _normalize_text(payload.get("signature")).lower()
        rule = _normalize_text(payload.get("rule")).lower()
        for lookup in (signature, rule):
            if lookup and lookup in self._signature_to_techniques:
                extracted.update(self._signature_to_techniques[lookup])

        return tuple(sorted(extracted))

    def compare_vendor_detection_performance(self, *, tenant_id: str) -> list[dict[str, Any]]:
        aggregate: dict[str, dict[str, Any]] = {}
        for event in self._events.values():
            if event.tenant_id != tenant_id:
                continue
            bucket = aggregate.setdefault(
                event.vendor_id,
                {
                    "vendor_id": event.vendor_id,
                    "vendor_name": self._vendors[event.vendor_id].name,
                    "detections": 0,
                    "mapped_detections": 0,
                    "high_or_critical": 0,
                    "severity_score_total": 0,
                },
            )
            bucket["detections"] += 1
            bucket["severity_score_total"] += _severity_score(event.normalized_severity)
            if event.technique_ids:
                bucket["mapped_detections"] += 1
            if event.normalized_severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}:
                bucket["high_or_critical"] += 1

        results: list[dict[str, Any]] = []
        for row in aggregate.values():
            total = int(row["detections"])
            mapped = int(row["mapped_detections"])
            high_crit = int(row["high_or_critical"])
            avg_severity = float(row["severity_score_total"]) / float(total)
            results.append(
                {
                    "vendor_id": row["vendor_id"],
                    "vendor_name": row["vendor_name"],
                    "detections": total,
                    "mapped_detections": mapped,
                    "mapped_rate": round(mapped / float(total), 4),
                    "high_or_critical_rate": round(high_crit / float(total), 4),
                    "avg_severity_score": round(avg_severity, 4),
                }
            )
        return sorted(results, key=lambda item: (-item["mapped_rate"], -item["avg_severity_score"], item["vendor_id"]))

    @property
    def control_vendors(self) -> dict[str, ControlVendor]:
        return dict(self._vendors)

    @property
    def control_instances(self) -> dict[str, ControlInstance]:
        return dict(self._instances)

    @property
    def detection_events(self) -> dict[str, DetectionEvent]:
        return dict(self._events)

