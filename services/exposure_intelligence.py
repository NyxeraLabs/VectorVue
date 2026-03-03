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

"""Exposure intelligence service (Phase 4 Sprint 4.2)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ExposureError(ValueError):
    """Raised when exposure operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


class ExposureStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


@dataclass(frozen=True, slots=True)
class ServiceEndpoint:
    """Port/service abstraction layer row."""

    protocol: str
    port: int
    service: str
    product: str | None = None
    version: str | None = None
    banner: str | None = None

    def __post_init__(self) -> None:
        if self.protocol not in {"tcp", "udp"}:
            raise ExposureError("protocol must be tcp|udp")
        if self.port <= 0 or self.port > 65535:
            raise ExposureError("port must be 1..65535")
        if not self.service.strip():
            raise ExposureError("service is required")


@dataclass(frozen=True, slots=True)
class ExposureFinding:
    """ExposureFinding table row."""

    exposure_id: str
    tenant_id: str
    asset_id: str
    endpoint: ServiceEndpoint
    fingerprint: str
    severity_score: float
    misconfigurations: tuple[str, ...]
    exploitable: bool
    public_exposure: bool
    first_seen_at: datetime
    last_seen_at: datetime
    status: ExposureStatus = ExposureStatus.OPEN
    score_history: tuple[float, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.exposure_id.strip():
            raise ExposureError("exposure_id is required")
        if not self.tenant_id.strip():
            raise ExposureError("tenant_id is required")
        if not self.asset_id.strip():
            raise ExposureError("asset_id is required")
        if len(self.fingerprint) != 64:
            raise ExposureError("fingerprint must be sha256 hex")
        if self.last_seen_at < self.first_seen_at:
            raise ExposureError("last_seen_at cannot be earlier than first_seen_at")
        if not (0.0 <= self.severity_score <= 1.0):
            raise ExposureError("severity_score must be 0..1")


class ExposureIntelligenceService:
    """In-memory exposure lifecycle model and scoring engine."""

    def __init__(self) -> None:
        self._rows: dict[str, ExposureFinding] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"exposure-{self._counter:06d}"

    def normalize_service_endpoint(
        self,
        *,
        protocol: str,
        port: int,
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
    ) -> ServiceEndpoint:
        proto = protocol.strip().lower()
        svc = (service_name or self._guess_service(port)).strip().lower()
        return ServiceEndpoint(
            protocol=proto,
            port=int(port),
            service=svc,
            product=(product or "").strip() or None,
            version=(version or "").strip() or None,
            banner=(banner or "").strip() or None,
        )

    def service_fingerprint(self, endpoint: ServiceEndpoint) -> str:
        source = "|".join(
            [
                endpoint.protocol,
                str(endpoint.port),
                endpoint.service,
                endpoint.product or "",
                endpoint.version or "",
                endpoint.banner or "",
            ]
        )
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def detect_misconfigurations(
        self,
        *,
        endpoint: ServiceEndpoint,
        public_exposure: bool,
        tls_version: str | None = None,
        allows_default_credentials: bool = False,
        directory_listing_enabled: bool = False,
        weak_authentication: bool = False,
    ) -> tuple[str, ...]:
        findings: set[str] = set()
        admin_ports = {22, 23, 3389, 5985, 5986}
        if public_exposure and endpoint.port in admin_ports:
            findings.add("public_admin_interface")
        if tls_version and tls_version.strip() in {"1.0", "1.1", "ssl3"}:
            findings.add("legacy_tls")
        if allows_default_credentials:
            findings.add("default_credentials")
        if directory_listing_enabled and endpoint.service in {"http", "https"}:
            findings.add("directory_listing")
        if weak_authentication:
            findings.add("weak_authentication")
        return tuple(sorted(findings))

    def calculate_exposure_severity(
        self,
        *,
        endpoint: ServiceEndpoint,
        misconfigurations: tuple[str, ...],
        public_exposure: bool,
        exploitable: bool,
        asset_criticality: str = "medium",
    ) -> float:
        base = 0.12
        service_weight = {
            "rdp": 0.32,
            "ssh": 0.24,
            "http": 0.16,
            "https": 0.18,
            "database": 0.28,
            "smb": 0.30,
        }
        base += service_weight.get(endpoint.service, 0.14)
        base += min(0.25, len(misconfigurations) * 0.06)
        if public_exposure:
            base += 0.12
        if exploitable:
            base += 0.15
        criticality_boost = {
            "low": 0.0,
            "medium": 0.05,
            "high": 0.10,
            "critical": 0.15,
        }
        base += criticality_boost.get(asset_criticality.lower(), 0.05)
        return round(_clamp(base, 0.0, 1.0), 4)

    def upsert_exposure(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        endpoint: ServiceEndpoint,
        public_exposure: bool,
        exploitable: bool,
        misconfigurations: tuple[str, ...],
        asset_criticality: str = "medium",
        observed_at: datetime | None = None,
    ) -> ExposureFinding:
        seen_at = observed_at or datetime.now(timezone.utc)
        fingerprint = self.service_fingerprint(endpoint)
        key = f"{tenant_id}|{asset_id}|{fingerprint}"
        severity = self.calculate_exposure_severity(
            endpoint=endpoint,
            misconfigurations=misconfigurations,
            public_exposure=public_exposure,
            exploitable=exploitable,
            asset_criticality=asset_criticality,
        )
        existing = self._rows.get(key)
        if existing:
            history = existing.score_history + (severity,)
            updated = replace(
                existing,
                severity_score=severity,
                misconfigurations=tuple(sorted(set(existing.misconfigurations).union(misconfigurations))),
                exploitable=exploitable or existing.exploitable,
                public_exposure=public_exposure or existing.public_exposure,
                last_seen_at=seen_at if seen_at > existing.last_seen_at else existing.last_seen_at,
                score_history=history,
                status=ExposureStatus.OPEN if existing.status == ExposureStatus.RESOLVED else existing.status,
            )
            self._rows[key] = updated
            return updated
        row = ExposureFinding(
            exposure_id=self._next_id(),
            tenant_id=tenant_id,
            asset_id=asset_id,
            endpoint=endpoint,
            fingerprint=fingerprint,
            severity_score=severity,
            misconfigurations=tuple(sorted(set(misconfigurations))),
            exploitable=exploitable,
            public_exposure=public_exposure,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
            status=ExposureStatus.OPEN,
            score_history=(severity,),
        )
        self._rows[key] = row
        return row

    def resolve_exposure(self, *, exposure_id: str, resolved_at: datetime | None = None) -> ExposureFinding:
        key, row = self._find(exposure_id)
        at = resolved_at or datetime.now(timezone.utc)
        updated = replace(
            row,
            status=ExposureStatus.RESOLVED,
            last_seen_at=at if at > row.last_seen_at else row.last_seen_at,
        )
        self._rows[key] = updated
        return updated

    def exposure_age_days(self, *, exposure_id: str, reference_time: datetime | None = None) -> float:
        _, row = self._find(exposure_id)
        now = reference_time or datetime.now(timezone.utc)
        seconds = max(0.0, (now - row.first_seen_at).total_seconds())
        return round(seconds / 86400.0, 4)

    def exposure_trend(self, *, exposure_id: str) -> str:
        _, row = self._find(exposure_id)
        if row.status == ExposureStatus.RESOLVED:
            return "resolved"
        if len(row.score_history) <= 1:
            return "new"
        delta = row.score_history[-1] - row.score_history[0]
        if delta >= 0.15:
            return "increasing"
        if delta <= -0.15:
            return "decreasing"
        return "stable"

    def list_exposures(self, *, tenant_id: str) -> list[ExposureFinding]:
        rows = [row for row in self._rows.values() if row.tenant_id == tenant_id]
        return sorted(rows, key=lambda item: (-item.severity_score, item.exposure_id))

    def _find(self, exposure_id: str) -> tuple[str, ExposureFinding]:
        for key, row in self._rows.items():
            if row.exposure_id == exposure_id:
                return key, row
        raise ExposureError("exposure not found")

    @staticmethod
    def _guess_service(port: int) -> str:
        mapping = {
            22: "ssh",
            80: "http",
            443: "https",
            445: "smb",
            1433: "database",
            3306: "database",
            3389: "rdp",
            5432: "database",
        }
        return mapping.get(int(port), "unknown")

