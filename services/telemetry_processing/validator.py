# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

"""Canonical telemetry schema + MITRE ATT&CK mapping validation."""

from __future__ import annotations

import html
import re
from enum import Enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SQLI_PATTERNS = [
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
    re.compile(r"\binsert\s+into\b", re.IGNORECASE),
    re.compile(r"\bupdate\s+\w+\s+set\b", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
]


def _sanitize_text(value: str) -> str:
    return html.escape(value.strip(), quote=True)


def _assert_not_injection(value: str) -> None:
    for pattern in SQLI_PATTERNS:
        if pattern.search(value):
            raise ValueError("Potential injection pattern detected")


def _sanitize_recursive(value: Any) -> Any:
    if isinstance(value, str):
        _assert_not_injection(value)
        return _sanitize_text(value)[:2048]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            clean_key = _sanitize_text(str(k))[:80]
            out[clean_key] = _sanitize_recursive(v)
        return out
    if isinstance(value, list):
        return [_sanitize_recursive(item) for item in value]
    return value


class ExecutionLifecycle(str, Enum):
    PLANNED = "planned"
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


ALLOWED_LIFECYCLE_TRANSITIONS: dict[ExecutionLifecycle, set[ExecutionLifecycle]] = {
    ExecutionLifecycle.PLANNED: {ExecutionLifecycle.QUEUED, ExecutionLifecycle.CANCELED},
    ExecutionLifecycle.QUEUED: {ExecutionLifecycle.DISPATCHED, ExecutionLifecycle.CANCELED},
    ExecutionLifecycle.DISPATCHED: {ExecutionLifecycle.RUNNING, ExecutionLifecycle.FAILED, ExecutionLifecycle.CANCELED},
    ExecutionLifecycle.RUNNING: {ExecutionLifecycle.SUCCEEDED, ExecutionLifecycle.FAILED, ExecutionLifecycle.CANCELED},
    ExecutionLifecycle.SUCCEEDED: set(),
    ExecutionLifecycle.FAILED: set(),
    ExecutionLifecycle.CANCELED: set(),
}


def validate_lifecycle_transition(
    previous_state: ExecutionLifecycle | None,
    current_state: ExecutionLifecycle,
) -> None:
    if previous_state is None:
        return
    allowed_targets = ALLOWED_LIFECYCLE_TRANSITIONS.get(previous_state, set())
    if current_state not in allowed_targets:
        raise ValueError(
            f"Invalid execution lifecycle transition: {previous_state.value} -> {current_state.value}"
        )


class ExecutionMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(min_length=1, max_length=128)
    lifecycle_state: ExecutionLifecycle
    previous_lifecycle_state: ExecutionLifecycle | None = None
    started_at: datetime
    completed_at: datetime | None = None
    failure_reason: str | None = Field(default=None, max_length=1024)
    correlation_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_transition_and_timing(self) -> "ExecutionMetadataV2":
        validate_lifecycle_transition(self.previous_lifecycle_state, self.lifecycle_state)
        if self.completed_at and self.completed_at < self.started_at:
            raise ValueError("execution.completed_at cannot be earlier than execution.started_at")
        if self.failure_reason and self.lifecycle_state != ExecutionLifecycle.FAILED:
            raise ValueError("execution.failure_reason is allowed only when lifecycle_state=failed")
        return self


class AssetMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=128)
    asset_ref: str = Field(min_length=1, max_length=512)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    platform: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, max_length=64)


class IdentityMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(min_length=1, max_length=256)
    principal_type: str = Field(min_length=1, max_length=64)
    privilege_level: str = Field(min_length=1, max_length=64)
    account_domain: str | None = Field(default=None, max_length=255)


class TTPMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    tactic_id: str = Field(pattern=r"^TA\d{4}$")
    subtechnique_id: str | None = Field(default=None, pattern=r"^T\d{4}\.\d{3}$")
    procedure: str | None = Field(default=None, max_length=1024)


class DetectionMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: bool
    detection_source: str | None = Field(default=None, max_length=128)
    detection_latency_seconds: int | None = Field(default=None, ge=0)
    alert_id: str | None = Field(default=None, max_length=256)
    alert_severity: str | None = Field(default=None, max_length=32)


class ResponseMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    responded: bool
    response_action: str | None = Field(default=None, max_length=256)
    response_latency_seconds: int | None = Field(default=None, ge=0)
    contained: bool = False
    containment_latency_seconds: int | None = Field(default=None, ge=0)


class ControlMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(min_length=1, max_length=128)
    control_type: str = Field(min_length=1, max_length=64)
    control_vendor: str | None = Field(default=None, max_length=128)
    control_version: str | None = Field(default=None, max_length=64)
    effectiveness_score: float | None = Field(default=None, ge=0.0, le=1.0)


class TelemetryContractV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution: ExecutionMetadataV2
    asset: AssetMetadataV2
    identity: IdentityMetadataV2
    ttp: TTPMetadataV2
    detection: DetectionMetadataV2
    response: ResponseMetadataV2
    control: ControlMetadataV2


class CanonicalTelemetryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    event_type: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    source_system: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    severity: str = Field(min_length=2, max_length=16)
    observed_at: datetime
    mitre_techniques: list[str] = Field(min_length=1, max_length=32)
    mitre_tactics: list[str] = Field(default_factory=list, max_length=32)
    description: str | None = Field(default=None, max_length=2048)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"info", "low", "medium", "high", "critical"}
        if normalized not in allowed:
            raise ValueError("severity must be one of info|low|medium|high|critical")
        return normalized

    @field_validator("mitre_techniques")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or not isinstance(item, str):
                raise ValueError("mitre_techniques entries must be non-empty strings")
            # ATT&CK TTP format: T#### or T####.###
            import re

            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", item.strip().upper()):
                raise ValueError("mitre_techniques entries must match T#### or T####.###")
        return [i.strip().upper() for i in value]

    @field_validator("mitre_tactics")
    @classmethod
    def validate_tactics(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or not isinstance(item, str):
                raise ValueError("mitre_tactics entries must be non-empty strings")
            import re

            if not re.fullmatch(r"TA\d{4}", item.strip().upper()):
                raise ValueError("mitre_tactics entries must match TA####")
        return [i.strip().upper() for i in value]

    @model_validator(mode="after")
    def sanitize_and_block_injection(self) -> "CanonicalTelemetryPayload":
        if self.description:
            _assert_not_injection(self.description)
            self.description = _sanitize_text(self.description)

        clean_attributes: dict[str, Any] = {}
        for key, raw_value in self.attributes.items():
            clean_key = _sanitize_text(str(key))[:80]
            clean_attributes[clean_key] = _sanitize_recursive(raw_value)
        attestation_hash = str(
            clean_attributes.get("attestation_measurement_hash", "")
        ).strip()
        if not re.fullmatch(r"^[a-fA-F0-9]{64}$", attestation_hash):
            raise ValueError(
                "attributes.attestation_measurement_hash must be 64-char sha256 hex"
            )
        self.attributes = clean_attributes
        return self


def validate_canonical_payload(payload: dict) -> CanonicalTelemetryPayload:
    return CanonicalTelemetryPayload.model_validate(payload)


def validate_telemetry_contract_v2(payload: CanonicalTelemetryPayload) -> TelemetryContractV2:
    schema_version = str(payload.attributes.get("schema_version", "")).strip()
    if not schema_version.startswith("2."):
        raise ValueError("contract v2 validation requires schema version 2.x")
    contract_v2 = payload.attributes.get("contract_v2")
    if not isinstance(contract_v2, dict):
        raise ValueError("attributes.contract_v2 must be an object when schema_version is 2.x")
    return TelemetryContractV2.model_validate(contract_v2)
