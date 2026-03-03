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

"""ASM to adversary bridge service (Phase 4 Sprint 4.3)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from services.exposure_intelligence import ExposureFinding


class AsmAdversaryBridgeError(ValueError):
    """Raised when bridge operations fail."""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


@dataclass(frozen=True, slots=True)
class ExposureTechniqueMapping:
    exposure_id: str
    asset_id: str
    technique_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttackPathStep:
    asset_id: str
    exposure_id: str
    technique_id: str
    probability: float
    rationale: str


@dataclass(frozen=True, slots=True)
class AttackPath:
    """Automated attack path row."""

    path_id: str
    tenant_id: str
    steps: tuple[AttackPathStep, ...]
    composite_risk: float
    initial_access_probability: float
    metadata: dict[str, Any] = field(default_factory=dict)


class AsmAdversaryBridgeService:
    """Translate ASM exposures into adversary-centric path and campaign suggestions."""

    def __init__(self) -> None:
        self._service_to_techniques: dict[str, tuple[str, ...]] = {
            "rdp": ("T1133", "T1021.001"),
            "ssh": ("T1133", "T1021.004"),
            "smb": ("T1021.002", "T1550.002"),
            "http": ("T1190",),
            "https": ("T1190",),
            "database": ("T1190", "T1078"),
        }
        self._misconfig_to_techniques: dict[str, tuple[str, ...]] = {
            "default_credentials": ("T1078",),
            "weak_authentication": ("T1110",),
            "public_admin_interface": ("T1133",),
            "directory_listing": ("T1083",),
            "legacy_tls": ("T1190",),
        }

    def map_exposure_to_techniques(self, exposure: ExposureFinding) -> ExposureTechniqueMapping:
        techniques: set[str] = set()
        techniques.update(self._service_to_techniques.get(exposure.endpoint.service, tuple()))
        for item in exposure.misconfigurations:
            techniques.update(self._misconfig_to_techniques.get(item, tuple()))
        if not techniques:
            techniques.add("T1595")
        ordered = tuple(sorted(techniques))
        return ExposureTechniqueMapping(
            exposure_id=exposure.exposure_id,
            asset_id=exposure.asset_id,
            technique_ids=ordered,
        )

    def initial_access_probability(
        self,
        *,
        exposure: ExposureFinding,
        mapped_techniques: tuple[str, ...] | None = None,
    ) -> float:
        techniques = mapped_techniques or self.map_exposure_to_techniques(exposure).technique_ids
        base = exposure.severity_score * 0.55
        base += 0.20 if exposure.public_exposure else 0.0
        base += 0.20 if exposure.exploitable else 0.0
        base += min(0.12, len(exposure.misconfigurations) * 0.03)
        base += min(0.08, len(techniques) * 0.01)
        return round(_clamp(base, 0.0, 1.0), 4)

    def build_attack_path(self, *, tenant_id: str, exposures: list[ExposureFinding]) -> AttackPath:
        candidates = [item for item in exposures if item.tenant_id == tenant_id]
        if not candidates:
            raise AsmAdversaryBridgeError("no exposures for tenant")
        scored: list[tuple[ExposureFinding, tuple[str, ...], float]] = []
        for row in candidates:
            mapping = self.map_exposure_to_techniques(row).technique_ids
            probability = self.initial_access_probability(exposure=row, mapped_techniques=mapping)
            scored.append((row, mapping, probability))
        scored.sort(key=lambda item: item[2], reverse=True)
        selected = scored[:3]
        steps: list[AttackPathStep] = []
        for row, mapping, probability in selected:
            for technique_id in mapping[:2]:
                steps.append(
                    AttackPathStep(
                        asset_id=row.asset_id,
                        exposure_id=row.exposure_id,
                        technique_id=technique_id,
                        probability=probability,
                        rationale=f"Derived from {row.endpoint.service} exposure and misconfiguration context",
                    )
                )
        initial_access = selected[0][2]
        avg_prob = sum(item[2] for item in selected) / float(len(selected))
        avg_severity = sum(item[0].severity_score for item in selected) / float(len(selected))
        composite = _clamp((avg_prob * 0.55) + (avg_severity * 0.45), 0.0, 1.0)
        pid_seed = "|".join(f"{item[0].exposure_id}:{item[2]}" for item in selected)
        path_id = hashlib.sha256(f"{tenant_id}|{pid_seed}".encode("utf-8")).hexdigest()[:16]
        return AttackPath(
            path_id=f"path-{path_id}",
            tenant_id=tenant_id,
            steps=tuple(steps),
            composite_risk=round(composite, 4),
            initial_access_probability=round(initial_access, 4),
            metadata={
                "source_exposure_count": len(selected),
                "candidate_exposure_count": len(candidates),
            },
        )

    def attack_surface_risk_index(self, *, tenant_id: str, exposures: list[ExposureFinding]) -> float:
        rows = [item for item in exposures if item.tenant_id == tenant_id]
        if not rows:
            return 0.0
        probabilities = [self.initial_access_probability(exposure=row) for row in rows]
        severities = [row.severity_score for row in rows]
        exploitability_rate = sum(1.0 for row in rows if row.exploitable) / float(len(rows))
        public_rate = sum(1.0 for row in rows if row.public_exposure) / float(len(rows))
        score = (
            (sum(probabilities) / float(len(probabilities))) * 0.45
            + (sum(severities) / float(len(severities))) * 0.30
            + exploitability_rate * 0.15
            + public_rate * 0.10
        )
        return round(_clamp(score, 0.0, 1.0), 4)

    def suggest_campaigns(self, *, tenant_id: str, exposures: list[ExposureFinding]) -> list[dict[str, Any]]:
        if not [item for item in exposures if item.tenant_id == tenant_id]:
            return []
        path = self.build_attack_path(tenant_id=tenant_id, exposures=exposures)
        risk_index = self.attack_surface_risk_index(tenant_id=tenant_id, exposures=exposures)
        objective = "Validate external attack path and lateral expansion controls"
        technique_chain = [step.technique_id for step in path.steps]
        suggestion = {
            "campaign_id": f"cmp-{path.path_id}",
            "tenant_id": tenant_id,
            "objective": objective,
            "seed_path_id": path.path_id,
            "initial_access_probability": path.initial_access_probability,
            "attack_surface_risk_index": risk_index,
            "composite_path_risk": path.composite_risk,
            "technique_chain": technique_chain,
            "priority": "high" if risk_index >= 0.7 else "medium",
        }
        return [suggestion]

