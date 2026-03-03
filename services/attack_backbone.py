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

"""MITRE ATT&CK relational backbone and import pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any


class AttackBackboneError(ValueError):
    """Raised when ATT&CK backbone operations fail."""


@dataclass(frozen=True, slots=True)
class AttackTactic:
    tactic_id: str
    name: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    technique_id: str
    name: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class AttackSubTechnique:
    subtechnique_id: str
    technique_id: str
    name: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class TechniqueTacticMapping:
    technique_id: str
    tactic_id: str


@dataclass(frozen=True, slots=True)
class TechniquePlatformMapping:
    technique_id: str
    platform: str


@dataclass(frozen=True, slots=True)
class TechniqueDataSourceMapping:
    technique_id: str
    data_source: str


@dataclass(frozen=True, slots=True)
class TechniqueMitigationMapping:
    technique_id: str
    mitigation: str


@dataclass(frozen=True, slots=True)
class TechniqueDetectionGuidanceMapping:
    technique_id: str
    guidance: str


@dataclass(frozen=True, slots=True)
class AttackSyncSummary:
    tactics: int
    techniques: int
    subtechniques: int
    tactic_mappings: int
    platform_mappings: int
    data_source_mappings: int
    mitigation_mappings: int
    detection_guidance_mappings: int


TACTIC_CATALOG: tuple[AttackTactic, ...] = (
    AttackTactic("TA0001", "Initial Access"),
    AttackTactic("TA0002", "Execution"),
    AttackTactic("TA0003", "Persistence"),
    AttackTactic("TA0004", "Privilege Escalation"),
    AttackTactic("TA0005", "Defense Evasion"),
    AttackTactic("TA0006", "Credential Access"),
    AttackTactic("TA0007", "Discovery"),
    AttackTactic("TA0008", "Lateral Movement"),
    AttackTactic("TA0009", "Collection"),
    AttackTactic("TA0010", "Exfiltration"),
    AttackTactic("TA0011", "Command and Control"),
    AttackTactic("TA0040", "Impact"),
)


# Prefix heuristics aligned with legacy IntelligenceEngine behavior.
TECHNIQUE_PREFIX_TO_TACTIC: dict[str, str] = {
    "T1566": "TA0001",
    "T1059": "TA0002",
    "T1543": "TA0003",
    "T1068": "TA0004",
    "T1003": "TA0006",
    "T1021": "TA0008",
    "T1041": "TA0010",
}


def _normalize_technique_id(value: str) -> str:
    tid = value.strip().upper()
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
        raise AttackBackboneError("invalid technique id")
    return tid


def infer_default_tactic_ids(technique_id: str) -> tuple[str, ...]:
    normalized = _normalize_technique_id(technique_id)
    prefix = normalized.split(".")[0]
    tactic_id = TECHNIQUE_PREFIX_TO_TACTIC.get(prefix)
    return (tactic_id,) if tactic_id else tuple()


class AttackBackboneService:
    """In-memory ATT&CK relational layer with idempotent sync semantics."""

    def __init__(self) -> None:
        self._tactics: dict[str, AttackTactic] = {}
        self._techniques: dict[str, AttackTechnique] = {}
        self._subtechniques: dict[str, AttackSubTechnique] = {}
        self._technique_tactic_map: set[TechniqueTacticMapping] = set()
        self._technique_platform_map: set[TechniquePlatformMapping] = set()
        self._technique_data_source_map: set[TechniqueDataSourceMapping] = set()
        self._technique_mitigation_map: set[TechniqueMitigationMapping] = set()
        self._technique_detection_guidance_map: set[TechniqueDetectionGuidanceMapping] = set()
        for tactic in TACTIC_CATALOG:
            self.upsert_tactic(tactic)

    def upsert_tactic(self, tactic: AttackTactic) -> None:
        self._tactics[tactic.tactic_id] = tactic

    def upsert_technique(self, technique: AttackTechnique) -> None:
        technique_id = _normalize_technique_id(technique.technique_id)
        if "." in technique_id:
            raise AttackBackboneError("subtechnique ids must be inserted via upsert_subtechnique")
        self._techniques[technique_id] = AttackTechnique(
            technique_id=technique_id,
            name=technique.name.strip(),
            description=technique.description.strip(),
        )

    def upsert_subtechnique(self, subtechnique: AttackSubTechnique) -> None:
        subtechnique_id = _normalize_technique_id(subtechnique.subtechnique_id)
        if "." not in subtechnique_id:
            raise AttackBackboneError("subtechnique id must include parent suffix")
        parent = subtechnique_id.split(".")[0]
        if parent != _normalize_technique_id(subtechnique.technique_id).split(".")[0]:
            raise AttackBackboneError("subtechnique parent mismatch")
        if parent not in self._techniques:
            self.upsert_technique(AttackTechnique(technique_id=parent, name=parent))
        self._subtechniques[subtechnique_id] = AttackSubTechnique(
            subtechnique_id=subtechnique_id,
            technique_id=parent,
            name=subtechnique.name.strip(),
            description=subtechnique.description.strip(),
        )

    def link_technique_to_tactic(self, technique_id: str, tactic_id: str) -> None:
        tid = _normalize_technique_id(technique_id).split(".")[0]
        if tid not in self._techniques:
            raise AttackBackboneError("technique not found")
        if tactic_id not in self._tactics:
            raise AttackBackboneError("tactic not found")
        self._technique_tactic_map.add(TechniqueTacticMapping(technique_id=tid, tactic_id=tactic_id))

    def link_technique_to_platform(self, technique_id: str, platform: str) -> None:
        tid = _normalize_technique_id(technique_id).split(".")[0]
        if tid not in self._techniques:
            raise AttackBackboneError("technique not found")
        self._technique_platform_map.add(
            TechniquePlatformMapping(technique_id=tid, platform=platform.strip().lower())
        )

    def link_technique_to_data_source(self, technique_id: str, data_source: str) -> None:
        tid = _normalize_technique_id(technique_id).split(".")[0]
        if tid not in self._techniques:
            raise AttackBackboneError("technique not found")
        self._technique_data_source_map.add(
            TechniqueDataSourceMapping(technique_id=tid, data_source=data_source.strip())
        )

    def link_technique_to_mitigation(self, technique_id: str, mitigation: str) -> None:
        tid = _normalize_technique_id(technique_id).split(".")[0]
        if tid not in self._techniques:
            raise AttackBackboneError("technique not found")
        self._technique_mitigation_map.add(
            TechniqueMitigationMapping(technique_id=tid, mitigation=mitigation.strip())
        )

    def link_technique_to_detection_guidance(self, technique_id: str, guidance: str) -> None:
        tid = _normalize_technique_id(technique_id).split(".")[0]
        if tid not in self._techniques:
            raise AttackBackboneError("technique not found")
        self._technique_detection_guidance_map.add(
            TechniqueDetectionGuidanceMapping(technique_id=tid, guidance=guidance.strip())
        )

    def import_from_reference(
        self,
        *,
        reference_path: Path,
        metadata_by_technique: dict[str, dict[str, list[str]]] | None = None,
    ) -> AttackSyncSummary:
        """Import ATT&CK techniques from `mitre_reference.txt`-style source."""
        metadata_by_technique = metadata_by_technique or {}
        if not reference_path.exists():
            raise AttackBackboneError(f"reference file not found: {reference_path}")

        with reference_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw or "|" not in raw:
                    continue
                parts = raw.split("|")
                if len(parts) < 2:
                    continue
                tid_raw = parts[0].strip()
                name = parts[1].strip()
                description = parts[2].strip() if len(parts) > 2 else ""
                try:
                    tid = _normalize_technique_id(tid_raw)
                except AttackBackboneError:
                    continue

                if "." in tid:
                    parent = tid.split(".")[0]
                    self.upsert_technique(AttackTechnique(technique_id=parent, name=parent))
                    self.upsert_subtechnique(
                        AttackSubTechnique(
                            subtechnique_id=tid,
                            technique_id=parent,
                            name=name,
                            description=description,
                        )
                    )
                    technique_id = parent
                else:
                    self.upsert_technique(
                        AttackTechnique(
                            technique_id=tid,
                            name=name,
                            description=description,
                        )
                    )
                    technique_id = tid

                md = metadata_by_technique.get(technique_id, {})
                tactic_ids = list(dict.fromkeys(md.get("tactics", infer_default_tactic_ids(technique_id))))
                for tactic_id in tactic_ids:
                    if tactic_id in self._tactics:
                        self.link_technique_to_tactic(technique_id, tactic_id)
                for platform in md.get("platforms", []):
                    if platform.strip():
                        self.link_technique_to_platform(technique_id, platform)
                for data_source in md.get("data_sources", []):
                    if data_source.strip():
                        self.link_technique_to_data_source(technique_id, data_source)
                for mitigation in md.get("mitigations", []):
                    if mitigation.strip():
                        self.link_technique_to_mitigation(technique_id, mitigation)
                for guidance in md.get("detection_guidance", []):
                    if guidance.strip():
                        self.link_technique_to_detection_guidance(technique_id, guidance)

        return self.summary()

    def summary(self) -> AttackSyncSummary:
        return AttackSyncSummary(
            tactics=len(self._tactics),
            techniques=len(self._techniques),
            subtechniques=len(self._subtechniques),
            tactic_mappings=len(self._technique_tactic_map),
            platform_mappings=len(self._technique_platform_map),
            data_source_mappings=len(self._technique_data_source_map),
            mitigation_mappings=len(self._technique_mitigation_map),
            detection_guidance_mappings=len(self._technique_detection_guidance_map),
        )

    @property
    def tactics(self) -> dict[str, AttackTactic]:
        return dict(self._tactics)

    @property
    def techniques(self) -> dict[str, AttackTechnique]:
        return dict(self._techniques)

    @property
    def subtechniques(self) -> dict[str, AttackSubTechnique]:
        return dict(self._subtechniques)

    @property
    def technique_tactic_map(self) -> set[TechniqueTacticMapping]:
        return set(self._technique_tactic_map)

    @property
    def technique_platform_map(self) -> set[TechniquePlatformMapping]:
        return set(self._technique_platform_map)

    @property
    def technique_data_source_map(self) -> set[TechniqueDataSourceMapping]:
        return set(self._technique_data_source_map)

    @property
    def technique_mitigation_map(self) -> set[TechniqueMitigationMapping]:
        return set(self._technique_mitigation_map)

    @property
    def technique_detection_guidance_map(self) -> set[TechniqueDetectionGuidanceMapping]:
        return set(self._technique_detection_guidance_map)


def parse_technique_metadata(path: Path) -> dict[str, dict[str, list[str]]]:
    """Parse optional JSON metadata enrichment for ATT&CK import."""
    if not path.exists():
        raise AttackBackboneError(f"metadata file not found: {path}")
    import json

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise AttackBackboneError("metadata root must be JSON object")
    parsed: dict[str, dict[str, list[str]]] = {}
    for tid_raw, fields in raw.items():
        tid = _normalize_technique_id(str(tid_raw)).split(".")[0]
        field_obj = fields if isinstance(fields, dict) else {}
        parsed[tid] = {
            "tactics": [str(v).strip().upper() for v in field_obj.get("tactics", []) if str(v).strip()],
            "platforms": [str(v).strip() for v in field_obj.get("platforms", []) if str(v).strip()],
            "data_sources": [str(v).strip() for v in field_obj.get("data_sources", []) if str(v).strip()],
            "mitigations": [str(v).strip() for v in field_obj.get("mitigations", []) if str(v).strip()],
            "detection_guidance": [
                str(v).strip() for v in field_obj.get("detection_guidance", []) if str(v).strip()
            ],
        }
    return parsed
