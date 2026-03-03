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

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from services.attack_backbone import (
    AttackBackboneService,
    TechniqueDataSourceMapping,
    TechniqueDetectionGuidanceMapping,
    TechniqueMitigationMapping,
    TechniquePlatformMapping,
    TechniqueTacticMapping,
)


class AttackBackboneSyncTests(unittest.TestCase):
    @staticmethod
    def _extract_ids_from_reference(path: Path) -> set[str]:
        ids: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            parts = line.split("|")
            if not parts:
                continue
            ids.add(parts[0].strip().upper())
        return ids

    def _reference_file(self) -> Path:
        tmp = tempfile.NamedTemporaryFile(prefix="attack_ref_", suffix=".txt", delete=False)
        tmp.write(
            (
                "T1059|Command and Scripting Interpreter|Execution via command shell\n"
                "T1059.001|PowerShell|PowerShell sub-technique\n"
                "T1021|Remote Services|Lateral movement through remote services\n"
            ).encode("utf-8")
        )
        tmp.flush()
        tmp.close()
        return Path(tmp.name)

    def test_import_creates_tactic_technique_and_subtechnique_tables(self) -> None:
        service = AttackBackboneService()
        path = self._reference_file()
        summary = service.import_from_reference(reference_path=path)

        self.assertGreaterEqual(summary.tactics, 12)
        self.assertIn("T1059", service.techniques)
        self.assertIn("T1021", service.techniques)
        self.assertIn("T1059.001", service.subtechniques)
        self.assertIn(
            TechniqueTacticMapping(technique_id="T1059", tactic_id="TA0002"),
            service.technique_tactic_map,
        )
        self.assertIn(
            TechniqueTacticMapping(technique_id="T1021", tactic_id="TA0008"),
            service.technique_tactic_map,
        )

    def test_import_populates_platform_data_source_mitigation_and_detection_guidance(self) -> None:
        service = AttackBackboneService()
        path = self._reference_file()
        metadata = {
            "T1059": {
                "tactics": ["TA0002"],
                "platforms": ["windows", "linux"],
                "data_sources": ["process monitoring"],
                "mitigations": ["application control"],
                "detection_guidance": ["alert on suspicious shell parent-child lineage"],
            }
        }
        service.import_from_reference(reference_path=path, metadata_by_technique=metadata)

        self.assertIn(
            TechniquePlatformMapping(technique_id="T1059", platform="windows"),
            service.technique_platform_map,
        )
        self.assertIn(
            TechniqueDataSourceMapping(technique_id="T1059", data_source="process monitoring"),
            service.technique_data_source_map,
        )
        self.assertIn(
            TechniqueMitigationMapping(technique_id="T1059", mitigation="application control"),
            service.technique_mitigation_map,
        )
        self.assertIn(
            TechniqueDetectionGuidanceMapping(
                technique_id="T1059",
                guidance="alert on suspicious shell parent-child lineage",
            ),
            service.technique_detection_guidance_map,
        )

    def test_sync_is_idempotent(self) -> None:
        service = AttackBackboneService()
        path = self._reference_file()
        first = service.import_from_reference(reference_path=path)
        second = service.import_from_reference(reference_path=path)

        self.assertEqual(first.techniques, second.techniques)
        self.assertEqual(first.subtechniques, second.subtechniques)
        self.assertEqual(first.tactic_mappings, second.tactic_mappings)

    def test_real_reference_file_alignment_is_complete(self) -> None:
        service = AttackBackboneService()
        reference = Path(__file__).resolve().parents[2] / "mitre_reference.txt"
        expected_ids = self._extract_ids_from_reference(reference)
        summary = service.import_from_reference(reference_path=reference)

        imported_ids = set(service.techniques.keys()) | set(service.subtechniques.keys())
        self.assertEqual(imported_ids, expected_ids)
        self.assertEqual(summary.techniques + summary.subtechniques, len(expected_ids))


if __name__ == "__main__":
    unittest.main()
