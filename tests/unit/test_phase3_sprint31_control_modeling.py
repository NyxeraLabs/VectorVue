# Copyright (c) 2026 NyxeraLabs
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

"""Phase 3 Sprint 3.1 tests for control modeling and detection normalization."""

from __future__ import annotations

import unittest

from services.control_modeling import ControlModelingService, ControlType, normalize_alert_severity


class ControlModelingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = ControlModelingService()
        self.service.upsert_control_vendor(vendor_id="crowdstrike", name="CrowdStrike")
        self.service.upsert_control_vendor(vendor_id="microsoft", name="Microsoft Defender")
        self.service.upsert_control_instance(
            control_instance_id="ctrl-inst-1",
            tenant_id="tenant-a",
            control_id="CTRL-EDR-001",
            vendor_id="crowdstrike",
            control_type=ControlType.DETECTIVE,
            name="Falcon Sensor",
        )
        self.service.upsert_control_instance(
            control_instance_id="ctrl-inst-2",
            tenant_id="tenant-a",
            control_id="CTRL-XDR-001",
            vendor_id="microsoft",
            control_type=ControlType.DETECTIVE,
            name="Defender XDR",
        )

    def test_alert_severity_normalization(self) -> None:
        self.assertEqual(normalize_alert_severity("informational").value, "info")
        self.assertEqual(normalize_alert_severity("p1").value, "high")
        self.assertEqual(normalize_alert_severity("5").value, "critical")
        self.assertEqual(normalize_alert_severity("unknown").value, "medium")

    def test_normalization_maps_techniques_from_payload_and_text(self) -> None:
        event = self.service.normalize_and_record_detection_event(
            detection_event_id="evt-001",
            tenant_id="tenant-a",
            control_instance_id="ctrl-inst-1",
            payload={
                "id": "alert-1",
                "title": "Suspicious command execution T1059",
                "severity": "severe",
                "description": "Observed behavior linked to T1059.001 and persistence",
                "technique_ids": ["T1021", "invalid"],
            },
        )
        self.assertEqual(event.normalized_severity.value, "high")
        self.assertEqual(event.alert_id, "alert-1")
        self.assertEqual(event.vendor_id, "crowdstrike")
        self.assertEqual(event.technique_ids, ("T1021", "T1059", "T1059.001"))

    def test_signature_mapping_is_applied_when_payload_has_no_ttp(self) -> None:
        self.service.register_detection_to_technique_mapping(
            signature="lsass-memory-read",
            technique_ids=["T1003.001", "T1003"],
        )
        event = self.service.normalize_and_record_detection_event(
            detection_event_id="evt-002",
            tenant_id="tenant-a",
            control_instance_id="ctrl-inst-1",
            payload={
                "alert_id": "alert-2",
                "name": "Credential access attempt",
                "priority": "P0",
                "signature": "lsass-memory-read",
            },
        )
        self.assertEqual(event.normalized_severity.value, "critical")
        self.assertEqual(event.technique_ids, ("T1003", "T1003.001"))

    def test_vendor_performance_comparison(self) -> None:
        self.service.normalize_and_record_detection_event(
            detection_event_id="evt-003",
            tenant_id="tenant-a",
            control_instance_id="ctrl-inst-1",
            payload={
                "id": "a-3",
                "title": "Scripting behavior T1059",
                "severity": "high",
            },
        )
        self.service.normalize_and_record_detection_event(
            detection_event_id="evt-004",
            tenant_id="tenant-a",
            control_instance_id="ctrl-inst-2",
            payload={
                "id": "a-4",
                "title": "Suspicious process launch",
                "risk_level": "low",
            },
        )
        rankings = self.service.compare_vendor_detection_performance(tenant_id="tenant-a")
        self.assertEqual(len(rankings), 2)
        self.assertEqual(rankings[0]["vendor_id"], "crowdstrike")
        self.assertGreater(rankings[0]["mapped_rate"], rankings[1]["mapped_rate"])


if __name__ == "__main__":
    unittest.main()
