# Copyright (c) 2026 NyxeraLabs
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

"""Phase 4 Sprint 4.2 tests for exposure intelligence lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from services.exposure_intelligence import ExposureIntelligenceService


class ExposureIntelligenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = ExposureIntelligenceService()
        self.now = datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc)

    def test_service_abstraction_and_fingerprinting(self) -> None:
        endpoint = self.svc.normalize_service_endpoint(
            protocol="TCP",
            port=22,
            service_name="SSH",
            product="OpenSSH",
            version="9.6",
            banner="OpenSSH_9.6",
        )
        self.assertEqual(endpoint.service, "ssh")
        fp = self.svc.service_fingerprint(endpoint)
        self.assertEqual(len(fp), 64)

    def test_misconfiguration_rules_and_scoring(self) -> None:
        endpoint = self.svc.normalize_service_endpoint(protocol="tcp", port=3389, service_name="rdp")
        findings = self.svc.detect_misconfigurations(
            endpoint=endpoint,
            public_exposure=True,
            tls_version="1.0",
            allows_default_credentials=True,
            weak_authentication=True,
        )
        self.assertIn("public_admin_interface", findings)
        self.assertIn("legacy_tls", findings)
        score = self.svc.calculate_exposure_severity(
            endpoint=endpoint,
            misconfigurations=findings,
            public_exposure=True,
            exploitable=True,
            asset_criticality="critical",
        )
        self.assertGreater(score, 0.8)

    def test_exposure_lifecycle_age_and_trend(self) -> None:
        endpoint = self.svc.normalize_service_endpoint(protocol="tcp", port=443, service_name="https")
        first = self.svc.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-1",
            endpoint=endpoint,
            public_exposure=False,
            exploitable=False,
            misconfigurations=(),
            observed_at=self.now,
        )
        second = self.svc.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-1",
            endpoint=endpoint,
            public_exposure=True,
            exploitable=True,
            misconfigurations=("weak_authentication",),
            asset_criticality="high",
            observed_at=self.now + timedelta(days=3),
        )
        self.assertEqual(first.exposure_id, second.exposure_id)
        trend = self.svc.exposure_trend(exposure_id=second.exposure_id)
        self.assertEqual(trend, "increasing")
        age = self.svc.exposure_age_days(
            exposure_id=second.exposure_id,
            reference_time=self.now + timedelta(days=5),
        )
        self.assertEqual(age, 5.0)
        resolved = self.svc.resolve_exposure(
            exposure_id=second.exposure_id,
            resolved_at=self.now + timedelta(days=6),
        )
        self.assertEqual(resolved.status.value, "resolved")
        self.assertEqual(self.svc.exposure_trend(exposure_id=second.exposure_id), "resolved")

    def test_exposure_list_sorted_by_severity(self) -> None:
        ep_low = self.svc.normalize_service_endpoint(protocol="tcp", port=80, service_name="http")
        ep_high = self.svc.normalize_service_endpoint(protocol="tcp", port=3389, service_name="rdp")
        self.svc.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-low",
            endpoint=ep_low,
            public_exposure=False,
            exploitable=False,
            misconfigurations=(),
        )
        self.svc.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-high",
            endpoint=ep_high,
            public_exposure=True,
            exploitable=True,
            misconfigurations=("public_admin_interface",),
            asset_criticality="critical",
        )
        rows = self.svc.list_exposures(tenant_id="tenant-a")
        self.assertEqual(len(rows), 2)
        self.assertGreaterEqual(rows[0].severity_score, rows[1].severity_score)


if __name__ == "__main__":
    unittest.main()
