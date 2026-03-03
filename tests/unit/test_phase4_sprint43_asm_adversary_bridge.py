"""Phase 4 Sprint 4.3 tests for ASM to adversary bridge."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from services.asm_adversary_bridge import AsmAdversaryBridgeService
from services.exposure_intelligence import ExposureIntelligenceService


class AsmAdversaryBridgeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.exposure = ExposureIntelligenceService()
        self.bridge = AsmAdversaryBridgeService()
        self.now = datetime(2026, 3, 3, 13, 0, 0, tzinfo=timezone.utc)

    def _sample_exposures(self) -> list:
        ep1 = self.exposure.normalize_service_endpoint(protocol="tcp", port=3389, service_name="rdp")
        ep2 = self.exposure.normalize_service_endpoint(protocol="tcp", port=443, service_name="https")
        ep3 = self.exposure.normalize_service_endpoint(protocol="tcp", port=22, service_name="ssh")
        f1 = self.exposure.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-a",
            endpoint=ep1,
            public_exposure=True,
            exploitable=True,
            misconfigurations=("public_admin_interface", "weak_authentication"),
            asset_criticality="critical",
            observed_at=self.now,
        )
        f2 = self.exposure.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-b",
            endpoint=ep2,
            public_exposure=True,
            exploitable=False,
            misconfigurations=("legacy_tls",),
            asset_criticality="high",
            observed_at=self.now,
        )
        f3 = self.exposure.upsert_exposure(
            tenant_id="tenant-a",
            asset_id="asset-c",
            endpoint=ep3,
            public_exposure=False,
            exploitable=True,
            misconfigurations=("default_credentials",),
            asset_criticality="medium",
            observed_at=self.now,
        )
        return [f1, f2, f3]

    def test_exposure_to_technique_mapping_engine(self) -> None:
        rows = self._sample_exposures()
        mapped = self.bridge.map_exposure_to_techniques(rows[0])
        self.assertIn("T1133", mapped.technique_ids)
        self.assertIn("T1110", mapped.technique_ids)

    def test_initial_access_probability_scoring(self) -> None:
        rows = self._sample_exposures()
        high = self.bridge.initial_access_probability(exposure=rows[0])
        low = self.bridge.initial_access_probability(exposure=rows[1])
        self.assertGreater(high, low)
        self.assertGreaterEqual(high, 0.0)
        self.assertLessEqual(high, 1.0)

    def test_automated_attack_path_builder_and_risk_index(self) -> None:
        rows = self._sample_exposures()
        path = self.bridge.build_attack_path(tenant_id="tenant-a", exposures=rows)
        self.assertTrue(path.path_id.startswith("path-"))
        self.assertGreater(len(path.steps), 0)
        risk = self.bridge.attack_surface_risk_index(tenant_id="tenant-a", exposures=rows)
        self.assertGreaterEqual(risk, 0.0)
        self.assertLessEqual(risk, 1.0)

    def test_campaign_suggestion_engine(self) -> None:
        rows = self._sample_exposures()
        suggestions = self.bridge.suggest_campaigns(tenant_id="tenant-a", exposures=rows)
        self.assertEqual(len(suggestions), 1)
        first = suggestions[0]
        self.assertIn("campaign_id", first)
        self.assertGreater(len(first["technique_chain"]), 0)


if __name__ == "__main__":
    unittest.main()

