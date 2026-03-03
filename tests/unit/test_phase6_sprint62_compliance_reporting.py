"""Phase 6 Sprint 6.2 tests for compliance mapping and reporting."""

from __future__ import annotations

import tempfile
import unittest
import zipfile

from services.compliance_reporting import ComplianceReportingService


class ComplianceReportingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = ComplianceReportingService()

    def test_framework_mapping_validation(self) -> None:
        nist = self.svc.list_control_mappings(framework="NIST")
        iso = self.svc.list_control_mappings(framework="ISO27001")
        soc2 = self.svc.list_control_mappings(framework="SOC2")
        self.assertGreaterEqual(len(nist), 3)
        self.assertGreaterEqual(len(iso), 3)
        self.assertGreaterEqual(len(soc2), 3)
        self.assertEqual(nist[0].framework, "NIST")

    def test_assurance_report_generation_and_signed_export(self) -> None:
        report = self.svc.generate_assurance_report(
            tenant_id="tenant-a",
            framework="NIST",
            period_label="2026-Q1",
            control_states=[
                {"control_id": "CTRL_DETECT_001", "state": "operating"},
                {"control_id": "CTRL_ACCESS_001", "state": "degraded"},
                {"control_id": "CTRL_IR_001", "state": "failed"},
            ],
            analytics_summary={
                "overall_assurance_score": 0.62,
                "residual_risk_score": 0.38,
                "trend": {"trend": "stable"},
            },
        )
        self.assertEqual(report["framework"], "NIST")
        self.assertEqual(report["summary"]["controls_total"], 3)
        self.assertIn("pass_rate", report["summary"])

        with tempfile.TemporaryDirectory() as tmp:
            pkg = self.svc.build_signed_audit_export_package(report=report, output_dir=tmp)
            self.assertTrue(pkg["zip_path"].endswith(".zip"))
            self.assertEqual(len(pkg["report_hash"]), 64)
            with zipfile.ZipFile(pkg["zip_path"], "r") as zf:
                names = set(zf.namelist())
            self.assertEqual(names, {"report.json", "checksums.txt", "signature.txt"})

    def test_multi_cycle_validation_comparison(self) -> None:
        cycle_a = self.svc.generate_assurance_report(
            tenant_id="tenant-a",
            framework="SOC2",
            period_label="2026-01",
            control_states=[],
            analytics_summary={"overall_assurance_score": 0.45, "residual_risk_score": 0.55},
        )
        cycle_b = self.svc.generate_assurance_report(
            tenant_id="tenant-a",
            framework="SOC2",
            period_label="2026-02",
            control_states=[],
            analytics_summary={"overall_assurance_score": 0.60, "residual_risk_score": 0.40},
        )
        comparison = self.svc.compare_validation_cycles(cycle_reports=[cycle_a, cycle_b])
        self.assertEqual(comparison["trend"], "improving")
        self.assertGreater(comparison["delta_assurance"], 0.0)
        self.assertLess(comparison["delta_risk"], 0.0)


if __name__ == "__main__":
    unittest.main()

