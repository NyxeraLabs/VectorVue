# Copyright (c) 2026 NyxeraLabs
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

"""Phase 6 Sprint 6.1 tests for coverage analytics engine."""

from __future__ import annotations

import unittest

from services.coverage_analytics import CoverageAnalyticsService


class CoverageAnalyticsServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = CoverageAnalyticsService()
        self.technique_rows = [
            {
                "technique_id": "T1078",
                "detection_present": True,
                "execution_count": 4,
                "confidence_score": 0.86,
                "maturity_index": 0.82,
            },
            {
                "technique_id": "T1021.002",
                "detection_present": True,
                "execution_count": 3,
                "confidence_score": 0.70,
                "maturity_index": 0.68,
            },
            {
                "technique_id": "T1059",
                "detection_present": False,
                "execution_count": 2,
                "confidence_score": 0.45,
                "maturity_index": 0.40,
            },
        ]

    def test_heatmap_and_technique_tactic_scores(self) -> None:
        metrics = self.svc.build_technique_metrics(technique_rows=self.technique_rows)
        heatmap = self.svc.generate_attack_heatmap(technique_metrics=metrics)
        tech_scores = self.svc.technique_level_coverage_score(technique_metrics=metrics)
        tactic_scores = self.svc.tactic_level_coverage_score(technique_metrics=metrics)
        self.assertIn("T1078", tech_scores)
        self.assertTrue(any("T1078" in bucket for bucket in heatmap.values()))
        self.assertGreaterEqual(len(tactic_scores), 1)

    def test_detection_effectiveness_and_control_reliability(self) -> None:
        metrics = self.svc.build_technique_metrics(technique_rows=self.technique_rows)
        de_index = self.svc.detection_effectiveness_index(technique_metrics=metrics)
        reliability = self.svc.control_reliability_score(
            control_state_rows=[
                {"state": "operating", "failure_rate": 0.05, "coverage_percent": 92},
                {"state": "degraded", "failure_rate": 0.20, "coverage_percent": 78},
                {"state": "failed", "failure_rate": 0.60, "coverage_percent": 35},
            ]
        )
        self.assertGreaterEqual(de_index, 0.0)
        self.assertLessEqual(de_index, 1.0)
        self.assertGreaterEqual(reliability, 0.0)
        self.assertLessEqual(reliability, 1.0)

    def test_historical_trend_and_executive_summary(self) -> None:
        metrics = self.svc.build_technique_metrics(technique_rows=self.technique_rows)
        trend = self.svc.historical_trend_comparison(
            snapshots=[
                {"cycle": "2026-01", "overall_score": 0.49},
                {"cycle": "2026-02", "overall_score": 0.54},
                {"cycle": "2026-03", "overall_score": 0.58},
            ]
        )
        summary = self.svc.executive_risk_summary(
            technique_metrics=metrics,
            control_reliability=0.67,
            trend=trend,
        )
        self.assertEqual(trend["trend"], "improving")
        self.assertIn("overall_assurance_score", summary)
        self.assertIn("residual_risk_score", summary)
        self.assertEqual(summary["technique_count"], 3)


if __name__ == "__main__":
    unittest.main()
