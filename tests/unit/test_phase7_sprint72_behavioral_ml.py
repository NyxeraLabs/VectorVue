"""Phase 7 Sprint 7.2 tests for behavioral + ML anomaly service."""

from __future__ import annotations

import unittest

from services.behavioral_ml import BehavioralMLService


class BehavioralMLServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = BehavioralMLService()

    def test_anomaly_correlation_engine(self) -> None:
        rows = self.svc.correlate_anomalies(
            events=[
                {"asset_id": "host-a", "technique_id": "T1021.002", "observed_at": "2026-03-03T10:00:00Z"},
                {"asset_id": "host-a", "technique_id": "T1021.002", "observed_at": "2026-03-03T10:05:00Z"},
                {"asset_id": "host-a", "technique_id": "T1021.002", "observed_at": "2026-03-03T10:10:00Z"},
                {"asset_id": "host-b", "technique_id": "T1059", "observed_at": "2026-03-03T10:11:00Z"},
            ]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["technique_id"], "T1021.002")
        self.assertGreater(rows[0]["correlation_score"], 0.0)

    def test_baseline_deviation_and_weighting(self) -> None:
        baselines = self.svc.compute_baselines(
            history_by_technique={
                "T1021.002": [3, 4, 3, 5, 4, 3, 4],
                "T1059": [8, 9, 7, 8, 9, 8, 8],
            }
        )
        deviation = self.svc.detection_deviation_score(
            observed_count=12,
            baseline=baselines["T1021.002"],
        )
        self.assertGreater(deviation, 0.0)
        weighted = self.svc.technique_anomaly_weight(
            technique_id="T1021.002",
            deviation_score=deviation,
            tactic_weight=1.2,
        )
        self.assertGreaterEqual(weighted, deviation)
        self.assertLessEqual(weighted, 1.0)

    def test_ml_confidence_adjustment_and_regression_suite(self) -> None:
        baselines = self.svc.compute_baselines(
            history_by_technique={
                "T1003": [1, 1, 1, 2, 1, 1, 1, 1, 2, 1],
                "T1059": [8, 8, 8, 9, 7, 8, 8, 9, 8, 8],
            }
        )
        scored = self.svc.score_current_observations(
            observed_by_technique={"T1003": 7, "T1059": 8},
            baselines=baselines,
            base_confidence_by_technique={"T1003": 0.62, "T1059": 0.62},
            tactic_weight_by_technique={"T1003": 1.3, "T1059": 1.0},
        )
        self.assertEqual(len(scored), 2)
        top = scored[0]
        self.assertEqual(top.technique_id, "T1003")
        self.assertGreater(top.weighted_anomaly_score, scored[1].weighted_anomaly_score)
        self.assertGreaterEqual(top.adjusted_confidence, 0.0)
        self.assertLessEqual(top.adjusted_confidence, 1.0)


if __name__ == "__main__":
    unittest.main()

