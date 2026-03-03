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

import unittest

from services.technique_scoring import TechniqueCoverageService, TechniqueScoringError


class TechniqueScoringRegressionTests(unittest.TestCase):
    def test_detection_presence_and_latency_improve_confidence(self) -> None:
        svc = TechniqueCoverageService()
        baseline = svc.record_execution(
            technique_id="T1059",
            detection_present=False,
            detection_latency_seconds=None,
            alert_quality_weight=0.1,
            response_observed=False,
            containment_observed=False,
        )
        improved = svc.record_execution(
            technique_id="T1059",
            detection_present=True,
            detection_latency_seconds=8,
            alert_quality_weight=0.9,
            response_observed=True,
            containment_observed=True,
        )
        self.assertGreater(improved.confidence_score, baseline.confidence_score)
        self.assertGreater(improved.maturity_index, baseline.maturity_index)

    def test_false_negative_tracking_reduces_scores(self) -> None:
        svc = TechniqueCoverageService()
        svc.record_execution(
            technique_id="T1021",
            detection_present=True,
            detection_latency_seconds=12,
            alert_quality_weight=0.8,
            response_observed=True,
            containment_observed=False,
        )
        initial = svc.get("T1021")
        downgraded = svc.update_false_negative_count(
            technique_id="T1021",
            false_negative_count=3,
        )
        self.assertLess(downgraded.confidence_score, initial.confidence_score)
        self.assertLess(downgraded.maturity_index, initial.maturity_index)

    def test_response_and_containment_flags_are_persisted(self) -> None:
        svc = TechniqueCoverageService()
        row = svc.record_execution(
            technique_id="T1134",
            detection_present=True,
            detection_latency_seconds=22,
            alert_quality_weight=0.7,
            response_observed=True,
            containment_observed=True,
        )
        self.assertTrue(row.response_observed)
        self.assertTrue(row.containment_observed)

    def test_summary_contains_technique_coverage_fields(self) -> None:
        svc = TechniqueCoverageService()
        svc.record_execution(
            technique_id="T1548",
            detection_present=True,
            detection_latency_seconds=6,
            alert_quality_weight=0.85,
            response_observed=True,
            containment_observed=False,
        )
        summary = svc.summary()
        self.assertEqual(len(summary), 1)
        keys = set(summary[0].keys())
        self.assertIn("confidence_score", keys)
        self.assertIn("maturity_index", keys)
        self.assertIn("false_negative_count", keys)

    def test_invalid_technique_id_rejected(self) -> None:
        svc = TechniqueCoverageService()
        with self.assertRaises(TechniqueScoringError):
            svc.ensure_technique("")


if __name__ == "__main__":
    unittest.main()
