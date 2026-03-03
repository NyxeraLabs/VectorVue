"""Phase 3 Sprint 3.2 tests for SOC and IR readiness metrics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from services.soc_ir_readiness import ResponseStatus, SocIrReadinessService


class SocIrReadinessServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SocIrReadinessService()
        self.now = datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc)

    def test_timing_metrics_and_escalation_timeline(self) -> None:
        signal = self.now
        detected = self.now + timedelta(minutes=5)
        acknowledged = detected + timedelta(minutes=3)
        responded = detected + timedelta(minutes=12)
        contained = detected + timedelta(minutes=30)
        closed = detected + timedelta(minutes=45)
        self.service.upsert_response_action(
            response_action_id="ra-1",
            tenant_id="tenant-a",
            detection_event_id="evt-1",
            action_type="isolate_host",
            owner="soc-l1",
            status=ResponseStatus.CLOSED,
            signal_observed_at=signal,
            detected_at=detected,
            acknowledged_at=acknowledged,
            responded_at=responded,
            contained_at=contained,
            closed_at=closed,
            sla_target_minutes=20,
        )
        self.assertEqual(self.service.time_to_detect_minutes(response_action_id="ra-1"), 5.0)
        self.assertEqual(self.service.time_to_respond_minutes(response_action_id="ra-1"), 12.0)
        self.assertEqual(self.service.time_to_contain_minutes(response_action_id="ra-1"), 30.0)
        timeline = self.service.escalation_timeline(response_action_id="ra-1")
        stages = [row["stage"] for row in timeline]
        self.assertEqual(stages, ["signal_observed", "detected", "acknowledged", "responded", "contained", "closed"])

    def test_sla_violation_logic_for_open_and_late_response(self) -> None:
        signal = self.now
        detected = self.now + timedelta(minutes=2)
        self.service.upsert_response_action(
            response_action_id="ra-open",
            tenant_id="tenant-a",
            detection_event_id="evt-2",
            action_type="triage_alert",
            owner="soc-l1",
            status=ResponseStatus.OPEN,
            signal_observed_at=signal,
            detected_at=detected,
            sla_target_minutes=15,
        )
        verdict_open = self.service.detect_sla_violation(
            response_action_id="ra-open",
            reference_time=detected + timedelta(minutes=40),
        )
        self.assertTrue(verdict_open["breached"])
        self.assertEqual(verdict_open["reason"], "open_timeout")

        self.service.upsert_response_action(
            response_action_id="ra-late",
            tenant_id="tenant-a",
            detection_event_id="evt-3",
            action_type="block_ioc",
            owner="soc-l2",
            status=ResponseStatus.RESPONDED,
            signal_observed_at=signal,
            detected_at=detected,
            responded_at=detected + timedelta(minutes=21),
            sla_target_minutes=20,
        )
        verdict_late = self.service.detect_sla_violation(response_action_id="ra-late")
        self.assertTrue(verdict_late["breached"])
        self.assertEqual(verdict_late["reason"], "response_timeout")

    def test_soc_effectiveness_and_ir_readiness_scores(self) -> None:
        base = self.now
        self.service.upsert_response_action(
            response_action_id="ra-good-1",
            tenant_id="tenant-a",
            detection_event_id="evt-g1",
            action_type="isolate_host",
            owner="soc-l2",
            status=ResponseStatus.CONTAINED,
            signal_observed_at=base,
            detected_at=base + timedelta(minutes=4),
            responded_at=base + timedelta(minutes=10),
            contained_at=base + timedelta(minutes=24),
            sla_target_minutes=25,
        )
        self.service.upsert_response_action(
            response_action_id="ra-good-2",
            tenant_id="tenant-a",
            detection_event_id="evt-g2",
            action_type="disable_account",
            owner="ir",
            status=ResponseStatus.RESPONDED,
            signal_observed_at=base,
            detected_at=base + timedelta(minutes=6),
            responded_at=base + timedelta(minutes=18),
            sla_target_minutes=20,
        )
        self.service.upsert_response_action(
            response_action_id="ra-bad",
            tenant_id="tenant-a",
            detection_event_id="evt-b1",
            action_type="manual_triage",
            owner="soc-l1",
            status=ResponseStatus.OPEN,
            signal_observed_at=base,
            detected_at=base + timedelta(minutes=30),
            sla_target_minutes=15,
        )
        soc = self.service.soc_effectiveness_index(tenant_id="tenant-a")
        ir = self.service.ir_readiness_composite_score(tenant_id="tenant-a")
        self.assertGreaterEqual(soc, 0.0)
        self.assertLessEqual(soc, 1.0)
        self.assertGreaterEqual(ir, 0.0)
        self.assertLessEqual(ir, 1.0)
        violations = self.service.list_sla_violations(
            tenant_id="tenant-a",
            reference_time=base + timedelta(minutes=90),
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["response_action_id"], "ra-bad")


if __name__ == "__main__":
    unittest.main()

