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

"""Compliance mapping and assurance reporting service (Phase 6 Sprint 6.2)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ComplianceReportingError(ValueError):
    """Raised when compliance reporting operations fail."""


@dataclass(frozen=True, slots=True)
class AssuranceControlMapping:
    framework: str
    control_id: str
    requirement_ref: str
    title: str
    domain: str


_MAPPING_CATALOG: dict[str, tuple[AssuranceControlMapping, ...]] = {
    "NIST": (
        AssuranceControlMapping("NIST", "CTRL_DETECT_001", "DE.CM-1", "Detection Logging Coverage", "monitoring"),
        AssuranceControlMapping("NIST", "CTRL_ACCESS_001", "PR.AC-4", "Privileged Access Accountability", "identity"),
        AssuranceControlMapping("NIST", "CTRL_IR_001", "RS.MI-1", "Incident Response Timeliness", "response"),
    ),
    "ISO27001": (
        AssuranceControlMapping("ISO27001", "CTRL_DETECT_001", "A.8.16", "Detection Logging Coverage", "monitoring"),
        AssuranceControlMapping("ISO27001", "CTRL_ACCESS_001", "A.5.16", "Privileged Access Accountability", "identity"),
        AssuranceControlMapping("ISO27001", "CTRL_EVID_001", "A.5.33", "Evidence Integrity Chain", "governance"),
    ),
    "SOC2": (
        AssuranceControlMapping("SOC2", "CTRL_MON_001", "CC7.2", "Continuous Monitoring Discipline", "monitoring"),
        AssuranceControlMapping("SOC2", "CTRL_IR_001", "CC7.4", "Incident Response Timeliness", "response"),
        AssuranceControlMapping("SOC2", "CTRL_EVID_001", "CC6.6", "Evidence Integrity Chain", "governance"),
    ),
}


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _signing_key() -> str:
    return os.environ.get("VV_COMPLIANCE_SIGNING_KEY", os.environ.get("VV_AUTH_SECRET", "vectorvue-compliance-dev-key"))


def _hmac(raw: str) -> str:
    return hmac.new(_signing_key().encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


class ComplianceReportingService:
    """Compliance mapping, reporting, and signed export utility service."""

    def list_control_mappings(self, *, framework: str) -> list[AssuranceControlMapping]:
        key = framework.strip().upper()
        if key not in _MAPPING_CATALOG:
            raise ComplianceReportingError("framework mapping not found")
        return list(_MAPPING_CATALOG[key])

    def generate_assurance_report(
        self,
        *,
        tenant_id: str,
        framework: str,
        control_states: list[dict[str, Any]],
        analytics_summary: dict[str, Any],
        period_label: str,
    ) -> dict[str, Any]:
        mappings = self.list_control_mappings(framework=framework)
        state_index = {
            str(row.get("control_id", "")).strip().upper(): str(row.get("state", "insufficient_evidence")).strip().lower()
            for row in control_states
        }
        control_rows: list[dict[str, Any]] = []
        passed = 0
        degraded = 0
        failed = 0
        for mapping in mappings:
            state = state_index.get(mapping.control_id, "insufficient_evidence")
            if state == "operating":
                passed += 1
            elif state == "degraded":
                degraded += 1
            elif state == "failed":
                failed += 1
            control_rows.append(
                {
                    "framework": mapping.framework,
                    "control_id": mapping.control_id,
                    "requirement_ref": mapping.requirement_ref,
                    "title": mapping.title,
                    "domain": mapping.domain,
                    "state": state,
                }
            )

        total = len(control_rows)
        pass_rate = (passed / float(total)) if total else 0.0
        coverage_score = float(analytics_summary.get("overall_assurance_score", 0.0))
        residual_risk = float(analytics_summary.get("residual_risk_score", 1.0))
        report = {
            "report_id": _sha256(f"{tenant_id}|{framework}|{period_label}|{datetime.now(timezone.utc).isoformat()}")[:16],
            "tenant_id": tenant_id,
            "framework": framework.strip().upper(),
            "period": period_label,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "controls_total": total,
                "controls_operating": passed,
                "controls_degraded": degraded,
                "controls_failed": failed,
                "pass_rate": round(pass_rate, 4),
                "overall_assurance_score": round(coverage_score, 4),
                "residual_risk_score": round(residual_risk, 4),
            },
            "controls": control_rows,
            "analytics": dict(analytics_summary),
        }
        return report

    def build_signed_audit_export_package(
        self,
        *,
        report: dict[str, Any],
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        payload_json = _canonical_json(report)
        report_hash = _sha256(payload_json)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        base_dir = Path(output_dir or os.environ.get("VV_COMPLIANCE_EXPORT_DIR", "/tmp/vectorvue_compliance_exports"))
        base_dir.mkdir(parents=True, exist_ok=True)
        temp_dir = Path(tempfile.mkdtemp(prefix="assurance_export_", dir=str(base_dir)))

        (temp_dir / "report.json").write_text(payload_json, encoding="utf-8")
        checksums = {"report.json": report_hash}
        checksums_txt = "\n".join(f"{k}={v}" for k, v in checksums.items()) + "\n"
        (temp_dir / "checksums.txt").write_text(checksums_txt, encoding="utf-8")
        signature = _hmac(checksums_txt)
        (temp_dir / "signature.txt").write_text(signature, encoding="utf-8")

        zip_path = base_dir / f"assurance_{report.get('tenant_id', 'tenant')}_{report.get('framework', 'framework')}_{timestamp}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(temp_dir / "report.json", arcname="report.json")
            zf.write(temp_dir / "checksums.txt", arcname="checksums.txt")
            zf.write(temp_dir / "signature.txt", arcname="signature.txt")

        return {
            "zip_path": str(zip_path),
            "report_hash": report_hash,
            "signature": signature,
            "checksums": checksums,
        }

    def compare_validation_cycles(
        self,
        *,
        cycle_reports: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if len(cycle_reports) < 2:
            return {"trend": "insufficient_data", "delta_assurance": 0.0, "delta_risk": 0.0, "cycles": cycle_reports}
        ordered = sorted(cycle_reports, key=lambda item: str(item.get("period", "")))
        first = ordered[0]
        last = ordered[-1]
        first_assurance = float(first.get("summary", {}).get("overall_assurance_score", 0.0))
        last_assurance = float(last.get("summary", {}).get("overall_assurance_score", 0.0))
        first_risk = float(first.get("summary", {}).get("residual_risk_score", 1.0))
        last_risk = float(last.get("summary", {}).get("residual_risk_score", 1.0))
        delta_assurance = round(last_assurance - first_assurance, 4)
        delta_risk = round(last_risk - first_risk, 4)
        if delta_assurance >= 0.05 and delta_risk <= -0.05:
            trend = "improving"
        elif delta_assurance <= -0.05 and delta_risk >= 0.05:
            trend = "regressing"
        else:
            trend = "mixed"
        return {
            "trend": trend,
            "delta_assurance": delta_assurance,
            "delta_risk": delta_risk,
            "cycles": ordered,
        }

