# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 -> Apache-2.0

import tempfile
import unittest
from pathlib import Path

from scripts import security_ci_policy_gate as gate


class SecurityCIPolicyGateTests(unittest.TestCase):
    def test_runtime_flags_accept_enabled_controls(self) -> None:
        compose = {
            "services": {
                "vectorvue_telemetry_gateway": {
                    "environment": {
                        "VV_TG_REQUIRE_MTLS": "true",
                        "VV_TG_REQUIRE_PAYLOAD_SIGNATURE": "1",
                    }
                }
            }
        }
        gate._check_runtime_security_flags(compose)

    def test_runtime_flags_reject_disabled_mtls(self) -> None:
        compose = {
            "services": {
                "vectorvue_telemetry_gateway": {
                    "environment": {
                        "VV_TG_REQUIRE_MTLS": "0",
                        "VV_TG_REQUIRE_PAYLOAD_SIGNATURE": "true",
                    }
                }
            }
        }
        with self.assertRaises(SystemExit):
            gate._check_runtime_security_flags(compose)

    def test_runtime_flags_reject_disabled_signature(self) -> None:
        compose = {
            "services": {
                "vectorvue_telemetry_gateway": {
                    "environment": {
                        "VV_TG_REQUIRE_MTLS": "true",
                        "VV_TG_REQUIRE_PAYLOAD_SIGNATURE": "off",
                    }
                }
            }
        }
        with self.assertRaises(SystemExit):
            gate._check_runtime_security_flags(compose)

    def test_code_guard_rejects_missing_required_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            gateway_dir = repo / "services" / "telemetry_gateway"
            gateway_dir.mkdir(parents=True, exist_ok=True)
            (gateway_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")

            with self.assertRaises(SystemExit):
                gate._check_code_guards(repo)

    def test_code_guard_accepts_required_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            gateway_dir = repo / "services" / "telemetry_gateway"
            gateway_dir.mkdir(parents=True, exist_ok=True)
            (gateway_dir / "main.py").write_text(
                "Unsigned telemetry is disabled by policy\n"
                "def _enforce_signed_tenant_metadata():\n"
                "    return True\n",
                encoding="utf-8",
            )

            gate._check_code_guards(repo)


if __name__ == "__main__":
    unittest.main()
