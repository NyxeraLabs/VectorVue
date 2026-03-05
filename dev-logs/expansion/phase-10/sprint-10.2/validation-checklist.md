# Validation Checklist

- [x] Python compile checks pass for:
  - `scripts/seed_db.py`
  - `app/demo_tui.py`
  - `vv_client_api.py`
- [x] Python compile checks pass for SpectraStrike seed exporter script.
- [x] Full `make demo-seed` integration run validated in live stack.
- [x] Portal runtime build validated in Docker build pipeline.
- [x] Remediation tracker includes federation-derived campaign-tagged tasks after seed.
- [ ] TUI assisted demo manually validated against seeded federation records.

## 2026-03-05 Final Addendum
- [x] `python3 -m py_compile scripts/seed_db.py`
- [x] `npm --prefix portal run test:unit`
- [x] Workflow files updated for portal unit test execution in CI.
- [x] Federation seed path now writes evidence + evidence timeline activity rows for imported findings/events.
- [ ] `npm --prefix portal run build` (blocked in this environment: portal dependencies not installed locally)
- [x] `scripts/check_license_headers.py` passes.
- [x] `scripts/security_ci_policy_gate.py` passes.
- [x] `python3 -m py_compile services/telemetry_gateway/main.py scripts/security_ci_policy_gate.py scripts/seed_db.py app/demo_tui.py tests/unit/test_tui_demo_flow.py`.
- [ ] `python -m unittest tests.unit.test_phase1_sprint11_telemetry_gateway -v` (blocked in this environment: `fastapi` not installed in local venv).
