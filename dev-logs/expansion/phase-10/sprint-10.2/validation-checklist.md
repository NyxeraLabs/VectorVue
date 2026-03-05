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
