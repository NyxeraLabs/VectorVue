# Technical Notes - Phase 9 Sprint 9.1 (Incremental)

## Demo TUI State Persistence Hardening
- `app/demo_tui.py` now resolves demo state through candidate paths:
  1. `VECTORVUE_DEMO_STATE_PATH` (if set)
  2. `~/.vectorvue/demo_state.json`
  3. `<cwd>/.vectorvue/demo_state.json`
  4. `/tmp/vectorvue-<uid>/demo_state.json`
- `load_demo_state()` now scans candidates and loads the first valid existing state.
- `save_demo_state()` now attempts candidates in order and falls back automatically on `OSError`.
- `reset_demo_state()` now returns the resolved persisted path.

## CLI UX Alignment
- `vv.py --demo-reset` now prints the actual resolved state file path rather than a fixed `~/.vectorvue/...` path.
