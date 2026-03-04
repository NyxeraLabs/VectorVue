# Validation Checklist - Phase 9 Sprint 9.1 (Incremental)

## Static Validation
- [x] `app/demo_tui.py` no longer assumes `~/.vectorvue` is always writable.
- [x] `VECTORVUE_DEMO_STATE_PATH` override is supported.
- [x] `vv.py --demo-reset` prints resolved path returned by `reset_demo_state()`.

## Runtime Validation
- [x] Direct script smoke check: save/load/reset works against writable temp path.
- [x] Fallback smoke check: invalid read-only-like primary path (`/proc/...`) falls back to writable project-local path.
- [ ] Full `run-tui-demo-fast` validation in your environment pending.
