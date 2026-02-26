## Sprint 8.1 — Security Gates in Pipeline
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Blocks insecure telemetry control regressions from merging by enforcing fail-closed CI security gates.

### Tasks
- [x] Add dedicated security enforcement CI workflow
- [x] Add SAST stage for core services
- [x] Add dependency vulnerability scanning stage
- [x] Add fail-closed policy gate for mTLS and payload signature controls
- [x] Add security regression test stage and sprint unit tests
- [x] Update sprint documentation and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
