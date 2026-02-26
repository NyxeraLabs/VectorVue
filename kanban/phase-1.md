## Sprint 1.1 — Service Bootstrapping
Status: In Progress
Owner: José María Micoli
Risk Level: High
Security Impact: Introduces internal-only telemetry gateway with mTLS identity checks, certificate pinning, signature verification, and replay rejection.

### Tasks
- [x] Bootstrap telemetry gateway service package
- [x] Enforce mTLS client identity requirement
- [x] Add certificate pinning for SpectraStrike client cert fingerprint
- [x] Add security tests for auth/signature/replay rejection
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
