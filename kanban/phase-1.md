## Sprint 1.1 — Service Bootstrapping
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Introduced internal-only telemetry gateway with mTLS identity checks and certificate pinning.

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

## Sprint 1.2 — Payload Security Layer
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Enforces signed telemetry verification, Redis-backed replay prevention, and operator burst rate limiting.

### Tasks
- [x] Validate Ed25519 telemetry payload signatures
- [x] Reject unsigned telemetry payloads
- [x] Add Redis nonce store for replay prevention
- [x] Enforce timestamp skew window (±30s)
- [x] Enforce per-operator rate limiting and burst anomaly detection
- [x] Add security tests for forged/expired/replayed/burst requests

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
