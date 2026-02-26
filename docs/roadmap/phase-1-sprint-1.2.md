# Phase 1 Sprint 1.2 - Payload Security Layer

## Objective
Enforce payload authenticity, replay resistance, and operator burst protections in the telemetry gateway.

## Deliverables
- Ed25519 verification for telemetry request signatures.
- Strict header requirements for signed telemetry.
- Redis nonce store for replay prevention.
- ±30s timestamp skew enforcement.
- Per-operator rate limiting and burst anomaly rejection.
- Security tests covering forged/expired/replayed/burst scenarios.

## Exit Criteria
- Forged payloads are rejected.
- Expired timestamps are rejected.
- Reused nonces are rejected.
- Burst requests exceed threshold and return `429`.
