# Phase 1 Sprint 1.1 - Service Bootstrapping

## Objective
Bootstrap a private telemetry gateway service with strict service authentication and certificate pinning controls.

## Deliverables
- Internal gateway service package under `services/telemetry_gateway/`.
- mTLS identity enforcement and cert fingerprint pinning.
- Mandatory Ed25519 signature verification for telemetry payloads.
- Anti-replay nonce guard and clock-skew checks.
- Private compose service with internal-only network (`telemetry_private`).
- Security regression test suite for gateway hardening controls.

## Exit Criteria
- Gateway is not publicly exposed.
- Gateway rejects requests without valid pinned client certificate fingerprint.
- Gateway rejects unsigned or invalidly signed telemetry.
- Gateway rejects replay attempts.
