# Phase 1 Sprint 1.2 - Payload Security Layer

## Threat Model
- Asset: telemetry payload authenticity, freshness, and ingestion availability.
- Adversary: forged sender, replay attacker, operator-level burst flood.
- Trust policy: no implicit trust in source network or caller identity alone.

## Attack Vectors Considered
- Forged telemetry body with invalid signature.
- Unsigned payload submission.
- Replay of prior signed payload (same nonce/timestamp).
- Expired timestamp replay outside allowed skew window.
- Operator burst submissions intended to exhaust ingest capacity.

## Mitigations Implemented
- Ed25519 payload signature verification enforced per request.
- Mandatory `X-Telemetry-Signature`, `X-Telemetry-Timestamp`, and `X-Telemetry-Nonce` headers.
- Timestamp skew enforcement (default ±30 seconds).
- Nonce replay protection backed by Redis (`VV_TG_NONCE_BACKEND=redis`).
- Per-operator per-minute rate limiting and burst anomaly rejection via Redis.
- Fail-closed mode if Redis nonce/rate-limit backends are unavailable.

## Residual Risk
- Rate limiting currently keyed by `operator_id`; abusive distributed operator identities can still increase load.
- Telemetry queue isolation and backpressure controls are deferred to Phase 2.

## Future Improvements
- Add adaptive anomaly thresholds by operator baseline.
- Add dedicated metrics/alerts for rate-limit and replay rejection rates.
- Add multi-region nonce consistency strategy.
