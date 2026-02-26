## What changed
- Added Ed25519 payload signature verification.
- Added replay protection (nonce + timestamp skew window).
- Added operator rate limiting protections.

## Why
- Enforce signed, fresh, and bounded telemetry traffic.

## Security impact
- Rejects unsigned, replayed, forged, and burst-abusive telemetry requests.

## Rollback plan
- Revert payload security layer changes and related tests.
- Re-validate gateway behavior against baseline.

## Validation steps
- Confirm unsigned/forged payload rejection.
- Confirm replay and expired timestamp rejection.
- Confirm rate-limit enforcement under burst conditions.
