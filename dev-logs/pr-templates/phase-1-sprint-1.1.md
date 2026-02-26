## What changed
- Bootstrapped telemetry gateway service.
- Added mTLS service identity enforcement and certificate pinning controls.

## Why
- Move ingestion into hardened internal-only path with explicit cryptographic trust.

## Security impact
- Rejects untrusted clients and mismatched cert identities.

## Rollback plan
- Revert gateway bootstrap and security-enforcement additions.
- Restore previous integration behavior in dev branch only.

## Validation steps
- Confirm gateway rejects missing/invalid mTLS client identity.
- Confirm cert pinning mismatch requests are rejected.
