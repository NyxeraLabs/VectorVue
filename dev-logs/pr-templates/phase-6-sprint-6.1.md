## What changed
- Added append-only tamper-evident audit log module.
- Added hash-chain linkage and periodic sealing behavior.

## Why
- Detect post-event audit trail tampering attempts.

## Security impact
- Enables integrity verification for telemetry accept/reject audit history.

## Rollback plan
- Revert tamper-evident log integration.
- Restore prior logging behavior.

## Validation steps
- Confirm chain verification passes for untouched log.
- Confirm tampering is detected as integrity failure.
