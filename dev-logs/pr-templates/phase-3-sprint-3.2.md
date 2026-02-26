## What changed
- Added input sanitization and injection-pattern blocking.
- Added strict tenant mapping via signed metadata enforcement.

## Why
- Prevent injection abuse and cross-tenant mapping violations.

## Security impact
- Enforces tenant boundary integrity for telemetry processing.

## Rollback plan
- Revert sanitization and tenant mapping controls.
- Re-run tenant-isolation regression suite.

## Validation steps
- Confirm XSS/HTML content sanitization.
- Confirm injection payload rejection.
- Confirm cross-tenant mapping violation rejection.
