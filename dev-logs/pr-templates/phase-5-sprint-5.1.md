## What changed
- Enforced cert-based service identity trust model.
- Removed shared-secret trust path between services.

## Why
- Align internal communications with zero-trust identity principles.

## Security impact
- Reduces secret-sprawl risk and trust ambiguity.

## Rollback plan
- Revert service identity enforcement changes.
- Restore previous service trust configuration in dev.

## Validation steps
- Confirm service identity mapping is required.
- Confirm shared-secret fallback is not used.
