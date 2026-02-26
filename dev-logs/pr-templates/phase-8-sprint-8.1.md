## What changed
- Added dedicated security enforcement CI workflow.
- Added SAST and dependency vulnerability scanning stages.
- Added security policy gate for mTLS/signature/tenant guard controls.

## Why
- Fail closed in CI when critical telemetry security controls regress.

## Security impact
- Blocks insecure merges before integration.

## Rollback plan
- Revert security workflow and policy gate script.
- Restore previous CI pipeline configuration.

## Validation steps
- Run policy gate and security unit tests.
- Confirm CI fails when mTLS/signature guards are weakened.
