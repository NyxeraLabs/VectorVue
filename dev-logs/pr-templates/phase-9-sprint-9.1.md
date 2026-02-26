## What changed
- Added full-system red-team simulation suite for attack-path validation.
- Wired suite into security regression CI gate.

## Why
- Require adversarial validation before production promotion.

## Security impact
- Promotion is blocked when replay, forgery, MITM, tenant-boundary, tamper-log, queue-poisoning, or rate-limit controls regress.

## Rollback plan
- Revert red-team test suite and workflow invocation.
- Re-run baseline CI checks.

## Validation steps
- Execute Phase 9.1 red-team unit tests.
- Verify security enforcement workflow passes with secure configuration.
