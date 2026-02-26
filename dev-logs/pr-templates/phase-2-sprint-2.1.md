## What changed
- Introduced internal queue layer for telemetry ingest.
- Added dead-letter queue routing for malformed events.
- Added per-message integrity hash generation.

## Why
- Isolate processing path and preserve integrity/auditability of queued messages.

## Security impact
- Limits direct processing exposure and improves malformed payload containment.

## Rollback plan
- Revert queue and DLQ integration changes.
- Restore previous telemetry handoff path in dev branch.

## Validation steps
- Confirm malformed events go to DLQ.
- Confirm integrity hash generated for queued events.
