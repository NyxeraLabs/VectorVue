## What changed
- Removed telemetry ingestion capability from client-facing API.
- Kept read-only tenant client portal API behavior only.
- Added validation/tests and cleanup artifacts for removed ingestion paths.

## Why
- Eliminate public telemetry ingestion attack surface and enforce strict separation of duties.

## Security impact
- Prevents telemetry submission from client API paths.
- Reduces abuse and cross-boundary ingestion risk.

## Rollback plan
- Revert this sprint commit and restore prior telemetry ingestion modules/routes.
- Re-run security tests and endpoint inventory checks.

## Validation steps
- Verify no client API endpoint accepts telemetry POST ingestion.
- Run sprint security tests and route regression checks.
