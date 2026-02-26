## What changed
- Added signed federation evidence bundle schema.
- Added proof-of-origin verification and federation verify endpoint protections.

## Why
- Ensure federated evidence is authenticated and integrity-checked.

## Security impact
- Rejects forged federation signatures and invalid bundle structures.

## Rollback plan
- Revert federation schema/verifier/endpoint changes.
- Re-run federation regression tests.

## Validation steps
- Confirm valid signatures pass verification.
- Confirm forged signatures and invalid schema fail.
