## What changed
- Added strict canonical schema validation.
- Added MITRE mapping validation checks.

## Why
- Ensure only known-good telemetry schema and ATT&CK references are accepted.

## Security impact
- Blocks malformed and schema-extension payload attacks.

## Rollback plan
- Revert strict validation and MITRE checks.
- Re-run compatibility and security tests.

## Validation steps
- Confirm additional properties are rejected.
- Confirm invalid MITRE codes are rejected.
