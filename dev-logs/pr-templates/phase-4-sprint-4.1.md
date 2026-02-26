## What changed
- Implemented envelope encryption for evidence blobs.
- Added HSM provider abstraction for key-management integration.

## Why
- Provide tenant-scoped confidentiality with hardware-backed key strategy.

## Security impact
- Protects evidence at rest and isolates decryption by tenant context.

## Rollback plan
- Revert evidence encryption and HSM integration modules.
- Restore prior evidence storage handling.

## Validation steps
- Confirm encrypt/decrypt round-trip for same tenant.
- Confirm wrong-tenant decryption is rejected.
