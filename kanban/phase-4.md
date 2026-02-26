## Sprint 4.1 — Field-Level Encryption
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Encrypts evidence blobs at rest with tenant-scoped envelope keys anchored in HSM root key material.

### Tasks
- [x] Implement envelope encryption for evidence blobs
- [x] Enforce per-tenant key derivation for wrapping keys
- [x] Add HSM provider abstraction for root key retrieval
- [x] Integrate evidence encryption/decryption in evidence engine flow
- [x] Add security tests for tenant isolation and key rotation
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
