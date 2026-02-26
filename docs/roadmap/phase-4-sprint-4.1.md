# Phase 4 Sprint 4.1 - Field-Level Encryption and HSM Integration

## Objective
Encrypt evidence blobs with per-tenant keys and anchor root key material in an HSM provider abstraction.

## Deliverables
- Envelope encryption utility for evidence payload blobs.
- Per-tenant KEK derivation and tenant-bound decryption enforcement.
- HSM provider abstraction with key-id based root-key retrieval.
- Evidence engine integration for encrypted-at-rest payload blobs.
- Unit tests for crypto roundtrip, tenant isolation, and key rotation.

## Exit Criteria
- Evidence blobs are persisted encrypted.
- Wrong-tenant decryption attempts fail.
- Key-id rotation paths are supported.
