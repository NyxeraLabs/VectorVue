<!-- NYXERA_BRANDING_HEADER_START -->
<p align="center">
  <img src="https://docs.vectorvue.nyxera.cloud/assets/img/product-logo.png" alt="VectorVue" width="220" />
</p>

<p align="center">
  <a href="https://docs.vectorvue.nyxera.cloud">Docs</a> |
  <a href="https://vectorvue.nyxera.cloud">VectorVue</a> |
  <a href="https://nexus.nyxera.cloud">Nexus</a> |
  <a href="https://nyxera.cloud">Nyxera Labs</a>
</p>
<!-- NYXERA_BRANDING_HEADER_END -->

# Phase 4 Sprint 4.1 - Cryptographic Architecture

## Summary
Evidence blobs are now stored as encrypted envelopes, using per-record data keys wrapped by tenant-derived keys anchored in HSM root material.

## Threat Model
- Assume datastore compromise; ciphertext confidentiality must remain intact without HSM root key access.

## Attack Vectors Considered
- Offline ciphertext analysis from DB dump.
- Decryption under incorrect tenant context.
- Key reuse across tenants.

## Mitigations Implemented
- Envelope format with explicit key metadata and tenant binding.
- Per-tenant KEK derivation from HSM root key.
- AES-GCM authenticated encryption for both payload and wrapped DEK.
- Decrypt path enforces tenant equality before unwrap/decrypt.

## Residual Risk
- Root key management discipline is operationally critical.

## Future Improvements
- Remote HSM attestation + key usage audit trail.
- Per-tenant dedicated root-key domains for high-sensitivity tenants.

## Architecture Diagram
```mermaid
flowchart LR
  APP[Evidence Engine]
  HSM[HSM Root Key Provider]
  DERIVE[HKDF Tenant KEK]
  ENV[Envelope Crypto\nDEK + AES-GCM]
  DB[(compliance_events.payload_json)]

  APP --> HSM
  HSM --> DERIVE
  APP --> ENV
  DERIVE --> ENV
  ENV --> DB
```

<!-- NYXERA_BRANDING_FOOTER_START -->

---

<p align="center">
  <img src="https://docs.vectorvue.nyxera.cloud/assets/img/nyxera-logo.png" alt="Nyxera Labs" width="110" />
</p>

<p align="center">
  2026 VectorVue by Nyxera Labs. All rights reserved.
</p>

<p align="center">
  <a href="https://docs.vectorvue.nyxera.cloud">Docs</a> |
  <a href="https://vectorvue.nyxera.cloud">VectorVue</a> |
  <a href="https://nexus.nyxera.cloud">Nexus</a> |
  <a href="https://nyxera.cloud">Nyxera Labs</a>
</p>
<!-- NYXERA_BRANDING_FOOTER_END -->
