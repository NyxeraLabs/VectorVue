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

# Phase 4 Sprint 4.1 - Field-Level Encryption

## Threat Model
- Asset: evidence payload blobs stored in compliance event records and export pipelines.
- Adversary: database snapshot thief, lateral internal reader, key exfiltration attacker.
- Trust boundary: evidence serialization path at write/read in evidence engine.

## Attack Vectors Considered
- Raw evidence blob disclosure from DB backups.
- Cross-tenant decryption attempts.
- Root key compromise blast radius across tenants.

## Mitigations Implemented
- Added envelope encryption for evidence blobs (`vv-evidence-env-v1`).
- Data encrypted with per-record DEK (`AES-256-GCM`).
- DEK wrapped with tenant-derived KEK (HKDF-SHA256 over HSM root key + tenant ID).
- Tenant-bound AAD enforces decryption context integrity.
- Evidence export path decrypts only when tenant context matches envelope tenant.

## Residual Risk
- Current HSM provider bootstrap can be configured via environment JSON for dev/CI compatibility.
- Production operations must source root keys from true HSM-backed secret distribution.

## Future Improvements
- Replace bootstrap provider with cloud/HSM-native key handle integration.
- Add key-rotation metadata table and automated rewrap workflow.

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
