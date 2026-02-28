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

## Sprint 3.1 — Schema Enforcement
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Blocks malformed telemetry and invalid MITRE mappings before processing pipeline entry.

### Tasks
- [x] Define canonical telemetry schema
- [x] Reject additional payload properties
- [x] Validate MITRE ATT&CK technique/tactic formats
- [x] Route schema violations to DLQ
- [x] Add schema and MITRE security tests
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression

## Sprint 3.2 — Sanitization and Isolation
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Prevents injection payloads and enforces strict signed tenant mapping to block cross-tenant telemetry claims.

### Tasks
- [x] Escape HTML/JS in canonical string fields
- [x] Block injection patterns in payload text
- [x] Enforce strict signed tenant metadata structure
- [x] Enforce operator-to-tenant mapping policy
- [x] Add security tests for sanitization and tenant mapping
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression

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
