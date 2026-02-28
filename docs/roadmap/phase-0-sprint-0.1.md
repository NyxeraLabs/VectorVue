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

# Phase 0 - Sprint 0.1 - Telemetry Capability Removal

## Sprint Objective
Remove telemetry ingestion capability from the client API so tenant portal usage is constrained to read-only client data and signed compliance retrieval.

## Deliverables
- Removed active telemetry ingestion routes from runtime API.
- Removed SpectraStrike ingestion modules from codebase.
- Added DB cleanup script: `sql/phase0_sprint01_telemetry_removal.sql`.
- Added security regression tests for endpoint removal and method hardening.
- Updated security and architecture documentation for reduced attack surface.

## Exit Criteria
- No public client API endpoint accepts telemetry POST payloads.
- No `/api/v1/integrations/spectrastrike/*` endpoint is exposed.
- Regression tests confirm the removed attack surface.

## Roll-forward Notes
Next sprint should implement a dedicated private telemetry gateway with mTLS and signed payload validation. No telemetry ingestion should be reintroduced to client API.

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
