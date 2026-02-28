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

# Phase 1 Sprint 1.1 - Service Bootstrapping

## Objective
Bootstrap a private telemetry gateway service with strict service authentication and certificate pinning controls.

## Deliverables
- Internal gateway service package under `services/telemetry_gateway/`.
- mTLS identity enforcement and cert fingerprint pinning.
- Mandatory Ed25519 signature verification for telemetry payloads.
- Anti-replay nonce guard and clock-skew checks.
- Private compose service with internal-only network (`telemetry_private`).
- Security regression test suite for gateway hardening controls.

## Exit Criteria
- Gateway is not publicly exposed.
- Gateway rejects requests without valid pinned client certificate fingerprint.
- Gateway rejects unsigned or invalidly signed telemetry.
- Gateway rejects replay attempts.

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
