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

## Sprint 1.1 — Service Bootstrapping
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Introduced internal-only telemetry gateway with mTLS identity checks and certificate pinning.

### Tasks
- [x] Bootstrap telemetry gateway service package
- [x] Enforce mTLS client identity requirement
- [x] Add certificate pinning for SpectraStrike client cert fingerprint
- [x] Add security tests for auth/signature/replay rejection
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression

## Sprint 1.2 — Payload Security Layer
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Enforces signed telemetry verification, Redis-backed replay prevention, and operator burst rate limiting.

### Tasks
- [x] Validate Ed25519 telemetry payload signatures
- [x] Reject unsigned telemetry payloads
- [x] Add Redis nonce store for replay prevention
- [x] Enforce timestamp skew window (±30s)
- [x] Enforce per-operator rate limiting and burst anomaly detection
- [x] Add security tests for forged/expired/replayed/burst requests

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
