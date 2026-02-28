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

# Phase 5 Sprint 5.1 - Service Identity

## Threat Model
- Asset: service-to-service trust decisions for telemetry ingress.
- Adversary: rogue internal caller, spoofed service identity, reused static trust values.
- Trust boundary: gateway ingress identity authentication.

## Attack Vectors Considered
- Unknown service identity attempting ingest.
- Certificate fingerprint mismatch for claimed identity.
- Implicit trust based on a single static environment value.

## Mitigations Implemented
- Replaced single shared cert fingerprint env with explicit identity map:
  - `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`
- Enforced identity-aware cert auth headers:
  - `X-Service-Identity`
  - `X-Client-Cert-Sha256`
- Gateway now rejects unknown identities and identity/fingerprint mismatches.
- Added service identity certificate/key/CA path validation at startup.
- Added per-service identity cert mounts/env paths in compose service definitions.

## Residual Risk
- Trust still depends on trusted TLS terminator header integrity.
- Identity map remains static configuration and requires controlled deployment updates.

## Future Improvements
- Move identity map to signed control-plane policy distribution.
- Bind direct mTLS peer cert extraction in gateway runtime (no proxy header dependency).

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
