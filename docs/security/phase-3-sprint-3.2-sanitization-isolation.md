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

# Phase 3 Sprint 3.2 - Sanitization and Isolation

## Threat Model
- Asset: tenant-scoped telemetry integrity and processing trust boundaries.
- Adversary: attacker injecting HTML/JS or SQL-like payload fragments, cross-tenant event forger.
- Trust boundary: signed telemetry ingest before queue publish.

## Attack Vectors Considered
- HTML/JS content injection in descriptive telemetry fields.
- SQL-like injection markers in canonical payload text values.
- Operator claiming another tenant context in request envelope.
- Signed metadata mismatch between identity fields and payload mapping.

## Mitigations Implemented
- Canonical payload sanitization now escapes HTML/JS characters for string fields.
- Injection-pattern blocking rejects SQL-like attack markers.
- Strict signed metadata model enforces tenant/operator/campaign identity tuple.
- Explicit operator-to-tenant mapping (`VV_TG_OPERATOR_TENANT_MAP`) blocks cross-tenant claims.
- Violations are rejected before queue publish; schema failures route to DLQ.

## Residual Risk
- Mapping table is environment-configured and requires disciplined change control.
- Sanitization is rule-based and should evolve with threat intel.

## Future Improvements
- Move operator-tenant mapping to signed control-plane config source.
- Add centralized policy engine for text sanitization and deny-list updates.

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
