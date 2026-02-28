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

# Phase 8 Sprint 8.1 - Security CI/CD Enforcement

## Threat Model
- Asset: CI/CD decision path that gates merges into trusted branches.
- Adversary: contributor (malicious or compromised) attempting to merge code with weakened telemetry security controls.
- Trust boundary: GitHub Actions security workflow and repository policy gate script.

## Attack Vectors Considered
- Silent disablement of telemetry mTLS requirement.
- Silent bypass of payload signature enforcement.
- Removal of tenant mapping or fail-closed guards while tests remain green.
- Dependency vulnerabilities introduced through transitive updates.

## Mitigations Implemented
- Added dedicated security workflow with:
  - SAST (`bandit`) stage.
  - Dependency scanning (`pip-audit`) stage.
  - Security regression gate stage.
- Added repository policy gate script that fails pipeline when:
  - `VV_TG_REQUIRE_MTLS` is not enabled.
  - `VV_TG_REQUIRE_PAYLOAD_SIGNATURE` is not enabled.
  - expected fail-closed guard strings are absent from telemetry gateway code.
- Added sprint-specific unit test coverage for policy gate pass/fail behavior.

## Residual Risk
- CI controls are effective only when protected branches enforce required checks.
- String-based guard presence checks detect removal but do not prove full behavioral equivalence.

## Future Improvements
- Enforce required workflow checks via branch protection as code.
- Replace selected string checks with AST-level semantic validation.
- Add SBOM generation and artifact signing verification in release workflow.

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
