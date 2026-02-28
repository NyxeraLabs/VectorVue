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

# Phase 5 Sprint 5.1 - Zero Trust Service Identity Architecture

## Summary
Service authentication now uses explicit service identity + certificate fingerprint mapping instead of a single shared trust value.

## Threat Model
- Assume no internal service is trusted by default.
- Require explicit identity and cryptographic certificate binding per caller.

## Attack Vectors Considered
- Identity spoofing by unknown service ID.
- Certificate mismatch for valid identity.
- Shared static trust variable misuse.

## Mitigations Implemented
- Identity map enforcement (`service_id -> cert_sha256`).
- Identity cert/key/CA artifacts configured per service container.
- Gateway startup fails if local identity artifacts are missing.

## Residual Risk
- Identity-policy lifecycle management remains environment-based.

## Future Improvements
- SPIFFE/SPIRE or mesh-based workload identities.
- Centralized policy signing and rollout validation.

## Architecture Diagram
```mermaid
flowchart LR
  SVC[Caller Service]
  IDMAP[Identity Policy Map]
  GW[Telemetry Gateway]

  SVC -->|X-Service-Identity + cert fingerprint| GW
  IDMAP --> GW
  GW -->|allow only mapped identity+cert| Ingest[Telemetry Ingest]
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
