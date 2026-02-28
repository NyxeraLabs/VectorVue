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

# Phase 2 Sprint 2.1 - Queue Layer Architecture

## Summary
Telemetry gateway now publishes accepted messages to an internal NATS subject and routes malformed payloads to a dedicated dead-letter subject.

## Threat Model
- Queue ingress must remain internal-only.
- Queue payload integrity must be verifiable.

## Attack Vectors Considered
- Queue endpoint exposure.
- Malformed payload poisoning.
- Payload mutation between producer and consumer.

## Mitigations Implemented
- Added `nats` service without host port exposure.
- Added `telemetry_private` internal network path for gateway-to-queue.
- Added dead-letter routing for invalid JSON/schema payloads.
- Added SHA-256 integrity hash field in queued envelopes.

## Residual Risk
- Downstream verification of integrity hash is deferred.

## Future Improvements
- Queue authn/authz and subject-level policy enforcement.
- Consumer acknowledgements with integrity attestations.

## Architecture Diagram
```mermaid
flowchart LR
  SS[SpectraStrike]
  TG[Telemetry Gateway]
  NATS[(NATS Internal Queue)]
  DLQ[(NATS DLQ Subject)]
  PE[Processing Engine - Phase 3]

  SS --> TG
  TG -->|valid + hashed envelope| NATS
  TG -->|malformed + error envelope| DLQ
  NATS --> PE
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
