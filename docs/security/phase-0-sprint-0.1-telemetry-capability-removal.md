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

# Phase 0 Sprint 0.1 - Telemetry Capability Removal

## Scope
This sprint removes telemetry ingestion from the client API and keeps the client API focused on tenant portal read and compliance access patterns.

## Threat Model
- Asset: tenant telemetry data, client API attack surface, tenant isolation boundaries.
- Adversary: external actor abusing public write routes, compromised integration client, replay actor.
- Trust boundary: all public client API endpoints.

## Attack Vectors Considered
- Unauthorized telemetry POST attempts to `/api/v1/client/events`.
- Abuse of `/api/v1/integrations/spectrastrike/*` ingestion endpoints.
- Replay or forged ingestion payload submissions.
- Lateral tenant probing through ingest status APIs.

## Mitigations Implemented
- Removed SpectraStrike telemetry ingestion router from the runtime API.
- Removed client telemetry event ingestion endpoint from `vv_client_api.py`.
- Removed ingestion DTO/controller/service modules previously used by SpectraStrike ingest flows.
- Added security regression tests to enforce endpoint absence and write-method rejection on read-only resources.
- Added SQL cleanup script to drop telemetry ingestion tables:
  - `spectrastrike_ingest_requests`
  - `spectrastrike_idempotency`
  - `spectrastrike_events`
  - `spectrastrike_findings`
  - `client_activity_events`

## Residual Risk
- Portal code may still attempt telemetry calls; these now fail closed (`404`).
- Existing deployed databases require explicit cleanup script execution.
- Legacy docs/manual references can reintroduce confusion if not retired consistently.

## Future Improvements
- Introduce dedicated private telemetry gateway (Phase 1) with mandatory mTLS and signature verification.
- Add startup policy checks that fail service boot when public telemetry ingestion routes are present.
- Add CI policy gate that scans OpenAPI for forbidden ingestion endpoints.

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
