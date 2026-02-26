<!--
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
-->

# SpectraStrike Integration API (Legacy Status)

> Status: Retired from public client API in Phase 0 Sprint 0.1.

Public endpoints under `/api/v1/integrations/spectrastrike/*` are no longer part of the client API surface and must not be reintroduced.

## Current Supported Integration Path

SpectraStrike integration is now supported only through the hardened internal telemetry gateway and federation verification model documented here:

- [Secure SpectraStrike ↔ VectorVue Integration Manual](../integration/spectrastrike-vectorvue.md)
- [Security Expansion Appendix](../Expansion_Appendix.md)
- [Product Roadmap](../ROADMAP.md)

## Security Requirements (Current)

- Zero-trust service-to-service communication.
- Mandatory mTLS certificate identity validation.
- Mandatory Ed25519 payload signatures.
- Replay protection (timestamp window + nonce enforcement).
- Tenant mapping enforcement through signed metadata.
- Tamper-evident logging of accept/reject outcomes.

## Prohibited Patterns

- Shared secrets between SpectraStrike and VectorVue services.
- Unsigned telemetry ingestion.
- Public client API write endpoints for telemetry ingestion.
- mTLS bypass or optional certificate identity checks.
