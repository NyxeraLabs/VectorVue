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

# VectorVue Client API Manual

This manual provides production-safe integration guidance for client-facing APIs.

## 1. Security Model

- JWT authentication with tenant claim required
- Tenant-scoped reads only for client data APIs
- Compliance APIs return signed response envelopes
- Client API telemetry ingestion is disabled (Phase 0 Sprint 0.1)

## 2. Base URL and Authentication

Default local endpoint:

- `https://127.0.0.1`

Login:

- `POST /api/v1/client/auth/login`

Use access token in all calls:

- `Authorization: Bearer <token>`

## 3. Core Client Endpoints

- `GET /api/v1/client/findings`
- `GET /api/v1/client/findings/{finding_id}`
- `GET /api/v1/client/evidence`
- `GET /api/v1/client/evidence/{finding_id}`
- `GET /api/v1/client/reports`
- `GET /api/v1/client/reports/{report_id}/download`
- `GET /api/v1/client/risk`
- `GET /api/v1/client/risk-summary`
- `GET /api/v1/client/risk-trend`
- `GET /api/v1/client/remediation`
- `GET /api/v1/client/remediation-status`

## 4. Analytics Endpoints

- `GET /ml/client/security-score`
- `GET /ml/client/risk`
- `GET /ml/client/detection-gaps`
- `GET /ml/client/anomalies`
- `POST /ml/client/simulate`
- `GET /ml/operator/suggestions/{campaign_id}`

Client analytics response contract:

- `score`
- `confidence`
- `explanation`
- `model_version`
- `generated_at`

## 5. Compliance Endpoints

- `POST /audit/session`
- `GET /compliance/frameworks`
- `GET /compliance/{framework}/controls`
- `GET /compliance/{framework}/score`
- `GET /compliance/{framework}/report`
- `GET /compliance/audit-window`

Compliance responses include:

- `data`
- `signature` (cryptographic signature envelope)

## 6. Example Login Flow

```bash
curl -k -X POST https://127.0.0.1/api/v1/client/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "acme_viewer",
    "password": "AcmeView3r!",
    "tenant_id": "10000000-0000-0000-0000-000000000001"
  }'
```

## 7. Telemetry Endpoint Status

`POST /api/v1/client/events` and `/api/v1/integrations/spectrastrike/*` are retired and not exposed by the runtime API.

## 8. Integration Validation Checklist

1. Authenticate and resolve tenant context.
2. Read findings, risk, and remediation data.
3. Confirm telemetry ingestion endpoints are not exposed.
4. Call one analytics endpoint.
5. Call one compliance endpoint and validate signature envelope presence.

## 9. Operational Commands

```bash
make deploy
make seed-clients
make api-smoke
```

## 10. Related References

- [Compliance API Spec](../COMPLIANCE_API_SPEC.md)
- [Auditor Guide](../AUDITOR_GUIDE.md)
- [Phase 0 Sprint 0.1 Roadmap](../roadmap/phase-0-sprint-0.1.md)
- [Security Expansion Appendix](../Expansion_Appendix.md)
- [Secure SpectraStrike ↔ VectorVue Integration](../integration/spectrastrike-vectorvue.md)

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
