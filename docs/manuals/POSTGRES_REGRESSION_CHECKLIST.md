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

# PostgreSQL Regression Checklist

Use this checklist before release cutover and after major migrations.

## 1. Platform Boot

- [ ] `make deploy` completes without errors
- [ ] `vectorvue_app` health endpoint reports healthy
- [ ] login and token issuance operate normally

## 2. Core Workflows

- [ ] campaign data loads and tenant scoping is correct
- [ ] findings and evidence APIs return expected payloads
- [ ] remediation and risk endpoints return expected payloads
- [ ] report listing and download paths are functional
- [ ] portal builder validation passes: `docker compose --profile qa run --rm vectorvue_portal_builder npm run build`

## 3. Analytics and Workers

- [ ] ML worker is running and queue listener is active
- [ ] analytics endpoints return score/confidence/explanation contract
- [ ] no cross-tenant analytics leakage observed

## 4. Compliance Assurance

- [ ] compliance workers are running
- [ ] `/compliance/frameworks` returns signed response envelope
- [ ] framework score/report endpoints return valid dataset hash
- [ ] audit window endpoint returns expected counts
- [ ] `/api/v1/client/legal/documents` returns full legal payload with current hash/version
- [ ] `/api/v1/client/legal/accept` + `/api/v1/client/auth/register` enforce server-side legal acceptance

## 5. Data Integrity

- [ ] immutable compliance event behavior enforced
- [ ] hash-chain validation succeeds for sampled tenant
- [ ] evidence export package checksums verify

## 6. Security Controls

- [ ] RBAC enforcement works by role
- [ ] tenant claim enforcement blocks unauthorized scope access
- [ ] telemetry ingestion respects privacy constraints
- [ ] tenant theming cannot remove platform brand lock/attribution metadata from theme API payload

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
