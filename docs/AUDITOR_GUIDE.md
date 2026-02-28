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

# VectorVue Auditor Guide

This guide enables external auditors to validate control evidence independently.

## Objective

Confirm that framework compliance states are reproducible from exported datasets without relying on platform trust assumptions.

## Preconditions

1. Tenant has active operational data in selected time window.
2. Compliance schema is applied.
3. Auditor has authorized credentials.

## Audit Procedure

### 1. Select Time Window

Call:

- `GET /compliance/audit-window?framework=ISO27001&days=90`

Record:

- `from_ts`
- `to_ts`
- observation and evidence volumes

### 2. Retrieve Signed Compliance Report

Call:

- `GET /compliance/ISO27001/report?days=90`

Record:

- `dataset_hash`
- `signature`
- audit package metadata

### 3. Download Evidence Package

Use audit token workflow and download endpoint where required.

Verify package contents:

- `controls.json`
- `evidence.json`
- `metadata.json`
- `checksums.txt`
- `signature.txt`

### 4. Verify Integrity

1. Recompute file checksums and compare with `checksums.txt`.
2. Verify response signature envelope.
3. Validate compliance event hash chain using `previous_event_hash` and `chain_hash`.

### 5. Recompute Control Effectiveness

Using exported policy thresholds and observations, recompute control state:

- `operating`
- `degraded`
- `failed`
- `insufficient_evidence`

Compare with platform output.

### 6. Recompute Framework Score

Aggregate control states and coverage into framework-level score.
Compare with `/compliance/{framework}/score`.

## Minimal Acceptance Checklist

- Tenant scope is correct
- Dataset hash is stable
- Chain integrity is valid
- Recomputed control states match
- Recomputed framework score is consistent

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
