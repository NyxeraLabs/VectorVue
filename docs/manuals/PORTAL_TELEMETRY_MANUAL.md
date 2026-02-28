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

# VectorVue Portal Telemetry Manual

This manual defines how client portal telemetry is captured for security intelligence and assurance analytics.

## 1. Purpose

Telemetry supports:

- time-to-acknowledge measurement
- remediation latency measurement
- dashboard/report consultation analysis
- defensive effectiveness model datasets

This is not marketing telemetry.

## 2. Privacy Constraints

Telemetry does not store:

- IP addresses
- user-agent strings
- keystrokes or typed content

Telemetry stores only security workflow actions.

## 3. Event Types

- `FINDING_VIEWED`
- `FINDING_ACKNOWLEDGED`
- `REMEDIATION_OPENED`
- `REMEDIATION_COMPLETED`
- `REPORT_DOWNLOADED`
- `DASHBOARD_VIEWED`

## 4. Storage Model

Table: `client_activity_events`

Core fields:

- `id`
- `tenant_id`
- `user_id` (nullable)
- `event_type`
- `object_type`
- `object_id`
- `severity` (nullable)
- `timestamp`
- `metadata_json`

Primary index:

- `(tenant_id, timestamp DESC)`

## 5. Runtime Flow

1. Portal calls telemetry endpoint.
2. API validates tenant auth and event schema.
3. API applies basic rate limiting.
4. API sanitizes metadata.
5. Event is inserted asynchronously.
6. API returns `202 Accepted` quickly.

## 6. Operational Commands

```bash
make phase7e-migrate
make phase8-migrate
make seed-clients
```

## 7. Analytics Usage

Telemetry data can be used to compute:

- MTTA (Mean Time to Acknowledge)
- MTTR (Mean Time to Remediate)
- risk awareness behavior
- defensive responsiveness indicators

Reference SQL: `docs/manuals/PHASE7E_TELEMETRY_QUERIES.sql`


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
