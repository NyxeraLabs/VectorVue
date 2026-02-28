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

# PostgreSQL Usage Guide

This runbook covers day-to-day PostgreSQL operations for VectorVue deployments.

## 1. Start Services

```bash
docker compose up -d postgres redis vectorvue_app
```

## 2. Initialize Schema and Migrations

```bash
make pg-schema-bootstrap
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

## 3. Seed Environment

```bash
make seed-clients
```

## 4. Health Validation

```bash
make api-smoke
docker compose ps
```

## 5. Backup

Example logical backup:

```bash
docker compose exec -T postgres pg_dump -U vectorvue -d vectorvue_db > backup.sql
```

## 6. Restore

```bash
docker compose exec -T postgres psql -U vectorvue -d vectorvue_db < backup.sql
```

## 7. Reset (Non-Production)

```bash
make pg-reset
```

## 8. Safety Notes

- Validate tenant scoping after any restore.
- Re-run smoke checks after migration or restore.
- Restrict direct database access to platform operators.


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
