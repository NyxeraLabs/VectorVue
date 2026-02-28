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

# PostgreSQL Migration Guide

This guide describes migration and validation for PostgreSQL-backed VectorVue environments.

## 1. Included Assets

- `sql/postgres_schema.sql`
- `scripts/export_pg_schema.py`
- `scripts/migrate_sqlite_to_postgres.py`
- `tests/test_postgres_smoke.py`

## 2. Start Database Service

```bash
docker compose up -d postgres
docker compose ps
```

## 3. Apply Schema

```bash
make pg-schema-bootstrap
```

## 4. Optional SQLite-to-PostgreSQL Data Migration

```bash
docker compose run --rm vectorvue_app python scripts/migrate_sqlite_to_postgres.py \
  --sqlite vectorvue.db \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --schema sql/postgres_schema.sql \
  --truncate
```

## 5. Apply Platform Migrations

```bash
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

## 6. Validate Runtime

```bash
make deploy
make api-smoke
```

## 7. Regression Checks

Use checklist:

- `docs/manuals/POSTGRES_REGRESSION_CHECKLIST.md`


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
