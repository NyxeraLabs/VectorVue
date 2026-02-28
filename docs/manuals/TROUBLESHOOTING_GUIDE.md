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

# VectorVue Troubleshooting Guide

This guide covers high-frequency operational issues in production and demo environments.

## 1. Deployment Fails (`make deploy`)

Checks:

1. Verify Docker daemon is running.
2. Verify Compose can start postgres/redis.
3. Check container logs:

```bash
docker compose logs --tail=120 vectorvue_app
docker compose logs --tail=120 vectorvue_postgres
```

## 2. Migration Errors

If schema errors appear during migration:

1. Verify migration order:

```bash
make pg-schema-bootstrap
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

2. Recheck PostgreSQL health and rerun failing step.

## 3. Portal Login Fails

1. Confirm tenant URL is correct.
2. Confirm seeded credentials are current.
3. Rerun demo seed in non-production:

```bash
make seed-clients
```

4. If onboarding used `make wizard` option `2`, confirm tenant host map is set in `.env`:

```bash
rg '^VV_TENANT_HOST_MAP=' .env
```

## 4. Worker Restart Loops

1. Inspect worker logs:

```bash
docker compose logs --tail=120 vectorvue_ml_worker
docker compose logs --tail=120 vectorvue_compliance_observation_worker
docker compose logs --tail=120 vectorvue_compliance_daily_worker
```

2. Rebuild and recreate relevant services:

```bash
docker compose build vectorvue_app
docker compose up -d --force-recreate vectorvue_app vectorvue_ml_worker vectorvue_compliance_observation_worker vectorvue_compliance_daily_worker
```

## 5. Compliance Endpoint Errors

1. Verify compliance migration applied: `make phase9-migrate`.
2. Verify tenant-authenticated token and role.
3. Verify compliance workers are running.

## 6. Data Scope or Tenant Mismatch

1. Stop integration workflow immediately.
2. Capture request/tenant identifiers.
3. Escalate to platform admin for scope verification.

## 7. Slow Responses

1. Check postgres and redis health.
2. Check worker backlog and queue processing.
3. Review app logs for timeouts and heavy queries.

## 8. Support Handoff Template

Include:

- command run
- timestamp
- service logs snippet
- tenant/environment impacted
- expected vs actual behavior

## 9. TUI Onboarding Wizard Fails

1. Confirm you are logged in as `admin` role.
2. Confirm PostgreSQL is reachable from app container.
3. Confirm base migrations and tenant theme migration are applied:

```bash
make pg-schema-bootstrap
make phase65-migrate
make phase7d-migrate
```

4. Retry onboarding in TUI with `Ctrl+Shift+W`.
5. If failure persists, collect app logs:

```bash
docker compose logs --tail=120 vectorvue_app
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
