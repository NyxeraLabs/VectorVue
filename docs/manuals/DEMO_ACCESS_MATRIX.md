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

# VectorVue Demo Access Matrix

This guide provides demo identities, tenant URLs, and a reliable walkthrough sequence for sales and delivery demonstrations.

## 1. Demo Seed Output

Command:

```bash
make seed-clients
```

Default seed includes:

- two tenant portals
- two client users per tenant
- red-team operator accounts
- two campaigns per tenant with populated findings, reports, remediation, analytics, and compliance-ready activity

## 2. Default Accounts

### 2.1 Global Operator Accounts

- `redteam_admin` / `RedTeamAdm1n!` (`ADMIN`)
- `rt_lead` / `LeadOperat0r!` (`LEAD`)
- `rt_operator` / `CoreOperat0r!` (`OPERATOR`)

### 2.2 Tenant A

- Tenant: `ACME Industries`
- Tenant ID: `10000000-0000-0000-0000-000000000001`
- Portal: `https://acme.vectorvue.local/login`
- `acme_viewer` / `AcmeView3r!` (`viewer`)
- `acme_operator` / `AcmeOperat0r!` (`operator`)

### 2.3 Tenant B

- Tenant: `Globex Corporation`
- Tenant ID: `20000000-0000-0000-0000-000000000002`
- Portal: `https://globex.vectorvue.local/login`
- `globex_viewer` / `GlobexView3r!` (`viewer`)
- `globex_operator` / `GlobexOperat0r!` (`operator`)

## 3. Recommended 10-Minute Demo Script

1. Run `make deploy` and `make seed-clients`.
2. Login as `acme_viewer`.
3. Show Overview -> Analytics -> Findings -> Remediation -> Reports -> Risk.
4. Download one report and one findings export.
5. Switch to `globex_viewer` and repeat key pages to demonstrate tenant isolation.
6. Optionally show one compliance endpoint response envelope from API.

## 4. Variable Overrides

Use Make variables to customize accounts and tenant identities for customer demos.

Example:

```bash
make seed-clients \
  PANEL1_TENANT_NAME="Northwind Health" \
  PANEL1_CLIENT_USER_1="northwind_viewer" \
  PANEL1_CLIENT_PASS_1="StrongPass123!"
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
