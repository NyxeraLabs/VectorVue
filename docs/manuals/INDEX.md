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

# VectorVue Documentation Index

This is the official documentation entrypoint for production and commercial usage.

Use documents by operational role and task. Internal phase names are intentionally minimized in operator-facing material.

## Role-Based Navigation

### 1. Client Stakeholder / Portal User

1. [Client Portal Manual](./CLIENT_PORTAL_MANUAL.md)
2. [Demo Access Matrix](./DEMO_ACCESS_MATRIX.md)
3. [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)

### 2. Security Operator / Delivery Team

1. [Getting Started](./GETTING_STARTED.md)
2. [Operator Manual](./OPERATOR_MANUAL.md)
3. [VectorVue User Guide](./VECTORVUE_USER_GUIDE.md)
4. [Portal Telemetry Manual](./PORTAL_TELEMETRY_MANUAL.md)

### 3. API / Integration Engineer

1. [Client API Manual](./CLIENT_API_MANUAL.md)
2. [Client Analytics Manual](./PHASE8_CLIENT_ANALYTICS_MANUAL.md)
3. [Compliance API Specification](../COMPLIANCE_API_SPEC.md)
4. [PostgreSQL Usage Guide](./POSTGRES_USAGE_GUIDE.md)
5. [Secure SpectraStrike ↔ VectorVue Integration](../integration/spectrastrike-vectorvue.md)
6. [SpectraStrike Integration API (Legacy Status)](./SPECTRASTRIKE_INTEGRATION_API.md)
7. [SpectraStrike Payload Examples](./SPECTRASTRIKE_PAYLOAD_EXAMPLES.md)

### 4. Auditor / Governance / Risk

1. [Auditor Guide](../AUDITOR_GUIDE.md)
2. [Compliance API Specification](../COMPLIANCE_API_SPEC.md)
3. [Architecture Specification](./ARCHITECTURE_SPEC.md)
4. [User Policy](./USER_POLICY.md)

### 5. Platform Engineering / SRE

1. [Deployment](./Deployment.md)
2. [PostgreSQL Migration Guide](./POSTGRES_MIGRATION_GUIDE.md)
3. [PostgreSQL Regression Checklist](./POSTGRES_REGRESSION_CHECKLIST.md)
4. [Documentation Policy](./DOCUMENTATION_POLICY.md)
5. [Security Expansion Appendix](../Expansion_Appendix.md)

## Common Operational Tasks

- Guided deployment/bootstrap menu: `make wizard`
- Deploy platform: `make deploy`
- Seed commercial demo data: `make seed-clients`
- Start TUI onboarding flow: `make run-tui` then `Ctrl+Shift+W`
- Verify API health: `make api-smoke`
- Validate PostgreSQL migrations: `make pg-schema-bootstrap`
- Apply compliance schema only: `make phase9-migrate`

## Product Planning Reference

- [Roadmap](../ROADMAP.md)
- [Security Expansion Appendix](../Expansion_Appendix.md)
- [Secure SpectraStrike ↔ VectorVue Integration](../integration/spectrastrike-vectorvue.md)

## Legal & Compliance Enforcement

- `make install` enforces mandatory legal validation before installation completes.
- `make deploy` is for development/testing workflows and does not enforce installer legal gating.

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
