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
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-22 -> Apache-2.0
-->

# VectorVue + SpectraStrike End User Guide

## 1) Installation (Linux/macOS)

1. Install `git`, `make`, Docker Engine, and Docker Compose.
2. Clone `VectorVue` and `SpectraStrike` into the same parent directory.
3. Install Python dependencies in both projects.

## 2) Docker Requirements

- Docker Engine 24+
- Docker Compose v2+
- 8 GB RAM minimum

## 3) How To Generate Certs

Use the certificate/key material under `deploy/certs`:

- mTLS: `ca.crt`, `server.crt`, `server.key`, `client.crt`, `client.key`
- Ed25519: `spectrastrike_ed25519.key`, `vectorvue_feedback_ed25519.key`

## 4) How To Start Both Platforms

1. `cd VectorVue`
2. `make local-federation-up`
3. `cd ../SpectraStrike`
4. `make local-federation-up`

## 5) How To Run First Execution (nmap example)

```bash
cd SpectraStrike
PYTHONPATH=src .venv/bin/python -m pkg.integration.host_integration_smoke \
  --tenant-id 10000000-0000-0000-0000-000000000001 \
  --check-vectorvue
```

## 6) How To Verify Federation Is Active

- Gateway accepts only mTLS + Ed25519 signed requests.
- Smoke output should show `vectorvue_event_status=accepted`.
- Audit logs should include accepted cognitive graph/feedback events.

## 7) How To View Findings In VectorVue

1. Open VectorVue UI.
2. Authenticate as tenant user.
3. Open findings and risk panels.
4. Confirm latest ingestion artifacts.

## 8) How Feedback Loop Works

1. VectorVue stores execution graph metadata.
2. Feedback endpoint computes adjustments from trusted graph records.
3. Response is Ed25519-signed with active feedback `kid`.
4. SpectraStrike verifies signature and applies policy adjustments.

## 9) Troubleshooting

- `Unknown service identity`: check `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`.
- `Invalid telemetry signature`: check trusted SpectraStrike public key.
- `Operator tenant mapping violation`: fix `VV_TG_OPERATOR_TENANT_MAP`.
- `Execution graph schema not allowed`: send `execution.graph.v1`.
- `Replay detected`: regenerate nonce.

## 10) Security Explanation (Plain English)

VectorVue only accepts telemetry that proves source identity and payload integrity. It rejects anything with invalid signatures, stale/replayed nonces, wrong tenant mapping, or wrong schema version.

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
