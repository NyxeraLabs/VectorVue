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

# VectorVue Federation Gateway Configuration

This folder contains local/operator-managed configuration references for the
SpectraStrike federation intake channel.

Do not commit secrets. Certificates and private keys are ignored via
`.gitignore` in this directory.

Required gateway environment values:

- `VV_TG_REQUIRE_MTLS=1`
- `VV_TG_REQUIRE_PAYLOAD_SIGNATURE=1`
- `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`
- `VV_TG_SPECTRASTRIKE_ED25519_PUBKEY`
- `VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY`
- `VV_TG_OPERATOR_TENANT_MAP`
- `VV_TG_NONCE_BACKEND`
- `VV_TG_REDIS_URL`
- `VV_TG_RATE_LIMIT_BACKEND`
- `VV_TG_ALLOWED_SCHEMA_VERSION`
- `VV_TG_ENFORCE_SCHEMA_VERSION`

Certificate trust chain:

1. `deploy/certs/ca.crt` trusted CA root/intermediate.
2. `deploy/certs/server.crt` and `deploy/certs/server.key` gateway identity.
3. SpectraStrike client cert fingerprint pinned in
   `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`.

Local dockerized layout on this host:

- Gateway cert/key/CA:
  - `/home/xoce/Workspace/VectorVue/deploy/certs/server.crt`
  - `/home/xoce/Workspace/VectorVue/deploy/certs/server.key`
  - `/home/xoce/Workspace/VectorVue/deploy/certs/ca.crt`
- SpectraStrike federation verify key:
  - `/home/xoce/Workspace/VectorVue/deploy/certs/spectrastrike_ed25519.pub.pem`

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
