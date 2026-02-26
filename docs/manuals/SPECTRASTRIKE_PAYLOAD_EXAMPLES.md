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

# SpectraStrike Payload Examples (Hardened Federation Model)

This document contains payload examples for the current secure integration model.

Public client API ingestion endpoints are retired. Use internal telemetry gateway and federation verify contracts only.

## 1. Telemetry Ingest Payload (Gateway)

```json
{
  "operator_id": "op-001",
  "campaign_id": "cmp-001",
  "tenant_id": "10000000-0000-0000-0000-000000000001",
  "execution_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "timestamp": 1772107200,
  "nonce": "nonce-telemetry-00000001",
  "signed_metadata": {
    "tenant_id": "10000000-0000-0000-0000-000000000001",
    "operator_id": "op-001",
    "campaign_id": "cmp-001"
  },
  "payload": {
    "event_id": "evt-001",
    "event_type": "PROCESS_ANOMALY",
    "source_system": "spectrastrike-sensor",
    "severity": "high",
    "observed_at": "2026-02-26T12:00:00Z",
    "mitre_techniques": ["T1059.001"],
    "mitre_tactics": ["TA0002"],
    "description": "Observed suspicious process chain",
    "attributes": {
      "asset_ref": "host-nyc-01"
    }
  }
}
```

Required headers for this payload:
- `X-Service-Identity`
- `X-Client-Cert-Sha256`
- `X-Telemetry-Timestamp`
- `X-Telemetry-Nonce`
- `X-Telemetry-Signature` (Ed25519 signature over canonical message)

## 2. Federation Verify Bundle Payload

```json
{
  "bundle": {
    "operator_id": "op-001",
    "campaign_id": "cmp-001",
    "execution_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "timestamp": 1772107200,
    "nonce": "nonce-federation-00000001",
    "signature": "BASE64_ED25519_SIGNATURE"
  }
}
```

## 3. Accepted Gateway Response

```json
{
  "accepted": true,
  "request_id": "36d8e970-b189-4ac6-bbe5-e3a2b97e4f5a"
}
```

## 4. Rejected Response Examples

Invalid signature:

```json
{
  "detail": "Invalid telemetry signature"
}
```

Replay nonce:

```json
{
  "detail": "Replay detected: nonce already used"
}
```

Tenant mapping violation:

```json
{
  "detail": "Operator tenant mapping violation"
}
```

## 5. Reference Documents

- [Secure SpectraStrike ↔ VectorVue Integration](../integration/spectrastrike-vectorvue.md)
- [Security Expansion Appendix](../Expansion_Appendix.md)
- [Client API Manual](./CLIENT_API_MANUAL.md)
