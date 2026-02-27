<!--
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-22 -> Apache-2.0
-->

# VectorVue SDK Developer Guide

## Architecture Overview

- Telemetry Gateway validates federation transport and signatures.
- Processing layer validates canonical telemetry schema.
- Analytics/finding layers enrich and expose assurance results.
- Cognitive endpoints return signed feedback adjustments.

## How Federation Signing Works

- Inbound telemetry from SpectraStrike: Ed25519 verify on canonical signed input.
- Outbound feedback to SpectraStrike: Ed25519 sign with active `kid` private key.

## Canonical Telemetry Schema Definition

Key required fields:

- `event_id`, `event_type`, `source_system`, `severity`
- `mitre_techniques`, `mitre_tactics`, `description`
- `attributes.schema_version`
- `attributes.attestation_measurement_hash` (64-char hex)

## How To Extend Tool Wrappers (Metasploit, Sliver, Mythic)

Wrappers are implemented in SpectraStrike. VectorVue expects normalized canonical payloads and does not accept tool-specific raw shapes at ingress.

## How To Emit Signed Telemetry

Producer-side (SpectraStrike):

1. Canonicalize payload.
2. Sign `timestamp.nonce.payload` with Ed25519 private key.
3. Send with required federation headers and mTLS cert.

## How To Validate Feedback Signatures

Consumer-side (SpectraStrike):

1. Read `kid`, `signature`, `signed_at`, `nonce`, `schema_version`.
2. Build canonical tuple.
3. Resolve public verify key by `kid`.
4. Verify Ed25519 signature and nonce freshness.

## Test Strategy

- Gateway unit tests for signature, replay, tenant mapping, schema.
- Red-team tests for tampering and forged signatures.
- End-to-end smoke tests through SpectraStrike wrappers.

## Key Rotation Strategy

- Keep `VV_TG_FEEDBACK_ED25519_KEYS_JSON` with current and next keys.
- Set `VV_TG_FEEDBACK_ACTIVE_KID` to current signing key.
- Rotate by updating active `kid` after verifiers trust the new key.
- Retire old key after overlap window and validation pass.
