# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

"""Proof-of-origin verifier for federation signed evidence bundles."""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from services.federation.schemas import SignedEvidenceBundle


def federation_bundle_hash(bundle: SignedEvidenceBundle) -> str:
    canonical = f"{bundle.operator_id}|{bundle.campaign_id}|{bundle.execution_hash}|{bundle.timestamp}|{bundle.nonce}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_federation_public_key_b64() -> str:
    return (
        os.environ.get("VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY", "").strip()
        or os.environ.get("VV_TG_SPECTRASTRIKE_ED25519_PUBKEY", "").strip()
    )


def verify_proof_of_origin(bundle: SignedEvidenceBundle, public_key_b64: str | None = None) -> bool:
    key_b64 = public_key_b64 or _load_federation_public_key_b64()
    if not key_b64:
        raise RuntimeError("Federation public key is not configured")

    key_bytes = base64.b64decode(key_b64)
    if len(key_bytes) != 32:
        raise RuntimeError("Federation public key must be Ed25519 32-byte key")

    signature = base64.b64decode(bundle.signature)
    message = f"{bundle.operator_id}|{bundle.campaign_id}|{bundle.execution_hash}|{bundle.timestamp}|{bundle.nonce}".encode("utf-8")

    key = Ed25519PublicKey.from_public_bytes(key_bytes)
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
