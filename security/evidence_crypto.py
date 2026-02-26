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

"""Envelope encryption utilities for tenant-scoped evidence blobs with HSM root keys."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HSMProvider(Protocol):
    """HSM provider abstraction for root key retrieval."""

    def get_root_key(self, key_id: str) -> bytes:
        ...


@dataclass(frozen=True)
class EvidenceEnvelope:
    version: str
    algorithm: str
    key_id: str
    tenant_id: str
    wrapped_dek_b64: str
    dek_wrap_nonce_b64: str
    data_nonce_b64: str
    ciphertext_b64: str

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "wrapped_dek_b64": self.wrapped_dek_b64,
            "dek_wrap_nonce_b64": self.dek_wrap_nonce_b64,
            "data_nonce_b64": self.data_nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
        }


class EnvJsonHSMProvider:
    """Read root keys from JSON map. Intended for development and CI bootstrapping.

    Production deployments should inject this map via HSM-backed secret sync.
    """

    def __init__(self, env_name: str = "VV_HSM_ROOT_KEYS_JSON"):
        raw = os.environ.get(env_name, "").strip()
        if not raw:
            raise RuntimeError(f"{env_name} is required for evidence encryption")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{env_name} must be valid JSON") from exc
        if not isinstance(parsed, dict) or not parsed:
            raise RuntimeError(f"{env_name} must be a non-empty JSON object")
        self._keys: dict[str, bytes] = {}
        for key_id, value in parsed.items():
            if not isinstance(value, str) or not value:
                raise RuntimeError("HSM key values must be non-empty base64 strings")
            self._keys[str(key_id)] = base64.b64decode(value)

    def get_root_key(self, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if not key:
            raise RuntimeError(f"HSM root key not found for key_id={key_id}")
        if len(key) not in {16, 24, 32}:
            raise RuntimeError("HSM root key must be 128/192/256-bit")
        return key


class InMemoryHSMProvider:
    """Test-only HSM provider."""

    def __init__(self, keys: dict[str, bytes]):
        self._keys = dict(keys)

    def get_root_key(self, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise RuntimeError(f"missing key: {key_id}")
        return key


def _aad(tenant_id: str, key_id: str) -> bytes:
    return f"tenant:{tenant_id}|key:{key_id}|purpose:evidence-blob".encode("utf-8")


def _derive_tenant_kek(root_key: bytes, tenant_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=tenant_id.encode("utf-8"),
        info=b"vectorvue-evidence-kek-v1",
    )
    return hkdf.derive(root_key)


def _default_key_id() -> str:
    return os.environ.get("VV_HSM_EVIDENCE_ROOT_KEY_ID", "vv-evidence-root-v1").strip()


def _provider(provider: HSMProvider | None = None) -> HSMProvider:
    return provider or EnvJsonHSMProvider()


def encrypt_evidence_blob(tenant_id: str, plaintext: bytes, provider: HSMProvider | None = None, key_id: str | None = None) -> dict[str, str]:
    kid = key_id or _default_key_id()
    hsm = _provider(provider)
    root_key = hsm.get_root_key(kid)
    tenant_kek = _derive_tenant_kek(root_key, tenant_id)

    dek = AESGCM.generate_key(bit_length=256)
    data_nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, _aad(tenant_id, kid))

    wrap_nonce = os.urandom(12)
    wrapped_dek = AESGCM(tenant_kek).encrypt(wrap_nonce, dek, _aad(tenant_id, kid))

    return EvidenceEnvelope(
        version="vv-evidence-env-v1",
        algorithm="AES-256-GCM+HKDF-SHA256",
        key_id=kid,
        tenant_id=tenant_id,
        wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("utf-8"),
        dek_wrap_nonce_b64=base64.b64encode(wrap_nonce).decode("utf-8"),
        data_nonce_b64=base64.b64encode(data_nonce).decode("utf-8"),
        ciphertext_b64=base64.b64encode(ciphertext).decode("utf-8"),
    ).to_dict()


def decrypt_evidence_blob(tenant_id: str, envelope: dict[str, str], provider: HSMProvider | None = None) -> bytes:
    if envelope.get("version") != "vv-evidence-env-v1":
        raise ValueError("Unsupported evidence envelope version")
    if envelope.get("tenant_id") != tenant_id:
        raise ValueError("Tenant mismatch for evidence envelope")

    kid = str(envelope["key_id"])
    hsm = _provider(provider)
    root_key = hsm.get_root_key(kid)
    tenant_kek = _derive_tenant_kek(root_key, tenant_id)

    wrapped_dek = base64.b64decode(envelope["wrapped_dek_b64"])
    wrap_nonce = base64.b64decode(envelope["dek_wrap_nonce_b64"])
    data_nonce = base64.b64decode(envelope["data_nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])

    dek = AESGCM(tenant_kek).decrypt(wrap_nonce, wrapped_dek, _aad(tenant_id, kid))
    plaintext = AESGCM(dek).decrypt(data_nonce, ciphertext, _aad(tenant_id, kid))
    return plaintext


def is_encrypted_evidence_blob(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return value.get("version") == "vv-evidence-env-v1" and "ciphertext_b64" in value
