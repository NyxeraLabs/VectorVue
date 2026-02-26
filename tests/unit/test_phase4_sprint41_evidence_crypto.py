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

from __future__ import annotations

import base64
import json
import os
import unittest

from security.evidence_crypto import decrypt_evidence_blob, encrypt_evidence_blob, is_encrypted_evidence_blob


class Phase4Sprint41EvidenceCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_backup = dict(os.environ)
        os.environ["VV_HSM_ROOT_KEYS_JSON"] = json.dumps(
            {
                "vv-evidence-root-v1": base64.b64encode(b"A" * 32).decode("utf-8"),
                "vv-evidence-root-v2": base64.b64encode(b"B" * 32).decode("utf-8"),
            }
        )
        os.environ["VV_HSM_EVIDENCE_ROOT_KEY_ID"] = "vv-evidence-root-v1"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_envelope_roundtrip_for_tenant(self):
        tenant_id = "10000000-0000-0000-0000-000000000001"
        plaintext = b'{"finding":"critical","evidence":"blob"}'

        envelope = encrypt_evidence_blob(tenant_id=tenant_id, plaintext=plaintext)
        self.assertTrue(is_encrypted_evidence_blob(envelope))
        recovered = decrypt_evidence_blob(tenant_id=tenant_id, envelope=envelope)
        self.assertEqual(recovered, plaintext)

    def test_decrypt_rejects_wrong_tenant(self):
        tenant_a = "10000000-0000-0000-0000-000000000001"
        tenant_b = "20000000-0000-0000-0000-000000000002"
        envelope = encrypt_evidence_blob(tenant_id=tenant_a, plaintext=b"secret")

        with self.assertRaises(ValueError):
            decrypt_evidence_blob(tenant_id=tenant_b, envelope=envelope)

    def test_supports_hsm_key_id_rotation(self):
        tenant_id = "10000000-0000-0000-0000-000000000001"
        envelope_v1 = encrypt_evidence_blob(tenant_id=tenant_id, plaintext=b"payload-v1", key_id="vv-evidence-root-v1")
        envelope_v2 = encrypt_evidence_blob(tenant_id=tenant_id, plaintext=b"payload-v2", key_id="vv-evidence-root-v2")

        self.assertEqual(envelope_v1["key_id"], "vv-evidence-root-v1")
        self.assertEqual(envelope_v2["key_id"], "vv-evidence-root-v2")
        self.assertEqual(decrypt_evidence_blob(tenant_id=tenant_id, envelope=envelope_v1), b"payload-v1")
        self.assertEqual(decrypt_evidence_blob(tenant_id=tenant_id, envelope=envelope_v2), b"payload-v2")

if __name__ == "__main__":
    unittest.main()
