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
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from services.federation.schemas import SignedEvidenceBundle
from services.federation.verifier import federation_bundle_hash, verify_proof_of_origin


class Phase7Sprint71FederationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_b64 = base64.b64encode(self.private.public_key().public_bytes_raw()).decode("utf-8")

    def _bundle(self, signature: str | None = None) -> SignedEvidenceBundle:
        operator_id = "op-001"
        campaign_id = "cmp-001"
        execution_hash = "f" * 64
        ts = int(time.time())
        nonce = "nonce-phase71-001"
        if signature is None:
            msg = f"{operator_id}|{campaign_id}|{execution_hash}|{ts}|{nonce}".encode("utf-8")
            signature = base64.b64encode(self.private.sign(msg)).decode("utf-8")
        return SignedEvidenceBundle(
            operator_id=operator_id,
            campaign_id=campaign_id,
            execution_hash=execution_hash,
            timestamp=ts,
            nonce=nonce,
            signature=signature,
        )

    def test_signed_bundle_schema_and_hash(self):
        bundle = self._bundle()
        digest = federation_bundle_hash(bundle)
        self.assertEqual(len(digest), 64)

    def test_proof_of_origin_valid_signature(self):
        bundle = self._bundle()
        self.assertTrue(verify_proof_of_origin(bundle, public_key_b64=self.public_b64))

    def test_proof_of_origin_rejects_forged_signature(self):
        forged = Ed25519PrivateKey.generate()
        bundle = self._bundle()
        msg = f"{bundle.operator_id}|{bundle.campaign_id}|{bundle.execution_hash}|{bundle.timestamp}|{bundle.nonce}".encode("utf-8")
        forged_sig = base64.b64encode(forged.sign(msg)).decode("utf-8")
        bad_bundle = self._bundle(signature=forged_sig)
        self.assertFalse(verify_proof_of_origin(bad_bundle, public_key_b64=self.public_b64))

    def test_schema_rejects_additional_property(self):
        bundle = self._bundle().model_dump(mode="json")
        bundle["unexpected"] = "x"
        with self.assertRaises(ValidationError):
            SignedEvidenceBundle.model_validate(bundle)


if __name__ == "__main__":
    unittest.main()
