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

"""Federation schema and proof-of-origin verification utilities."""

from services.federation.schemas import SignedEvidenceBundle
from services.federation.verifier import federation_bundle_hash, verify_proof_of_origin

__all__ = ["SignedEvidenceBundle", "federation_bundle_hash", "verify_proof_of_origin"]
