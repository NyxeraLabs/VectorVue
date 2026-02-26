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

"""Federation signed evidence bundle schema."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SignedEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    execution_hash: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    timestamp: int
    nonce: str = Field(min_length=12, max_length=128)
    signature: str = Field(min_length=12, max_length=4096)
