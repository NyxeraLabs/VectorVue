#!/usr/bin/env python3
# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

"""Import ATT&CK relational backbone from reference files."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from services.attack_backbone import AttackBackboneService, parse_technique_metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Import ATT&CK relational backbone")
    parser.add_argument(
        "--reference",
        default="mitre_reference.txt",
        help="Path to mitre_reference.txt input file",
    )
    parser.add_argument(
        "--metadata-json",
        default="",
        help="Optional JSON file with per-technique metadata enrichments",
    )
    args = parser.parse_args()

    reference_path = Path(args.reference)
    metadata = {}
    if args.metadata_json.strip():
        metadata = parse_technique_metadata(Path(args.metadata_json))

    service = AttackBackboneService()
    summary = service.import_from_reference(
        reference_path=reference_path,
        metadata_by_technique=metadata,
    )

    print("ATT&CK sync complete")
    print(f"tactics={summary.tactics}")
    print(f"techniques={summary.techniques}")
    print(f"subtechniques={summary.subtechniques}")
    print(f"technique_tactic_mappings={summary.tactic_mappings}")
    print(f"technique_platform_mappings={summary.platform_mappings}")
    print(f"technique_data_source_mappings={summary.data_source_mappings}")
    print(f"technique_mitigation_mappings={summary.mitigation_mappings}")
    print(f"technique_detection_guidance_mappings={summary.detection_guidance_mappings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
