#!/usr/bin/env python3

# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 -> Apache-2.0

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Phase 9 stress profiles")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--profile", default="balanced")
    parser.add_argument("--profiles-file", default="scripts/phase9_stress_profiles.json")
    args = parser.parse_args()

    profile_path = Path(args.profiles_file)
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    profiles = {entry["name"]: entry for entry in data.get("profiles", [])}
    if args.profile not in profiles:
        print(f"profile '{args.profile}' not found")
        return 1

    profile = profiles[args.profile]
    cmd = [
        sys.executable,
        "scripts/phase9_load_test.py",
        "--base-url",
        args.base_url,
        "--tenant-id",
        args.tenant_id,
        "--username",
        args.username,
        "--password",
        args.password,
        "--users",
        str(profile["users"]),
        "--duration-sec",
        str(profile["duration_sec"]),
        "--max-error-rate",
        str(profile["max_error_rate"]),
    ]
    print("running:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
