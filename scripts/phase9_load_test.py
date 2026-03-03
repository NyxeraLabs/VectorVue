#!/usr/bin/env python3

# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 -> Apache-2.0

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def _request_json(method: str, url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, dict]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, json.loads(raw) if raw else {}


def _request_code(url: str, headers: dict[str, str]) -> tuple[int, float]:
    started = time.perf_counter()
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            _ = resp.read()
            return resp.status, (time.perf_counter() - started) * 1000.0
    except urllib.error.HTTPError as exc:
        _ = exc.read()
        return exc.code, (time.perf_counter() - started) * 1000.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 9 load test for client API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--users", type=int, default=12)
    parser.add_argument("--duration-sec", type=int, default=20)
    parser.add_argument("--max-error-rate", type=float, default=0.03)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    login_status, login_payload = _request_json(
        "POST",
        f"{base_url}/api/v1/client/auth/login",
        body={"username": args.username, "password": args.password, "tenant_id": args.tenant_id},
    )
    if login_status != 200:
        print(f"login failed with status={login_status}")
        return 1

    token = str(login_payload.get("access_token", ""))
    if not token:
        print("login response missing access_token")
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    endpoints = [
        "/api/v1/client/findings?page=1&page_size=25",
        "/api/v1/client/reports?page=1&page_size=25",
        "/api/v1/client/remediation",
        "/api/v1/client/risk",
        "/api/v1/client/risk-trend",
        "/api/v1/client/remediation-status",
        "/ml/client/risk",
        "/ml/client/security-score",
    ]

    lock = threading.Lock()
    latencies: list[float] = []
    total = 0
    errors = 0
    stop_at = time.time() + max(5, args.duration_sec)

    def worker(worker_id: int) -> None:
        nonlocal total, errors
        idx = worker_id % len(endpoints)
        while time.time() < stop_at:
            endpoint = endpoints[idx % len(endpoints)]
            idx += 1
            status, latency_ms = _request_code(f"{base_url}{endpoint}", headers)
            with lock:
                total += 1
                latencies.append(latency_ms)
                if status >= 400:
                    errors += 1

    with ThreadPoolExecutor(max_workers=max(1, args.users)) as executor:
        for worker_id in range(max(1, args.users)):
            executor.submit(worker, worker_id)

    if total == 0:
        print("no requests executed")
        return 1

    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    summary = {
        "total_requests": total,
        "error_requests": errors,
        "error_rate": round(errors / total, 5),
        "latency_avg_ms": round(sum(latencies) / len(latencies), 2),
        "latency_p95_ms": round(p95, 2),
        "latency_max_ms": round(max(latencies), 2),
    }
    print(json.dumps(summary, indent=2))

    if summary["error_rate"] > args.max_error_rate:
        print("error rate above threshold")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
