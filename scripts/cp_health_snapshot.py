#!/usr/bin/env python3
"""Emit a read-only ao2-control-plane health snapshot.

The snapshot reads the authenticated `/api/v1/healthz/extended` observer
endpoint and optionally scans local log files for ERROR/WARN/PANIC counters.
It never prints bearer values and never mutates control-plane or AO artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-health-snapshot.v1"
ERROR_RE = re.compile(r"\b(ERROR|WARN|PANIC)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} did not contain a JSON object")
    return value


def fetch_healthz_extended(base_url: str, token: str, timeout: float) -> dict[str, Any]:
    if not token:
        raise ValueError("AO2 control-plane bearer token is required")
    url = base_url.rstrip("/") + "/api/v1/healthz/extended"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to fetch healthz extended endpoint: {exc}") from exc
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("healthz extended endpoint did not return a JSON object")
    return value


def scan_log_file(path: Path) -> dict[str, Any]:
    counts = {"ERROR": 0, "WARN": 0, "PANIC": 0}
    line_count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line_count += 1
                for match in ERROR_RE.finditer(line):
                    counts[match.group(1)] += 1
    except OSError as exc:
        return {
            "file": path.name,
            "readable": False,
            "error": str(exc),
            "line_count": line_count,
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "error_count": 0,
            "warn_count": 0,
            "panic_count": 0,
            "finding_count": 0,
        }

    finding_count = counts["ERROR"] + counts["WARN"] + counts["PANIC"]
    return {
        "file": path.name,
        "readable": True,
        "line_count": line_count,
        "size_bytes": path.stat().st_size,
        "error_count": counts["ERROR"],
        "warn_count": counts["WARN"],
        "panic_count": counts["PANIC"],
        "finding_count": finding_count,
    }


def scan_logs(log_dir: Path | None) -> list[dict[str, Any]]:
    if log_dir is None:
        return []
    if not log_dir.exists():
        raise FileNotFoundError(f"log dir does not exist: {log_dir}")
    if not log_dir.is_dir():
        raise NotADirectoryError(f"log dir is not a directory: {log_dir}")
    files = [
        path
        for path in sorted(log_dir.iterdir())
        if path.is_file() and path.suffix.lower() in {".err", ".log", ".ndjson", ".txt"}
    ]
    return [scan_log_file(path) for path in files]


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    if args.healthz_json:
        health = read_json_file(args.healthz_json)
        health_source = "file"
    else:
        token = os.environ.get(args.api_token_env, "")
        health = fetch_healthz_extended(args.base_url, token, args.timeout_seconds)
        health_source = "control-plane"

    per_log_summary = scan_logs(args.log_dir)
    total_findings = sum(int(item.get("finding_count", 0)) for item in per_log_summary)
    error_request_count = int(health.get("error_request_count") or 0)
    last_error_utc = health.get("last_error_utc")
    status = "passed"
    if total_findings or error_request_count or last_error_utc:
        status = "attention"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": status,
        "control_plane": {
            "base_url": args.base_url.rstrip("/"),
            "health_source": health_source,
            "role": "read_only_observer",
            "mutates_ao_artifacts": False,
        },
        "healthz_extended": health,
        "log_scan": {
            "log_dir": str(args.log_dir) if args.log_dir else None,
            "file_count": len(per_log_summary),
            "finding_count": total_findings,
            "per_log_summary": per_log_summary,
        },
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "provider_auth": "local_oauth_cli_only",
            "token_in_output": False,
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8744")
    parser.add_argument("--api-token-env", default="AO2_CP_API_TOKEN")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--healthz-json", type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--out", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        snapshot = build_snapshot(args)
    except Exception as exc:
        print(f"cp-health-snapshot: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
