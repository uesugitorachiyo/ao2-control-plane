#!/usr/bin/env python3
"""Run an ao2-control-plane audit-log rotation drill.

The drill starts an ephemeral local control plane with
AO2_CP_AUDIT_LOG_FILE and AO2_CP_AUDIT_LOG_MAX_BYTES configured to a
small threshold, drives authenticated read traffic until rotation occurs,
then verifies status, metrics, live NDJSON, and the rotated sidecar. It
uses a generated bearer only in process environment and HTTP headers; the
token is never written to stdout, stderr, URLs, or generated artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-audit-log-rotation-drill.v1"
ROOT = Path(__file__).resolve().parents[1]
ROTATED_TOTAL_RE = re.compile(r"^ao2_cp_audit_log_rotated_total\s+([0-9]+(?:\.[0-9]+)?)$", re.MULTILINE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def parse_json(body: bytes) -> dict[str, Any]:
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("expected JSON object")
    return parsed


def metric_value(metrics: str, pattern: re.Pattern[str]) -> float:
    match = pattern.search(metrics)
    if not match:
        raise ValueError("missing ao2_cp_audit_log_rotated_total metric")
    return float(match.group(1))


class Server:
    def __init__(
        self,
        server_bin: Path,
        work_dir: Path,
        token: str,
        port: int,
        max_bytes: int,
    ) -> None:
        self.server_bin = server_bin
        self.work_dir = work_dir
        self.token = token
        self.port = port
        self.max_bytes = max_bytes
        self.base_url = f"http://127.0.0.1:{port}"
        self.data_dir = work_dir / "data"
        self.audit_log_file = work_dir / "logs" / "audit.ndjson"
        self.process_logs = work_dir / "process-logs"
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        self.process_logs.mkdir(parents=True, exist_ok=True)
        stdout = (self.process_logs / "ao2-cp-server.out.log").open("wb")
        stderr = (self.process_logs / "ao2-cp-server.err.log").open("wb")
        env = os.environ.copy()
        for forbidden in ("OPENAI" + "_API_KEY", "ANTHROPIC" + "_API_KEY"):
            env.pop(forbidden, None)
        env.update(
            {
                "AO2_CP_API_TOKEN": self.token,
                "AO2_CP_BIND": f"127.0.0.1:{self.port}",
                "AO2_CP_DATA_DIR": str(self.data_dir),
                "AO2_CP_AUDIT_LOG_FILE": str(self.audit_log_file),
                "AO2_CP_AUDIT_LOG_MAX_BYTES": str(self.max_bytes),
                "AO2_CP_AUDIT_LOG_CAPACITY": "512",
            }
        )
        self.process = subprocess.Popen(
            [str(self.server_bin)],
            cwd=str(ROOT),
            env=env,
            stdout=stdout,
            stderr=stderr,
        )

    def wait_ready(self, timeout_seconds: float) -> None:
        deadline = time.time() + timeout_seconds
        last_status: int | None = None
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError(f"ao2-cp-server exited early with code {self.process.returncode}")
            try:
                status, _ = http_request("GET", self.base_url, "/healthz", timeout=1.0)
                last_status = status
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.2)
        raise TimeoutError(f"ao2-cp-server did not become ready; last_status={last_status}")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def drive_rotation(server: Server, request_count: int, timeout: float) -> None:
    for index in range(request_count):
        path = f"/api/v1/control-plane/routes.json?rotation_drill={index:04d}"
        status, body = http_request("GET", server.base_url, path, token=server.token, timeout=timeout)
        if status != 200:
            raise RuntimeError(f"GET {path} returned {status}: {body.decode('utf-8', 'replace')[:200]}")


def read_status(server: Server, timeout: float) -> dict[str, Any]:
    status, body = http_request("GET", server.base_url, "/api/v1/status", token=server.token, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"GET /api/v1/status returned {status}")
    return parse_json(body)


def read_metrics(server: Server, timeout: float) -> str:
    status, body = http_request("GET", server.base_url, "/api/v1/metrics", token=server.token, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"GET /api/v1/metrics returned {status}")
    return body.decode("utf-8")


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def run_drill(args: argparse.Namespace) -> dict[str, Any]:
    server_bin = args.server_bin.resolve()
    if not server_bin.is_file():
        raise FileNotFoundError(f"server binary not found: {server_bin}")
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="ao2-cp-audit-rotation-"))
    work_dir = work_dir.resolve()
    token = secrets.token_hex(32)
    timeout = float(args.timeout_seconds)
    server = Server(
        server_bin=server_bin,
        work_dir=work_dir,
        token=token,
        port=args.port or find_free_port(),
        max_bytes=args.max_bytes,
    )
    try:
        server.start()
        server.wait_ready(timeout)
        drive_rotation(server, args.requests, timeout)
        status = read_status(server, timeout)
        metrics = read_metrics(server, timeout)
    finally:
        server.stop()

    rotation = status["audit_log"]["persistence"]["rotation"]
    rotation_count = int(rotation.get("count") or 0)
    rotated_sidecar = Path(str(server.audit_log_file) + ".1")
    live_size = server.audit_log_file.stat().st_size if server.audit_log_file.exists() else 0
    rotated_size = rotated_sidecar.stat().st_size if rotated_sidecar.exists() else 0
    metric_rotated_total = metric_value(metrics, ROTATED_TOTAL_RE)
    passed = (
        rotation_count >= 1
        and metric_rotated_total >= 1
        and server.audit_log_file.exists()
        and rotated_sidecar.exists()
        and live_size <= args.max_bytes
        and rotated_size > 0
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "passed" if passed else "failed",
        "work_dir": str(work_dir),
        "server_bin": str(server_bin),
        "audit_log_file": str(server.audit_log_file),
        "rotated_sidecar": str(rotated_sidecar),
        "configured_max_bytes": args.max_bytes,
        "requests_sent": args.requests,
        "rotation_count": rotation_count,
        "metric_rotated_total": metric_rotated_total,
        "last_rotated_unix_micros": rotation.get("last_rotated_unix_micros"),
        "live_file_size_bytes": live_size,
        "rotated_sidecar_size_bytes": rotated_size,
        "live_file_line_count": count_lines(server.audit_log_file),
        "rotated_sidecar_line_count": count_lines(rotated_sidecar),
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "provider_auth": "local_oauth_cli_only",
            "token_in_output": False,
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", type=Path, default=ROOT / "target/release/ao2-cp-server")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--port", type=int)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--max-bytes", type=int, default=4096)
    parser.add_argument("--requests", type=int, default=80)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = run_drill(args)
    except Exception as exc:
        print(f"cp-audit-log-rotation-drill: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
