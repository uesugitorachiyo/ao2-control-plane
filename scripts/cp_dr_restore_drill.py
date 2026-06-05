#!/usr/bin/env python3
"""Run an ao2-control-plane disaster-recovery restore drill.

The drill starts an ephemeral local control plane, ingests known fixtures,
archives the content-addressed data directory, restores that archive into a
fresh directory, restarts the control plane, and verifies byte-identical
readback by SHA. It uses a generated bearer only in process environment and
HTTP headers; the token is never written to stdout, stderr, or artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-dr-restore-drill.v1"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = (
    ("acceptance_codex", "/api/v1/acceptance", "tests/fixtures/codex-acceptance-v0.4.66.json"),
    ("acceptance_claude", "/api/v1/acceptance", "tests/fixtures/claude-acceptance-v0.4.66.json"),
    ("control_plane_bundle", "/api/v1/control-plane/bundle", "tests/fixtures/control-plane-bundle-sample.json"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_fixture(path: Path) -> bytes:
    return path.read_bytes()


def http_request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def json_body(value: bytes) -> dict[str, Any]:
    parsed = json.loads(value.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("expected JSON object")
    return parsed


class Server:
    def __init__(self, server_bin: Path, data_dir: Path, token: str, port: int, log_dir: Path):
        self.server_bin = server_bin
        self.data_dir = data_dir
        self.token = token
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.log_dir = log_dir
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        stdout = (self.log_dir / f"ao2-cp-server-{self.port}.out.log").open("wb")
        stderr = (self.log_dir / f"ao2-cp-server-{self.port}.err.log").open("wb")
        env = os.environ.copy()
        for forbidden in ("OPENAI" + "_API_KEY", "ANTHROPIC" + "_API_KEY"):
            env.pop(forbidden, None)
        env.update(
            {
                "AO2_CP_API_TOKEN": self.token,
                "AO2_CP_BIND": f"127.0.0.1:{self.port}",
                "AO2_CP_DATA_DIR": str(self.data_dir),
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


def archive_data_dir(data_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(data_dir, arcname="data")


def restore_data_dir(archive_path: Path, restore_root: Path) -> Path:
    restore_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError(f"unsafe archive member: {member.name}")
        archive.extractall(restore_root)
    return restore_root / "data"


def post_fixture(server: Server, endpoint: str, fixture_path: Path, timeout: float) -> dict[str, Any]:
    body = load_fixture(fixture_path)
    status, response = http_request(
        "POST",
        server.base_url,
        endpoint,
        token=server.token,
        body=body,
        timeout=timeout,
    )
    if status != 200:
        raise RuntimeError(f"POST {endpoint} returned {status}: {response.decode('utf-8', 'replace')[:200]}")
    receipt = json_body(response)
    sha = str(receipt.get("sha256", ""))
    if not sha:
        raise RuntimeError(f"POST {endpoint} did not return sha256")
    return {
        "endpoint": endpoint,
        "fixture": str(fixture_path.relative_to(ROOT)),
        "fixture_sha256": sha256_bytes(body),
        "receipt_sha256": sha,
    }


def verify_readback(server: Server, evidence: dict[str, Any], timeout: float) -> dict[str, Any]:
    endpoint = str(evidence["endpoint"])
    sha = str(evidence["receipt_sha256"])
    fixture_path = ROOT / str(evidence["fixture"])
    expected = load_fixture(fixture_path)
    status, response = http_request(
        "GET",
        server.base_url,
        f"{endpoint}/{sha}",
        token=server.token,
        timeout=timeout,
    )
    if status != 200:
        raise RuntimeError(f"GET {endpoint}/{sha} returned {status}")
    byte_identical = response == expected
    return {
        "endpoint": endpoint,
        "sha256": sha,
        "byte_identical": byte_identical,
        "readback_sha256": sha256_bytes(response),
        "expected_sha256": sha256_bytes(expected),
    }


def run_drill(args: argparse.Namespace) -> dict[str, Any]:
    server_bin = args.server_bin.resolve()
    if not server_bin.is_file():
        raise FileNotFoundError(f"server binary not found: {server_bin}")
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="ao2-cp-dr-restore-"))
    work_dir = work_dir.resolve()
    token = secrets.token_hex(32)
    timeout = float(args.timeout_seconds)

    original = Server(
        server_bin=server_bin,
        data_dir=work_dir / "original-data",
        token=token,
        port=args.port or find_free_port(),
        log_dir=work_dir / "logs" / "original",
    )
    restored: Server | None = None
    evidence: list[dict[str, Any]] = []
    restored_readback: list[dict[str, Any]] = []

    try:
        original.start()
        original.wait_ready(timeout)
        for label, endpoint, fixture in DEFAULT_FIXTURES:
            item = post_fixture(original, endpoint, ROOT / fixture, timeout)
            item["label"] = label
            evidence.append(item)
        original_readback = [verify_readback(original, item, timeout) for item in evidence]
        if not all(item["byte_identical"] for item in original_readback):
            raise RuntimeError("original server readback was not byte-identical")
        original.stop()

        backup_archive = work_dir / "backup" / "ao2-cp-data.tar.gz"
        archive_data_dir(original.data_dir, backup_archive)
        restored_data_dir = restore_data_dir(backup_archive, work_dir / "restore-root")
        restored = Server(
            server_bin=server_bin,
            data_dir=restored_data_dir,
            token=token,
            port=find_free_port(),
            log_dir=work_dir / "logs" / "restored",
        )
        restored.start()
        restored.wait_ready(timeout)
        restored_readback = [verify_readback(restored, item, timeout) for item in evidence]
    finally:
        original.stop()
        if restored is not None:
            restored.stop()

    status = "passed" if all(item["byte_identical"] for item in restored_readback) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": status,
        "work_dir": str(work_dir),
        "server_bin": str(server_bin),
        "backup_archive": str(work_dir / "backup" / "ao2-cp-data.tar.gz"),
        "original_data_dir": str(work_dir / "original-data"),
        "restored_data_dir": str(work_dir / "restore-root" / "data"),
        "ingested_evidence": evidence,
        "restored_readback": restored_readback,
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "restore_target": "content-addressed observer data directory",
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
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = run_drill(args)
    except Exception as exc:
        print(f"cp-dr-restore-drill: {exc}", file=sys.stderr)
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
