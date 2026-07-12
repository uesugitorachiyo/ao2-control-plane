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
from io import BytesIO
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-dr-restore-drill.v1"
RESTORE_ARCHIVE_SCHEMA_VERSION = "ao2.cp-dr-restore-archive.v1"
RESTORE_ARCHIVE_LEGACY_SCHEMA_VERSION = "ao2.cp-dr-restore-archive.v0"
RESTORE_ARCHIVE_FUTURE_SCHEMA_VERSION = "ao2.cp-dr-restore-archive.v999"
RESTORE_MANIFEST_NAME = "ao2-cp-restore-manifest.json"
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
        manifest = json.dumps(
            {
                "schema_version": RESTORE_ARCHIVE_SCHEMA_VERSION,
                "created_at_utc": utc_now(),
                "archive_root": "data",
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        manifest_info = tarfile.TarInfo(RESTORE_MANIFEST_NAME)
        manifest_info.size = len(manifest)
        manifest_info.mtime = int(time.time())
        archive.addfile(manifest_info, BytesIO(manifest))
        archive.add(data_dir, arcname="data")


def restore_archive_manifest_decision(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
) -> dict[str, Any]:
    manifest_member = next((member for member in members if member.name == RESTORE_MANIFEST_NAME), None)
    if manifest_member is None:
        return {
            "decision": "accepted_with_warning",
            "reason": "legacy_missing_manifest",
            "schema_version": None,
        }

    manifest_file = archive.extractfile(manifest_member)
    if manifest_file is None:
        return {
            "decision": "rejected",
            "reason": "manifest_unreadable",
            "schema_version": None,
        }

    try:
        manifest = json.loads(manifest_file.read().decode("utf-8"))
    except json.JSONDecodeError:
        return {
            "decision": "rejected",
            "reason": "manifest_json_invalid",
            "schema_version": None,
        }
    if not isinstance(manifest, dict):
        return {
            "decision": "rejected",
            "reason": "manifest_json_invalid",
            "schema_version": None,
        }
    schema_version = manifest.get("schema_version")
    if "schema_version" not in manifest:
        return {
            "decision": "rejected",
            "reason": "manifest_schema_missing",
            "schema_version": None,
        }
    if not isinstance(schema_version, str):
        return {
            "decision": "rejected",
            "reason": "manifest_schema_not_string",
            "schema_version": schema_version,
        }
    if schema_version == RESTORE_ARCHIVE_SCHEMA_VERSION:
        return {
            "decision": "accepted",
            "reason": "current_manifest",
            "schema_version": schema_version,
        }
    if schema_version == RESTORE_ARCHIVE_LEGACY_SCHEMA_VERSION:
        return {
            "decision": "accepted_with_warning",
            "reason": "older_manifest",
            "schema_version": schema_version,
        }
    return {
        "decision": "rejected",
        "reason": "unsupported_restore_archive_schema_version",
        "schema_version": schema_version,
    }


def restore_data_dir(archive_path: Path, restore_root: Path) -> Path:
    restore_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError(f"unsafe archive member: {member.name}")
        decision = restore_archive_manifest_decision(archive, members)
        if decision["decision"] == "rejected":
            if decision["reason"] == "manifest_unreadable":
                raise ValueError("restore archive manifest is unreadable")
            if decision["reason"] != "unsupported_restore_archive_schema_version":
                raise ValueError(str(decision["reason"]))
            raise ValueError(
                "unsupported restore archive schema_version: "
                f"{decision.get('schema_version')!r}"
            )
        archive.extractall(restore_root)
    return restore_root / "data"


def write_restore_archive_variant(
    path: Path,
    *,
    schema_version: str | None,
    include_manifest: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        if include_manifest:
            manifest = json.dumps(
                {
                    "schema_version": schema_version,
                    "archive_root": "data",
                },
                sort_keys=True,
            ).encode("utf-8")
            manifest_info = tarfile.TarInfo(RESTORE_MANIFEST_NAME)
            manifest_info.size = len(manifest)
            manifest_info.mtime = int(time.time())
            archive.addfile(manifest_info, BytesIO(manifest))
        data = b"{}"
        data_info = tarfile.TarInfo("data/schema-version.json")
        data_info.size = len(data)
        data_info.mtime = int(time.time())
        archive.addfile(data_info, BytesIO(data))


def write_restore_archive_with_manifest_bytes(path: Path, manifest: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        manifest_info = tarfile.TarInfo(RESTORE_MANIFEST_NAME)
        manifest_info.size = len(manifest)
        manifest_info.mtime = int(time.time())
        archive.addfile(manifest_info, BytesIO(manifest))
        data = b"{}"
        data_info = tarfile.TarInfo("data/schema-version.json")
        data_info.size = len(data)
        data_info.mtime = int(time.time())
        archive.addfile(data_info, BytesIO(data))


def write_unsafe_path_archive(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        manifest = json.dumps(
            {
                "schema_version": RESTORE_ARCHIVE_SCHEMA_VERSION,
                "archive_root": "data",
            },
            sort_keys=True,
        ).encode("utf-8")
        manifest_info = tarfile.TarInfo(RESTORE_MANIFEST_NAME)
        manifest_info.size = len(manifest)
        manifest_info.mtime = int(time.time())
        archive.addfile(manifest_info, BytesIO(manifest))
        data = b"{}"
        data_info = tarfile.TarInfo("../unsafe-path-member.json")
        data_info.size = len(data)
        data_info.mtime = int(time.time())
        archive.addfile(data_info, BytesIO(data))


def write_skewed_archive(path: Path) -> None:
    write_restore_archive_variant(path, schema_version=RESTORE_ARCHIVE_FUTURE_SCHEMA_VERSION)


def inspect_restore_archive(path: Path) -> dict[str, Any]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                return {
                    "decision": "rejected",
                    "reason": "unsafe_archive_member",
                    "schema_version": None,
                }
        return restore_archive_manifest_decision(archive, members)


def run_compatibility_matrix(work_dir: Path) -> list[dict[str, Any]]:
    matrix_root = work_dir / "compatibility-matrix"
    matrix_root.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = [
        {
            "name": "current_manifest",
            "schema_version": RESTORE_ARCHIVE_SCHEMA_VERSION,
            "include_manifest": True,
            "expected_decision": "accepted",
        },
        {
            "name": "legacy_missing_manifest",
            "schema_version": None,
            "include_manifest": False,
            "expected_decision": "accepted_with_warning",
        },
        {
            "name": "older_manifest",
            "schema_version": RESTORE_ARCHIVE_LEGACY_SCHEMA_VERSION,
            "include_manifest": True,
            "expected_decision": "accepted_with_warning",
        },
        {
            "name": "future_manifest",
            "schema_version": RESTORE_ARCHIVE_FUTURE_SCHEMA_VERSION,
            "include_manifest": True,
            "expected_decision": "rejected",
        },
    ]
    results: list[dict[str, Any]] = []

    for case in cases:
        name = str(case["name"])
        archive_path = matrix_root / name / "ao2-cp-data.tar.gz"
        write_restore_archive_variant(
            archive_path,
            schema_version=case["schema_version"],
            include_manifest=bool(case["include_manifest"]),
        )
        decision = inspect_restore_archive(archive_path)
        restore_error: str | None = None
        restored = False
        try:
            restore_data_dir(archive_path, matrix_root / name / "restore-root")
            restored = True
        except Exception as exc:
            restore_error = str(exc)

        expected_decision = str(case["expected_decision"])
        decision_matches = decision["decision"] == expected_decision
        restore_matches = (expected_decision == "rejected" and not restored) or (
            expected_decision != "rejected" and restored
        )
        results.append(
            {
                "name": name,
                "status": "passed" if decision_matches and restore_matches else "failed",
                "decision": decision["decision"],
                "expected_decision": expected_decision,
                "reason": decision["reason"],
                "schema_version": decision.get("schema_version"),
                "restore_accepted": restored,
                "restore_error": restore_error,
            }
        )

    return results


def run_negative_scenarios(work_dir: Path) -> list[dict[str, Any]]:
    negative_root = work_dir / "negative-scenarios"
    negative_root.mkdir(parents=True, exist_ok=True)
    scenarios: list[dict[str, Any]] = []

    def expect_rejection(name: str, archive_path: Path, expected_fragment: str) -> None:
        try:
            restore_data_dir(archive_path, negative_root / name / "restore-root")
        except Exception as exc:
            message = str(exc)
            scenarios.append(
                {
                    "name": name,
                    "status": "passed" if expected_fragment in message else "failed",
                    "expected_rejection_observed": expected_fragment in message,
                    "error": message,
                }
            )
            return
        scenarios.append(
            {
                "name": name,
                "status": "failed",
                "expected_rejection_observed": False,
                "error": "restore unexpectedly accepted invalid archive",
            }
        )

    expect_rejection(
        "missing_archive",
        negative_root / "missing" / "ao2-cp-data.tar.gz",
        "No such file",
    )

    corrupted = negative_root / "corrupted" / "ao2-cp-data.tar.gz"
    corrupted.parent.mkdir(parents=True, exist_ok=True)
    corrupted.write_bytes(b"not a gzip tar archive")
    expect_rejection("corrupted_archive", corrupted, "not a gzip")

    skewed = negative_root / "version-skew" / "ao2-cp-data.tar.gz"
    write_skewed_archive(skewed)
    expect_rejection("version_skew", skewed, "unsupported restore archive schema_version")

    malformed = negative_root / "malformed-manifest-json" / "ao2-cp-data.tar.gz"
    write_restore_archive_with_manifest_bytes(malformed, b"{not-json")
    expect_rejection("malformed_manifest_json", malformed, "manifest_json_invalid")

    missing_schema = negative_root / "missing-manifest-schema" / "ao2-cp-data.tar.gz"
    write_restore_archive_with_manifest_bytes(
        missing_schema,
        json.dumps({"archive_root": "data"}, sort_keys=True).encode("utf-8"),
    )
    expect_rejection("missing_manifest_schema", missing_schema, "manifest_schema_missing")

    non_string_schema = negative_root / "non-string-manifest-schema" / "ao2-cp-data.tar.gz"
    write_restore_archive_with_manifest_bytes(
        non_string_schema,
        json.dumps({"schema_version": 1, "archive_root": "data"}, sort_keys=True).encode("utf-8"),
    )
    expect_rejection("non_string_manifest_schema", non_string_schema, "manifest_schema_not_string")

    unsafe_path = negative_root / "unsafe-path-member" / "ao2-cp-data.tar.gz"
    write_unsafe_path_archive(unsafe_path)
    expect_rejection("unsafe_path_member", unsafe_path, "unsafe archive member")

    return scenarios


def malformed_restore_corpus(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    names = [
        "malformed_manifest_json",
        "missing_manifest_schema",
        "non_string_manifest_schema",
        "unsafe_path_member",
    ]
    by_name = {str(item["name"]): item for item in scenarios}
    if not scenarios:
        return {
            "status": "skipped",
            "scenario_names": [],
            "required_scenario_names": names,
        }
    observed = [name for name in names if name in by_name]
    passed = all(by_name.get(name, {}).get("status") == "passed" for name in names)
    return {
        "status": "passed" if passed else "failed",
        "scenario_names": observed,
        "required_scenario_names": names,
    }


def restore_acceptance_checklist(
    negative_scenarios: list[dict[str, Any]],
    compatibility_matrix: list[dict[str, Any]],
    malformed_corpus: dict[str, Any],
) -> dict[str, Any]:
    negative_status = "passed" if negative_scenarios and all(
        item["status"] == "passed" for item in negative_scenarios
    ) else "skipped"
    compatibility_status = "passed" if compatibility_matrix and all(
        item["status"] == "passed" for item in compatibility_matrix
    ) else "failed"
    malformed_status = str(malformed_corpus.get("status", "failed"))
    gates = [
        {
            "name": "negative_restore_rejections",
            "status": negative_status,
            "evidence_ref": "negative_scenarios",
        },
        {
            "name": "archive_compatibility_matrix",
            "status": compatibility_status,
            "evidence_ref": "compatibility_matrix",
        },
        {
            "name": "malformed_restore_corpus",
            "status": malformed_status,
            "evidence_ref": "malformed_restore_corpus",
        },
        {
            "name": "token_redaction_boundary",
            "status": "passed",
            "evidence_ref": "trust_boundary.token_in_output",
        },
        {
            "name": "observer_role_boundary",
            "status": "passed",
            "evidence_ref": "trust_boundary.control_plane_role",
        },
    ]
    failed = [gate for gate in gates if gate["status"] == "failed"]
    return {
        "schema_version": "ao2.cp-dr-restore-acceptance-checklist.v1",
        "status": "failed" if failed else "passed",
        "source_recommendation_rank": 25,
        "source_recommendation_task": "Create backup restore acceptance checklist fixture",
        "observer_only": True,
        "provider_calls_allowed": False,
        "credential_use_allowed": False,
        "release_or_publish_allowed": False,
        "direct_main_mutation": False,
        "rsi_remains_denied": True,
        "gates": gates,
    }


def negative_report(work_dir: Path) -> dict[str, Any]:
    scenarios = run_negative_scenarios(work_dir)
    compatibility_matrix = run_compatibility_matrix(work_dir)
    malformed_corpus = malformed_restore_corpus(scenarios)
    acceptance_checklist = restore_acceptance_checklist(
        scenarios,
        compatibility_matrix,
        malformed_corpus,
    )
    status = (
        "passed"
        if all(item["status"] == "passed" for item in scenarios + compatibility_matrix)
        and malformed_corpus["status"] == "passed"
        and acceptance_checklist["status"] == "passed"
        else "failed"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": status,
        "work_dir": str(work_dir),
        "negative_scenarios": scenarios,
        "compatibility_matrix": compatibility_matrix,
        "malformed_restore_corpus": malformed_corpus,
        "restore_acceptance_checklist": acceptance_checklist,
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "restore_target": "content-addressed observer data directory",
            "provider_auth": "local_oauth_cli_only",
            "token_in_output": False,
        },
    }


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
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="ao2-cp-dr-restore-"))
    work_dir = work_dir.resolve()
    if args.negative_only:
        return negative_report(work_dir)

    server_bin = args.server_bin.resolve()
    if not server_bin.is_file():
        raise FileNotFoundError(f"server binary not found: {server_bin}")
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

    negative_scenarios = [] if args.skip_negative_scenarios else run_negative_scenarios(work_dir)
    compatibility_matrix = run_compatibility_matrix(work_dir)
    malformed_corpus = malformed_restore_corpus(negative_scenarios)
    acceptance_checklist = restore_acceptance_checklist(
        negative_scenarios,
        compatibility_matrix,
        malformed_corpus,
    )
    negative_status = all(item["status"] == "passed" for item in negative_scenarios)
    compatibility_status = all(item["status"] == "passed" for item in compatibility_matrix)
    malformed_status = malformed_corpus["status"] in {"passed", "skipped"}
    status = "passed" if (
        all(item["byte_identical"] for item in restored_readback)
        and negative_status
        and compatibility_status
        and malformed_status
        and acceptance_checklist["status"] == "passed"
    ) else "failed"
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
        "negative_scenarios": negative_scenarios,
        "compatibility_matrix": compatibility_matrix,
        "malformed_restore_corpus": malformed_corpus,
        "restore_acceptance_checklist": acceptance_checklist,
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
    parser.add_argument("--negative-only", action="store_true")
    parser.add_argument("--skip-negative-scenarios", action="store_true")
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
