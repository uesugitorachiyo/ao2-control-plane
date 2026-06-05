#!/usr/bin/env python3
"""Fetch a token-safe AO2 Control Plane release support handoff kit.

This helper is intentionally small and dependency-free so it works on macOS,
Ubuntu, and Windows. It reads the bearer value from an environment variable,
fetches read-only observer surfaces, writes only response bodies and a sanitized
summary, and never prints or stores the token.

Example:
  AO2_CP_AUTH_VALUE="Bearer $AO2_CP_API_TOKEN" \
    python3 fetch_release_support_handoff.py \
      --base-url http://127.0.0.1:8744 \
      --out-dir ./release-handoff \
      --keep-latest 7
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SECRET_MARKERS = {
    "authorization_bearer_header": re.compile(r"authorization\s*[:=]\s*bearer\s+[^\s\"']+", re.IGNORECASE),
    "ao2_cp_api_token_assignment": re.compile(r"AO2_CP_API_TOKEN\s*=", re.IGNORECASE),
    "openai_api_key_assignment": re.compile(r"OPENAI_API_KEY\s*=", re.IGNORECASE),
    "anthropic_api_key_assignment": re.compile(r"ANTHROPIC_API_KEY\s*=", re.IGNORECASE),
    "json_api_token_field": re.compile(r"\"(?:api_token|access_token|refresh_token|token)\"\s*:\s*\"[^\"]+\"", re.IGNORECASE),
}

ENDPOINTS = {
    "release-support-verifier-handoff.json": "/api/v1/release/support-bundle/handoff.json",
    "release-support-bundle.json": "/api/v1/release/support-bundle/download",
    "SHA256SUMS": "/api/v1/release/support-bundle/SHA256SUMS",
    "release-support-bundle-verify.json": "/api/v1/release/support-bundle/verify.json",
    "release-support-bundle-manifest.json": "/api/v1/release/support-bundle/manifest.json",
}

PHASE1_PORTABLE_ENDPOINTS = {
    "phase1-portable-manifest.json": "/api/v1/phase1/promotion/portable-manifest/download",
    "ao2-phase1-operator-support-bundle.json": "/api/v1/phase1/promotion/operator-support-bundle/download",
    "ao2-phase1-gap-report.json": "/api/v1/phase1/promotion/gap-report/download",
    "phase1-SHA256SUMS": "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS",
}

PHASE1_PORTABLE_VERIFY_ENDPOINT = "/api/v1/phase1/promotion/portable-manifest/verify.json"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_canonical_json_file(path: Path) -> str:
    return sha256_bytes(canonical_json(json.loads(path.read_text(encoding="utf-8"))).encode("utf-8"))


def secret_marker_failures(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    return [f"{path.name}: forbidden marker {name}" for name, pattern in SECRET_MARKERS.items() if pattern.search(raw)]


def build_url(base_url: str, path: str, keep_latest: int | None) -> str:
    base = base_url.rstrip("/")
    query = ""
    if keep_latest is not None:
        query = "?" + urllib.parse.urlencode({"keep_latest": str(keep_latest)})
    return f"{base}{path}{query}"


def fetch(url: str, authorization: str, timeout: float, body: bytes | None = None) -> tuple[bytes, dict[str, str]]:
    headers = {"Authorization": authorization, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310: operator-provided local/private control-plane URL
        headers = {key.lower(): value for key, value in response.headers.items()}
        return response.read(), headers


def write_fetches(base_url: str, out_dir: Path, authorization: str, keep_latest: int | None, timeout: float) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    fetched: list[dict[str, Any]] = []
    for filename, endpoint in ENDPOINTS.items():
        url = build_url(base_url, endpoint, keep_latest)
        body, headers = fetch(url, authorization, timeout)
        path = out_dir / filename
        path.write_bytes(body)
        fetched.append({
            "filename": filename,
            "endpoint": endpoint,
            "bytes": len(body),
            "sha256": sha256_bytes(body),
            "canonical_sha256": sha256_canonical_json_file(path) if filename.endswith(".json") else None,
            "content_type": headers.get("content-type", ""),
            "digest_header": headers.get("x-ao2-cp-support-bundle-sha256") or headers.get("x-ao2-cp-sha256"),
        })
    return fetched


def write_phase1_portable_handoff(base_url: str, out_dir: Path, authorization: str, keep_latest: int | None, timeout: float) -> dict[str, Any]:
    fetched: list[dict[str, Any]] = []
    for filename, endpoint in PHASE1_PORTABLE_ENDPOINTS.items():
        url = build_url(base_url, endpoint, keep_latest)
        body, headers = fetch(url, authorization, timeout)
        path = out_dir / filename
        path.write_bytes(body)
        fetched.append({
            "filename": filename,
            "endpoint": endpoint,
            "bytes": len(body),
            "sha256": sha256_bytes(body),
            "canonical_sha256": sha256_canonical_json_file(path) if filename.endswith(".json") else None,
            "content_type": headers.get("content-type", ""),
            "digest_header": headers.get("x-ao2-cp-portable-manifest-sha256") or headers.get("x-ao2-cp-support-bundle-sha256") or headers.get("x-ao2-cp-gap-report-sha256"),
        })

    manifest_path = out_dir / "phase1-portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts: dict[str, Any] = {}
    for artifact in manifest.get("artifacts", []):
        name = artifact.get("name")
        filename = artifact.get("filename")
        if name and filename:
            artifact_path = out_dir / filename
            if artifact_path.exists():
                artifacts[name] = json.loads(artifact_path.read_text(encoding="utf-8"))
    upload = {
        "schema_version": "ao2.cp-phase1-portable-manifest-verification-upload.v1",
        "manifest": manifest,
        "artifacts": artifacts,
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
        },
    }
    upload_path = out_dir / "phase1-portable-manifest-verify-upload.json"
    upload_path.write_text(json.dumps(upload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verify_body, verify_headers = fetch(
        build_url(base_url, PHASE1_PORTABLE_VERIFY_ENDPOINT, keep_latest),
        authorization,
        timeout,
        body=upload_path.read_bytes(),
    )
    verify_path = out_dir / "phase1-portable-manifest-verification.json"
    verify_path.write_bytes(verify_body)
    fetched.extend([
        {
            "filename": upload_path.name,
            "endpoint": "local-generated-upload",
            "bytes": upload_path.stat().st_size,
            "sha256": sha256_bytes(upload_path.read_bytes()),
            "canonical_sha256": sha256_canonical_json_file(upload_path),
            "content_type": "application/json; charset=utf-8",
            "digest_header": None,
        },
        {
            "filename": verify_path.name,
            "endpoint": PHASE1_PORTABLE_VERIFY_ENDPOINT,
            "bytes": len(verify_body),
            "sha256": sha256_bytes(verify_body),
            "canonical_sha256": sha256_canonical_json_file(verify_path),
            "content_type": verify_headers.get("content-type", ""),
            "digest_header": None,
        },
    ])
    verification = json.loads(verify_path.read_text(encoding="utf-8"))
    return {
        "status": "passed" if verification.get("status") == "verified" else "failed",
        "fetched": fetched,
        "verification_status": verification.get("status"),
        "verification_upload": upload_path.name,
        "verification_result": verify_path.name,
        "trust_boundary": "read-only observer; does not mutate AO artifacts or approve releases",
    }


def run_offline_verifier(out_dir: Path, verifier: Path | None) -> dict[str, Any]:
    if verifier is None:
        candidate = Path(__file__).with_name("verify_release_support_bundle.py")
        verifier = candidate if candidate.exists() else None
    if verifier is None or not verifier.exists():
        return {"status": "not_run", "reason": "verify_release_support_bundle.py not found"}
    cmd = [sys.executable, str(verifier), "--json", "--checksums", str(out_dir / "SHA256SUMS"), str(out_dir / "release-support-bundle.json")]
    completed = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stdout = completed.stdout.strip()
    parsed: Any = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {"raw_stdout": stdout}
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "exit_code": completed.returncode,
        "command": "python verify_release_support_bundle.py --json --checksums SHA256SUMS release-support-bundle.json",
        "result": parsed,
        "stderr": completed.stderr.strip(),
    }


def validate_handoff(out_dir: Path) -> list[str]:
    failures: list[str] = []
    handoff_path = out_dir / "release-support-verifier-handoff.json"
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff.get("schema_version") != "ao2.cp-release-support-verifier-handoff.v1":
        failures.append("handoff schema_version is not ao2.cp-release-support-verifier-handoff.v1")
    if handoff.get("control_plane_role") != "read_only_observer":
        failures.append("handoff control_plane_role must remain read_only_observer")
    if handoff.get("release_acceptance_owner") != "factory-v3 evaluator-closer":
        failures.append("handoff release_acceptance_owner must remain factory-v3 evaluator-closer")
    if handoff.get("control_plane_approves_release") is not False:
        failures.append("handoff must not approve releases")
    if handoff.get("mutates_ao_artifacts") is not False:
        failures.append("handoff must not mutate AO artifacts")
    if handoff.get("contains_bearer_token") is not False:
        failures.append("handoff must declare contains_bearer_token=false")
    for path in out_dir.iterdir():
        if path.is_file() and path.name != "fetch-summary.json":
            failures.extend(secret_marker_failures(path))
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch AO2 Control Plane release support handoff artifacts without storing credentials.")
    parser.add_argument("--base-url", required=True, help="AO2 Control Plane base URL, e.g. http://127.0.0.1:8744")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for fetched token-free artifacts")
    parser.add_argument("--auth-env", default="AO2_CP_AUTH_VALUE", help="Environment variable containing full Authorization header value")
    parser.add_argument("--keep-latest", type=int, default=None, help="Optional keep_latest query value")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    parser.add_argument("--verifier", type=Path, default=None, help="Optional path to verify_release_support_bundle.py")
    parser.add_argument("--include-phase1-portable", action="store_true", help="Also fetch Phase 1 portable manifest artifacts, generate verification upload JSON, and post it to portable-manifest/verify.json")
    return parser.parse_args(argv[1:])


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    authorization = os.environ.get(args.auth_env)
    if not authorization:
        print(f"missing authorization value in ${args.auth_env}; expected full header value like 'Bearer ...'", file=sys.stderr)
        return 2
    if not authorization.lower().startswith("bearer "):
        print(f"${args.auth_env} must contain a bearer-style authorization header value", file=sys.stderr)
        return 2

    summary: dict[str, Any] = {
        "schema_version": "ao2.cp-release-support-fetch-summary.v1",
        "base_url": args.base_url.rstrip("/"),
        "keep_latest": args.keep_latest,
        "auth_source_env": args.auth_env,
        "auth_value_stored": False,
        "control_plane_role": "read_only_observer",
        "release_acceptance_owner": "factory-v3 evaluator-closer",
        "mutates_ao_artifacts": False,
        "control_plane_approves_release": False,
        "status": "failed",
        "fetched": [],
        "offline_verifier": {"status": "not_run"},
        "phase1_portable_handoff": {"status": "not_requested"},
        "failures": [],
    }
    try:
        summary["fetched"] = write_fetches(args.base_url, args.out_dir, authorization, args.keep_latest, args.timeout)
        summary["offline_verifier"] = run_offline_verifier(args.out_dir, args.verifier)
        if args.include_phase1_portable:
            summary["phase1_portable_handoff"] = write_phase1_portable_handoff(
                args.base_url,
                args.out_dir,
                authorization,
                args.keep_latest,
                args.timeout,
            )
        failures = validate_handoff(args.out_dir)
        if summary["offline_verifier"].get("status") == "failed":
            failures.append("offline verifier failed")
        if summary["phase1_portable_handoff"].get("status") == "failed":
            failures.append("phase1 portable manifest verification failed")
        summary["failures"] = failures
        summary["status"] = "failed" if failures else "passed"
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        summary["failures"] = [f"fetch failed: {type(exc).__name__}: {exc}"]
    finally:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "fetch-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    printable = {
        "status": summary["status"],
        "out_dir": str(args.out_dir),
        "fetched_files": [item["filename"] for item in summary.get("fetched", [])],
        "offline_verifier_status": summary.get("offline_verifier", {}).get("status"),
        "phase1_portable_handoff_status": summary.get("phase1_portable_handoff", {}).get("status"),
        "failures": summary.get("failures", []),
    }
    print(json.dumps(printable, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
