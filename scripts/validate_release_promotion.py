#!/usr/bin/env python3
"""Validate an immutable dry-run promotion plan before publication."""

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import re


SHA256_RE = re.compile(r"[0-9a-f]{64}")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
TARGETS = ("linux-x86_64", "macos-aarch64", "windows-x86_64")
REQUIRED_BASELINE_ARTIFACTS = (
    "ao2-control-plane-post-release-verification-ubuntu",
    "ao2-control-plane-post-release-verification-macos",
    "ao2-control-plane-post-release-verification-windows",
    "ao2-control-plane-post-release-pair-verification",
    "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
    "ao2-control-plane-post-release-active-stack-release-handoff-readback",
)


def fail(message: str):
    raise SystemExit(f"release promotion validation failed: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_checksums(path: Path):
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
            fail("malformed SHA256SUMS row")
        name = parts[1]
        if name in rows:
            fail(f"duplicate SHA256SUMS entry: {name}")
        rows[name] = parts[0]
    return rows


def safe_plan_path(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or ".." in posix.parts or "\\" in relative:
        fail(f"unsafe promotion-plan path: {relative}")
    candidate = root.joinpath(*posix.parts)
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        fail(f"promotion-plan path escapes or is missing: {relative}")
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"promotion-plan path is not a regular file: {relative}")
    return candidate


def validate(args):
    root = args.root.resolve(strict=True)
    summary_path = root / "summary.json"
    baseline_path = root / "post-release-baseline.json"
    checksums_path = root / "SHA256SUMS"
    notes_path = root / "release-notes.md"
    for path in (summary_path, baseline_path, checksums_path, notes_path):
        if path.is_symlink() or not path.is_file():
            fail(f"missing regular promotion-plan file: {path.name}")

    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        fail("source SHA must be exactly 40 lowercase hexadecimal characters")
    if not SHA256_RE.fullmatch(args.plan_sha256):
        fail("promotion-plan digest must be exactly 64 lowercase hexadecimal characters")
    if args.source_sha != args.event_sha:
        fail("requested source SHA does not match workflow source SHA")
    if args.tag != f"v{args.version}":
        fail("release tag must exactly match v<version>")
    expected_confirmation = (
        f"publish {args.tag} from {args.source_sha} with plan {args.plan_sha256}"
    )
    if args.confirmation != expected_confirmation:
        fail("exact publication confirmation mismatch")
    if sha256(summary_path) != args.plan_sha256:
        fail("immutable promotion-plan digest mismatch")

    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"malformed promotion-plan JSON: {error}")
    expected_fields = {
        "schema_version": "ao2.cp-release-promotion-plan.v1",
        "status": "prepared",
        "version": args.version,
        "tag": args.tag,
        "dry_run": True,
        "source_commit": args.source_sha,
        "release_notes_sha256": sha256(notes_path),
    }
    for field, expected in expected_fields.items():
        if summary.get(field) != expected:
            fail(f"summary field mismatch: {field}")

    baseline_expected = {
        "schema_version": "ao2.cp-post-release-verification-baseline.v1",
        "status": "passed",
        "repo": "uesugitorachiyo/ao2-control-plane",
        "branch": "main",
        "workflow": "Post Release Verification",
        "head_sha": args.source_sha,
        "missing_artifacts": [],
        "expired_artifacts": [],
    }
    for field, expected in baseline_expected.items():
        if baseline.get(field) != expected:
            fail(f"post-release baseline field mismatch: {field}")
    expected_baseline_fields = {
        "schema_version",
        "status",
        "repo",
        "branch",
        "workflow",
        "run_id",
        "run_url",
        "head_sha",
        "checked_at_utc",
        "required_artifacts",
        "missing_artifacts",
        "expired_artifacts",
        "trust_boundary",
    }
    if set(baseline) != expected_baseline_fields:
        fail("post-release baseline has unexpected or missing fields")
    run_id = baseline.get("run_id")
    if type(run_id) is not int or run_id <= 0:
        fail("post-release baseline run ID is invalid")
    expected_run_url = (
        f"https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/{run_id}"
    )
    if baseline.get("run_url") != expected_run_url:
        fail("post-release baseline run URL is invalid")
    checked_at_raw = baseline.get("checked_at_utc")
    if not isinstance(checked_at_raw, str):
        fail("post-release baseline checked timestamp is invalid")
    try:
        checked_at = datetime.fromisoformat(checked_at_raw.replace("Z", "+00:00"))
    except ValueError:
        fail("post-release baseline checked timestamp is invalid")
    if checked_at.tzinfo is None:
        fail("post-release baseline checked timestamp must include a timezone")
    now = datetime.now(timezone.utc)
    checked_at = checked_at.astimezone(timezone.utc)
    if checked_at > now + timedelta(minutes=5):
        fail("post-release baseline checked timestamp is in the future")
    if now - checked_at > timedelta(hours=24):
        fail("post-release baseline is stale")
    required_artifacts = baseline.get("required_artifacts")
    if not isinstance(required_artifacts, list) or [
        item.get("name") for item in required_artifacts if isinstance(item, dict)
    ] != list(REQUIRED_BASELINE_ARTIFACTS):
        fail("post-release baseline artifact identity mismatch")
    if any(
        not isinstance(item, dict)
        or set(item) != {"name", "id", "size_in_bytes", "expired"}
        or item.get("expired") is not False
        or type(item.get("id")) is not int
        or type(item.get("size_in_bytes")) is not int
        or item["size_in_bytes"] < 0
        for item in required_artifacts
    ):
        fail("post-release baseline artifact metadata is invalid")
    baseline_trust = baseline.get("trust_boundary")
    required_false = (
        "downloads_github_actions_artifacts",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "mutates_github_releases",
        "credential_material_included",
    )
    if (
        not isinstance(baseline_trust, dict)
        or set(baseline_trust) != set(required_false)
        or any(
        baseline_trust.get(field) is not False for field in required_false
        )
    ):
        fail("post-release baseline trust boundary is unsafe")
    if summary.get("post_release_verification_baseline") != baseline:
        fail("summary embedded baseline does not match baseline artifact")
    if summary.get("required_post_release_artifacts") != list(REQUIRED_BASELINE_ARTIFACTS):
        fail("summary required post-release artifact list mismatch")

    assets = summary.get("archive_assets")
    if not isinstance(assets, list) or len(assets) != len(TARGETS):
        fail("promotion plan must contain exactly three archive assets")
    expected_names = {
        f"ao2-control-plane-{args.version}-{target}.tar.gz" for target in TARGETS
    }
    if {asset.get("name") for asset in assets if isinstance(asset, dict)} != expected_names:
        fail("promotion-plan archive names do not match the three-target contract")

    checksums = parse_checksums(checksums_path)
    expected_checksum_names = expected_names | {
        "summary.json",
        "post-release-baseline.json",
        "release-notes.md",
    }
    if set(checksums) != expected_checksum_names:
        fail("SHA256SUMS does not exactly cover promotion assets and evidence")
    if checksums["summary.json"] != args.plan_sha256:
        fail("SHA256SUMS summary digest mismatch")
    if checksums["post-release-baseline.json"] != sha256(baseline_path):
        fail("post-release baseline digest mismatch")
    if checksums["release-notes.md"] != sha256(notes_path):
        fail("release notes digest mismatch")

    actual_paths = set()
    for asset in assets:
        if set(asset) != {"name", "path", "sha256", "size_bytes", "target_label"}:
            fail("archive asset has unexpected or missing fields")
        name = asset["name"]
        target = asset["target_label"]
        if target not in TARGETS or name != f"ao2-control-plane-{args.version}-{target}.tar.gz":
            fail("archive target identity mismatch")
        path = safe_plan_path(root, asset["path"])
        if path.name != name:
            fail("archive path/name mismatch")
        digest = sha256(path)
        if asset["sha256"] != digest or checksums[name] != digest:
            fail(f"archive digest mismatch: {name}")
        if type(asset["size_bytes"]) is not int or asset["size_bytes"] != path.stat().st_size:
            fail(f"archive size mismatch: {name}")
        actual_paths.add(path.resolve())

    downloaded_archives = {
        path.resolve()
        for path in (root / "downloaded").glob("**/ao2-control-plane-*.tar.gz")
        if path.is_file()
    }
    if downloaded_archives != actual_paths:
        fail("downloaded archive closure does not exactly match the promotion plan")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--event-sha", required=True)
    args = parser.parse_args()
    validate(args)
    print("release_promotion_validation=passed")


if __name__ == "__main__":
    main()
