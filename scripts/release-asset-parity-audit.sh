#!/usr/bin/env bash
set -euo pipefail

AO2_CP_RELEASE_REPO="${AO2_CP_RELEASE_REPO:-uesugitorachiyo/ao2-control-plane}"
AO2_CP_RELEASE_TAG="${AO2_CP_RELEASE_TAG:-v0.1.13}"
AO2_CP_RELEASE_ASSET_PARITY_ROOT="${AO2_CP_RELEASE_ASSET_PARITY_ROOT:-target/release-asset-parity-audit}"
AO2_CP_RELEASE_ASSET_PARITY_SUMMARY_JSON="${AO2_CP_RELEASE_ASSET_PARITY_SUMMARY_JSON:-$AO2_CP_RELEASE_ASSET_PARITY_ROOT/summary.json}"
AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON="${AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON:-}"
AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS="${AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS:-}"
AO2_CP_RELEASE_ASSET_PARITY_RELEASE_NOTES="${AO2_CP_RELEASE_ASSET_PARITY_RELEASE_NOTES:-docs/releases/${AO2_CP_RELEASE_TAG}-notes.md}"
AO2_CP_RELEASE_ASSET_PARITY_STRICT="${AO2_CP_RELEASE_ASSET_PARITY_STRICT:-0}"

mkdir -p "$AO2_CP_RELEASE_ASSET_PARITY_ROOT"
mkdir -p "$(dirname "$AO2_CP_RELEASE_ASSET_PARITY_SUMMARY_JSON")"

if command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
elif command -v python >/dev/null 2>&1; then
  python_bin="python"
else
  echo "missing Python interpreter: python3 or python required" >&2
  exit 1
fi

if [ -z "$AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON" ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "missing gh CLI: set AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON for offline audit" >&2
    exit 1
  fi
  AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON="$AO2_CP_RELEASE_ASSET_PARITY_ROOT/release-view.json"
  gh release view "$AO2_CP_RELEASE_TAG" \
    --repo "$AO2_CP_RELEASE_REPO" \
    --json tagName,name,isDraft,isPrerelease,publishedAt,assets,url \
    >"$AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON"
fi

if [ -z "$AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS" ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "missing gh CLI: set AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS for offline audit" >&2
    exit 1
  fi
  checksum_dir="$AO2_CP_RELEASE_ASSET_PARITY_ROOT/download"
  rm -rf "$checksum_dir"
  mkdir -p "$checksum_dir"
  gh release download "$AO2_CP_RELEASE_TAG" \
    --repo "$AO2_CP_RELEASE_REPO" \
    --pattern SHA256SUMS \
    --dir "$checksum_dir" \
    --clobber
  AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS="$checksum_dir/SHA256SUMS"
fi

if [ ! -f "$AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS" ]; then
  echo "missing release checksum manifest: $AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS" >&2
  exit 1
fi

"$python_bin" - \
  "$AO2_CP_RELEASE_REPO" \
  "$AO2_CP_RELEASE_TAG" \
  "$AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON" \
  "$AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS" \
  "$AO2_CP_RELEASE_ASSET_PARITY_RELEASE_NOTES" \
  "$AO2_CP_RELEASE_ASSET_PARITY_SUMMARY_JSON" \
  "$AO2_CP_RELEASE_ASSET_PARITY_STRICT" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

(
    release_repo,
    release_tag,
    release_view_path,
    checksums_path,
    release_notes_path,
    summary_path,
    strict_raw,
) = sys.argv[1:]

version = release_tag[1:] if release_tag.startswith("v") else release_tag
target_labels = ["linux-x86_64", "macos-aarch64", "windows-x86_64"]
expected_platform_archives = [
    f"ao2-control-plane-{version}-{target}.tar.gz" for target in target_labels
]
expected_evidence_assets = [
    "summary.json",
]
required_assets = ["SHA256SUMS"] + expected_platform_archives + expected_evidence_assets
checksum_required_assets = expected_platform_archives

release_view_bytes = Path(release_view_path).read_bytes()
release_view = json.loads(release_view_bytes.decode("utf-8"))
assets = release_view.get("assets", [])
asset_names = sorted(asset.get("name", "") for asset in assets if asset.get("name"))

checksum_text = Path(checksums_path).read_text(encoding="utf-8")
checksum_entries = []
checksum_sha256_by_asset = {}
for line in checksum_text.splitlines():
    parts = line.strip().split()
    if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
        asset_name = parts[-1].lstrip("*")
        checksum_entries.append(asset_name)
        checksum_sha256_by_asset[asset_name] = parts[0].lower()

notes_archives = []
notes_sha256_by_archive = {}
notes_path = Path(release_notes_path)
if notes_path.exists():
    notes_text = notes_path.read_text(encoding="utf-8")
    archive_pattern = (
        r"ao2-control-plane-\d+\.\d+\.\d+-(?:linux-x86_64|macos-aarch64|windows-x86_64)\.tar\.gz"
    )
    notes_archives = sorted(
        set(
            re.findall(
                archive_pattern,
                notes_text,
            )
        )
    )
    for match in re.finditer(
        rf"`({archive_pattern})`\s*\|\s*`([0-9a-fA-F]{{64}})`",
        notes_text,
    ):
        notes_sha256_by_archive[match.group(1)] = match.group(2).lower()

asset_name_set = set(asset_names)
checksum_entry_set = set(checksum_entries)
notes_archive_set = set(notes_archives)

missing_platform_archives = [
    name for name in expected_platform_archives if name not in asset_name_set
]
missing_evidence_assets = [
    name for name in expected_evidence_assets if name not in asset_name_set
]
missing_checksum_entries = [
    name for name in checksum_required_assets if name not in checksum_entry_set
]
release_notes_archive_drift = sorted(
    (notes_archive_set - asset_name_set) | (set(expected_platform_archives) - notes_archive_set)
)
release_notes_checksum_drift = [
    {
        "asset": name,
        "checksum_manifest_sha256": checksum_sha256_by_asset[name],
        "release_notes_sha256": notes_sha256_by_archive[name],
    }
    for name in expected_platform_archives
    if name in checksum_sha256_by_asset
    and name in notes_sha256_by_archive
    and checksum_sha256_by_asset[name] != notes_sha256_by_archive[name]
]

gaps = []
if missing_platform_archives:
    gaps.append(
        {
            "gap_kind": "missing_platform_archives",
            "severity": "release_attention",
            "assets": missing_platform_archives,
        }
    )
if missing_evidence_assets:
    gaps.append(
        {
            "gap_kind": "missing_evidence_assets",
            "severity": "release_attention",
            "assets": missing_evidence_assets,
        }
    )
if missing_checksum_entries:
    gaps.append(
        {
            "gap_kind": "missing_checksum_entries",
            "severity": "release_attention",
            "assets": missing_checksum_entries,
        }
    )
if release_notes_archive_drift:
    gaps.append(
        {
            "gap_kind": "release_notes_archive_drift",
            "severity": "release_attention",
            "assets": release_notes_archive_drift,
        }
    )
if release_notes_checksum_drift:
    gaps.append(
        {
            "gap_kind": "release_notes_checksum_drift",
            "severity": "release_attention",
            "assets": [item["asset"] for item in release_notes_checksum_drift],
        }
    )

status = "attention" if gaps else "passed"
strict = strict_raw == "1"
summary = {
    "schema_version": "ao2.cp-release-asset-parity-audit.v1",
    "status": status,
    "strict": strict,
    "release_repo": release_repo,
    "release_tag": release_tag,
    "release_name": release_view.get("name", ""),
    "release_url": release_view.get("url", ""),
    "published_at": release_view.get("publishedAt", ""),
    "stable_release": not bool(release_view.get("isDraft")) and not bool(release_view.get("isPrerelease")),
    "release_view_json": str(Path(release_view_path)),
    "release_view_sha256": hashlib.sha256(release_view_bytes).hexdigest(),
    "checksum_manifest": str(Path(checksums_path)),
    "release_notes": str(notes_path),
    "expected_platform_archives": expected_platform_archives,
    "expected_evidence_assets": expected_evidence_assets,
    "published_assets": asset_names,
    "checksum_entries": sorted(checksum_entries),
    "checksum_sha256_by_asset": checksum_sha256_by_asset,
    "release_notes_archives": notes_archives,
    "release_notes_sha256_by_archive": notes_sha256_by_archive,
    "missing_platform_archives": missing_platform_archives,
    "missing_evidence_assets": missing_evidence_assets,
    "missing_checksum_entries": missing_checksum_entries,
    "release_notes_archive_drift": release_notes_archive_drift,
    "release_notes_checksum_drift": release_notes_checksum_drift,
    "gaps": gaps,
    "trust_boundary": {
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    },
}

Path(summary_path).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"control_plane_release_asset_parity={status}")
print(f"control_plane_release_asset_parity_summary={summary_path}")
if status != "passed" and strict:
    raise SystemExit(1)
PY
