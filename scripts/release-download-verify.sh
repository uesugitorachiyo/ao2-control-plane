#!/usr/bin/env bash
set -euo pipefail

AO2_CP_RELEASE_REPO="${AO2_CP_RELEASE_REPO:-uesugitorachiyo/ao2-control-plane}"
AO2_CP_RELEASE_TAG="${AO2_CP_RELEASE_TAG:-v0.1.12}"
AO2_CP_RELEASE_DOWNLOAD_DIR="${AO2_CP_RELEASE_DOWNLOAD_DIR:-target/release-download/$AO2_CP_RELEASE_TAG}"
AO2_CP_RELEASE_DOWNLOAD_OFFLINE="${AO2_CP_RELEASE_DOWNLOAD_OFFLINE:-0}"
AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON="${AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON:-}"

if [ "$AO2_CP_RELEASE_DOWNLOAD_OFFLINE" != "1" ]; then
  rm -rf "$AO2_CP_RELEASE_DOWNLOAD_DIR"
fi
mkdir -p "$AO2_CP_RELEASE_DOWNLOAD_DIR"

if [ "$AO2_CP_RELEASE_DOWNLOAD_OFFLINE" != "1" ]; then
  gh release download "$AO2_CP_RELEASE_TAG" \
    --repo "$AO2_CP_RELEASE_REPO" \
    --dir "$AO2_CP_RELEASE_DOWNLOAD_DIR" \
    --clobber
fi

if [ ! -f "$AO2_CP_RELEASE_DOWNLOAD_DIR/SHA256SUMS" ]; then
  echo "missing release checksum manifest: $AO2_CP_RELEASE_DOWNLOAD_DIR/SHA256SUMS" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  (cd "$AO2_CP_RELEASE_DOWNLOAD_DIR" && shasum -a 256 -c SHA256SUMS)
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$AO2_CP_RELEASE_DOWNLOAD_DIR" && sha256sum -c SHA256SUMS)
else
  echo "missing checksum verifier: shasum or sha256sum required" >&2
  exit 1
fi

if [ -n "$AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON" ]; then
  mkdir -p "$(dirname "$AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON")"
  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    python_bin="python"
  else
    echo "missing Python interpreter: python3 or python required" >&2
    exit 1
  fi
  "$python_bin" - "$AO2_CP_RELEASE_REPO" "$AO2_CP_RELEASE_TAG" "$AO2_CP_RELEASE_DOWNLOAD_DIR" "$AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

release_repo, release_tag, download_dir, summary_path = sys.argv[1:]
download_root = Path(download_dir)
assets = []

for path in sorted(download_root.iterdir(), key=lambda p: p.name):
    if not path.is_file():
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assets.append(
        {
            "name": path.name,
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "sha256": digest,
        }
    )

summary = {
    "schema_version": "ao2.cp-release-publication-closure.v1",
    "status": "passed",
    "release_repo": release_repo,
    "release_tag": release_tag,
    "download_dir": str(download_root),
    "checksum_manifest": str(download_root / "SHA256SUMS"),
    "checksum_verified": True,
    "assets": assets,
    "trust_boundary": {
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    },
}
Path(summary_path).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

printf "control_plane_release_checksum_verify=passed\n"
printf "control_plane_release_download_dir=%s\n" "$AO2_CP_RELEASE_DOWNLOAD_DIR"
printf "control_plane_release_download_verify=passed\n"
if [ -n "$AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON" ]; then
  printf "control_plane_release_publication_closure=passed\n"
  printf "control_plane_release_publication_closure_summary=%s\n" "$AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON"
fi
