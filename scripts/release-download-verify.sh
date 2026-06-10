#!/usr/bin/env bash
set -euo pipefail

AO2_CP_RELEASE_REPO="${AO2_CP_RELEASE_REPO:-uesugitorachiyo/ao2-control-plane}"
AO2_CP_RELEASE_TAG="${AO2_CP_RELEASE_TAG:-v0.1.12}"
AO2_CP_RELEASE_DOWNLOAD_DIR="${AO2_CP_RELEASE_DOWNLOAD_DIR:-target/release-download/$AO2_CP_RELEASE_TAG}"

rm -rf "$AO2_CP_RELEASE_DOWNLOAD_DIR"
mkdir -p "$AO2_CP_RELEASE_DOWNLOAD_DIR"

gh release download "$AO2_CP_RELEASE_TAG" \
  --repo "$AO2_CP_RELEASE_REPO" \
  --dir "$AO2_CP_RELEASE_DOWNLOAD_DIR" \
  --clobber

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

printf "control_plane_release_checksum_verify=passed\n"
printf "control_plane_release_download_dir=%s\n" "$AO2_CP_RELEASE_DOWNLOAD_DIR"
printf "control_plane_release_download_verify=passed\n"
