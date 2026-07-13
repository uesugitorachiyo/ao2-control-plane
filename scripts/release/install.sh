#!/usr/bin/env sh
set -eu

cd "$(dirname -- "$0")"

INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-$HOME/.local/bin}}"
SERVER_NAME="ao2-cp-server"
GC_NAME="ao2-cp-gc"
RECEIPT_NAME="ao2-control-plane.install-receipt.json"
SERVER_BACKUP=".$SERVER_NAME.ao2-previous"
GC_BACKUP=".$GC_NAME.ao2-previous"
PREVIOUS_RECEIPT=".ao2-control-plane.install-receipt.previous.json"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    echo "install requires sha256sum or shasum" >&2
    return 1
  fi
}

expected_sha() {
  awk -v path="$1" '$2 == path { print $1 }' SHA256SUMS
}

verify_payload() {
  path="$1"
  checksum_path="${2:-$1}"
  expected=$(expected_sha "$checksum_path")
  if [ -z "$expected" ]; then
    echo "missing checksum for $checksum_path" >&2
    return 1
  fi
  actual=$(sha256_file "$path")
  if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $path" >&2
    return 1
  fi
}

verify_payload "bin/$SERVER_NAME"
verify_payload "bin/$GC_NAME"
command -v python3 >/dev/null 2>&1 || {
  echo "install requires python3 to emit $RECEIPT_NAME" >&2
  exit 1
}

mkdir -p "$INSTALL_DIR"
STAGE=$(mktemp -d "$INSTALL_DIR/.ao2-control-plane.stage.XXXXXX")
transaction_started=0
committed=0
server_prior=0
gc_prior=0
receipt_prior=0
server_moved=0
gc_moved=0
receipt_moved=0
server_installed=0
gc_installed=0
receipt_installed=0

cleanup() {
  if [ "$transaction_started" -eq 1 ] && [ "$committed" -eq 0 ]; then
    if [ "$server_installed" -eq 1 ]; then rm -f "$INSTALL_DIR/$SERVER_NAME"; fi
    if [ "$gc_installed" -eq 1 ]; then rm -f "$INSTALL_DIR/$GC_NAME"; fi
    if [ "$receipt_installed" -eq 1 ]; then rm -f "$INSTALL_DIR/$RECEIPT_NAME"; fi
    if [ "$server_moved" -eq 1 ] && [ -f "$INSTALL_DIR/$SERVER_BACKUP" ]; then
      mv "$INSTALL_DIR/$SERVER_BACKUP" "$INSTALL_DIR/$SERVER_NAME"
    fi
    if [ "$gc_moved" -eq 1 ] && [ -f "$INSTALL_DIR/$GC_BACKUP" ]; then
      mv "$INSTALL_DIR/$GC_BACKUP" "$INSTALL_DIR/$GC_NAME"
    fi
    if [ "$receipt_moved" -eq 1 ] && [ -f "$INSTALL_DIR/$PREVIOUS_RECEIPT" ]; then
      mv "$INSTALL_DIR/$PREVIOUS_RECEIPT" "$INSTALL_DIR/$RECEIPT_NAME"
    fi
  fi
  rm -rf "$STAGE"
}
trap cleanup EXIT HUP INT TERM

cp "bin/$SERVER_NAME" "$STAGE/$SERVER_NAME"
cp "bin/$GC_NAME" "$STAGE/$GC_NAME"
chmod 755 "$STAGE/$SERVER_NAME" "$STAGE/$GC_NAME"
verify_payload "$STAGE/$SERVER_NAME" "bin/$SERVER_NAME" 2>/dev/null || {
  echo "checksum mismatch for staged $SERVER_NAME" >&2
  exit 1
}
verify_payload "$STAGE/$GC_NAME" "bin/$GC_NAME" 2>/dev/null || {
  echo "checksum mismatch for staged $GC_NAME" >&2
  exit 1
}

server_sha=$(sha256_file "$STAGE/$SERVER_NAME")
gc_sha=$(sha256_file "$STAGE/$GC_NAME")
server_prior_sha=""
gc_prior_sha=""
if [ -f "$INSTALL_DIR/$SERVER_NAME" ]; then
  server_prior=1
  server_prior_sha=$(sha256_file "$INSTALL_DIR/$SERVER_NAME")
fi
if [ -f "$INSTALL_DIR/$GC_NAME" ]; then
  gc_prior=1
  gc_prior_sha=$(sha256_file "$INSTALL_DIR/$GC_NAME")
fi
version=$(python3 -c 'import json; print(json.load(open("RELEASE-MANIFEST.json", encoding="utf-8"))["version"])')

python3 - "$STAGE/$RECEIPT_NAME" "$version" "$INSTALL_DIR" \
  "$server_sha" "$server_prior" "$server_prior_sha" \
  "$gc_sha" "$gc_prior" "$gc_prior_sha" <<'PY'
import json
import sys
from pathlib import Path

output, version, install_dir = sys.argv[1:4]
rows = []
arguments = sys.argv[4:]
for name, offset in (("ao2-cp-server", 0), ("ao2-cp-gc", 3)):
    sha256, prior_present, prior_sha256 = arguments[offset : offset + 3]
    rows.append(
        {
            "backup_path": str(Path(install_dir) / f".{name}.ao2-previous"),
            "name": name,
            "path": str(Path(install_dir) / name),
            "prior_present": prior_present == "1",
            "prior_sha256": prior_sha256 or None,
            "sha256": sha256,
        }
    )
payload = {
    "schema_version": "ao2-control-plane.install-receipt.v1",
    "operation": "install",
    "version": version,
    "install_dir": install_dir,
    "binaries": rows,
    "preserves_data_and_config": True,
}
Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

rm -f "$INSTALL_DIR/$SERVER_BACKUP" "$INSTALL_DIR/$GC_BACKUP" "$INSTALL_DIR/$PREVIOUS_RECEIPT"
transaction_started=1
if [ "$server_prior" -eq 1 ]; then
  mv "$INSTALL_DIR/$SERVER_NAME" "$INSTALL_DIR/$SERVER_BACKUP"
  server_moved=1
fi
if [ "$gc_prior" -eq 1 ]; then
  mv "$INSTALL_DIR/$GC_NAME" "$INSTALL_DIR/$GC_BACKUP"
  gc_moved=1
fi
if [ -f "$INSTALL_DIR/$RECEIPT_NAME" ]; then
  receipt_prior=1
  mv "$INSTALL_DIR/$RECEIPT_NAME" "$INSTALL_DIR/$PREVIOUS_RECEIPT"
  receipt_moved=1
fi
mv "$STAGE/$SERVER_NAME" "$INSTALL_DIR/$SERVER_NAME"
server_installed=1
mv "$STAGE/$GC_NAME" "$INSTALL_DIR/$GC_NAME"
gc_installed=1
mv "$STAGE/$RECEIPT_NAME" "$INSTALL_DIR/$RECEIPT_NAME"
receipt_installed=1
committed=1

printf 'ao2_control_plane_installed=%s\n' "$INSTALL_DIR/$SERVER_NAME"
printf 'ao2_control_plane_gc_installed=%s\n' "$INSTALL_DIR/$GC_NAME"
printf 'ao2_control_plane_install_receipt=%s\n' "$INSTALL_DIR/$RECEIPT_NAME"
