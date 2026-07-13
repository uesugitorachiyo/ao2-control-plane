#!/usr/bin/env sh
set -eu

INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-$HOME/.local/bin}}"
SERVER_NAME="ao2-cp-server"
GC_NAME="ao2-cp-gc"
RECEIPT_NAME="ao2-control-plane.install-receipt.json"
SERVER_BACKUP=".$SERVER_NAME.ao2-previous"
GC_BACKUP=".$GC_NAME.ao2-previous"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

command -v python3 >/dev/null 2>&1 || {
  echo "rollback requires python3" >&2
  exit 1
}
[ -f "$INSTALL_DIR/$RECEIPT_NAME" ] || {
  echo "missing install receipt: $INSTALL_DIR/$RECEIPT_NAME" >&2
  exit 1
}

metadata=$(python3 - "$INSTALL_DIR/$RECEIPT_NAME" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
if receipt.get("schema_version") != "ao2-control-plane.install-receipt.v1":
    raise SystemExit("unsupported install receipt schema")
rows = {row["name"]: row for row in receipt.get("binaries", [])}
for name in ("ao2-cp-server", "ao2-cp-gc"):
    row = rows.get(name)
    if not row:
        raise SystemExit(f"install receipt missing {name}")
    print("1" if row.get("prior_present") else "0", row.get("prior_sha256") or "-")
PY
)
set -- $metadata
server_prior=$1
server_prior_sha=$2
gc_prior=$3
gc_prior_sha=$4

if [ "$server_prior" -eq 1 ]; then
  [ -f "$INSTALL_DIR/$SERVER_BACKUP" ] || {
    echo "missing rollback backup: $INSTALL_DIR/$SERVER_BACKUP" >&2
    exit 1
  }
  [ "$(sha256_file "$INSTALL_DIR/$SERVER_BACKUP")" = "$server_prior_sha" ] || {
    echo "checksum mismatch for $INSTALL_DIR/$SERVER_BACKUP" >&2
    exit 1
  }
fi
if [ "$gc_prior" -eq 1 ]; then
  [ -f "$INSTALL_DIR/$GC_BACKUP" ] || {
    echo "missing rollback backup: $INSTALL_DIR/$GC_BACKUP" >&2
    exit 1
  }
  [ "$(sha256_file "$INSTALL_DIR/$GC_BACKUP")" = "$gc_prior_sha" ] || {
    echo "checksum mismatch for $INSTALL_DIR/$GC_BACKUP" >&2
    exit 1
  }
fi

STAGE=$(mktemp -d "$INSTALL_DIR/.ao2-control-plane.rollback.XXXXXX")
transaction_started=0
committed=0
server_moved=0
gc_moved=0
server_installed=0
gc_installed=0
cleanup() {
  if [ "$transaction_started" -eq 1 ] && [ "$committed" -eq 0 ]; then
    if [ "$server_installed" -eq 1 ]; then rm -f "$INSTALL_DIR/$SERVER_NAME"; fi
    if [ "$gc_installed" -eq 1 ]; then rm -f "$INSTALL_DIR/$GC_NAME"; fi
    if [ "$server_moved" -eq 1 ] && [ -f "$INSTALL_DIR/.$SERVER_NAME.ao2-rollback-current" ]; then
      mv "$INSTALL_DIR/.$SERVER_NAME.ao2-rollback-current" "$INSTALL_DIR/$SERVER_NAME"
    fi
    if [ "$gc_moved" -eq 1 ] && [ -f "$INSTALL_DIR/.$GC_NAME.ao2-rollback-current" ]; then
      mv "$INSTALL_DIR/.$GC_NAME.ao2-rollback-current" "$INSTALL_DIR/$GC_NAME"
    fi
  fi
  rm -rf "$STAGE"
}
trap cleanup EXIT HUP INT TERM

if [ "$server_prior" -eq 1 ]; then cp "$INSTALL_DIR/$SERVER_BACKUP" "$STAGE/$SERVER_NAME"; fi
if [ "$gc_prior" -eq 1 ]; then cp "$INSTALL_DIR/$GC_BACKUP" "$STAGE/$GC_NAME"; fi
rm -f "$INSTALL_DIR/.$SERVER_NAME.ao2-rollback-current" "$INSTALL_DIR/.$GC_NAME.ao2-rollback-current"
transaction_started=1
if [ -f "$INSTALL_DIR/$SERVER_NAME" ]; then
  mv "$INSTALL_DIR/$SERVER_NAME" "$INSTALL_DIR/.$SERVER_NAME.ao2-rollback-current"
  server_moved=1
fi
if [ -f "$INSTALL_DIR/$GC_NAME" ]; then
  mv "$INSTALL_DIR/$GC_NAME" "$INSTALL_DIR/.$GC_NAME.ao2-rollback-current"
  gc_moved=1
fi
if [ "$server_prior" -eq 1 ]; then
  mv "$STAGE/$SERVER_NAME" "$INSTALL_DIR/$SERVER_NAME"
  server_installed=1
fi
if [ "$gc_prior" -eq 1 ]; then
  mv "$STAGE/$GC_NAME" "$INSTALL_DIR/$GC_NAME"
  gc_installed=1
fi

python3 - "$INSTALL_DIR/$RECEIPT_NAME" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
receipt = json.loads(path.read_text(encoding="utf-8"))
receipt["operation"] = "rollback"
receipt["rolled_back_version"] = receipt.get("version")
receipt["preserves_data_and_config"] = True
path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
committed=1
printf 'ao2_control_plane_rollback=passed\n'
printf 'ao2_control_plane_install_receipt=%s\n' "$INSTALL_DIR/$RECEIPT_NAME"
