#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_ROOT="$ROOT/target/long-lived-control-plane"
BIND="127.0.0.1:18745"
BUILD=1
ONCE_CHECK=0
TOKEN_SOURCE=""

usage() {
  cat <<'USAGE'
Usage: scripts/start-long-lived-dev.sh [options]

Options:
  --data-dir <dir>       Long-lived dev root (default: target/long-lived-control-plane)
  --bind <host:port>     Bind address (default: 127.0.0.1:18745)
  --token-source <path>  Copy an existing token file into the dev root
  --no-build            Do not build ao2-cp-server before starting
  --once-check          Initialize and print token-free status without starting
  -h, --help            Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-dir)
      DATA_ROOT="$2"
      shift 2
      ;;
    --bind)
      BIND="$2"
      shift 2
      ;;
    --token-source)
      TOKEN_SOURCE="$2"
      shift 2
      ;;
    --no-build)
      BUILD=0
      shift
      ;;
    --once-check)
      ONCE_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TOKEN_FILE="$DATA_ROOT/api-token"
LOG_DIR="$DATA_ROOT/logs"
CP_DATA_DIR="$DATA_ROOT/data"
PUBLISH_DIR="$DATA_ROOT/publishes"
PID_FILE="$DATA_ROOT/server.pid"

mkdir -p "$CP_DATA_DIR" "$LOG_DIR" "$PUBLISH_DIR"

if [ -n "$TOKEN_SOURCE" ] && [ ! -f "$TOKEN_FILE" ]; then
  install -m 600 "$TOKEN_SOURCE" "$TOKEN_FILE"
fi

if [ ! -f "$TOKEN_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    umask 177
    openssl rand -hex 32 > "$TOKEN_FILE"
  else
    umask 177
    python3 - "$TOKEN_FILE" <<'PY'
import secrets
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
path.chmod(stat.S_IRUSR | stat.S_IWUSR)
PY
  fi
fi
chmod 600 "$TOKEN_FILE"

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

echo "long_lived_dev_root=$DATA_ROOT"
echo "token_file=$TOKEN_FILE"
echo "mode=$(file_mode "$TOKEN_FILE")"
echo "bind=$BIND"

if [ "$ONCE_CHECK" -eq 1 ]; then
  echo "once_check=passed"
  exit 0
fi

cd "$ROOT"

if [ "$BUILD" -eq 1 ]; then
  cargo build --release -p ao2-cp-server
fi

SERVER_BIN="$ROOT/target/release/ao2-cp-server"
if [ ! -x "$SERVER_BIN" ]; then
  echo "server binary missing: $SERVER_BIN" >&2
  exit 1
fi

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "server_pid=$(cat "$PID_FILE")"
  echo "already_running=true"
  exit 0
fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  AO2_CP_API_TOKEN="$(cat "$TOKEN_FILE")" \
  AO2_CP_BIND="$BIND" \
  AO2_CP_DATA_DIR="$CP_DATA_DIR" \
  nohup "$SERVER_BIN" \
    > "$LOG_DIR/ao2-cp-server.${ts}.log" \
    2> "$LOG_DIR/ao2-cp-server.${ts}.err" &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

echo "server_pid=$SERVER_PID"
echo "log_file=$LOG_DIR/ao2-cp-server.${ts}.log"
echo "err_file=$LOG_DIR/ao2-cp-server.${ts}.err"

for _ in $(seq 1 50); do
  if curl -fsS "http://$BIND/healthz" >/dev/null 2>&1; then
    echo "healthz=ok"
    exit 0
  fi
  sleep 0.2
done

echo "healthz=failed" >&2
exit 1
