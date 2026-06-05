#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${AO2_CP_LONG_LIVED_SMOKE_ROOT:-$ROOT/target/long-lived-dev-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
DATA_ROOT="$OUT_ROOT/long-lived-control-plane"
BIND="${AO2_CP_LONG_LIVED_SMOKE_BIND:-127.0.0.1:19877}"
LIVE="${AO2_CP_LONG_LIVED_SMOKE_LIVE:-0}"
LIVE_BUILD="${AO2_CP_LONG_LIVED_SMOKE_BUILD:-1}"
SUMMARY="$OUT_ROOT/summary.json"
START_LOG="$OUT_ROOT/start-long-lived-dev.out"
START_ERR="$OUT_ROOT/start-long-lived-dev.err"
LIVE_START_1_LOG="$OUT_ROOT/live-start-1.out"
LIVE_START_1_ERR="$OUT_ROOT/live-start-1.err"
LIVE_START_2_LOG="$OUT_ROOT/live-start-2.out"
LIVE_START_2_ERR="$OUT_ROOT/live-start-2.err"
LIVE_READYZ_1="$OUT_ROOT/live-readyz-1.json"
LIVE_READYZ_2="$OUT_ROOT/live-readyz-2.json"
LIVE_STATUS="$OUT_ROOT/live-status.json"

mkdir -p "$OUT_ROOT"

cleanup_live_server() {
  pid_file="$DATA_ROOT/server.pid"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 50); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
          break
        fi
        sleep 0.1
      done
    fi
    rm -f "$pid_file"
  fi
}

trap cleanup_live_server EXIT

env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  "$ROOT/scripts/start-long-lived-dev.sh" \
    --once-check \
    --no-build \
    --data-dir "$DATA_ROOT" \
    --bind "$BIND" \
    >"$START_LOG" 2>"$START_ERR"

if [ "$LIVE" = "1" ]; then
  start_args=(--data-dir "$DATA_ROOT" --bind "$BIND")
  if [ "$LIVE_BUILD" != "1" ]; then
    start_args+=(--no-build)
  fi

  env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
    "$ROOT/scripts/start-long-lived-dev.sh" "${start_args[@]}" \
    >"$LIVE_START_1_LOG" 2>"$LIVE_START_1_ERR"

  token_before_sha256="$(shasum -a 256 "$DATA_ROOT/api-token" | awk '{print $1}')"
  curl -fsS "http://$BIND/readyz" >"$LIVE_READYZ_1"

  cleanup_live_server

  env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
    "$ROOT/scripts/start-long-lived-dev.sh" --no-build "${start_args[@]}" \
    >"$LIVE_START_2_LOG" 2>"$LIVE_START_2_ERR"

  token_after_sha256="$(shasum -a 256 "$DATA_ROOT/api-token" | awk '{print $1}')"
  curl -fsS "http://$BIND/readyz" >"$LIVE_READYZ_2"

  python3 - "$LIVE_STATUS" "$token_before_sha256" "$token_after_sha256" <<'PY'
import json
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
token_before_sha256 = sys.argv[2]
token_after_sha256 = sys.argv[3]
status_path.write_text(
    json.dumps(
        {
            "schema_version": "ao2.cp-long-lived-dev-live-restart.v1",
            "status": "passed" if token_before_sha256 == token_after_sha256 else "failed",
            "token_reused_after_restart": token_before_sha256 == token_after_sha256,
            "token_sha256": token_after_sha256,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
if token_before_sha256 != token_after_sha256:
    raise SystemExit(1)
PY

  cleanup_live_server
fi

python3 - "$DATA_ROOT" "$BIND" "$SUMMARY" "$START_LOG" "$START_ERR" "$LIVE" "$LIVE_START_1_LOG" "$LIVE_START_1_ERR" "$LIVE_START_2_LOG" "$LIVE_START_2_ERR" "$LIVE_READYZ_1" "$LIVE_READYZ_2" "$LIVE_STATUS" <<'PY'
import json
import re
import stat
import sys
from pathlib import Path

data_root = Path(sys.argv[1])
bind = sys.argv[2]
summary_path = Path(sys.argv[3])
start_log = Path(sys.argv[4])
start_err = Path(sys.argv[5])
live = sys.argv[6] == "1"
live_start_1_log = Path(sys.argv[7])
live_start_1_err = Path(sys.argv[8])
live_start_2_log = Path(sys.argv[9])
live_start_2_err = Path(sys.argv[10])
live_readyz_1 = Path(sys.argv[11])
live_readyz_2 = Path(sys.argv[12])
live_status_path = Path(sys.argv[13])

token_file = data_root / "api-token"
token = token_file.read_text(encoding="utf-8").strip()
combined_output = start_log.read_text(encoding="utf-8") + start_err.read_text(encoding="utf-8")

checks = []

def add(name, passed, detail=""):
    checks.append({"name": name, "status": "passed" if passed else "failed", "detail": detail})

add("data_root_created", data_root.is_dir(), str(data_root))
add("data_dir_created", (data_root / "data").is_dir())
add("logs_dir_created", (data_root / "logs").is_dir())
add("publishes_dir_created", (data_root / "publishes").is_dir())
add("token_file_created", token_file.is_file())
add("token_file_mode_600", stat.S_IMODE(token_file.stat().st_mode) == 0o600, oct(stat.S_IMODE(token_file.stat().st_mode)))
add("token_shape_64_hex", re.fullmatch(r"[0-9a-f]{64}", token) is not None)
add("token_not_printed", token not in combined_output)
add("provider_keys_absent", "OPENAI_API_KEY" not in combined_output and "ANTHROPIC_API_KEY" not in combined_output)
add("once_check_passed", "once_check=passed" in combined_output)
add("bind_reported", f"bind={bind}" in combined_output)
add("token_file_reported_without_value", "token_file=" in combined_output and "AO2_CP_API_TOKEN=" not in combined_output)

live_restart_readiness = {"enabled": live}
if live:
    live_output = (
        live_start_1_log.read_text(encoding="utf-8")
        + live_start_1_err.read_text(encoding="utf-8")
        + live_start_2_log.read_text(encoding="utf-8")
        + live_start_2_err.read_text(encoding="utf-8")
    )
    readyz_1 = json.loads(live_readyz_1.read_text(encoding="utf-8"))
    readyz_2 = json.loads(live_readyz_2.read_text(encoding="utf-8"))
    live_status = json.loads(live_status_path.read_text(encoding="utf-8"))
    add("live_restart_readiness_first_readyz", readyz_1.get("status") == "ready", readyz_1)
    add("live_restart_readiness_second_readyz", readyz_2.get("status") == "ready", readyz_2)
    add("token_reused_after_restart", live_status.get("token_reused_after_restart") is True)
    add("live_token_not_printed", token not in live_output)
    add("live_provider_keys_absent", "OPENAI_API_KEY" not in live_output and "ANTHROPIC_API_KEY" not in live_output)
    live_restart_readiness = {
        "enabled": True,
        "readyz_first": str(live_readyz_1),
        "readyz_second": str(live_readyz_2),
        "status": str(live_status_path),
        "token_reused_after_restart": live_status.get("token_reused_after_restart"),
    }

status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
summary = {
    "schema_version": "ao2.cp-long-lived-dev-hardening-smoke.v1",
    "status": status,
    "bind": bind,
    "data_root": str(data_root),
    "start_stdout": str(start_log),
    "start_stderr": str(start_err),
    "live_restart_readiness": live_restart_readiness,
    "trust_boundary": {
        "role": "read_only_observer",
        "provider_api_keys_allowed": False,
        "token_printed": False,
    },
    "checks": checks,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"summary={summary_path}")
print(f"status={status}")
if status != "passed":
    for check in checks:
        if check["status"] != "passed":
            print(f"failed={check['name']} {check.get('detail', '')}", file=sys.stderr)
    raise SystemExit(1)
PY

printf "long_lived_dev_smoke_root=%s\n" "$OUT_ROOT"
printf "long_lived_dev_smoke_summary=%s\n" "$SUMMARY"
printf "long_lived_dev_smoke=passed\n"
