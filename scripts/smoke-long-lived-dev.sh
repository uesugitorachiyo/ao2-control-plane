#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${AO2_CP_LONG_LIVED_SMOKE_ROOT:-$ROOT/target/long-lived-dev-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
DATA_ROOT="$OUT_ROOT/long-lived-control-plane"
BIND="${AO2_CP_LONG_LIVED_SMOKE_BIND:-127.0.0.1:19877}"
SUMMARY="$OUT_ROOT/summary.json"
START_LOG="$OUT_ROOT/start-long-lived-dev.out"
START_ERR="$OUT_ROOT/start-long-lived-dev.err"

mkdir -p "$OUT_ROOT"

env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  "$ROOT/scripts/start-long-lived-dev.sh" \
    --once-check \
    --no-build \
    --data-dir "$DATA_ROOT" \
    --bind "$BIND" \
    >"$START_LOG" 2>"$START_ERR"

python3 - "$DATA_ROOT" "$BIND" "$SUMMARY" "$START_LOG" "$START_ERR" <<'PY'
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

status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
summary = {
    "schema_version": "ao2.cp-long-lived-dev-hardening-smoke.v1",
    "status": status,
    "bind": bind,
    "data_root": str(data_root),
    "start_stdout": str(start_log),
    "start_stderr": str(start_err),
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
