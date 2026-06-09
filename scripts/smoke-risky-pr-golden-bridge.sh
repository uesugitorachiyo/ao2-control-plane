#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT="${AO2_CP_RISKY_PR_GOLDEN_BRIDGE_SMOKE_ROOT:-$ROOT/target/risky-pr-golden-bridge-smoke/$STAMP}"
DATA_ROOT="$OUT_ROOT/long-lived-control-plane"
BIND="${AO2_CP_RISKY_PR_GOLDEN_BRIDGE_SMOKE_BIND:-127.0.0.1:19878}"
MANIFEST="${AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST:-$ROOT/target/risky-pr-golden-control-plane-bridge/artifact-manifest.json}"
BUILD=1

START_LOG="$OUT_ROOT/start.out"
START_ERR="$OUT_ROOT/start.err"
JSON_BODY="$OUT_ROOT/artifact-manifest-observer.json"
HTML_BODY="$OUT_ROOT/artifact-manifest.html"
SUMMARY="$OUT_ROOT/summary.json"

usage() {
  cat <<'USAGE'
Usage: scripts/smoke-risky-pr-golden-bridge.sh [options]

Starts a local ao2-cp-server with AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST
pointing at AO2's bridged golden artifact manifest, then verifies both
authenticated observer endpoints without printing bearer material.

Options:
  --manifest <path>   Manifest path (default:
                      target/risky-pr-golden-control-plane-bridge/artifact-manifest.json)
  --out-root <dir>    Evidence directory (default: target/risky-pr-golden-bridge-smoke/<timestamp>)
  --data-dir <dir>    Long-lived dev root for this smoke
  --bind <host:port>  Bind address (default: 127.0.0.1:19878)
  --no-build          Do not build ao2-cp-server before starting
  -h, --help          Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      DATA_ROOT="$OUT_ROOT/long-lived-control-plane"
      START_LOG="$OUT_ROOT/start.out"
      START_ERR="$OUT_ROOT/start.err"
      JSON_BODY="$OUT_ROOT/artifact-manifest-observer.json"
      HTML_BODY="$OUT_ROOT/artifact-manifest.html"
      SUMMARY="$OUT_ROOT/summary.json"
      shift 2
      ;;
    --data-dir)
      DATA_ROOT="$2"
      shift 2
      ;;
    --bind)
      BIND="$2"
      shift 2
      ;;
    --no-build)
      BUILD=0
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

mkdir -p "$OUT_ROOT"

cleanup_server() {
  pid_file="$DATA_ROOT/server.pid"
  if [ -f "$pid_file" ]; then
    pid="$(sed -n '1p' "$pid_file" 2>/dev/null || true)"
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

trap cleanup_server EXIT

if [ ! -f "$MANIFEST" ]; then
  echo "missing risky PR golden artifact manifest: $MANIFEST" >&2
  exit 1
fi

python3 - "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
payload = json.loads(manifest_path.read_text(encoding="utf-8"))
if payload.get("schema_version") != "ao2.risky-pr-golden-artifact-manifest.v1":
    raise SystemExit("unexpected manifest schema")
if payload.get("status") != "indexed":
    raise SystemExit("manifest is not indexed")
if payload.get("artifact_count") != len(payload.get("artifacts", [])):
    raise SystemExit("artifact_count does not match artifacts length")
PY

start_args=(--data-dir "$DATA_ROOT" --bind "$BIND")
if [ "$BUILD" != "1" ]; then
  start_args+=(--no-build)
fi

env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST="$MANIFEST" \
  "$ROOT/scripts/start-long-lived-dev.sh" "${start_args[@]}" \
  >"$START_LOG" 2>"$START_ERR"

TOKEN_FILE="$DATA_ROOT/api-token"
TOKEN="$(sed -n '1p' "$TOKEN_FILE")"

curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://$BIND/api/v1/risky-pr/golden/artifact-manifest.json" \
  >"$JSON_BODY"

curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://$BIND/api/v1/risky-pr/golden/artifact-manifest" \
  >"$HTML_BODY"

python3 - "$SUMMARY" "$MANIFEST" "$JSON_BODY" "$HTML_BODY" "$START_LOG" "$START_ERR" "$TOKEN_FILE" "$BIND" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
json_path = Path(sys.argv[3])
html_path = Path(sys.argv[4])
start_log = Path(sys.argv[5])
start_err = Path(sys.argv[6])
token_file = Path(sys.argv[7])
bind = sys.argv[8]

token = token_file.read_text(encoding="utf-8").strip()
observer_text = json_path.read_text(encoding="utf-8")
html = html_path.read_text(encoding="utf-8")
start_output = start_log.read_text(encoding="utf-8") + start_err.read_text(encoding="utf-8")
observer = json.loads(observer_text)
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

checks = []

def add(name, passed, detail=""):
    checks.append({"name": name, "status": "passed" if passed else "failed", "detail": detail})

add("observer_schema", observer.get("schema_version") == "ao2.cp-risky-pr-golden-artifact-manifest-observer.v1")
add("manifest_schema", observer.get("manifest", {}).get("schema_version") == "ao2.risky-pr-golden-artifact-manifest.v1")
add("manifest_matches_source", observer.get("manifest") == manifest)
add("control_plane_role", observer.get("control_plane_role") == "read-only-observer")
add("release_approval_deferred", observer.get("control_plane_approves_release") is False)
add("mutates_ao_artifacts", observer.get("mutates_ao_artifacts") is False)
add("mutates_observer_storage", observer.get("mutates_observer_storage") is False)
add("credential_material_included", observer.get("auth", {}).get("credential_material_included") is False)
add("credential_material_in_urls", observer.get("auth", {}).get("credential_material_in_urls") is False)
add(
    "configured_env",
    observer.get("source", {}).get("configured_env") == "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST",
)
add("html_title", "Risky PR Golden Artifact Manifest" in html)
add("html_role", "read-only-observer" in html)
add("html_manifest_schema", "ao2.risky-pr-golden-artifact-manifest.v1" in html)
add("token not in json", token not in observer_text)
add("token not in html", token not in html)
add("token not in start_output", token not in start_output)
add(
    "provider_keys_absent",
    "OPENAI_API_KEY" not in start_output
    and "ANTHROPIC_API_KEY" not in start_output
    and "OPENAI_API_KEY" not in observer_text
    and "ANTHROPIC_API_KEY" not in observer_text
    and "OPENAI_API_KEY" not in html
    and "ANTHROPIC_API_KEY" not in html,
)

status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
summary = {
    "schema_version": "ao2.cp-risky-pr-golden-bridge-smoke.v1",
    "status": status,
    "bind": bind,
    "json_observer": str(json_path),
    "html_observer": str(html_path),
    "manifest": {
        "configured_env": "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST",
        "path_redacted": True,
        "schema_version": manifest.get("schema_version"),
        "artifact_count": manifest.get("artifact_count"),
    },
    "trust_boundary": {
        "control_plane_role": "read-only-observer",
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_observer_storage": False,
        "credential_material_included": False,
        "credential_material_in_urls": False,
        "provider_api_keys_allowed": False,
        "token_printed": False,
    },
    "checks": checks,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if status != "passed":
    for check in checks:
        if check["status"] != "passed":
            print(f"failed={check['name']} {check.get('detail', '')}", file=sys.stderr)
    raise SystemExit(1)
PY

printf "risky_pr_golden_bridge_smoke_root=%s\n" "$OUT_ROOT"
printf "risky_pr_golden_bridge_smoke_summary=%s\n" "$SUMMARY"
printf "risky_pr_golden_bridge_smoke=passed\n"
