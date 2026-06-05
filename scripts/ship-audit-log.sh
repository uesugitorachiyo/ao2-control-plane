#!/usr/bin/env bash
# Stream the ao2-control-plane audit-log NDJSON to stdout for
# `vector`, `fluent-bit`, `logrotate`, or any downstream log shipper
# that expects newline-delimited JSON on its stdin.
#
# Usage:
#   scripts/ship-audit-log.sh [options]
#
# Options:
#   --base-url URL       Control-plane base URL.
#                        Default: http://127.0.0.1:8744
#   --token VALUE        Bearer token. If omitted, reads
#                        AO2_CP_API_TOKEN from the environment.
#                        Never printed to stdout/stderr.
#   --path PATH          Skip the /api/v1/status round-trip and
#                        use this NDJSON path directly.
#   --include-rotated    Emit the contents of <path>.1 (if it
#                        exists) before the live file. Without
#                        this flag, only the live file is
#                        streamed.
#   -f, --follow         Tail the live file with `tail -F` so
#                        new entries (and rotation events) are
#                        followed continuously. Without this
#                        flag, the live file is read once and
#                        the script exits.
#   -h, --help           Print this help and exit.
#
# Environment:
#   AO2_CP_API_TOKEN     Bearer used when --token is unset.
#   AO2_CP_AUDIT_LOG_FILE
#                        NDJSON path used when --path is unset
#                        and the /api/v1/status round-trip is
#                        skipped. (Equivalent to passing --path.)
#
# Exit codes:
#   0  success
#   2  missing or invalid argument
#   3  /api/v1/status round-trip failed
#   4  persistence is not enabled on the target server
#   5  live NDJSON file does not exist
#
# Trust boundary:
#   This helper is a read-only observer. It does not ingest,
#   approve, or mutate AO artifacts. It only reads NDJSON the
#   server has already written to disk and copies it to stdout.
#
# Security:
#   The bearer is only forwarded as an `Authorization` header
#   on the /api/v1/status round-trip; it is never written to
#   stdout, stderr, or any URL. Downstream shippers ingesting
#   this stream still need to apply their own redaction policy
#   if they want token-bearing request bodies to be scrubbed,
#   but the audit-log NDJSON itself does not contain bearer
#   values (the server strips them at write time).

set -euo pipefail

BASE_URL="http://127.0.0.1:8744"
TOKEN="${AO2_CP_API_TOKEN:-}"
EXPLICIT_PATH="${AO2_CP_AUDIT_LOG_FILE:-}"
INCLUDE_ROTATED=0
FOLLOW=0

print_help() {
    sed -n '2,/^set -euo pipefail$/{/^set -euo pipefail$/q;p;}' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-url)
            [[ $# -ge 2 ]] || { echo "ship-audit-log: --base-url requires a value" >&2; exit 2; }
            BASE_URL="$2"
            shift 2
            ;;
        --token)
            [[ $# -ge 2 ]] || { echo "ship-audit-log: --token requires a value" >&2; exit 2; }
            TOKEN="$2"
            shift 2
            ;;
        --path)
            [[ $# -ge 2 ]] || { echo "ship-audit-log: --path requires a value" >&2; exit 2; }
            EXPLICIT_PATH="$2"
            shift 2
            ;;
        --include-rotated)
            INCLUDE_ROTATED=1
            shift
            ;;
        -f|--follow)
            FOLLOW=1
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "ship-audit-log: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

resolve_path_via_status() {
    if [[ -z "$TOKEN" ]]; then
        echo "ship-audit-log: bearer required (set AO2_CP_API_TOKEN or pass --token)" >&2
        exit 2
    fi
    local status_json
    if ! status_json="$(curl -fsS --max-time 10 \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL/api/v1/status" 2>/dev/null)"; then
        echo "ship-audit-log: GET $BASE_URL/api/v1/status failed" >&2
        exit 3
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "ship-audit-log: jq is required to parse /api/v1/status (install jq, or pass --path)" >&2
        exit 3
    fi
    local enabled
    enabled="$(printf '%s' "$status_json" | jq -r '.audit_log.persistence.enabled // false')"
    if [[ "$enabled" != "true" ]]; then
        echo "ship-audit-log: audit-log persistence is not enabled on $BASE_URL" >&2
        exit 4
    fi
    local path
    path="$(printf '%s' "$status_json" | jq -r '.audit_log.persistence.path // ""')"
    if [[ -z "$path" ]]; then
        echo "ship-audit-log: /api/v1/status returned persistence.enabled=true with empty path" >&2
        exit 3
    fi
    printf '%s' "$path"
}

if [[ -n "$EXPLICIT_PATH" ]]; then
    LIVE_PATH="$EXPLICIT_PATH"
else
    LIVE_PATH="$(resolve_path_via_status)"
fi

ROTATED_PATH="${LIVE_PATH}.1"

if [[ "$INCLUDE_ROTATED" -eq 1 && -f "$ROTATED_PATH" ]]; then
    cat "$ROTATED_PATH"
fi

if [[ ! -f "$LIVE_PATH" ]]; then
    echo "ship-audit-log: live NDJSON file does not exist: $LIVE_PATH" >&2
    exit 5
fi

if [[ "$FOLLOW" -eq 1 ]]; then
    # `tail -F` (capital F) follows by name and re-opens the file when
    # the server rotates it (rename of live to <path>.1 + open of fresh
    # live), so the stream keeps producing without operator intervention.
    exec tail -n +1 -F "$LIVE_PATH"
else
    cat "$LIVE_PATH"
fi
