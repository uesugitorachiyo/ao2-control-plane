#!/usr/bin/env bash
# Run the ao2.cp-audit-log-rotation-drill.v1 bounded-growth drill on
# Mac/Linux. The generated bearer is kept inside the Python process
# environment and is never written to stdout, stderr, URLs, or artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/cp_audit_log_rotation_drill.py" "$@"
