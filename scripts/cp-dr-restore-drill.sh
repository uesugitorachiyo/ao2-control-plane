#!/usr/bin/env bash
# Run the ao2.cp-dr-restore-drill.v1 disaster-recovery drill on Mac/Linux.
# The generated bearer is kept inside the Python process environment and is
# never written to stdout, stderr, URLs, or generated artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/cp_dr_restore_drill.py" "$@"
