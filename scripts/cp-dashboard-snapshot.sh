#!/usr/bin/env bash
# Fetch token-safe local ao2-control-plane dashboard snapshots.
# The bearer value is read by the Python helper from --api-token-env and is
# never written to stdout, stderr, URLs, or generated artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/cp_dashboard_snapshot.py" "$@"
