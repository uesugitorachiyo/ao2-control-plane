#!/usr/bin/env bash
# Emit ao2.cp-health-snapshot.v1 for Mac/Linux operators.
# The bearer is read through --api-token-env by the Python implementation and
# is never written to stdout, stderr, URLs, or generated artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/cp_health_snapshot.py" "$@"
