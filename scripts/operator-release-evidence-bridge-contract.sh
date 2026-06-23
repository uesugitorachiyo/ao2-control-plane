#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="$ROOT/scripts/smoke-operator-release-evidence-bridge.py"
WORKFLOW="$ROOT/.github/workflows/ci.yml"
README="$ROOT/README.md"
FIXTURE="$ROOT/crates/ao2-cp-server/tests/fixtures/operator-release-evidence-bundle-summary.json"

fail() {
  echo "operator release evidence bridge contract failed: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -f "$path" ] || fail "missing file: $path"
}

require_text() {
  local path="$1"
  local needle="$2"
  grep -Fq -- "$needle" "$path" || fail "missing '$needle' in $path"
}

require_file "$SMOKE"
require_file "$WORKFLOW"
require_file "$README"
require_file "$FIXTURE"

require_text "$SMOKE" "ao2.cp-operator-release-evidence-bridge-smoke.v1"
require_text "$SMOKE" "ao2.cp-operator-release-evidence-readback.v1"
require_text "$SMOKE" "ao2.operator-release-evidence-bundle.v1"
require_text "$SMOKE" "AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY"
require_text "$SMOKE" "--download-latest-ao2-artifact"
require_text "$SMOKE" "ao2-operator-release-evidence-bundle"
require_text "$SMOKE" "ao2-dual-public-release-smoke"
require_text "$SMOKE" "ao2.dual-public-release-smoke.v1"
require_text "$SMOKE" "ao2-public-release-pair-digest-audit"
require_text "$SMOKE" "ao2.public-release-pair-digest-audit.v1"
require_text "$SMOKE" "public_pair_digest_archive_parity"
require_text "$SMOKE" "public_pair_digest_does_not_mutate_releases"
require_text "$SMOKE" "public_pair_digest_stores_no_credentials"
require_text "$SMOKE" "ao2.cp-ai-task-board-readback.v1"
require_text "$SMOKE" "dual_public_control_plane_does_not_approve_release"
require_text "$SMOKE" "/api/v1/release/operator-evidence.json"
require_text "$SMOKE" "/api/v1/release/operator-evidence"
require_text "$SMOKE" "token not in json"
require_text "$SMOKE" "provider_keys_absent"

require_text "$WORKFLOW" "AO2 release evidence bridge smoke"
require_text "$WORKFLOW" "AO2 release evidence hosted bridge smoke"
require_text "$WORKFLOW" "scripts/smoke-operator-release-evidence-bridge.py"
require_text "$WORKFLOW" "operator-release-evidence-bridge-smoke"
require_text "$WORKFLOW" "operator-release-evidence-hosted-bridge-smoke"
require_text "$WORKFLOW" "ao2-control-plane-operator-release-evidence-bridge-smoke"
require_text "$WORKFLOW" "ao2-control-plane-operator-release-evidence-hosted-bridge-smoke"
require_text "$WORKFLOW" "--download-latest-ao2-artifact"
require_text "$WORKFLOW" "GH_TOKEN: \${{ github.token }}"

require_text "$README" "AO2 release evidence bridge smoke"
require_text "$README" "nine-check release"
require_text "$README" "ao2-public-release-pair-digest-audit"
require_text "$FIXTURE" "\"schema_version\": \"ao2.operator-release-evidence-bundle.v1\""
require_text "$FIXTURE" "\"operator_release_evidence_ready\": true"
require_text "$FIXTURE" "\"artifact\": \"ao2-dual-public-release-smoke\""
require_text "$FIXTURE" "\"artifact\": \"ao2-public-release-pair-digest-audit\""
require_text "$FIXTURE" "\"archive_parity_status\": \"passed\""
require_text "$FIXTURE" "\"task_board_readback_schema\": \"ao2.cp-ai-task-board-readback.v1\""
require_text "$FIXTURE" "\"control_plane_approves_release\": false"

echo "operator_release_evidence_bridge_contract=passed"
