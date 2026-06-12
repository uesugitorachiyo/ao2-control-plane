#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AO2_CP_ARCHIVE="${AO2_CP_ARCHIVE:-dist/ao2-control-plane-0.1.13-macos-aarch64.tar.gz}"
AO2_CP_SMOKE_ROOT="${AO2_CP_SMOKE_ROOT:-$ROOT/target/release-smoke/$(date +%Y%m%d%H%M%S)}"
AO2_CP_SMOKE_JSON="${AO2_CP_SMOKE_JSON:-}"
AO2_CP_RELEASE_PUBLICATION="${AO2_CP_RELEASE_PUBLICATION:-$ROOT/tests/fixtures/ao2-release-publication-v0.4.79.json}"
AO2_CP_API_TOKEN="${AO2_CP_API_TOKEN:-smoke-token-$(uuidgen | tr -d - | head -c 32)}"
choose_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
PORT="${AO2_CP_PORT:-$(choose_free_port)}"
EXPECTED_MANIFEST_SCHEMA="ao2.cp-release-support-bundle-manifest.v1"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -f "$AO2_CP_ARCHIVE" ]]; then
  echo "missing ao2-control-plane release archive: $AO2_CP_ARCHIVE" >&2
  exit 1
fi
if [[ ! -f "$AO2_CP_RELEASE_PUBLICATION" ]]; then
  echo "missing AO2 release-publication fixture: $AO2_CP_RELEASE_PUBLICATION" >&2
  exit 1
fi

extract="$AO2_CP_SMOKE_ROOT/extract"
install_dir="$AO2_CP_SMOKE_ROOT/bin"
data_dir="$AO2_CP_SMOKE_ROOT/data"
mkdir -p "$extract" "$install_dir" "$data_dir"
tar -xzf "$AO2_CP_ARCHIVE" -C "$extract"

test -f "$extract/RELEASE-MANIFEST.json"
jq -e '.schema_version == "ao2-control-plane.release-manifest.v1"' "$extract/RELEASE-MANIFEST.json" >/dev/null
jq -e '.binary == "ao2-cp-server"' "$extract/RELEASE-MANIFEST.json" >/dev/null

AO2_CP_INSTALL_DIR="$install_dir" sh "$extract/install.sh" >/dev/null
"$install_dir/ao2-cp-server" --help >/dev/null

env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  AO2_CP_API_TOKEN="$AO2_CP_API_TOKEN" \
  AO2_CP_BIND="127.0.0.1:$PORT" \
  AO2_CP_DATA_DIR="$data_dir" \
  "$install_dir/ao2-cp-server" &
SERVER_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null

post() {
  curl -fsS -X POST \
    -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$2" \
    "http://127.0.0.1:$PORT$1"
}

get() {
  curl -fsS \
    -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
    "http://127.0.0.1:$PORT$1"
}

codex_fixture="$ROOT/tests/fixtures/codex-acceptance-v0.4.66.json"
claude_fixture="$ROOT/tests/fixtures/claude-acceptance-v0.4.66.json"
post /api/v1/acceptance "$codex_fixture" > "$AO2_CP_SMOKE_ROOT/codex-receipt.json"
post /api/v1/acceptance "$claude_fixture" > "$AO2_CP_SMOKE_ROOT/claude-receipt.json"
post /api/v1/release/publication "$AO2_CP_RELEASE_PUBLICATION" > "$AO2_CP_SMOKE_ROOT/release-publication-receipt.json"

get /api/v1/acceptance/dashboard.json > "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json"
jq -e '.schema_version == "ao2.cp-acceptance-dashboard.v1"' "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" >/dev/null
jq -e '.total_count == 2' "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" >/dev/null
jq -e '.source_class_counts.fixture == 2' "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" >/dev/null
jq -e '.source_class_counts.live == 0' "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" >/dev/null

get /api/v1/storage/support-bundle.json > "$AO2_CP_SMOKE_ROOT/support-bundle.json"
jq -e '.schema_version == "ao2.cp-support-bundle.v1"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.trust_boundary.role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.trust_boundary.mutates_ao_artifacts == false' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.latest_index_entries | length == 3' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.operator_handoff.relative_endpoints.release_handoff == "/api/v1/release/handoff"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.operator_handoff.relative_endpoints.release_readiness_json == "/api/v1/release/readiness.json"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.phase1_release_readiness.operator_links.release_handoff_json == "/api/v1/release/handoff.json"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.phase1_release_readiness.operator_links.release_readiness == "/api/v1/release/readiness"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null
jq -e '.phase1_release_readiness.observed_artifacts.release_publication.status == "published_verified"' "$AO2_CP_SMOKE_ROOT/support-bundle.json" >/dev/null

get /api/v1/phase1/promotion/gap-report.json > "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json"
jq -e '.schema_version == "ao2.cp-phase1-gap-report.v1"' "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json" >/dev/null
jq -e '.trust_boundary.role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json" >/dev/null
jq -e '.trust_boundary.mutates_ao_artifacts == false' "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json" >/dev/null

get /api/v1/release/publication/dashboard.json > "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json"
jq -e '.schema_version == "ao2.cp-release-publication-dashboard.v1"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
jq -e '.state == "release_published_verified"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
jq -e '.latest.release_tag == "v0.4.79"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
jq -e '.trust_boundary.role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
jq -e '.candidate_correlation.status as $s | $s == "matched" or $s == "mismatched" or $s == "missing"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
jq -e '.candidate_correlation.blockers | type == "array"' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" >/dev/null
get /api/v1/release/publication/dashboard > "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.html"
grep -q "AO2 Release Publication" "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.html"

get /api/v1/release/cockpit.json > "$AO2_CP_SMOKE_ROOT/release-cockpit.json"
jq -e '.schema_version == "ao2.cp-release-cockpit.v1"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
jq -e '.surfaces.release_publication.state == "release_published_verified"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
jq -e '.surfaces.release_publication.release_tag == "v0.4.79"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
jq -e '.trust_boundary.role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
jq -e '.candidate_correlation.status as $s | $s == "matched" or $s == "mismatched" or $s == "missing"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
jq -e '.candidate_correlation.blockers | type == "array"' "$AO2_CP_SMOKE_ROOT/release-cockpit.json" >/dev/null
get /api/v1/release/cockpit > "$AO2_CP_SMOKE_ROOT/release-cockpit.html"
grep -q "AO2 Release Cockpit" "$AO2_CP_SMOKE_ROOT/release-cockpit.html"

get /api/v1/release/handoff.json > "$AO2_CP_SMOKE_ROOT/release-handoff.json"
jq -e '.schema_version == "ao2.cp-release-candidate-handoff.v1"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.operator_handoff.control_plane_role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.operator_handoff.mutates_ao_artifacts == false' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.links.release_candidate_handoff == "/api/v1/release/handoff"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.links.release_readiness_json == "/api/v1/release/readiness.json"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.candidate_correlation.status as $s | $s == "matched" or $s == "mismatched" or $s == "missing"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
jq -e '.candidate_correlation.blockers | type == "array"' "$AO2_CP_SMOKE_ROOT/release-handoff.json" >/dev/null
get /api/v1/release/handoff > "$AO2_CP_SMOKE_ROOT/release-handoff.html"
grep -q "AO2 Release Candidate Handoff" "$AO2_CP_SMOKE_ROOT/release-handoff.html"

get /api/v1/release/readiness.json > "$AO2_CP_SMOKE_ROOT/release-readiness.json"
jq -e '.schema_version == "ao2.cp-release-readiness.v1"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.operator_decision.factory_v3_evaluator_closer_required == true' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.operator_decision.control_plane_approves_release == false' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.schema_version == "ao2.install-verification-evidence.v1"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.status == "verified"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.offline_verification_status == "verified"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.provider_api_keys_required == false' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.control_plane_approves_release == false' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.install_verification.mutates_ao_artifacts == false' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.candidate_correlation.status as $s | $s == "matched" or $s == "mismatched" or $s == "missing"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
jq -e '.candidate_correlation.blockers | type == "array"' "$AO2_CP_SMOKE_ROOT/release-readiness.json" >/dev/null
get /api/v1/release/readiness > "$AO2_CP_SMOKE_ROOT/release-readiness.html"
grep -q "AO2 Release Readiness" "$AO2_CP_SMOKE_ROOT/release-readiness.html"

get /api/v1/release/support-bundle.json > "$AO2_CP_SMOKE_ROOT/release-support-bundle.json"
jq -e '.schema_version == "ao2.cp-release-support-bundle.v1"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.bundle_kind == "portable_release_operator_handoff"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.trust_boundary.role == "read_only_observer"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.trust_boundary.mutates_ao_artifacts == false' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.operator_handoff.release_acceptance_owner == "factory-v3 evaluator-closer"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.release_assembly.schema_version == "ao2.cp-release-assembly.v1"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.release_assembly.control_plane_approves_release == false' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.install_verification.schema_version == "ao2.install-verification-evidence.v1"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.install_verification.status == "verified"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.install_verification.offline_verification_status == "verified"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.portable_bundle_manifest.included_surfaces[] | select(.id == "install_verification" and .path == "$.install_verification" and .schema_version == "ao2.install-verification-evidence.v1")' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.release_assembly.candidate_correlation_detail.status as $s | $s == "matched" or $s == "mismatched" or $s == "missing"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.release_assembly.candidate_correlation_detail.blockers | type == "array"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e --arg expected "$EXPECTED_MANIFEST_SCHEMA" '.portable_bundle_manifest.schema_version == $expected' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.portable_bundle_manifest.included_surfaces[] | select(.id == "release_readiness")' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.portable_bundle_manifest.integrity.algorithm == "sha256-ao2-cp-canonical-json-v1"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '.portable_bundle_manifest.integrity.scope == "embedded_support_bundle_surfaces"' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null
jq -e '(
  .portable_bundle_manifest.integrity.surface_sha256.release_assembly,
  .portable_bundle_manifest.integrity.surface_sha256.release_readiness,
  .portable_bundle_manifest.integrity.surface_sha256.release_candidate_handoff,
  .portable_bundle_manifest.integrity.surface_sha256.release_cockpit,
  .portable_bundle_manifest.integrity.surface_sha256.install_verification,
  .portable_bundle_manifest.integrity.surface_sha256.storage_support_bundle
) | test("^[0-9a-f]{64}$")' "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" >/dev/null

release_support_download="$AO2_CP_SMOKE_ROOT/release-support-bundle-download.json"
release_support_checksums="$AO2_CP_SMOKE_ROOT/release-support-bundle-SHA256SUMS"
release_support_verify="$AO2_CP_SMOKE_ROOT/release-support-bundle-offline-verify.json"
get /api/v1/release/support-bundle/download > "$release_support_download"
get /api/v1/release/support-bundle/SHA256SUMS > "$release_support_checksums"
python3 "$extract/verify_release_support_bundle.py" --checksums "$release_support_checksums" "$release_support_download" > "$release_support_verify"
release_support_bundle_download_sha256="$(jq -r '.bundle_sha256' "$release_support_verify")"
release_support_bundle_checksums_sha256="$(python3 - "$release_support_checksums" <<'PY'
from pathlib import Path
import sys
for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    if line.startswith('#') or not line.strip():
        continue
    parts = line.split()
    if len(parts) >= 2 and parts[1].startswith('ao2-release-support-bundle-'):
        print(parts[0])
        break
else:
    raise SystemExit('missing release support bundle checksum line')
PY
)"
if [[ "$release_support_bundle_download_sha256" != "$release_support_bundle_checksums_sha256" ]]; then
  echo "release support bundle checksum mismatch: verifier=$release_support_bundle_download_sha256 checksums=$release_support_bundle_checksums_sha256" >&2
  exit 1
fi

# Lane OO: read the .source-commit record embedded in the source tarball
# (or this checkout) so the per-target smoke JSON pins the source commit
# the target actually built against. The orchestrator writes this file
# before packaging; on a non-three-OS local run the file may not exist,
# in which case the per-target fields stay null. Future server-side
# validation can then cross-check top-level == every per-target.
source_commit_at_target=""
source_dirty_at_target=""
source_commit_schema_at_target=""
if [[ -f "$ROOT/.source-commit" ]]; then
  source_commit_at_target="$(jq -r '.source_commit // ""' "$ROOT/.source-commit" 2>/dev/null || true)"
  source_dirty_at_target="$(jq -r 'if has("source_dirty") then .source_dirty | tostring else "" end' "$ROOT/.source-commit" 2>/dev/null || true)"
  source_commit_schema_at_target="$(jq -r '.schema // ""' "$ROOT/.source-commit" 2>/dev/null || true)"
fi

candidate_correlation_status="$(jq -r '.candidate_correlation.status' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json")"
for surface_path in \
  "$AO2_CP_SMOKE_ROOT/release-cockpit.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-handoff.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-readiness.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-support-bundle.json:.release_assembly.candidate_correlation_detail"; do
  surface_file="${surface_path%%:*}"
  surface_filter="${surface_path#*:}"
  surface_status="$(jq -r "$surface_filter.status" "$surface_file")"
  if [[ "$surface_status" != "$candidate_correlation_status" ]]; then
    echo "candidate_correlation status drift: dashboard=$candidate_correlation_status $surface_file=$surface_status" >&2
    exit 1
  fi
done

# Lane II: emission-time internal-consistency guard. Re-derive the
# trailer values from the source JSON files RIGHT BEFORE emission so
# any in-process drift of $candidate_correlation_status between the
# initial computation/cross-surface check and the actual trailer/JSON
# emission is caught. A corrupted run-state could only fool the
# downstream aggregator if the source files themselves disagreed,
# which the initial check already gates. Lane II tightens that gate
# by re-fetching at the moment of emission rather than trusting that
# the variable was not clobbered between the two events.
candidate_correlation_status_emission="$(jq -r '.candidate_correlation.status' "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json")"
if [[ "$candidate_correlation_status_emission" != "$candidate_correlation_status" ]]; then
  echo "candidate_correlation_status emission_time_drift: initial=$candidate_correlation_status emission=$candidate_correlation_status_emission" >&2
  exit 1
fi
for surface_path in \
  "$AO2_CP_SMOKE_ROOT/release-cockpit.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-handoff.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-readiness.json:.candidate_correlation" \
  "$AO2_CP_SMOKE_ROOT/release-support-bundle.json:.release_assembly.candidate_correlation_detail"; do
  surface_file="${surface_path%%:*}"
  surface_filter="${surface_path#*:}"
  surface_status_emission="$(jq -r "$surface_filter.status" "$surface_file")"
  if [[ "$surface_status_emission" != "$candidate_correlation_status" ]]; then
    echo "candidate_correlation_status emission_time_drift: initial=$candidate_correlation_status $surface_file=$surface_status_emission" >&2
    exit 1
  fi
done

if [[ -n "$AO2_CP_SMOKE_JSON" ]]; then
  mkdir -p "$(dirname "$AO2_CP_SMOKE_JSON")"
  jq -n \
    --arg schema "ao2-control-plane.release-smoke.v1" \
    --arg status "passed" \
    --arg archive "$AO2_CP_ARCHIVE" \
    --arg smoke_root "$AO2_CP_SMOKE_ROOT" \
    --argjson smoke_port "$PORT" \
    --arg acceptance_dashboard "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" \
    --arg support_bundle "$AO2_CP_SMOKE_ROOT/support-bundle.json" \
    --arg phase1_gap_report "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json" \
    --arg release_publication_fixture "$AO2_CP_RELEASE_PUBLICATION" \
    --arg release_publication_dashboard "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" \
    --arg release_publication_dashboard_html "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.html" \
    --arg release_cockpit "$AO2_CP_SMOKE_ROOT/release-cockpit.json" \
    --arg release_cockpit_html "$AO2_CP_SMOKE_ROOT/release-cockpit.html" \
    --arg release_handoff "$AO2_CP_SMOKE_ROOT/release-handoff.json" \
    --arg release_handoff_html "$AO2_CP_SMOKE_ROOT/release-handoff.html" \
    --arg release_readiness "$AO2_CP_SMOKE_ROOT/release-readiness.json" \
    --arg release_readiness_html "$AO2_CP_SMOKE_ROOT/release-readiness.html" \
    --arg release_support_bundle "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" \
    --arg release_support_bundle_download "$release_support_download" \
    --arg release_support_bundle_checksums "$release_support_checksums" \
    --arg release_support_bundle_offline_verify "$release_support_verify" \
    --arg release_support_bundle_download_sha256 "$release_support_bundle_download_sha256" \
    --arg candidate_correlation_status "$candidate_correlation_status" \
    --arg source_commit_at_target "$source_commit_at_target" \
    --arg source_dirty_at_target "$source_dirty_at_target" \
    --arg source_commit_schema_at_target "$source_commit_schema_at_target" \
    --slurpfile dashboard "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json" \
    --slurpfile bundle "$AO2_CP_SMOKE_ROOT/support-bundle.json" \
    --slurpfile gap_report "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json" \
    --slurpfile release_publication "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json" \
    --slurpfile cockpit "$AO2_CP_SMOKE_ROOT/release-cockpit.json" \
    --slurpfile handoff "$AO2_CP_SMOKE_ROOT/release-handoff.json" \
    --slurpfile readiness "$AO2_CP_SMOKE_ROOT/release-readiness.json" \
    --slurpfile release_support "$AO2_CP_SMOKE_ROOT/release-support-bundle.json" \
    '{
      schema: $schema,
      status: $status,
      archive: $archive,
      smoke_root: $smoke_root,
      smoke_port: $smoke_port,
      acceptance_dashboard: $acceptance_dashboard,
      dashboard_source_counts: ($dashboard[0].source_class_counts // {}),
      support_bundle: $support_bundle,
      support_bundle_schema: ($bundle[0].schema_version // ""),
      phase1_gap_report: $phase1_gap_report,
      phase1_gap_report_schema: ($gap_report[0].schema_version // ""),
      release_publication_fixture: $release_publication_fixture,
      release_publication_dashboard: $release_publication_dashboard,
      release_publication_dashboard_html: $release_publication_dashboard_html,
      release_publication_schema: ($release_publication[0].schema_version // ""),
      release_publication_state: ($release_publication[0].state // ""),
      release_publication_tag: ($release_publication[0].latest.release_tag // ""),
      release_cockpit: $release_cockpit,
      release_cockpit_html: $release_cockpit_html,
      release_cockpit_schema: ($cockpit[0].schema_version // ""),
      release_cockpit_publication_state: ($cockpit[0].surfaces.release_publication.state // ""),
      release_handoff: $release_handoff,
      release_handoff_html: $release_handoff_html,
      release_handoff_schema: ($handoff[0].schema_version // ""),
      release_readiness: $release_readiness,
      release_readiness_html: $release_readiness_html,
      release_readiness_schema: ($readiness[0].schema_version // ""),
      release_readiness_status: ($readiness[0].status // ""),
      release_support_bundle: $release_support_bundle,
      release_support_bundle_download: $release_support_bundle_download,
      release_support_bundle_checksums: $release_support_bundle_checksums,
      release_support_bundle_offline_verify: $release_support_bundle_offline_verify,
      release_support_bundle_download_sha256: $release_support_bundle_download_sha256,
      release_support_bundle_schema: ($release_support[0].schema_version // ""),
      release_support_bundle_kind: ($release_support[0].bundle_kind // ""),
      release_support_bundle_integrity_algorithm: ($release_support[0].portable_bundle_manifest.integrity.algorithm // ""),
      release_assembly_status: ($release_support[0].release_assembly.status // ""),
      release_assembly_candidate_correlation: ($release_support[0].release_assembly.candidate_correlation // ""),
      candidate_correlation_status: $candidate_correlation_status,
      source_commit_at_target: $source_commit_at_target,
      source_dirty_at_target: $source_dirty_at_target,
      source_commit_schema_at_target: $source_commit_schema_at_target
    }' > "$AO2_CP_SMOKE_JSON"
fi

printf "ao2_control_plane_release_smoke=passed\n"
printf "smoke_root=%s\n" "$AO2_CP_SMOKE_ROOT"
printf "smoke_port=%s\n" "$PORT"
printf "acceptance_dashboard=%s\n" "$AO2_CP_SMOKE_ROOT/acceptance-dashboard.json"
printf "support_bundle=%s\n" "$AO2_CP_SMOKE_ROOT/support-bundle.json"
printf "phase1_gap_report=%s\n" "$AO2_CP_SMOKE_ROOT/phase1-gap-report.json"
printf "release_publication_dashboard=%s\n" "$AO2_CP_SMOKE_ROOT/release-publication-dashboard.json"
printf "release_cockpit=%s\n" "$AO2_CP_SMOKE_ROOT/release-cockpit.json"
printf "release_handoff=%s\n" "$AO2_CP_SMOKE_ROOT/release-handoff.json"
printf "release_readiness=%s\n" "$AO2_CP_SMOKE_ROOT/release-readiness.json"
printf "release_support_bundle=%s\n" "$AO2_CP_SMOKE_ROOT/release-support-bundle.json"
printf "release_support_bundle_download=%s\n" "$release_support_download"
printf "release_support_bundle_checksums=%s\n" "$release_support_checksums"
printf "release_support_bundle_offline_verify=%s\n" "$release_support_verify"
printf "release_support_bundle_download_sha256=%s\n" "$release_support_bundle_download_sha256"
printf "candidate_correlation_status=%s\n" "$candidate_correlation_status"
printf "source_commit_at_target=%s\n" "$source_commit_at_target"
printf "source_dirty_at_target=%s\n" "$source_dirty_at_target"
