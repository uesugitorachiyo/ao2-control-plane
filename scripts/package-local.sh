#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION="0.1.13"
OUT_DIR="$ROOT/dist"
BINARY="$ROOT/target/release/ao2-cp-server"
TARGET_LABEL=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --target-label)
      TARGET_LABEL="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$TARGET_LABEL" ]; then
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$os" in
    darwin) os_label="macos" ;;
    linux) os_label="linux" ;;
    msys*|mingw*|cygwin*) os_label="windows" ;;
    *) os_label="$os" ;;
  esac
  case "$arch" in
    arm64|aarch64) arch_label="aarch64" ;;
    x86_64|amd64) arch_label="x86_64" ;;
    *) arch_label="$arch" ;;
  esac
  TARGET_LABEL="$os_label-$arch_label"
fi

if [ ! -f "$BINARY" ]; then
  echo "missing ao2-control-plane binary: $BINARY" >&2
  exit 1
fi

case "$TARGET_LABEL" in
  *windows*) BINARY_NAME="ao2-cp-server.exe" ;;
  *) BINARY_NAME="ao2-cp-server" ;;
esac

# Derive the GC binary path from the same directory as the server
# binary so a custom --binary still finds its sibling ao2-cp-gc.
# Operators can run the GC out-of-band against the same data-dir the
# server is using (see docs/runbooks/storage-retention.md).
#
# The on-disk filename mirrors the server binary's extension: if the
# server is `foo/ao2-cp-server.exe` (Windows build) we look for
# `foo/ao2-cp-gc.exe`; otherwise `foo/ao2-cp-gc`. The TARGET_LABEL
# only governs the staged in-archive name (so the windows-x86_64 archive
# always ships `bin/ao2-cp-gc.exe`).
BINARY_DIR=$(CDPATH= cd -- "$(dirname -- "$BINARY")" && pwd)
BINARY_BASE=$(basename -- "$BINARY")
case "$BINARY_BASE" in
  *.exe) GC_SOURCE_NAME="ao2-cp-gc.exe" ;;
  *) GC_SOURCE_NAME="ao2-cp-gc" ;;
esac
GC_BINARY="$BINARY_DIR/$GC_SOURCE_NAME"
if [ ! -f "$GC_BINARY" ]; then
  echo "missing ao2-cp-gc binary alongside server binary: $GC_BINARY" >&2
  exit 1
fi
case "$TARGET_LABEL" in
  *windows*) GC_BINARY_NAME="ao2-cp-gc.exe" ;;
  *) GC_BINARY_NAME="ao2-cp-gc" ;;
esac

OUT_DIR=$(mkdir -p "$OUT_DIR" && CDPATH= cd -- "$OUT_DIR" && pwd)
STAGE=$(mktemp -d)
cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

mkdir -p "$STAGE/bin"
cp "$BINARY" "$STAGE/bin/$BINARY_NAME"
cp "$GC_BINARY" "$STAGE/bin/$GC_BINARY_NAME"
cp "$ROOT/scripts/verify_release_support_bundle.py" "$STAGE/verify_release_support_bundle.py"
cp "$ROOT/scripts/Verify-ReleaseSupportBundle.ps1" "$STAGE/Verify-ReleaseSupportBundle.ps1"
cp "$ROOT/scripts/fetch_release_support_handoff.py" "$STAGE/fetch_release_support_handoff.py"
cp "$ROOT/scripts/Fetch-ReleaseSupportHandoff.ps1" "$STAGE/Fetch-ReleaseSupportHandoff.ps1"
chmod 755 "$STAGE/bin/$BINARY_NAME" 2>/dev/null || true
chmod 755 "$STAGE/bin/$GC_BINARY_NAME" 2>/dev/null || true
chmod 755 "$STAGE/verify_release_support_bundle.py" 2>/dev/null || true
chmod 755 "$STAGE/fetch_release_support_handoff.py" 2>/dev/null || true

if command -v sha256sum >/dev/null 2>&1; then
  binary_sha=$(sha256sum "$STAGE/bin/$BINARY_NAME" | awk '{ print $1 }')
  gc_binary_sha=$(sha256sum "$STAGE/bin/$GC_BINARY_NAME" | awk '{ print $1 }')
  py_verifier_sha=$(sha256sum "$STAGE/verify_release_support_bundle.py" | awk '{ print $1 }')
  ps_verifier_sha=$(sha256sum "$STAGE/Verify-ReleaseSupportBundle.ps1" | awk '{ print $1 }')
  fetch_handoff_sha=$(sha256sum "$STAGE/fetch_release_support_handoff.py" | awk '{ print $1 }')
  ps_fetch_handoff_sha=$(sha256sum "$STAGE/Fetch-ReleaseSupportHandoff.ps1" | awk '{ print $1 }')
else
  binary_sha=$(shasum -a 256 "$STAGE/bin/$BINARY_NAME" | awk '{ print $1 }')
  gc_binary_sha=$(shasum -a 256 "$STAGE/bin/$GC_BINARY_NAME" | awk '{ print $1 }')
  py_verifier_sha=$(shasum -a 256 "$STAGE/verify_release_support_bundle.py" | awk '{ print $1 }')
  ps_verifier_sha=$(shasum -a 256 "$STAGE/Verify-ReleaseSupportBundle.ps1" | awk '{ print $1 }')
  fetch_handoff_sha=$(shasum -a 256 "$STAGE/fetch_release_support_handoff.py" | awk '{ print $1 }')
  ps_fetch_handoff_sha=$(shasum -a 256 "$STAGE/Fetch-ReleaseSupportHandoff.ps1" | awk '{ print $1 }')
fi
printf "%s  bin/%s\n" "$binary_sha" "$BINARY_NAME" > "$STAGE/SHA256SUMS"
printf "%s  bin/%s\n" "$gc_binary_sha" "$GC_BINARY_NAME" >> "$STAGE/SHA256SUMS"
printf "%s  verify_release_support_bundle.py\n" "$py_verifier_sha" >> "$STAGE/SHA256SUMS"
printf "%s  Verify-ReleaseSupportBundle.ps1\n" "$ps_verifier_sha" >> "$STAGE/SHA256SUMS"
printf "%s  fetch_release_support_handoff.py\n" "$fetch_handoff_sha" >> "$STAGE/SHA256SUMS"
printf "%s  Fetch-ReleaseSupportHandoff.ps1\n" "$ps_fetch_handoff_sha" >> "$STAGE/SHA256SUMS"

python3 - "$STAGE/RELEASE-MANIFEST.json" "$VERSION" "$TARGET_LABEL" "$BINARY_NAME" "$binary_sha" "$py_verifier_sha" "$ps_verifier_sha" "$fetch_handoff_sha" "$ps_fetch_handoff_sha" "$GC_BINARY_NAME" "$gc_binary_sha" <<'PY'
import json
import sys
from pathlib import Path

manifest = {
    "schema_version": "ao2-control-plane.release-manifest.v1",
    "name": "ao2-control-plane",
    "version": sys.argv[2],
    "target": sys.argv[3],
    "binary": sys.argv[4],
    "binary_path": f"bin/{sys.argv[4]}",
    "binary_sha256": sys.argv[5],
    "server": "ao2-cp-server",
    "operator_tools": {
        "gc": {
            "binary": sys.argv[10],
            "binary_path": f"bin/{sys.argv[10]}",
            "binary_sha256": sys.argv[11],
            "purpose": "operator-facing count-based retention pruner",
            "trust_boundary": "deletes content-addressed observer evidence on per-kind LRU; never approves AO2 digests, closes AO2 runs, or executes provider plugins",
            "usage_dry_run": f"bin/{sys.argv[10]} --data-dir <path> --keep-latest <N> --dry-run",
            "usage_apply": f"bin/{sys.argv[10]} --data-dir <path> --keep-latest <N> --apply",
        },
    },
    "trust_boundary": "read-only observer; never starts providers or approves AO2 runs",
    "support_bundle_trust_boundary": "offline verification only; no bearer tokens, provider keys, AO2 artifact mutation, or release approval",
    "offline_support_bundle_verifiers": {
        "python": {
            "path": "verify_release_support_bundle.py",
            "sha256": sys.argv[6],
            "command": "python3 verify_release_support_bundle.py release-support-bundle.json",
        },
        "powershell": {
            "path": "Verify-ReleaseSupportBundle.ps1",
            "sha256": sys.argv[7],
            "command": "pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-support-bundle.json",
        },
    },
    "release_support_handoff_fetcher": {
        "path": "fetch_release_support_handoff.py",
        "sha256": sys.argv[8],
        "command": "AO2_CP_AUTH_VALUE='<authorization-header>' python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir release-handoff",
        "powershell_path": "Fetch-ReleaseSupportHandoff.ps1",
        "powershell_sha256": sys.argv[9],
        "powershell_command": "$env:AO2_CP_AUTH_VALUE='<authorization-header>'; pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir release-handoff",
        "auth_value_stored": False,
        "outputs": [
            "release-support-verifier-handoff.json",
            "release-support-bundle.json",
            "SHA256SUMS",
            "release-support-bundle-verify.json",
            "release-support-bundle-manifest.json",
            "fetch-summary.json",
        ],
        "phase1_portable_handoff": {
            "flag": "--include-phase1-portable",
            "command": "AO2_CP_AUTH_VALUE='<authorization-header>' python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir phase1-handoff --include-phase1-portable",
            "powershell_flag": "-IncludePhase1Portable",
            "powershell_command": "$env:AO2_CP_AUTH_VALUE='<authorization-header>'; pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir phase1-handoff -IncludePhase1Portable",
            "verification_upload": "phase1-portable-manifest-verify-upload.json",
            "verification_result": "phase1-portable-manifest-verification.json",
            "outputs": [
                "phase1-portable-manifest.json",
                "ao2-phase1-operator-support-bundle.json",
                "ao2-phase1-gap-report.json",
                "phase1-SHA256SUMS",
                "phase1-portable-manifest-verify-upload.json",
                "phase1-portable-manifest-verification.json",
                "fetch-summary.json",
            ],
            "auth_value_stored": False,
            "trust_boundary": "read-only observer; no bearer tokens, provider keys, AO2 artifact mutation, or release approval",
        },
    },
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat > "$STAGE/install.sh" <<'SH'
#!/usr/bin/env sh
set -eu

cd "$(dirname -- "$0")"

INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-$HOME/.local/bin}}"
BINARY_NAME="ao2-cp-server"
mkdir -p "$INSTALL_DIR"

expected=$(awk '$2 == "bin/ao2-cp-server" { print $1 }' SHA256SUMS)
if [ -z "$expected" ]; then
  echo "missing checksum for bin/ao2-cp-server" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "bin/$BINARY_NAME" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "bin/$BINARY_NAME" | awk '{ print $1 }')
fi
if [ "$actual" != "$expected" ]; then
  echo "checksum mismatch for bin/$BINARY_NAME" >&2
  exit 1
fi

cp "bin/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"
printf "ao2_control_plane_installed=%s\n" "$INSTALL_DIR/$BINARY_NAME"

# ao2-cp-gc — operator-facing retention pruner.
GC_BINARY_NAME="ao2-cp-gc"
gc_expected=$(awk '$2 == "bin/ao2-cp-gc" { print $1 }' SHA256SUMS)
if [ -z "$gc_expected" ]; then
  echo "missing checksum for bin/ao2-cp-gc" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  gc_actual=$(sha256sum "bin/$GC_BINARY_NAME" | awk '{ print $1 }')
else
  gc_actual=$(shasum -a 256 "bin/$GC_BINARY_NAME" | awk '{ print $1 }')
fi
if [ "$gc_actual" != "$gc_expected" ]; then
  echo "checksum mismatch for bin/$GC_BINARY_NAME" >&2
  exit 1
fi

cp "bin/$GC_BINARY_NAME" "$INSTALL_DIR/$GC_BINARY_NAME"
chmod 755 "$INSTALL_DIR/$GC_BINARY_NAME"
printf "ao2_control_plane_gc_installed=%s\n" "$INSTALL_DIR/$GC_BINARY_NAME"
SH
chmod 755 "$STAGE/install.sh"

cat > "$STAGE/install.ps1" <<'PS1'
$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

$InstallDir = if ($env:AO2_CP_INSTALL_DIR) {
    $env:AO2_CP_INSTALL_DIR
} elseif ($env:AO2_INSTALL_DIR) {
    $env:AO2_INSTALL_DIR
} else {
    Join-Path $env:USERPROFILE ".local\bin"
}
$BinaryName = "ao2-cp-server.exe"
$Source = Join-Path "bin" $BinaryName

if (!(Test-Path $Source)) {
    throw "missing packaged binary: $Source"
}

$Expected = (Get-Content SHA256SUMS | Where-Object { $_ -match "bin/ao2-cp-server.exe$" } | ForEach-Object { ($_ -split "\s+")[0] } | Select-Object -First 1)
if (!$Expected) {
    throw "missing checksum for bin/ao2-cp-server.exe"
}
$Actual = (Get-FileHash -Algorithm SHA256 $Source).Hash.ToLowerInvariant()
if ($Actual -ne $Expected.ToLowerInvariant()) {
    throw "checksum mismatch for bin/ao2-cp-server.exe"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $Source (Join-Path $InstallDir $BinaryName)
Write-Output "ao2_control_plane_installed=$(Join-Path $InstallDir $BinaryName)"

# ao2-cp-gc — operator-facing retention pruner.
$GcBinaryName = "ao2-cp-gc.exe"
$GcSource = Join-Path "bin" $GcBinaryName

if (!(Test-Path $GcSource)) {
    throw "missing packaged binary: $GcSource"
}

$GcExpected = (Get-Content SHA256SUMS | Where-Object { $_ -match "bin/ao2-cp-gc.exe$" } | ForEach-Object { ($_ -split "\s+")[0] } | Select-Object -First 1)
if (!$GcExpected) {
    throw "missing checksum for bin/ao2-cp-gc.exe"
}
$GcActual = (Get-FileHash -Algorithm SHA256 $GcSource).Hash.ToLowerInvariant()
if ($GcActual -ne $GcExpected.ToLowerInvariant()) {
    throw "checksum mismatch for bin/ao2-cp-gc.exe"
}

Copy-Item -Force $GcSource (Join-Path $InstallDir $GcBinaryName)
Write-Output "ao2_control_plane_gc_installed=$(Join-Path $InstallDir $GcBinaryName)"
PS1

cat > "$STAGE/README.txt" <<'TXT'
ao2-control-plane release archive

This server is a read-only observer for AO2 signed evidence and memory exports.
It does not start providers and does not approve AO2 runs.

Unix install:
  AO2_CP_INSTALL_DIR=$HOME/.local/bin sh install.sh

Windows install:
  $env:AO2_CP_INSTALL_DIR="$env:USERPROFILE\.local\bin"
  powershell -ExecutionPolicy Bypass -File .\install.ps1

Offline release support-bundle fetch and verification:
  export AO2_CP_AUTH_VALUE="Bearer $AO2_CP_API_TOKEN"
  python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir release-handoff
  unset AO2_CP_AUTH_VALUE
  python3 verify_release_support_bundle.py release-handoff/release-support-bundle.json
  pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-handoff/release-support-bundle.json

Windows/PowerShell handoff fetch:
  $env:AO2_CP_AUTH_VALUE="Bearer <local-control-plane-token>"
  pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir release-handoff
  Remove-Item Env:\AO2_CP_AUTH_VALUE
  pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-handoff/release-support-bundle.json

Offline Phase 1 portable handoff fetch and manifest verification:
  export AO2_CP_AUTH_VALUE="Bearer $AO2_CP_API_TOKEN"
  python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir phase1-handoff --include-phase1-portable
  unset AO2_CP_AUTH_VALUE
  inspect phase1-handoff/phase1-portable-manifest-verify-upload.json
  inspect phase1-handoff/phase1-portable-manifest-verification.json

Windows/PowerShell Phase 1 portable handoff fetch:
  $env:AO2_CP_AUTH_VALUE="Bearer <local-control-plane-token>"
  pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir phase1-handoff -IncludePhase1Portable
  Remove-Item Env:\AO2_CP_AUTH_VALUE
  inspect phase1-handoff\phase1-portable-manifest-verify-upload.json
  inspect phase1-handoff\phase1-portable-manifest-verification.json

Operator landing flow (cross-OS: macOS, Ubuntu, Windows)

  Each HTTP surface below is a read-only observer view; the control plane
  never mutates AO2 artifacts and never approves releases. Operators
  triage in this order, then dive into the surface that owns the open
  dimension.

  1. Hermes -> /api/v1/phase1/promotion/operator-panel
       Single Phase 1 landing page for Hermes / factory-v3 operators.
       Source of truth for: operator action queue, readiness badges
       (checklist, signed_decision, signature, three_os, candidate_correlation).
       Drill into the named surface below for any non-passed badge.

  2. /api/v1/phase1/promotion/dashboard
       Source of truth for: phase1 state machine, phase readiness gap
       report (provider_readiness, live_provider_acceptance, release_gate,
       three_os_smoke), and the candidate_correlation triage verdict
       mirrored from the publication dashboard. Drill into /provider/*
       or /acceptance/* dashboards for provider-side dimensions.

  3. /api/v1/release/cockpit
       Source of truth for: release_publication state, provider_registry,
       provider_acceptance details (live codex / claude run ids, scores,
       source class), and the canonical candidate_correlation object.

  4. /api/v1/release/publication/dashboard
       Source of truth for: release publication assembly_blockers and
       the same candidate_correlation object — used to verify that the
       cockpit and the publication dashboard agree on the cross-evidence
       triage verdict.

  5. /api/v1/release/readiness, /api/v1/release/handoff, and the
     embedded release_assembly surface in the support bundle.
       Source of truth for: signed-gate readiness (release_cockpit,
       phase1_promotion, decision_signature, provider_acceptance,
       release_evaluator_decision, candidate_correlation, codex/claude
       acceptance, three_os_smoke, trust_boundary). These are also the
       four surfaces the offline support-bundle verifier hard-checks
       for candidate_correlation; cockpit/handoff/readiness use the
       candidate_correlation object, release_assembly uses
       candidate_correlation_detail (its top-level
       candidate_correlation is the status string consumed by
       cross-OS smoke scripts).

  All five candidate_correlation copies are byte-identical under a fixed
  scenario; the parity test
  all_release_publication_shaped_surfaces_agree_on_candidate_correlation
  fails loudly if any handler drifts.

Three-OS smoke parity gates (Lanes P, S, V, W)

  Two additional gates protect the release from cross-OS divergence,
  surfaced on cockpit/handoff/readiness JSON at top level and on the
  release readiness gate_results array.

  - candidate_correlation_parity (Lanes P, S):
      The aggregator (scripts/smoke-three-os-release.sh) parses each
      per-OS smoke log for its candidate_correlation_status=<value>
      trailer and resolves a cross-OS verdict
      (matched / mismatched / missing / drift / unknown). Registered
      as a hard readiness gate in Lane S — any verdict other than
      matched flips readiness from ready to attention.

  - candidate_correlation_content_hash_parity (Lane V):
      The aggregator additionally fetches each per-OS
      release-cockpit.json back to the orchestrator (cp for macOS,
      scp for Ubuntu/Windows under the existing BatchMode=yes SSH
      targets), normalizes the .candidate_correlation subtree via
      jq -cS, and sha256s the result. Cross-OS hash drift fails the
      smoke even when the status-level parity gate reports matched —
      catching content drift inside the blockers array or any other
      nested field.

  - Server-side parity recomputation (Lane W):
      validate_three_os_release_smoke in
      crates/ao2-cp-server/src/handlers/phase1_promotion.rs re-runs
      the aggregator's parity algorithm on ingestion and rejects any
      smoke whose posted top-level candidate_correlation_parity
      disagrees with the recomputation. Closes the
      server-trusted-input vs. recomputable-from-evidence gap so a
      tampered ingestion cannot stamp parity=matched while per-target
      evidence disagrees.

  Operator triage: read docs/runbooks/release-smoke.md for the
  authoritative triage path covering all four defense-in-depth
  layers, the on-disk smoke artifact layout, and the diff-by-hand
  commands for content-hash drift.

Audit-log rotation budget (Lanes UU, VV, XX, ZZ)

  Every rejected three-OS smoke ingestion is appended to the
  rejected-three-os-smoke.jsonl audit log (Lane LL). The log has a
  hard 1 MiB cap (Lane UU); when an append would cross the cap, the
  newest records are kept and oldest evicted FIFO. Three surfaces
  give operators visibility into the rotation budget:

  - HTML cockpit row (Lane VV):
      /api/v1/release/cockpit renders an "Audit log size" row with
      "<size> / <cap> bytes (Lane UU rotation cap)". The row flips
      to the warn class at >= 75% of cap (786432 bytes) so operators
      see "rotation imminent" without reading the JSON. Behavioral
      test cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv
      pins the warn threshold.

  - JSON pass-through (Lane XX):
      The cockpit, handoff, and readiness JSON endpoints each embed
      an identical rejected_smoke_audit object containing the
      Lane XX rotation-budget fields (count, audit_log_size_bytes,
      audit_log_cap_bytes) plus latest_timestamp_utc and
      latest_rejection_reason. Monitor authors can read any of the
      three JSON endpoints and see the same numbers. Pass-through
      enforced by cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx.

  - Recommended alert rules (Lane XX-doc, runbook section 9.6):
      Two complementary alerts cover the audit trail:
        - Rotation imminent: audit_log_size_bytes / audit_log_cap_bytes > 0.75
            Maps to the Lane VV warn-class transition; cockpit + monitor agree.
        - Tampering attempt spike: increase(count[1m]) > 10
            Catches slow tampering patterns that stay below 75% but
            accumulate over hours.
      Rule 1 answers "is the audit trail healthy?"; rule 2 answers
      "is something attacking us?". Monitor authors should pick both.

  - Offline-verifier byte-identity + cross-bundle drift (Lane ZZ):
      The offline verifier (verify_release_support_bundle.py and
      Verify-ReleaseSupportBundle.ps1) hashes the rejected_smoke_audit
      object on cockpit/handoff/readiness and fails on any non-identical
      hash set (marker rejected_smoke_audit_cross_surface_byte_identity).
      Catches tampered offline bundles where one surface's audit
      object was edited (count bumped to mask rejected tampering
      attempts) while the others were left untouched. The
      --compare-against PATH / -CompareAgainst PATH flag additionally
      surfaces cross-bundle rotation-budget drift as
      comparison_audit_log_rotation_budget_drift failures plus a
      structured audit_budget_diffs array; the signal is NOT folded
      into verdict_parity because between-captures activity is
      legitimate. Worked example:
        release_support_bundle_audit_log_byte_identity_and_cross_bundle_drift_lane_zz.

  Operator triage: read docs/runbooks/release-smoke.md sections
  9.5-9.10 for the JSON shape contract, the alert-rule expressions,
  the cross-surface consistency guarantee, the offline-verifier
  audit semantics, the concurrent-write mutex protection, and the
  cockpit on-call triage pointer.

  On-call triage (Lanes DDD + EEE + GGG):
    If you have been paged on the tampering-burst alert (Lane
    XX-doc rule 2: `increase(count[1m]) > 10`), the audit log
    itself is integrity-safe. The append path acquires a
    process-global tokio mutex
    (REJECTED_SMOKE_AUDIT_WRITER_LOCK in
    crates/ao2-cp-server/src/handlers/phase1_promotion.rs) for
    the entire read-projection-write region, so concurrent
    appends serialize cleanly and the file size cap holds. The
    summary reader stays lock-free because tokio::fs::write
    (truncate + write) is atomic relative to a fresh read.
    Worked example:
      audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation
    Higher-N regression coverage (Lane BBB):
      audit_log_rotation_stays_well_formed_under_n200_burst_lane_bbb
      audit_log_rotation_stays_well_formed_under_n500_burst_lane_bbb

    Load-bearing framing: a tampering-burst alert points at a
    tampering event, not at audit-log corruption. Read the log.
    If the cap is intact and every line parses as JSON, the
    surge is real; capture the rejection reasons + source
    commits and route the incident to factory-v3
    evaluator-closer. The cockpit/handoff/readiness HTML
    surfaces this same framing inline on the "Rejected Smoke
    Ingestions" section so an operator landing on any of the
    three surfaces does not need to know the runbook section
    number in advance. The runbook section for the full
    narrative is 9.9 (mutex + framing) and 9.10 (cockpit
    pointer).
TXT

ARCHIVE="$OUT_DIR/ao2-control-plane-$VERSION-$TARGET_LABEL.tar.gz"
(cd "$STAGE" && tar -czf "$ARCHIVE" bin install.sh install.ps1 verify_release_support_bundle.py Verify-ReleaseSupportBundle.ps1 fetch_release_support_handoff.py Fetch-ReleaseSupportHandoff.ps1 SHA256SUMS RELEASE-MANIFEST.json README.txt)
if command -v sha256sum >/dev/null 2>&1; then
  archive_sha=$(sha256sum "$ARCHIVE" | awk '{ print $1 }')
else
  archive_sha=$(shasum -a 256 "$ARCHIVE" | awk '{ print $1 }')
fi
printf "%s  %s\n" "$archive_sha" "$(basename "$ARCHIVE")" >> "$OUT_DIR/SHA256SUMS"

printf "ao2_control_plane_package=passed\n"
printf "archive=%s\n" "$ARCHIVE"
printf "sha256=%s\n" "$archive_sha"
