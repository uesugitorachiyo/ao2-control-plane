#!/usr/bin/env bash
# Cross-OS test-suite smoke for ao2-cp-server.
#
# Faster, less ceremony than scripts/smoke-three-os-release.sh — that one
# packages a release candidate and validates the release correlation
# protocol; this one just runs `cargo test -p ao2-cp-server --tests` on
# Mac (in-process), Ubuntu (via SSH), and Windows (via SSH ProxyJump) on
# the current `HEAD` tree and emits a JSON summary so a developer can
# trust that the same source compiles + passes on all three OSes before
# pushing.
#
# Usage:
#   scripts/smoke-three-os.sh                # runs all three
#   scripts/smoke-three-os.sh --skip-windows # skip Windows (e.g. when offline)
#   scripts/smoke-three-os.sh --tests-only metrics_endpoint,status_endpoint
#
# Required env (with defaults matching the working tree's known hosts):
#   AO2_CP_UBUNTU_SSH_TARGET   ssh alias for Ubuntu host
#   AO2_CP_WINDOWS_SSH_TARGET  ssh alias for Windows host (ProxyJump-capable)
#
# Emits:
#   target/smoke-three-os/<ts>/summary.json  ao2.cp-smoke-three-os.v1
#   target/smoke-three-os/<ts>/{mac,ubuntu,windows}.log
#
# Exit codes: 0 if every executed OS run passed, 1 if any failed,
# 2 for orchestration error (e.g. tarball failed to create).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AO2_CP_UBUNTU_SSH_TARGET="${AO2_CP_UBUNTU_SSH_TARGET:-ao2-ubuntu-nucx}"
AO2_CP_WINDOWS_SSH_TARGET="${AO2_CP_WINDOWS_SSH_TARGET:-win-hp255-via-ubuntu}"
AO2_CP_REMOTE_LINUX_ROOT="${AO2_CP_REMOTE_LINUX_ROOT:-/tmp/ao2-cp-smoke-three-os}"
AO2_CP_REMOTE_WINDOWS_ROOT_REL="${AO2_CP_REMOTE_WINDOWS_ROOT_REL:-AppData/Local/Temp/ao2-cp-smoke-three-os}"
AO2_CP_REMOTE_WINDOWS_ROOT_NATIVE="${AO2_CP_REMOTE_WINDOWS_ROOT_NATIVE:-C:/ao2-public-test/AppData/Local/Temp/ao2-cp-smoke-three-os}"

SKIP_MAC=0
SKIP_UBUNTU=0
SKIP_WINDOWS=0
TESTS_ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-mac)
            SKIP_MAC=1
            shift
            ;;
        --skip-ubuntu)
            SKIP_UBUNTU=1
            shift
            ;;
        --skip-windows)
            SKIP_WINDOWS=1
            shift
            ;;
        --tests-only)
            TESTS_ONLY="$2"
            shift 2
            ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

TS="$(date +%Y%m%d%H%M%S)"
OUT_ROOT="$ROOT/target/smoke-three-os/$TS"
mkdir -p "$OUT_ROOT"

SOURCE_TGZ="$OUT_ROOT/source.tgz"
SUMMARY_JSON="$OUT_ROOT/summary.json"
MAC_LOG="$OUT_ROOT/mac.log"
UBUNTU_LOG="$OUT_ROOT/ubuntu.log"
WINDOWS_LOG="$OUT_ROOT/windows.log"

SOURCE_COMMIT="$(git rev-parse HEAD)"
SOURCE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HOSTNAME_LOCAL="$(hostname -s 2>/dev/null || hostname)"

echo "[smoke-three-os] HEAD=$SOURCE_COMMIT ($SOURCE_BRANCH) → $OUT_ROOT"

# Tarball HEAD so all three runs build the same tree, even if the
# working copy gets dirty mid-run. `git archive HEAD` only captures
# committed state — anything uncommitted will NOT be tested.
git archive --format=tar.gz -o "$SOURCE_TGZ" HEAD
TGZ_SHA="$(shasum -a 256 "$SOURCE_TGZ" | awk '{print $1}')"
TGZ_BYTES="$(wc -c <"$SOURCE_TGZ" | tr -d ' ')"
echo "[smoke-three-os] source.tgz $TGZ_BYTES bytes sha256=$TGZ_SHA"

cargo_test_args=()
if [[ -n "$TESTS_ONLY" ]]; then
    IFS=',' read -ra split <<<"$TESTS_ONLY"
    for t in "${split[@]}"; do
        cargo_test_args+=(--test "$t")
    done
else
    cargo_test_args+=(--tests)
fi

###############################################################################
# Mac (in-process)
###############################################################################
mac_status="skipped"
mac_duration=0
if [[ "$SKIP_MAC" == "0" ]]; then
    echo "[smoke-three-os] mac: cargo test -p ao2-cp-server ${cargo_test_args[*]}"
    mac_start=$(date +%s)
    if cargo test -p ao2-cp-server "${cargo_test_args[@]}" >"$MAC_LOG" 2>&1; then
        mac_status="ok"
    else
        mac_status="failed"
    fi
    mac_duration=$(( $(date +%s) - mac_start ))
fi

###############################################################################
# Ubuntu (via SSH)
###############################################################################
ubuntu_status="skipped"
ubuntu_duration=0
if [[ "$SKIP_UBUNTU" == "0" ]]; then
    echo "[smoke-three-os] ubuntu: $AO2_CP_UBUNTU_SSH_TARGET → $AO2_CP_REMOTE_LINUX_ROOT"
    scp -q "$SOURCE_TGZ" "$AO2_CP_UBUNTU_SSH_TARGET:$AO2_CP_REMOTE_LINUX_ROOT.tgz"
    ubuntu_start=$(date +%s)
    if ssh "$AO2_CP_UBUNTU_SSH_TARGET" "
        source \$HOME/.cargo/env 2>/dev/null || true
        rm -rf '$AO2_CP_REMOTE_LINUX_ROOT'
        mkdir -p '$AO2_CP_REMOTE_LINUX_ROOT'
        tar -xzf '$AO2_CP_REMOTE_LINUX_ROOT.tgz' -C '$AO2_CP_REMOTE_LINUX_ROOT'
        cd '$AO2_CP_REMOTE_LINUX_ROOT'
        ulimit -n 65536
        cargo test -p ao2-cp-server ${cargo_test_args[*]}
    " >"$UBUNTU_LOG" 2>&1; then
        ubuntu_status="ok"
    else
        ubuntu_status="failed"
    fi
    ubuntu_duration=$(( $(date +%s) - ubuntu_start ))
fi

###############################################################################
# Windows (via SSH ProxyJump)
###############################################################################
windows_status="skipped"
windows_duration=0
if [[ "$SKIP_WINDOWS" == "0" ]]; then
    echo "[smoke-three-os] windows: $AO2_CP_WINDOWS_SSH_TARGET → $AO2_CP_REMOTE_WINDOWS_ROOT_REL"
    scp -q "$SOURCE_TGZ" "$AO2_CP_WINDOWS_SSH_TARGET:$AO2_CP_REMOTE_WINDOWS_ROOT_REL.tgz"
    win_script="$OUT_ROOT/win-script.sh"
    # Inside Git-Bash on Windows, use $HOME-relative POSIX paths so tar
    # does not mistake "C:/..." for an SSH-style remote.
    cat >"$win_script" <<EOF
#!/bin/bash
set -e
cd "\$HOME"
WIN_ROOT="\$HOME/$AO2_CP_REMOTE_WINDOWS_ROOT_REL"
WIN_TGZ="\$HOME/$AO2_CP_REMOTE_WINDOWS_ROOT_REL.tgz"
rm -rf "\$WIN_ROOT"
mkdir -p "\$WIN_ROOT"
tar -xzf "\$WIN_TGZ" -C "\$WIN_ROOT"
cd "\$WIN_ROOT"
export PATH="\$HOME/.cargo/bin:\$PATH"
cargo test -p ao2-cp-server ${cargo_test_args[*]}
EOF
    scp -q "$win_script" "$AO2_CP_WINDOWS_SSH_TARGET:$AO2_CP_REMOTE_WINDOWS_ROOT_REL-script.sh"
    windows_start=$(date +%s)
    if ssh "$AO2_CP_WINDOWS_SSH_TARGET" "powershell -NoProfile -Command \"& 'C:\\Program Files\\Git\\bin\\bash.exe' -l \\\"\\\$HOME\\$AO2_CP_REMOTE_WINDOWS_ROOT_REL-script.sh\\\"\"" >"$WINDOWS_LOG" 2>&1; then
        # PowerShell may swallow the exit code; double-check by tail.
        if tail -5 "$WINDOWS_LOG" | grep -q "FAILED\|error:"; then
            windows_status="failed"
        else
            windows_status="ok"
        fi
    else
        windows_status="failed"
    fi
    windows_duration=$(( $(date +%s) - windows_start ))
fi

###############################################################################
# Summary
###############################################################################
overall_status="ok"
for s in "$mac_status" "$ubuntu_status" "$windows_status"; do
    if [[ "$s" == "failed" ]]; then
        overall_status="failed"
    fi
done

cat >"$SUMMARY_JSON" <<EOF
{
  "schema_version": "ao2.cp-smoke-three-os.v1",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_commit": "$SOURCE_COMMIT",
  "source_branch": "$SOURCE_BRANCH",
  "source_tarball_sha256": "$TGZ_SHA",
  "source_tarball_bytes": $TGZ_BYTES,
  "orchestrator_host": "$HOSTNAME_LOCAL",
  "ubuntu_ssh_target": "$AO2_CP_UBUNTU_SSH_TARGET",
  "windows_ssh_target": "$AO2_CP_WINDOWS_SSH_TARGET",
  "tests_filter": "${TESTS_ONLY:-all}",
  "overall_status": "$overall_status",
  "runs": {
    "mac": { "status": "$mac_status", "duration_seconds": $mac_duration, "log": "mac.log" },
    "ubuntu": { "status": "$ubuntu_status", "duration_seconds": $ubuntu_duration, "log": "ubuntu.log" },
    "windows": { "status": "$windows_status", "duration_seconds": $windows_duration, "log": "windows.log" }
  }
}
EOF

echo "[smoke-three-os] summary → $SUMMARY_JSON"
echo "[smoke-three-os] mac=$mac_status ubuntu=$ubuntu_status windows=$windows_status overall=$overall_status"

if [[ "$overall_status" == "failed" ]]; then
    exit 1
fi
exit 0
