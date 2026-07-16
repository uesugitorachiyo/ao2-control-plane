#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AO2_CP_UBUNTU_SSH_TARGET="${AO2_CP_UBUNTU_SSH_TARGET:-ao2-ubuntu-nucx}"
AO2_CP_WINDOWS_SSH_TARGET="${AO2_CP_WINDOWS_SSH_TARGET:-win-hp255-via-ubuntu}"
AO2_CP_REQUIRE_WINDOWS="${AO2_CP_REQUIRE_WINDOWS:-1}"
AO2_CP_REQUIRE_UBUNTU="${AO2_CP_REQUIRE_UBUNTU:-1}"
AO2_CP_REMOTE_LINUX_ROOT="${AO2_CP_REMOTE_LINUX_ROOT:-/tmp/ao2-control-plane-three-os-smoke}"
AO2_CP_REMOTE_WINDOWS_ROOT="${AO2_CP_REMOTE_WINDOWS_ROOT:-C:/ao2-public-test/AppData/Local/Temp/ao2-control-plane-three-os-smoke}"
AO2_CP_VERSION="${AO2_CP_VERSION:-0.1.16}"
AO2_CP_RELEASE_CANDIDATE_VERSION="${AO2_CP_RELEASE_CANDIDATE_VERSION:-$AO2_CP_VERSION}"
AO2_CP_THREE_OS_SMOKE_ROOT="${AO2_CP_THREE_OS_SMOKE_ROOT:-$ROOT/target/three-os-release-smoke/$(date +%Y%m%d%H%M%S)}"
AO2_CP_THREE_OS_SMOKE_JSON="${AO2_CP_THREE_OS_SMOKE_JSON:-$AO2_CP_THREE_OS_SMOKE_ROOT/summary.json}"

mkdir -p "$AO2_CP_THREE_OS_SMOKE_ROOT"
AO2_CP_THREE_OS_SMOKE_ROOT="$(cd "$AO2_CP_THREE_OS_SMOKE_ROOT" && pwd)"

source_tgz="$AO2_CP_THREE_OS_SMOKE_ROOT/source.tgz"
mac_log="$AO2_CP_THREE_OS_SMOKE_ROOT/macos.log"
ubuntu_log="$AO2_CP_THREE_OS_SMOKE_ROOT/ubuntu.log"
windows_log="$AO2_CP_THREE_OS_SMOKE_ROOT/windows.log"
ubuntu_command_file="$AO2_CP_THREE_OS_SMOKE_ROOT/ubuntu-command.sh"
windows_command_file="$AO2_CP_THREE_OS_SMOKE_ROOT/windows-command.ps1"
report_md="$AO2_CP_THREE_OS_SMOKE_ROOT/report.md"

status_macos="failed"
status_ubuntu="failed"
status_windows="failed"
correlation_macos="unknown"
correlation_ubuntu="unknown"
correlation_windows="unknown"
candidate_correlation_parity="unknown"
# Lane OO: per-target source_commit_at_target captures the commit each
# per-OS run actually built against, read from the `.source-commit`
# record the orchestrator embedded into source.tgz. Aggregating these
# back to the top-level summary lets future server-side ingestion
# validate that top-level source_commit == every per-target value
# (orchestrator HEAD drift between packaging and the per-target run
# would manifest as a mismatch).
source_commit_at_target_macos="unknown"
source_commit_at_target_ubuntu="unknown"
source_commit_at_target_windows="unknown"
source_commit_per_target_drift="unknown"
correlation_content_hash_macos="missing"
correlation_content_hash_ubuntu="missing"
correlation_content_hash_windows="missing"
candidate_correlation_content_hash_parity="unknown"
# Lane Z: per-surface content hashes across release-publication-shaped
# surfaces. Each surface gets its own per-OS hash and its own drift
# verdict so an operator can pinpoint which surface drifted, not just
# that one of them did.
handoff_content_hash_macos="missing"
handoff_content_hash_ubuntu="missing"
handoff_content_hash_windows="missing"
handoff_content_hash_parity="unknown"
readiness_content_hash_macos="missing"
readiness_content_hash_ubuntu="missing"
readiness_content_hash_windows="missing"
readiness_content_hash_parity="unknown"
publication_dashboard_content_hash_macos="missing"
publication_dashboard_content_hash_ubuntu="missing"
publication_dashboard_content_hash_windows="missing"
publication_dashboard_content_hash_parity="unknown"
assembly_content_hash_macos="missing"
assembly_content_hash_ubuntu="missing"
assembly_content_hash_windows="missing"
assembly_content_hash_parity="unknown"
# Lane BB: extend the byte-identity audit beyond .candidate_correlation
# subtrees to additional cross-OS invariants. The .release_assembly.assembly_blockers
# array on the support-bundle captures downstream gate-state drift (a
# divergence the candidate_correlation surface alone cannot expose, since
# correlation could match across OSes while gate blockers diverge for
# orthogonal reasons like provider acceptance, decision signature
# presence, or readiness verdicts). Drift here exits the smoke non-zero
# independent of every Lane Z surface.
assembly_blockers_content_hash_macos="missing"
assembly_blockers_content_hash_ubuntu="missing"
assembly_blockers_content_hash_windows="missing"
assembly_blockers_content_hash_parity="unknown"

source_commit="$(git rev-parse HEAD)"
source_dirty="false"
if ! git diff --quiet || ! git diff --cached --quiet; then
  source_dirty="true"
fi

python3 - "$source_tgz" "$source_commit" "$source_dirty" <<'PY'
import io
import json
import subprocess
import sys
import tarfile
import time
from pathlib import Path

target = Path(sys.argv[1])
source_commit = sys.argv[2]
source_dirty = sys.argv[3]
tracked = subprocess.check_output(["git", "ls-files", "-z"])
others = subprocess.check_output(["git", "ls-files", "-z", "-o", "--exclude-standard"])
paths = [Path(p.decode()) for p in (tracked + others).split(b"\0") if p]

with tarfile.open(target, "w:gz") as archive:
    for path in sorted(set(paths)):
        if not path.is_file() or path.is_symlink():
            continue
        archive.add(path, arcname=path.as_posix(), recursive=False)
    # Lane OO: embed an authoritative .source-commit record into the source
    # tarball so each per-target run can emit `source_commit_at_target`
    # reflecting the commit it actually built against. The orchestrator's
    # `git rev-parse HEAD` is computed before packaging; embedding the value
    # ensures every target reports the same source commit even if the
    # orchestrator's working tree advances HEAD between packaging and the
    # per-target run. The file is written as JSON so future fields can be
    # added without changing the parser shape (see Lane OO + later lanes).
    payload = json.dumps(
        {
            "schema": "ao2-control-plane.source-commit.v1",
            "source_commit": source_commit,
            "source_dirty": source_dirty == "true",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    info = tarfile.TarInfo(name=".source-commit")
    info.size = len(payload)
    info.mtime = int(time.time())
    info.mode = 0o644
    info.type = tarfile.REGTYPE
    archive.addfile(info, io.BytesIO(payload))
PY

# Lane OO: also write `.source-commit` into the working tree so the
# in-place macOS run (which does NOT extract source.tgz) picks up the
# same authoritative source-commit record as the Ubuntu/Windows runs
# (which DO extract source.tgz). Writing AFTER packaging keeps the
# file out of the orchestrator's source tarball (the tarball already
# embeds a synthetic .source-commit member with identical content via
# archive.addfile above). The trap removes the working-tree copy on
# every exit path so a failed smoke does not leave a stray file. Server-
# side ingestion (Lane PP-server) can then assert top-level source_commit
# == every per-target source_commit_at_target uniformly across all three
# OSes.
working_tree_source_commit_file="$ROOT/.source-commit"
python3 - "$working_tree_source_commit_file" "$source_commit" "$source_dirty" <<'PY'
import json
import sys
from pathlib import Path

target = Path(sys.argv[1])
source_commit = sys.argv[2]
source_dirty = sys.argv[3]
payload = json.dumps(
    {
        "schema": "ao2-control-plane.source-commit.v1",
        "source_commit": source_commit,
        "source_dirty": source_dirty == "true",
    },
    sort_keys=True,
    separators=(",", ":"),
) + "\n"
target.write_text(payload, encoding="utf-8")
PY
trap 'rm -f "$working_tree_source_commit_file"' EXIT

write_remote_command_files() {
  cat >"$ubuntu_command_file" <<EOF
set -euo pipefail
export PATH="\$HOME/.cargo/bin:\$PATH"
cd '$AO2_CP_REMOTE_LINUX_ROOT/run'
tar -xzf ../source.tgz
cargo build --release -p ao2-cp-server
bash scripts/package-local.sh --out-dir dist --version '$AO2_CP_VERSION' --binary target/release/ao2-cp-server --target-label linux-x86_64
AO2_CP_ARCHIVE='dist/ao2-control-plane-$AO2_CP_VERSION-linux-x86_64.tar.gz' AO2_CP_SMOKE_ROOT='$AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-smoke' AO2_CP_SMOKE_JSON='$AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-release-smoke.json' bash scripts/smoke-release-archive.sh
EOF

  cat >"$windows_command_file" <<EOF
Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path '$AO2_CP_REMOTE_WINDOWS_ROOT/run' | Out-Null
Set-Location -LiteralPath '$AO2_CP_REMOTE_WINDOWS_ROOT/run'
tar -xzf ../source.tgz
cargo build --release -p ao2-cp-server
& 'C:/Program Files/Git/bin/bash.exe' scripts/package-local.sh --out-dir dist --version '$AO2_CP_VERSION' --binary target/release/ao2-cp-server.exe --target-label windows-x86_64
\$env:AO2_CP_ARCHIVE='dist/ao2-control-plane-$AO2_CP_VERSION-windows-x86_64.tar.gz'
\$env:AO2_CP_SMOKE_ROOT='$AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-smoke'
\$env:AO2_CP_SMOKE_JSON='$AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-release-smoke.json'
./scripts/smoke-release-archive.ps1
EOF
}

write_remote_command_files

write_json() {
  python3 - "$AO2_CP_THREE_OS_SMOKE_JSON" "$report_md" "$source_commit" "$source_dirty" "$status_macos" "$status_ubuntu" "$status_windows" "$mac_log" "$ubuntu_log" "$windows_log" "$AO2_CP_THREE_OS_SMOKE_ROOT" "$AO2_CP_VERSION" "$AO2_CP_RELEASE_CANDIDATE_VERSION" "$AO2_CP_UBUNTU_SSH_TARGET" "$AO2_CP_WINDOWS_SSH_TARGET" "$ubuntu_command_file" "$windows_command_file" "$correlation_macos" "$correlation_ubuntu" "$correlation_windows" "$candidate_correlation_parity" "$correlation_content_hash_macos" "$correlation_content_hash_ubuntu" "$correlation_content_hash_windows" "$candidate_correlation_content_hash_parity" "$handoff_content_hash_macos" "$handoff_content_hash_ubuntu" "$handoff_content_hash_windows" "$handoff_content_hash_parity" "$readiness_content_hash_macos" "$readiness_content_hash_ubuntu" "$readiness_content_hash_windows" "$readiness_content_hash_parity" "$publication_dashboard_content_hash_macos" "$publication_dashboard_content_hash_ubuntu" "$publication_dashboard_content_hash_windows" "$publication_dashboard_content_hash_parity" "$assembly_content_hash_macos" "$assembly_content_hash_ubuntu" "$assembly_content_hash_windows" "$assembly_content_hash_parity" "$assembly_blockers_content_hash_macos" "$assembly_blockers_content_hash_ubuntu" "$assembly_blockers_content_hash_windows" "$assembly_blockers_content_hash_parity" "$source_commit_at_target_macos" "$source_commit_at_target_ubuntu" "$source_commit_at_target_windows" "$source_commit_per_target_drift" <<'PY'
import json
import re
import sys
from pathlib import Path

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"),
    re.compile(r"(?i)(AO2_CP_API_TOKEN\s*=)[^\s\"']+"),
    re.compile(r"(?i)(OPENAI_API_KEY\s*=)[^\s\"']+"),
    re.compile(r"(?i)(ANTHROPIC_API_KEY\s*=)[^\s\"']+"),
]

def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(r"\1<redacted>", redacted)
    return redacted

def tail_text(path: str, lines: int = 40) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    return redact("\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]))

statuses = {"macos": sys.argv[5], "ubuntu": sys.argv[6], "windows": sys.argv[7]}
logs = {"macos": sys.argv[8], "ubuntu": sys.argv[9], "windows": sys.argv[10]}
failure_excerpts = {
    name: {"log": logs[name], "tail_text": tail_text(logs[name])}
    for name, status in statuses.items()
    if status != "passed"
}
summary = {
    "schema": "ao2-control-plane.three-os-release-smoke.v1",
    "version": sys.argv[12],
    "release_candidate_version": sys.argv[13],
    "source_commit": sys.argv[3],
    "source_dirty": sys.argv[4] == "true",
    "status": "passed" if all(value == "passed" for value in statuses.values()) else "failed",
    "trust_boundary": {
        "role": "read_only_observer",
        "mutates_ao_artifacts": False,
        "release_approval_owner": "factory-v3 evaluator-closer",
        "local_credentials": "OAuth/CLI/local AO2_CP_API_TOKEN only; no provider API-key authentication",
    },
    "targets": {
        "macos": {
            "status": statuses["macos"],
            "log": logs["macos"],
            "execution": "local",
            "candidate_correlation_status": sys.argv[18],
            "candidate_correlation_content_hash": sys.argv[22],
            "source_commit_at_target": sys.argv[46],
            "surface_content_hashes": {
                "release_cockpit": sys.argv[22],
                "release_handoff": sys.argv[26],
                "release_readiness": sys.argv[30],
                "release_publication_dashboard": sys.argv[34],
                "release_assembly": sys.argv[38],
                "release_assembly_blockers": sys.argv[42],
            },
        },
        "ubuntu": {
            "status": statuses["ubuntu"],
            "log": logs["ubuntu"],
            "ssh_target": sys.argv[14],
            "candidate_correlation_status": sys.argv[19],
            "candidate_correlation_content_hash": sys.argv[23],
            "source_commit_at_target": sys.argv[47],
            "surface_content_hashes": {
                "release_cockpit": sys.argv[23],
                "release_handoff": sys.argv[27],
                "release_readiness": sys.argv[31],
                "release_publication_dashboard": sys.argv[35],
                "release_assembly": sys.argv[39],
                "release_assembly_blockers": sys.argv[43],
            },
        },
        "windows": {
            "status": statuses["windows"],
            "log": logs["windows"],
            "ssh_target": sys.argv[15],
            "candidate_correlation_status": sys.argv[20],
            "candidate_correlation_content_hash": sys.argv[24],
            "source_commit_at_target": sys.argv[48],
            "surface_content_hashes": {
                "release_cockpit": sys.argv[24],
                "release_handoff": sys.argv[28],
                "release_readiness": sys.argv[32],
                "release_publication_dashboard": sys.argv[36],
                "release_assembly": sys.argv[40],
                "release_assembly_blockers": sys.argv[44],
            },
        },
    },
    "candidate_correlation_parity": sys.argv[21],
    "candidate_correlation_content_hash_parity": sys.argv[25],
    "surface_content_hash_parity": {
        "release_cockpit": sys.argv[25],
        "release_handoff": sys.argv[29],
        "release_readiness": sys.argv[33],
        "release_publication_dashboard": sys.argv[37],
        "release_assembly": sys.argv[41],
        "release_assembly_blockers": sys.argv[45],
    },
    "source_commit_per_target": {
        "macos": sys.argv[46],
        "ubuntu": sys.argv[47],
        "windows": sys.argv[48],
    },
    "source_commit_per_target_drift": sys.argv[49] == "true",
    "source_commit_per_target_drift_status": sys.argv[49],
    "failure_excerpts": failure_excerpts,
    "rerun_commands": {
        "all_required": "AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh",
        "macos_only": "AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh",
        "ubuntu_optional": "AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh",
        "windows_optional": "AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh",
    },
    "remote_command_files": {
        "ubuntu": sys.argv[16],
        "windows": sys.argv[17],
    },
    "report": sys.argv[2],
    "root": sys.argv[11],
}
Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
Path(sys.argv[1]).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_macos() {
  (
    set -e;
    {
    echo "macos_release_smoke=starting"
    cargo build --release -p ao2-cp-server
    bash scripts/package-local.sh \
      --out-dir dist \
      --version "$AO2_CP_VERSION" \
      --binary target/release/ao2-cp-server \
      --target-label macos-aarch64
    AO2_CP_ARCHIVE="dist/ao2-control-plane-$AO2_CP_VERSION-macos-aarch64.tar.gz" \
    AO2_CP_SMOKE_ROOT="$AO2_CP_THREE_OS_SMOKE_ROOT/macos-smoke" \
    AO2_CP_SMOKE_JSON="$AO2_CP_THREE_OS_SMOKE_ROOT/macos-release-smoke.json" \
      bash scripts/smoke-release-archive.sh
    echo "macos_release_smoke=passed"
    } >"$mac_log" 2>&1
  )
}

run_ubuntu() {
  (
    set -e;
    {
    echo "ubuntu_release_smoke=starting"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$AO2_CP_UBUNTU_SSH_TARGET" \
      "rm -rf '$AO2_CP_REMOTE_LINUX_ROOT/run' && mkdir -p '$AO2_CP_REMOTE_LINUX_ROOT/run'"
    scp -o BatchMode=yes -o ConnectTimeout=10 "$source_tgz" \
      "$AO2_CP_UBUNTU_SSH_TARGET:$AO2_CP_REMOTE_LINUX_ROOT/source.tgz"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$AO2_CP_UBUNTU_SSH_TARGET" \
      "set -euo pipefail; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd '$AO2_CP_REMOTE_LINUX_ROOT/run'; tar -xzf ../source.tgz; cargo build --release -p ao2-cp-server; bash scripts/package-local.sh --out-dir dist --version '$AO2_CP_VERSION' --binary target/release/ao2-cp-server --target-label linux-x86_64; AO2_CP_ARCHIVE='dist/ao2-control-plane-$AO2_CP_VERSION-linux-x86_64.tar.gz' AO2_CP_SMOKE_ROOT='$AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-smoke' AO2_CP_SMOKE_JSON='$AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-release-smoke.json' bash scripts/smoke-release-archive.sh"
    echo "ubuntu_release_smoke=passed"
    } >"$ubuntu_log" 2>&1
  )
}

run_windows() {
  (
    set -e;
    {
    echo "windows_release_smoke=starting"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$AO2_CP_WINDOWS_SSH_TARGET" \
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force -Path '$AO2_CP_REMOTE_WINDOWS_ROOT' | Out-Null; if (Test-Path '$AO2_CP_REMOTE_WINDOWS_ROOT/run') { Remove-Item -Recurse -Force '$AO2_CP_REMOTE_WINDOWS_ROOT/run' }\""
    scp -o BatchMode=yes -o ConnectTimeout=10 "$source_tgz" \
      "$AO2_CP_WINDOWS_SSH_TARGET:$AO2_CP_REMOTE_WINDOWS_ROOT/source.tgz"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$AO2_CP_WINDOWS_SSH_TARGET" \
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue; Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force -Path '$AO2_CP_REMOTE_WINDOWS_ROOT/run' | Out-Null; Set-Location -LiteralPath '$AO2_CP_REMOTE_WINDOWS_ROOT/run'; tar -xzf ../source.tgz; cargo build --release -p ao2-cp-server; & 'C:/Program Files/Git/bin/bash.exe' scripts/package-local.sh --out-dir dist --version '$AO2_CP_VERSION' --binary target/release/ao2-cp-server.exe --target-label windows-x86_64; \$env:AO2_CP_ARCHIVE='dist/ao2-control-plane-$AO2_CP_VERSION-windows-x86_64.tar.gz'; \$env:AO2_CP_SMOKE_ROOT='$AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-smoke'; \$env:AO2_CP_SMOKE_JSON='$AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-release-smoke.json'; ./scripts/smoke-release-archive.ps1\""
    echo "windows_release_smoke=passed"
    } >"$windows_log" 2>&1
  )
}

extract_correlation_status() {
  local log_path="$1"
  if [[ ! -f "$log_path" ]]; then
    printf "unknown"
    return
  fi
  local value
  # Windows PowerShell emits CRLF; strip trailing \r so the cross-OS
  # parity check sees "mismatched" == "mismatched" instead of treating
  # "mismatched\r" as a third distinct value (Lane CRLF-1).
  value="$(grep -E '^candidate_correlation_status=' "$log_path" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true)"
  if [[ -z "$value" ]]; then
    printf "unknown"
  else
    printf "%s" "$value"
  fi
}

# Lane OO: aggregator-side extraction of per-target source_commit_at_target.
# The per-target bash and PowerShell scripts emit the value as a trailer
# line after the smoke completes (read from the .source-commit record the
# orchestrator embedded into the source.tgz). Aggregating these values
# back to the top-level summary lets future server-side validation assert
# top-level == every per-target, catching orchestrator HEAD drift between
# packaging and the per-target run.
extract_source_commit_at_target() {
  local log_path="$1"
  if [[ ! -f "$log_path" ]]; then
    printf "unknown"
    return
  fi
  local value
  # Strip trailing \r emitted by Windows PowerShell so the per-target
  # source_commit_per_target_drift check compares "<sha>" == "<sha>"
  # instead of seeing "<sha>\r" as a divergent commit (Lane CRLF-2).
  value="$(grep -E '^source_commit_at_target=' "$log_path" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true)"
  if [[ -z "$value" ]]; then
    printf "unknown"
  else
    printf "%s" "$value"
  fi
}

# Lane V: byte-identity content-hash parity across the three per-OS
# smokes. Today each per-OS smoke verifies its own release-cockpit.json
# locally; the aggregator never compares the three downloaded
# cockpits. A full-content drift inside `.candidate_correlation`
# (status, blockers array, anything else under that subtree) would
# slip past Lane P's status-only parity gate. Lane V fetches the
# per-OS cockpit back to the orchestrator, extracts the
# `.candidate_correlation` subtree, normalizes via jq -S (deterministic
# key ordering), and sha256s the result. Any cross-OS hash drift fires
# the aggregator independently of the status-level parity gate.
fetch_macos_artifact() {
  local relative_path="$1"
  local dest_dir="$2"
  local src="$AO2_CP_THREE_OS_SMOKE_ROOT/macos-smoke/$relative_path"
  if [[ ! -f "$src" ]]; then
    return 1
  fi
  mkdir -p "$dest_dir"
  cp "$src" "$dest_dir/$relative_path"
}

fetch_ubuntu_artifact() {
  local relative_path="$1"
  local dest_dir="$2"
  if [[ "$status_ubuntu" != "passed" ]]; then
    return 1
  fi
  mkdir -p "$dest_dir"
  scp -o BatchMode=yes -o ConnectTimeout=10 \
    "$AO2_CP_UBUNTU_SSH_TARGET:$AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-smoke/$relative_path" \
    "$dest_dir/$relative_path" >/dev/null 2>&1
}

fetch_windows_artifact() {
  local relative_path="$1"
  local dest_dir="$2"
  if [[ "$status_windows" != "passed" ]]; then
    return 1
  fi
  mkdir -p "$dest_dir"
  scp -o BatchMode=yes -o ConnectTimeout=10 \
    "$AO2_CP_WINDOWS_SSH_TARGET:$AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-smoke/$relative_path" \
    "$dest_dir/$relative_path" >/dev/null 2>&1
}

compute_correlation_content_hash() {
  compute_artifact_subtree_hash "$1" '.candidate_correlation // {}'
}

# Lane Z: generic content-hash helper used to extend the byte-identity
# audit beyond release-cockpit.json. Takes an artifact path and a jq
# filter, returns sha256 of the normalized subtree (or "missing" /
# "unknown" on graceful failure).
compute_artifact_subtree_hash() {
  local artifact_path="$1"
  local jq_filter="$2"
  if [[ ! -f "$artifact_path" ]]; then
    printf "missing"
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf "unknown"
    return
  fi
  local normalized
  normalized="$(jq -cS "$jq_filter" "$artifact_path" 2>/dev/null || true)"
  if [[ -z "$normalized" || "$normalized" == "null" || "$normalized" == "{}" ]]; then
    printf "missing"
    return
  fi
  local hash
  if command -v sha256sum >/dev/null 2>&1; then
    hash="$(printf "%s" "$normalized" | sha256sum | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    hash="$(printf "%s" "$normalized" | shasum -a 256 | awk '{print $1}')"
  else
    printf "unknown"
    return
  fi
  printf "%s" "$hash"
}

# Lane Z: parity across three per-OS hashes for a single surface.
# Same algorithm as compute_content_hash_parity but parameterized so
# we don't repeat per-surface bookkeeping.
compute_surface_hash_parity() {
  local hash_macos="$1"
  local hash_ubuntu="$2"
  local hash_windows="$3"
  local observed=()
  if [[ "$status_macos" == "passed" && "$hash_macos" != "missing" && "$hash_macos" != "unknown" ]]; then
    observed+=("$hash_macos")
  fi
  if [[ "$status_ubuntu" == "passed" && "$hash_ubuntu" != "missing" && "$hash_ubuntu" != "unknown" ]]; then
    observed+=("$hash_ubuntu")
  fi
  if [[ "$status_windows" == "passed" && "$hash_windows" != "missing" && "$hash_windows" != "unknown" ]]; then
    observed+=("$hash_windows")
  fi
  if [[ ${#observed[@]} -eq 0 ]]; then
    printf "unknown"
    return
  fi
  local reference="${observed[0]}"
  for value in "${observed[@]}"; do
    if [[ "$value" != "$reference" ]]; then
      printf "drift"
      return
    fi
  done
  printf "matched"
}

compute_content_hash_parity() {
  local observed=()
  if [[ "$status_macos" == "passed" && "$correlation_content_hash_macos" != "missing" && "$correlation_content_hash_macos" != "unknown" ]]; then
    observed+=("$correlation_content_hash_macos")
  fi
  if [[ "$status_ubuntu" == "passed" && "$correlation_content_hash_ubuntu" != "missing" && "$correlation_content_hash_ubuntu" != "unknown" ]]; then
    observed+=("$correlation_content_hash_ubuntu")
  fi
  if [[ "$status_windows" == "passed" && "$correlation_content_hash_windows" != "missing" && "$correlation_content_hash_windows" != "unknown" ]]; then
    observed+=("$correlation_content_hash_windows")
  fi
  if [[ ${#observed[@]} -eq 0 ]]; then
    printf "unknown"
    return
  fi
  local reference="${observed[0]}"
  for value in "${observed[@]}"; do
    if [[ "$value" != "$reference" ]]; then
      printf "drift"
      return
    fi
  done
  printf "matched"
}

if run_macos; then
  status_macos="passed"
fi
correlation_macos="$(extract_correlation_status "$mac_log")"
source_commit_at_target_macos="$(extract_source_commit_at_target "$mac_log")"

if run_ubuntu; then
  status_ubuntu="passed"
elif [[ "$AO2_CP_REQUIRE_UBUNTU" != "1" ]]; then
  status_ubuntu="skipped"
fi
correlation_ubuntu="$(extract_correlation_status "$ubuntu_log")"
source_commit_at_target_ubuntu="$(extract_source_commit_at_target "$ubuntu_log")"

if run_windows; then
  status_windows="passed"
elif [[ "$AO2_CP_REQUIRE_WINDOWS" != "1" ]]; then
  status_windows="skipped"
fi
correlation_windows="$(extract_correlation_status "$windows_log")"
source_commit_at_target_windows="$(extract_source_commit_at_target "$windows_log")"

compute_parity() {
  local observed=()
  if [[ "$status_macos" == "passed" ]]; then observed+=("$correlation_macos"); fi
  if [[ "$status_ubuntu" == "passed" ]]; then observed+=("$correlation_ubuntu"); fi
  if [[ "$status_windows" == "passed" ]]; then observed+=("$correlation_windows"); fi
  if [[ ${#observed[@]} -eq 0 ]]; then
    printf "unknown"
    return
  fi
  local reference="${observed[0]}"
  for value in "${observed[@]}"; do
    if [[ "$value" != "$reference" ]]; then
      printf "drift"
      return
    fi
  done
  printf "%s" "$reference"
}
candidate_correlation_parity="$(compute_parity)"

# Lane OO: source_commit_per_target_drift returns "true" when any
# per-target source_commit_at_target differs from the orchestrator's
# top-level source_commit (or from each other), "false" when every
# observed target agrees with the top-level, and "unknown" when no
# target ran successfully or no target emitted the field. A "true"
# verdict signals orchestrator HEAD drift between packaging and the
# per-target run — the future server-side ingestion validator (Lane
# PP-server) is expected to reject the bundle on this signal.
compute_source_commit_drift() {
  local observed=()
  if [[ "$status_macos" == "passed" && "$source_commit_at_target_macos" != "unknown" ]]; then
    observed+=("$source_commit_at_target_macos")
  fi
  if [[ "$status_ubuntu" == "passed" && "$source_commit_at_target_ubuntu" != "unknown" ]]; then
    observed+=("$source_commit_at_target_ubuntu")
  fi
  if [[ "$status_windows" == "passed" && "$source_commit_at_target_windows" != "unknown" ]]; then
    observed+=("$source_commit_at_target_windows")
  fi
  if [[ ${#observed[@]} -eq 0 ]]; then
    printf "unknown"
    return
  fi
  for value in "${observed[@]}"; do
    if [[ "$value" != "$source_commit" ]]; then
      printf "true"
      return
    fi
  done
  printf "false"
}
source_commit_per_target_drift="$(compute_source_commit_drift)"

# Lane V: fetch the per-OS release-cockpit.json back to the orchestrator
# and compute a content-hash parity across the three downloaded cockpits.
# The fetched files live under <smoke-root>/fetched-<os>/release-cockpit.json
# so an operator triaging drift can run `jq -cS .candidate_correlation`
# against each one and diff by hand.
fetched_macos_dir="$AO2_CP_THREE_OS_SMOKE_ROOT/fetched-macos"
fetched_ubuntu_dir="$AO2_CP_THREE_OS_SMOKE_ROOT/fetched-ubuntu"
fetched_windows_dir="$AO2_CP_THREE_OS_SMOKE_ROOT/fetched-windows"

if fetch_macos_artifact "release-cockpit.json" "$fetched_macos_dir"; then
  correlation_content_hash_macos="$(compute_correlation_content_hash "$fetched_macos_dir/release-cockpit.json")"
fi
if fetch_ubuntu_artifact "release-cockpit.json" "$fetched_ubuntu_dir"; then
  correlation_content_hash_ubuntu="$(compute_correlation_content_hash "$fetched_ubuntu_dir/release-cockpit.json")"
fi
if fetch_windows_artifact "release-cockpit.json" "$fetched_windows_dir"; then
  correlation_content_hash_windows="$(compute_correlation_content_hash "$fetched_windows_dir/release-cockpit.json")"
fi

candidate_correlation_content_hash_parity="$(compute_content_hash_parity)"

# Lane Z: extend the byte-identity audit to the four additional
# release-publication-shaped surfaces (handoff, readiness, publication
# dashboard, support bundle's release_assembly). Each surface gets a
# per-OS hash and a cross-OS parity verdict so an operator can
# pinpoint which surface drifted across the three platforms.
for surface_spec in \
  "release-handoff.json:.candidate_correlation // {}:handoff" \
  "release-readiness.json:.candidate_correlation // {}:readiness" \
  "release-publication-dashboard.json:.candidate_correlation // {}:publication_dashboard" \
  "release-support-bundle.json:.release_assembly.candidate_correlation_detail // {}:assembly" \
  "release-support-bundle.json:.release_assembly.assembly_blockers // []:assembly_blockers"; do
  IFS=':' read -r surface_file surface_filter surface_var <<<"$surface_spec"
  for os in macos ubuntu windows; do
    case "$os" in
      macos) dest="$fetched_macos_dir";;
      ubuntu) dest="$fetched_ubuntu_dir";;
      windows) dest="$fetched_windows_dir";;
    esac
    "fetch_${os}_artifact" "$surface_file" "$dest" || true
    var_name="${surface_var}_content_hash_${os}"
    if [[ -f "$dest/$surface_file" ]]; then
      printf -v "$var_name" "%s" "$(compute_artifact_subtree_hash "$dest/$surface_file" "$surface_filter")"
    fi
  done
done

handoff_content_hash_parity="$(compute_surface_hash_parity "$handoff_content_hash_macos" "$handoff_content_hash_ubuntu" "$handoff_content_hash_windows")"
readiness_content_hash_parity="$(compute_surface_hash_parity "$readiness_content_hash_macos" "$readiness_content_hash_ubuntu" "$readiness_content_hash_windows")"
publication_dashboard_content_hash_parity="$(compute_surface_hash_parity "$publication_dashboard_content_hash_macos" "$publication_dashboard_content_hash_ubuntu" "$publication_dashboard_content_hash_windows")"
assembly_content_hash_parity="$(compute_surface_hash_parity "$assembly_content_hash_macos" "$assembly_content_hash_ubuntu" "$assembly_content_hash_windows")"
assembly_blockers_content_hash_parity="$(compute_surface_hash_parity "$assembly_blockers_content_hash_macos" "$assembly_blockers_content_hash_ubuntu" "$assembly_blockers_content_hash_windows")"

write_json

{
  echo "# AO2 Control Plane Three-OS Release Smoke"
  echo
  echo "- source_commit: \`$source_commit\`"
  echo "- source_dirty: \`$source_dirty\`"
  echo "- summary: \`$AO2_CP_THREE_OS_SMOKE_JSON\`"
  echo
  echo "## Results"
  echo
  echo "- macos: \`$status_macos\` (candidate_correlation: \`$correlation_macos\`, content_hash: \`$correlation_content_hash_macos\`, source_commit_at_target: \`$source_commit_at_target_macos\`)"
  echo "- ubuntu: \`$status_ubuntu\` (candidate_correlation: \`$correlation_ubuntu\`, content_hash: \`$correlation_content_hash_ubuntu\`, source_commit_at_target: \`$source_commit_at_target_ubuntu\`)"
  echo "- windows: \`$status_windows\` (candidate_correlation: \`$correlation_windows\`, content_hash: \`$correlation_content_hash_windows\`, source_commit_at_target: \`$source_commit_at_target_windows\`)"
  echo "- candidate_correlation_parity: \`$candidate_correlation_parity\`"
  echo "- candidate_correlation_content_hash_parity: \`$candidate_correlation_content_hash_parity\`"
  echo "- source_commit_per_target_drift: \`$source_commit_per_target_drift\`"
  echo "- surface_content_hash_parity:"
  echo "  - release_cockpit: \`$candidate_correlation_content_hash_parity\`"
  echo "  - release_handoff: \`$handoff_content_hash_parity\`"
  echo "  - release_readiness: \`$readiness_content_hash_parity\`"
  echo "  - release_publication_dashboard: \`$publication_dashboard_content_hash_parity\`"
  echo "  - release_assembly: \`$assembly_content_hash_parity\`"
  echo "  - release_assembly_blockers: \`$assembly_blockers_content_hash_parity\`"
  echo
  echo "## Logs"
  echo
  echo "- macos: \`$mac_log\`"
  echo "- ubuntu: \`$ubuntu_log\`"
  echo "- windows: \`$windows_log\`"
  echo
  echo "## Remote command files"
  echo
  echo "- ubuntu: \`$ubuntu_command_file\`"
  echo "- windows: \`$windows_command_file\`"
  echo
  echo "## Trust boundary"
  echo
  echo "- role: \`read_only_observer\`"
  echo "- mutates_ao_artifacts: \`false\`"
  echo "- release_approval_owner: \`factory-v3 evaluator-closer\`"
  echo
  echo "## Rerun commands"
  echo
  echo "- all required: \`AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh\`"
  echo "- macOS only: \`AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh\`"
  echo "- Ubuntu optional: \`AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh\`"
  echo "- Windows optional: \`AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh\`"
  if [[ "$status_macos" != "passed" || "$status_ubuntu" != "passed" || "$status_windows" != "passed" ]]; then
    echo
    echo "## Failure excerpts"
    for entry in "macos:$status_macos:$mac_log" "ubuntu:$status_ubuntu:$ubuntu_log" "windows:$status_windows:$windows_log"; do
      IFS=: read -r os status log_path <<<"$entry"
      if [[ "$status" != "passed" && -f "$log_path" ]]; then
        echo
        echo "### $os"
        echo
        echo '```text'
        tail -n 40 "$log_path" \
          | python3 -c 'import re,sys; text=sys.stdin.read();
for pat in [r"(?i)(authorization\\s*[:=]\\s*bearer\\s+)[^\\s\\\"'"'"']+", r"(?i)(AO2_CP_API_TOKEN\\s*=)[^\\s\\\"'"'"']+", r"(?i)(OPENAI_API_KEY\\s*=)[^\\s\\\"'"'"']+", r"(?i)(ANTHROPIC_API_KEY\\s*=)[^\\s\\\"'"'"']+"]:
    text=re.sub(pat, r"\\1<redacted>", text)
sys.stdout.write(text)'
        echo '```'
      fi
    done
  fi
} >"$report_md"

cat "$AO2_CP_THREE_OS_SMOKE_JSON"

if [[ "$status_macos" != "passed" ]]; then
  exit 1
fi
if [[ "$AO2_CP_REQUIRE_UBUNTU" = "1" && "$status_ubuntu" != "passed" ]]; then
  exit 1
fi
if [[ "$AO2_CP_REQUIRE_WINDOWS" = "1" && "$status_windows" != "passed" ]]; then
  exit 1
fi
if [[ "$candidate_correlation_parity" == "drift" || "$candidate_correlation_parity" == "unknown" ]]; then
  echo "candidate_correlation_parity=$candidate_correlation_parity (macos=$correlation_macos ubuntu=$correlation_ubuntu windows=$correlation_windows)" >&2
  exit 1
fi
if [[ "$candidate_correlation_content_hash_parity" == "drift" ]]; then
  echo "candidate_correlation_content_hash_parity=drift (macos=$correlation_content_hash_macos ubuntu=$correlation_content_hash_ubuntu windows=$correlation_content_hash_windows)" >&2
  exit 1
fi
# Lane Z: per-surface drift fires the smoke even when the cockpit
# hash agrees, so an operator sees the dissenting surface immediately.
if [[ "$handoff_content_hash_parity" == "drift" ]]; then
  echo "release_handoff_content_hash_parity=drift (macos=$handoff_content_hash_macos ubuntu=$handoff_content_hash_ubuntu windows=$handoff_content_hash_windows)" >&2
  exit 1
fi
if [[ "$readiness_content_hash_parity" == "drift" ]]; then
  echo "release_readiness_content_hash_parity=drift (macos=$readiness_content_hash_macos ubuntu=$readiness_content_hash_ubuntu windows=$readiness_content_hash_windows)" >&2
  exit 1
fi
if [[ "$publication_dashboard_content_hash_parity" == "drift" ]]; then
  echo "release_publication_dashboard_content_hash_parity=drift (macos=$publication_dashboard_content_hash_macos ubuntu=$publication_dashboard_content_hash_ubuntu windows=$publication_dashboard_content_hash_windows)" >&2
  exit 1
fi
if [[ "$assembly_content_hash_parity" == "drift" ]]; then
  echo "release_assembly_content_hash_parity=drift (macos=$assembly_content_hash_macos ubuntu=$assembly_content_hash_ubuntu windows=$assembly_content_hash_windows)" >&2
  exit 1
fi
# Lane BB: gate-state drift on .release_assembly.assembly_blockers
# exits the smoke even when candidate_correlation matches across OSes.
# Two control planes can produce the same correlation status from
# orthogonal underlying state (e.g., one OS observes provider acceptance
# as live_complete, another as scripted_only) and still report
# correlation matched — the blockers array would diverge, and this
# gate exposes the divergence.
if [[ "$assembly_blockers_content_hash_parity" == "drift" ]]; then
  echo "release_assembly_blockers_content_hash_parity=drift (macos=$assembly_blockers_content_hash_macos ubuntu=$assembly_blockers_content_hash_ubuntu windows=$assembly_blockers_content_hash_windows)" >&2
  exit 1
fi
