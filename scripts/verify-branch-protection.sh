#!/usr/bin/env bash
set -euo pipefail

REPO="uesugitorachiyo/ao2-control-plane"
BRANCH="main"
REQUIRED_CHECKS=(
  "Cargo audit"
  "Cargo deny (bans + licenses + sources)"
  "Ingest smoke (macos-aarch64)"
  "Ingest smoke (ubuntu-x86_64)"
  "Ingest smoke (windows-x86_64)"
  "Lint (fmt + clippy)"
  "Release archive smoke (macos-aarch64)"
  "Release archive smoke (ubuntu-x86_64)"
  "Release archive smoke (windows-x86_64)"
  "Test (macos-latest)"
  "Test (ubuntu-latest)"
  "Test (windows-latest)"
)

usage() {
  cat <<'EOF'
usage: scripts/verify-branch-protection.sh [--repo <owner/name>] [--branch <branch>]

Verifies that the live GitHub branch protection and active branch rulesets
require only the current ao2-control-plane CI, ingest smoke, release archive
smoke, supply-chain, and lint checks. This script is read-only.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:?missing --repo value}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:?missing --branch value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    exit 2
  fi
}

require_tool gh
require_tool jq

# Emits mode=limited when the token can read branch metadata but cannot read
# the full branch protection endpoint.
mode="full"
if protection="$(gh api "repos/$REPO/branches/$BRANCH/protection" 2>/tmp/ao2-cp-branch-protection.err)"; then
  :
else
  mode="limited"
  protection="$(gh api "repos/$REPO/branches/$BRANCH")"
fi

check_jq() {
  local name="$1"
  local filter="$2"
  if ! printf '%s' "$protection" | jq -e "$filter" >/dev/null; then
    echo "branch_protection=failed check=$name" >&2
    printf '%s\n' "$protection" | jq . >&2
    exit 1
  fi
}

if [[ "$mode" == "full" ]]; then
  rulesets="$(gh api "repos/$REPO/rulesets")"
  check_jq "required_status_checks_strict" '.required_status_checks.strict == true'
  check_jq "enforce_admins" '.enforce_admins.enabled == true'
  check_jq "required_linear_history" '.required_linear_history.enabled == true'
  check_jq "allow_force_pushes_disabled" '.allow_force_pushes.enabled == false'
  check_jq "allow_deletions_disabled" '.allow_deletions.enabled == false'
  actual_checks="$(printf '%s' "$protection" | jq -r '.required_status_checks.contexts[]?' | sort)"
else
  check_jq "branch_protected" '.protected == true'
  check_jq "required_status_checks_enforced" '.protection.required_status_checks.enforcement_level == "everyone"'
  actual_checks="$(printf '%s' "$protection" | jq -r '.protection.required_status_checks.contexts[]?' | sort)"
fi

expected_checks="$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | sort)"
if [[ "$actual_checks" != "$expected_checks" ]]; then
  echo "branch_protection=failed check=required_status_checks" >&2
  echo "expected:" >&2
  printf '%s\n' "$expected_checks" >&2
  echo "actual:" >&2
  printf '%s\n' "$actual_checks" >&2
  exit 1
fi

if [[ "$mode" == "full" ]]; then
  ruleset_errors="$(RULESETS_JSON="$rulesets" python3 - "$BRANCH" "${REQUIRED_CHECKS[@]}" <<'PY'
import json
import os
import sys

branch = sys.argv[1]
allowed_contexts = set(sys.argv[2:])
rulesets = json.loads(os.environ["RULESETS_JSON"])
errors = []

for ruleset in rulesets:
    if ruleset.get("enforcement") != "active" or ruleset.get("target") != "branch":
        continue
    conditions = ruleset.get("conditions") or {}
    ref_name = conditions.get("ref_name") or {}
    includes = ref_name.get("include") or []
    excludes = ref_name.get("exclude") or []
    branch_refs = {branch, f"refs/heads/{branch}", "~DEFAULT_BRANCH"}
    if includes and not any(include in branch_refs for include in includes):
        continue
    if branch in excludes or f"refs/heads/{branch}" in excludes:
        continue
    for rule in ruleset.get("rules") or []:
        if rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters") or {}
        for check in parameters.get("required_status_checks") or []:
            context = check.get("context")
            if context and context not in allowed_contexts:
                errors.append(
                    f"{ruleset.get('name', '<unnamed>')}: unexpected required status check {context}"
                )

if errors:
    print("\n".join(errors))
PY
)"
  if [[ -n "$ruleset_errors" ]]; then
    echo "branch_protection=failed check=ruleset_status_checks_current" >&2
    printf '%s\n' "$ruleset_errors" >&2
    exit 1
  fi
fi

echo "branch_protection=passed"
echo "mode=$mode"
echo "repo=$REPO"
echo "branch=$BRANCH"
if [[ "$mode" == "full" ]]; then
  echo "rulesets_checked=true"
  echo "rulesets_count=$(printf '%s' "$rulesets" | jq 'length')"
else
  echo "rulesets_checked=false"
fi
printf 'required_check=%s\n' "${REQUIRED_CHECKS[@]}"
