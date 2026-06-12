#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "public export check failed: $*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "missing required file: $1"
}

reject_path() {
  if find . -path "$1" -print -quit | grep -q .; then
    fail "forbidden generated/private path present: $1"
  fi
}

require_file README.md
require_file LICENSE
require_file LICENSE-MIT
require_file LICENSE-APACHE
require_file docs/SECURITY.md
require_file docs/DEPLOYMENT.md
require_file public-export-manifest.json

reject_path "./target"
reject_path "./dist"
reject_path "./docs/status"

if git ls-files | grep -E '(^|/)[.]DS_Store$' >/dev/null; then
  fail "tracked .DS_Store present"
fi

scan_files="$(mktemp)"
find . -type f \
  -not -path "./.git/*" \
  -not -path "./target/*" \
  -not -path "./dist/*" \
  -not -path "./docs/status/*" \
  -not -path "./scripts/check-public-export.sh" \
  -print > "$scan_files"

secret_matches="$(grep -aEn -- '-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|(OPENAI_API_KEY|ANTHROPIC_API_KEY)[[:space:]]*=[[:space:]]*(sk|anthropic)-[A-Za-z0-9._=-]{20,}|Authorization:[[:space:]]*Bearer[[:space:]]+(ghp_[A-Za-z0-9_]{20,}|[A-Za-z0-9._=-]{32,})' $(cat "$scan_files") || true)"
if printf '%s\n' "$secret_matches" | grep -avE 'canary|secret|preview|test|should|redact|example|contains|assert|BEGIN PRIVATE KEY' | grep -q .; then
  printf '%s\n' "$secret_matches" >&2
  fail "real-looking private key, bearer token, or provider-key value found"
fi

if grep -aEn '/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+|C:\\\\Users\\\\[A-Za-z0-9._-]+|github[.]com/[^[:space:]]+/ao2[^[:space:]]*[-]private|ao2[^[:space:]]*[-]private' $(cat "$scan_files"); then
  fail "private path or private repo reference found"
fi

if grep -aEn 'ao2-control-plane-0\.1\.(0|1|2|3|4|5|6|7|8|9|10|11|12)-|v0\.1\.(0|1|2|3|4|5|6|7|8|9|10|11|12)\b' README.md .github/workflows/ci.yml scripts/package-local.sh; then
  fail "stale control-plane release artifact reference found"
fi

if ! grep -q 'version = "0.1.13"' Cargo.toml; then
  fail "Cargo.toml does not advertise ao2-control-plane version 0.1.13"
fi

rm -f "$scan_files"
echo "public export check passed: ao2-control-plane"
