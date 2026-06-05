#!/usr/bin/env bash
set -euo pipefail

# End-to-end smoke for ao2-cp-server. Acceptance bar for v0.1.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TOKEN="smoke-$(uuidgen | tr -d - | head -c 32)"
PORT=18744
DATA_DIR=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$DATA_DIR"' EXIT

echo "=== build ==="
cargo build --release -p ao2-cp-server

echo "=== start server ==="
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  AO2_CP_API_TOKEN="$TOKEN" \
  AO2_CP_BIND="127.0.0.1:$PORT" \
  AO2_CP_DATA_DIR="$DATA_DIR" \
  ./target/release/ao2-cp-server &
SERVER_PID=$!

echo "=== wait for healthz ==="
for i in {1..30}; do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" > /dev/null 2>&1; then
    echo "  ready"
    break
  fi
  sleep 0.2
done

CODEX_FIXTURE="$ROOT/tests/fixtures/codex-acceptance-v0.4.66.json"
CLAUDE_FIXTURE="$ROOT/tests/fixtures/claude-acceptance-v0.4.66.json"
BUNDLE_FIXTURE="$ROOT/tests/fixtures/control-plane-bundle-sample.json"
BAD_FIXTURE="$ROOT/tests/fixtures/bad-schema-version.json"

post() {
  local path="$1"; local body="$2"
  curl -fsS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$body" \
    "http://127.0.0.1:$PORT$path"
}

get() {
  curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT$1"
}

post_expect_fail() {
  local path="$1"; local body="$2"; local expected_status="$3"
  local actual
  actual=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$body" \
    "http://127.0.0.1:$PORT$path")
  if [[ "$actual" != "$expected_status" ]]; then
    echo "  expected $expected_status, got $actual"
    return 1
  fi
}

echo "=== POST codex acceptance ==="
CODEX_RECEIPT=$(post /api/v1/acceptance "$CODEX_FIXTURE")
CODEX_SHA=$(echo "$CODEX_RECEIPT" | jq -r .sha256)
echo "  sha=$CODEX_SHA"

echo "=== POST claude acceptance ==="
CLAUDE_RECEIPT=$(post /api/v1/acceptance "$CLAUDE_FIXTURE")
CLAUDE_SHA=$(echo "$CLAUDE_RECEIPT" | jq -r .sha256)
echo "  sha=$CLAUDE_SHA"

echo "=== POST control-plane bundle ==="
BUNDLE_RECEIPT=$(post /api/v1/control-plane/bundle "$BUNDLE_FIXTURE")
BUNDLE_SHA=$(echo "$BUNDLE_RECEIPT" | jq -r .sha256)
echo "  sha=$BUNDLE_SHA"

echo "=== GET /api/v1/acceptance — expect 2 entries ==="
COUNT=$(get /api/v1/acceptance | jq -r .total_count)
if [[ "$COUNT" != "2" ]]; then
  echo "  expected 2, got $COUNT"
  exit 1
fi

echo "=== GET /api/v1/acceptance/<sha> — byte-identical ==="
FETCHED=$(mktemp)
get "/api/v1/acceptance/$CODEX_SHA" > "$FETCHED"
diff "$CODEX_FIXTURE" "$FETCHED"
rm "$FETCHED"

echo "=== POST same codex again — idempotent ==="
CODEX_RECEIPT2=$(post /api/v1/acceptance "$CODEX_FIXTURE")
CODEX_SHA2=$(echo "$CODEX_RECEIPT2" | jq -r .sha256)
if [[ "$CODEX_SHA" != "$CODEX_SHA2" ]]; then
  echo "  sha changed across idempotent posts"
  exit 1
fi
COUNT_AFTER_REPOST=$(get /api/v1/acceptance | jq -r .total_count)
if [[ "$COUNT_AFTER_REPOST" != "2" ]]; then
  echo "  count changed: $COUNT_AFTER_REPOST"
  exit 1
fi

echo "=== POST bad-schema-version — expect 422 ==="
post_expect_fail /api/v1/acceptance "$BAD_FIXTURE" 422

echo "=== tamper test — modify stored bundle, GET should fail ==="
STORED_FILE="$DATA_DIR/acceptance/codex/$CODEX_SHA.json"
echo "{\"tampered\":true}" > "$STORED_FILE"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$PORT/api/v1/acceptance/$CODEX_SHA")
if [[ "$HTTP_CODE" != "500" ]]; then
  echo "  expected 500 on tamper, got $HTTP_CODE"
  exit 1
fi

echo "=== shutdown ==="
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "=== smoke OK ==="
