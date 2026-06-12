# Runbook: long-lived dev ao2-cp-server

Audience: developers running the **dev long-lived** `ao2-cp-server`
on `127.0.0.1:18745` as a foreground process, separate from the
production CP at `127.0.0.1:8744`.

Trust boundary: identical to the production runbook
(`operations.md`). The dev long-lived CP is a *read-only observer*
that stores content-addressed copies of locally-published AO2
bundles. It never mutates AO artifacts, never accepts an inbound
connection from outside `127.0.0.1`, and never holds any provider
secret. OAuth-only, observer-only, single-tenant.

---

## 1. Why a separate dev long-lived CP?

The production CP (`8744`) is started via systemd / launchd / NSSM
and serves operational workloads. The dev long-lived CP (`18745`)
runs as a foreground binary out of `target/release/`, stores its
data dir under `target/long-lived-control-plane/`, and is purpose-
built for developer-side multi-day verification runs (Phase 1
dashboard fills, multi-publish parity checks, parity-oracle replays).

Keeping them separate prevents dev-side write tests from polluting
production-grade evidence storage.

---

## 2. Layout

```
/Users/<you>/Documents/ao2/target/long-lived-control-plane/
├── api-token          # 0600, 32-byte hex string
├── data/              # content-addressed AO2 bundles
│   ├── acceptance/
│   ├── index.jsonl
│   ├── phase1-promotion-checklist/
│   ├── phase1-promotion-decision/
│   ├── phase1-promotion-decision-signature/
│   ├── provider-readiness/
│   └── three-os-release-smoke/
├── logs/              # rotated by start-time (current: per-startup)
│   ├── ao2-cp-server.YYYYMMDDTHHMMSSZ.err
│   └── ao2-cp-server.YYYYMMDDTHHMMSSZ.log
├── publishes/         # per-publish snapshots
│   └── YYYYMMDDTHHMMSSZ/
└── server.pid         # foreground PID
```

The `api-token` file is `chmod 0600`. Treat it like any local
credential — do not commit, do not echo to stdout, do not pass on
the command line.

---

## 3. Start procedure

Preferred bootstrap:

```bash
cd /Users/<you>/Documents/public/ao2-control-plane
scripts/start-long-lived-dev.sh
```

The bootstrap creates `target/long-lived-control-plane/{data,logs,publishes}`,
creates or reuses the `0600` token file, starts the server on
`127.0.0.1:18745`, and prints only token-free status lines.

Fast hardening smoke:

```bash
scripts/smoke-long-lived-dev.sh
```

The smoke initializes an isolated `target/long-lived-dev-smoke/...` root with
`--once-check`, verifies the data/log/publish directories, checks the token is
`0600` 64-character hex, and emits
`ao2.cp-long-lived-dev-hardening-smoke.v1`. It does not print bearer-token
values or provider API-key environment values.

Optional live restart/readiness smoke:

```bash
AO2_CP_LONG_LIVED_SMOKE_LIVE=1 scripts/smoke-long-lived-dev.sh
```

Live mode starts the local server, checks public `/readyz`, stops it, restarts
from the same data root, checks `/readyz` again, and records
`token_reused_after_restart` in the summary. It remains local-first and writes
only token-free status and readiness artifacts under the isolated smoke root.

Manual equivalent:

```bash
cd /Users/<you>/Documents/ao2

# (1) Build the binary (one-time per source change)
cargo build --release --bin ao2-cp-server

# (2) Initialize the data dir (idempotent — skips if present)
mkdir -p target/long-lived-control-plane/{data,logs,publishes}

# (3) Generate the API token if not already present
if [ ! -f target/long-lived-control-plane/api-token ]; then
    openssl rand -hex 32 > target/long-lived-control-plane/api-token
    chmod 0600 target/long-lived-control-plane/api-token
fi

# (4) Start, foregrounded, with logs to a timestamped pair of files
ts=$(date -u +%Y%m%dT%H%M%SZ)
export AO2_CP_API_TOKEN="$(cat target/long-lived-control-plane/api-token)"
export AO2_CP_BIND="127.0.0.1:18745"
export AO2_CP_DATA_DIR="$(pwd)/target/long-lived-control-plane/data"
nohup ./target/release/ao2-cp-server \
    > "target/long-lived-control-plane/logs/ao2-cp-server.${ts}.log" \
    2> "target/long-lived-control-plane/logs/ao2-cp-server.${ts}.err" &
echo $! > target/long-lived-control-plane/server.pid
```

Liveness check:
```bash
curl -sf http://127.0.0.1:18745/healthz | jq .
# {"status":"ok","version":"0.1.13","schema_version":"ao2.cp-healthz.v1"}
```

Readiness check (token-gated):
```bash
curl -sf -H "Authorization: Bearer $(cat target/long-lived-control-plane/api-token)" \
    http://127.0.0.1:18745/readyz | jq .
```

---

## 4. Stop procedure

```bash
cd /Users/<you>/Documents/ao2
kill "$(cat target/long-lived-control-plane/server.pid)"
rm target/long-lived-control-plane/server.pid
```

Or, if PID file is stale:
```bash
pkill -f 'target/release/ao2-cp-server' || true
```

Foregrounded → no systemd / launchd / NSSM involvement. SIGTERM
exits cleanly; the process flushes its access logs and exits within
~50ms.

---

## 5. Zero-error verification

After ≥ 1h of uptime:

```bash
# Uptime check (Linux/macOS)
ps -o pid,etime,user,command -p "$(cat target/long-lived-control-plane/server.pid)"

# Error scan — must return 0 lines on a healthy CP
grep -E ' (ERROR|WARN|PANIC) ' \
    target/long-lived-control-plane/logs/ao2-cp-server.*.err \
    | grep -v ' INFO '

# Access log count
wc -l target/long-lived-control-plane/logs/ao2-cp-server.*.log
```

Healthy outcome: process uptime > 1h, zero ERROR/WARN/PANIC lines
across all .err files since the most recent start, access log
counter monotonically increasing.

If the extended healthz endpoint is deployed (post-W5 P0):
```bash
curl -sf http://127.0.0.1:18745/api/v1/healthz/extended | jq .
# {
#   "schema_version": "ao2.cp-healthz-extended.v1",
#   "uptime_seconds": 29440,
#   "started_at_utc": "...",
#   "last_error_utc": null,
#   "request_count": 38,
#   "error_request_count": 0
# }
```

The CLI ships a probe with a graceful pre-W5-P0 fallback:
```bash
ao2 cp probe-extended \
    --cp-url http://127.0.0.1:18745 \
    --api-token-env AO2_CP_API_TOKEN \
    --write-json target/long-lived-control-plane/healthz-probe.json
# probe_source=healthz_extended   # if W5 P0 endpoint is deployed
# probe_source=synthesized_from_status   # if not (pre-W5 P0 fallback)
```

For release-evidence audit captures (read-only; trust boundary
intact), snapshot all release endpoints in one canonical bundle:
```bash
ao2 cp release-snapshot \
    --cp-url http://127.0.0.1:18745 \
    --api-token-env AO2_CP_API_TOKEN \
    --write-json target/long-lived-control-plane/release-snapshot.json
# captured_at_utc=...
# endpoints_ok=N/4
#   readiness: ok schema=ao2.cp-release-readiness.v1 ...
#   handoff: ok schema=ao2.cp-release-candidate-handoff.v1 ...
#   support_bundle_status: ok schema=ao2.cp-release-support-bundle.v1 ...
#   publication_latest: ok schema=ao2.cp-release-publication.v1 ...
```
The snapshot emits canonical `ao2.cp-release-snapshot.v1` JSON
with per-endpoint `body_sha256` so a downstream auditor (factory-v3
evaluator-closer) can verify what the CP served at capture time.

For unattended health evidence, emit a read-only health snapshot:

```bash
export AO2_CP_API_TOKEN="$(cat target/long-lived-control-plane/api-token)"
scripts/cp-health-snapshot.sh \
    --base-url http://127.0.0.1:18745 \
    --api-token-env AO2_CP_API_TOKEN \
    --log-dir target/long-lived-control-plane/logs \
    --out target/long-lived-control-plane/health-snapshot.json
```

Windows:

```powershell
$env:AO2_CP_API_TOKEN = Get-Content target\long-lived-control-plane\api-token
.\scripts\cp-health-snapshot.ps1 `
    -BaseUrl http://127.0.0.1:18745 `
    -ApiTokenEnv AO2_CP_API_TOKEN `
    -LogDir target\long-lived-control-plane\logs `
    -Out target\long-lived-control-plane\health-snapshot.json
```

The artifact schema is `ao2.cp-health-snapshot.v1`. It includes the
extended-health JSON, per-log ERROR/WARN/PANIC counters, and the
observer trust boundary. It does not include bearer-token values or
log-line contents.

---

## 6. Disaster recovery

The data dir is **content-addressed**. Every accepted bundle is
referenced by its SHA256 in `index.jsonl`. Recovery is:

```bash
# (1) Stop the CP
kill "$(cat target/long-lived-control-plane/server.pid)"

# (2) Move the corrupted/lost data dir aside (don't delete — for
#     forensics)
mv target/long-lived-control-plane/data \
   target/long-lived-control-plane/data.broken-$(date -u +%Y%m%dT%H%M%SZ)

# (3) Restart with a fresh data dir (the CP creates the directory
#     tree itself on first contact)
mkdir -p target/long-lived-control-plane/data
# ... re-run step 3 of the start procedure ...

# (4) Re-publish any Phase 1 evidence the AO2 CLI has on disk
ao2 release publish \
    --bundle target/phase1-governed-promotion/latest \
    --cp-url http://127.0.0.1:18745 \
    --token-env AO2_CP_API_TOKEN

# (5) Verify the dashboard re-fills
curl -sf -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
    http://127.0.0.1:18745/api/v1/dashboard/phase1 | jq .state
# Expect: "promotion_decision_observed"
```

Local AO2 bundles in `target/phase1-governed-promotion/` are the
source of truth — the CP is a *read-replica*. Losing the CP data
dir is recoverable; losing the AO2 bundles is the actual
disaster scenario.

Before relying on the procedure for unattended work, run the portable
restore drill against a built local server binary. The drill uses an
ephemeral token internally, starts a temporary CP, ingests known
fixtures, archives the content-addressed data directory, restores it
into a fresh directory, restarts the CP, and proves restored readback
is byte-identical by SHA:

```bash
cargo build -p ao2-cp-server
scripts/cp-dr-restore-drill.sh \
    --server-bin target/debug/ao2-cp-server \
    --work-dir target/dr-restore-drill/manual \
    --out target/dr-restore-drill/manual/dr-restore-report.json
```

Windows:

```powershell
cargo build -p ao2-cp-server
.\scripts\cp-dr-restore-drill.ps1 `
    -ServerBin target\debug\ao2-cp-server.exe `
    -WorkDir target\dr-restore-drill\manual `
    -Out target\dr-restore-drill\manual\dr-restore-report.json
```

The report schema is `ao2.cp-dr-restore-drill.v1`. It is read-only
observer evidence: it mutates only temporary CP data directories,
does not mutate AO artifacts, and does not write bearer-token values
to the report.

---

## 7. When NOT to use the dev long-lived CP

- Anything multi-user or shared
- Anything internet-facing (the bind is `127.0.0.1` and the
  service is single-tenant by design — exposing it would break
  trust assumptions)
- Production smoke tests against external providers (use the
  production CP on `8744` for that, which has the operations
  runbook's lifecycle management)
- CI workflows (CI has its own ephemeral CPs spun up per job)

---

## 8. Related runbooks

- `docs/runbooks/operations.md` — production CP lifecycle
- `docs/runbooks/storage-retention.md` — `ao2-cp-gc` companion
- `docs/runbooks/release-smoke.md` — release-line smoke procedure
- `docs/SECURITY.md` — trust boundary, TLS, secrets
