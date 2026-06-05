# Runbook: ao2-cp-server operations

Audience: operators running `ao2-cp-server` as a long-lived service on Linux
(systemd), macOS (launchd), or Windows (NSSM).

Trust boundary: every step in this runbook is **read-only** with respect to
AO2 evidence. The server is a read-only observer; it stores content-addressed
copies of bundles posted by local AO2 CLIs and never mutates AO artifacts or
approves AO runs. Operator commands here cover only the server's own data
directory, service lifecycle, and observer-side pruning.

---

## 1. Service lifecycle

### Linux (systemd)

```bash
sudo systemctl start    ao2-cp-server
sudo systemctl stop     ao2-cp-server
sudo systemctl restart  ao2-cp-server
sudo systemctl status   ao2-cp-server
sudo journalctl -fu     ao2-cp-server
```

### macOS (launchd, per-user LaunchAgent)

```bash
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist
launchctl bootout   gui/$UID ~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist
launchctl kickstart -k gui/$UID/com.uesugitorachiyo.ao2-cp-server   # restart
launchctl print     gui/$UID/com.uesugitorachiyo.ao2-cp-server
tail -F /var/log/ao2-cp-server/stderr.log
```

**Gotcha:** the plist *must* live under `~/Library/LaunchAgents/`. launchd
with TCC sandboxing will silently refuse to execute scripts/binaries that
reside under `~/Documents/` or other protected user directories.

### Windows (NSSM)

```powershell
nssm start    ao2-cp-server
nssm stop     ao2-cp-server
nssm restart  ao2-cp-server
nssm status   ao2-cp-server
Get-Content -Path "C:\ProgramData\ao2-control-plane\logs\ao2-cp-server.err.log" -Wait -Tail 100
```

---

## 2. Health probes

```bash
curl -sf http://127.0.0.1:8744/healthz   # liveness — returns version JSON
curl -sf http://127.0.0.1:8744/readyz    # readiness — token + writable data dir
```

`/readyz` returns 503 with a JSON error body if `AO2_CP_API_TOKEN` is unset
or the data directory is read-only. Wire both into your supervisor's
healthcheck.

### Browser-safe dashboard snapshots

The root page at `/` is public and links to authenticated dashboards. Browser
URLs must not include bearer tokens. For operator review in a normal browser,
generate local dashboard snapshots that inject the token as an HTTP header and
write token-free local files:

```bash
export AO2_CP_API_TOKEN="$(cat target/long-lived-control-plane/api-token)"
python3 scripts/cp_dashboard_snapshot.py \
  --base-url http://127.0.0.1:18745 \
  --out-dir target/cp-dashboard-snapshots/latest \
  --open
```

PowerShell:

```powershell
$env:AO2_CP_API_TOKEN = Get-Content target\long-lived-control-plane\api-token
.\scripts\cp-dashboard-snapshot.ps1 `
  -BaseUrl http://127.0.0.1:18745 `
  -OutDir target\cp-dashboard-snapshots\latest `
  -Open
```

The helper writes `index.html`, `manifest.json`, and local dashboard copies.
It fails closed if any fetched response contains the bearer value. The snapshots
are read-only observer copies; they do not approve releases, mutate AO
artifacts, or replace factory-v3 evaluator-closer acceptance.

---

## 3. Token rotation

Bearer tokens never appear in URLs, logs, or this runbook. To rotate:

1. Generate a fresh token: `openssl rand -hex 32`.
2. Replace the value in the platform's secret store:
   - Linux: `/etc/ao2-cp-server.env` (mode `0600`)
   - macOS: edit the plist's `EnvironmentVariables.AO2_CP_API_TOKEN`
   - Windows: re-run `deploy/windows/Install-Ao2CpServerService.ps1`
     with a refreshed `-TokenFile`
3. Restart the service.
4. Update the token in every AO2 CLI / Hermes config that posts to the
   control plane (look for `--api-token-env AO2_CP_API_TOKEN` invocations).
5. Verify with an authenticated read: `curl -H "Authorization: Bearer
   $AO2_CP_API_TOKEN" http://127.0.0.1:8744/api/v1/acceptance` should
   return JSON (not 401).

---

## 4. Upgrade

Server upgrades are stop → swap → start. The orphan sweep on startup
reconciles any in-flight write that crashed mid-fsync.

### Linux
```bash
sudo systemctl stop ao2-cp-server
sudo install -m 0755 -o root -g root ./dist/ao2-control-plane-X.Y.Z-linux-x86_64/bin/ao2-cp-server /usr/local/bin/ao2-cp-server
sudo systemctl start ao2-cp-server
sudo journalctl -fu ao2-cp-server | head
```

### macOS
```bash
launchctl bootout gui/$UID/com.uesugitorachiyo.ao2-cp-server
sudo install -m 0755 ./dist/ao2-control-plane-X.Y.Z-macos-aarch64/bin/ao2-cp-server /usr/local/bin/ao2-cp-server
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist
```

### Windows
```powershell
nssm stop ao2-cp-server
Copy-Item ".\dist\ao2-control-plane-X.Y.Z-windows-x86_64\bin\ao2-cp-server.exe" `
  "C:\Program Files\ao2-control-plane\bin\ao2-cp-server.exe" -Force
nssm start ao2-cp-server
```

**Always smoke after upgrade:**

```bash
scripts/smoke-release-archive.sh   # or .ps1 on Windows
```

---

## 5. Backup and restore

The data directory is the entire state. Bundles are content-addressed (SHA-256
over AO2 canonical JSON v1 / `ao2-canonical-v1`) and immutable; `index.jsonl` is append-only. No
transactional state to capture.

### Backup (online, no service stop required)

```bash
# Linux / macOS
tar -czf "ao2-cp-data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" -C /var/lib/ao2-cp-server data

# Windows
Compress-Archive -Path "C:\ProgramData\ao2-control-plane\data\*" `
  -DestinationPath "C:\Backups\ao2-cp-data-$((Get-Date).ToString('yyyyMMddTHHmmssZ')).zip"
```

### Restore (service must be stopped)

```bash
sudo systemctl stop ao2-cp-server
sudo rm -rf /var/lib/ao2-cp-server/data
sudo tar -xzf ao2-cp-data-YYYYMMDDTHHMMSSZ.tar.gz -C /var/lib/ao2-cp-server
sudo chown -R ao2cp:ao2cp /var/lib/ao2-cp-server/data
sudo systemctl start ao2-cp-server
```

Verify: dashboards (`/api/v1/acceptance/dashboard`,
`/api/v1/release/cockpit`) should render the restored evidence with no gaps
in the timeline.

### Restore drill

Before treating backup/restore as operationally ready on a host, run the
portable restore drill. It exercises the same content-addressed observer
data shape without touching production data: a temporary CP ingests fixture
evidence, the data directory is archived, the archive is restored to a new
directory, and restored readback is verified byte-identical by SHA.

Linux / macOS:

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

The report schema is `ao2.cp-dr-restore-drill.v1`. The drill is a
read-only observer check: it mutates only temporary control-plane data
directories, never AO artifacts, and never records bearer-token values.

---

## 6. Pruning observer copies

Pruning is opt-in, dry-run by default, and scoped to old `ao2-control-plane`
bundle files plus their signature sidecars. It does **not** touch AO2 run
directories, approvals, or trust-path artifacts.

```bash
# 1. Report only (no deletes)
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/report?keep_latest=25"

# 2. Dry-run prune (default — still no deletes)
curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/prune?keep_latest=25"

# 3. Real prune (after backup, after reviewing dry-run output)
curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/prune?keep_latest=25&execute=true"
```

Always backup before step 3.

---

## 7. Audit-log rotation drill

The control plane already has size-based audit-log NDJSON rotation:
configure `AO2_CP_AUDIT_LOG_FILE` and `AO2_CP_AUDIT_LOG_MAX_BYTES`.
When the live file crosses the threshold, it rotates to `<path>.1`
and opens a fresh live file. Use the drill below to prove that path on
Linux, macOS, or Windows before leaving a long-lived CP unattended.

Linux / macOS:

```bash
cargo build -p ao2-cp-server
scripts/cp-audit-log-rotation-drill.sh \
  --server-bin target/debug/ao2-cp-server \
  --work-dir target/audit-log-rotation-drill/manual \
  --out target/audit-log-rotation-drill/manual/rotation-report.json
```

Windows:

```powershell
cargo build -p ao2-cp-server
.\scripts\cp-audit-log-rotation-drill.ps1 `
  -ServerBin target\debug\ao2-cp-server.exe `
  -WorkDir target\audit-log-rotation-drill\manual `
  -Out target\audit-log-rotation-drill\manual\rotation-report.json
```

The report schema is `ao2.cp-audit-log-rotation-drill.v1`. The drill
is read-only observer evidence: it mutates only temporary CP data and
log directories, never AO artifacts, and never records bearer-token
values. A passing report proves:

- `rotation_count >= 1` on `/api/v1/status`;
- `ao2_cp_audit_log_rotated_total >= 1` on `/api/v1/metrics`;
- the live NDJSON file exists and is below `AO2_CP_AUDIT_LOG_MAX_BYTES`;
- the rotated `.1` sidecar exists and is non-empty.

---

## 8. Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Service starts then immediately exits with code 1; log says "forbidden env" | `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` leaked into process env | Remove from EnvironmentFile / plist / machine env; restart |
| Service starts then exits; log says "AO2_CP_API_TOKEN is required" | Token missing or empty in secret store | Set token (§3) and restart |
| Service running but `/readyz` 503s | Data dir not writable by service user | Check ownership/ACLs on data dir |
| `Os { code: 24, ... "Too many open files" }` under load | File-descriptor soft limit too low | All shipped templates set 65536; verify `cat /proc/$(pidof ao2-cp-server)/limits` shows it |
| 401 on every `/api/v1/*` request | Operator-side token drift after rotation | Re-sync `AO2_CP_API_TOKEN` in posting CLIs / Hermes config |
| Smoke fails post-upgrade with "manifest mismatch" | Old binary cached in PATH ahead of new one | `which ao2-cp-server` (or `where.exe`); fix PATH or reinstall |
| `/api/v1/release/support-bundle/verify.json` returns hash mismatch on Windows | PowerShell 5.1 canonical-JSON quirks in `Verify-ReleaseSupportBundle.ps1` | Upgrade to ao2-cp-server ≥ `eb23179`; the fix is shipped server-side |

---

## 9. Where to look when things go sideways

- Service logs: see §1.
- Server-side audit log: `<data-dir>/audit.log` (append-only NDJSON).
- Index: `<data-dir>/index.jsonl` (append-only NDJSON; rebuild from
  bundle files if corrupted by inspecting bundle sidecars).
- Dashboards: `/api/v1/release/cockpit`, `/api/v1/storage/dashboard`,
  `/api/v1/phase1/promotion/dashboard`. All require the bearer token in
  the `Authorization` header — never in the URL.

When in doubt, take a data-dir backup (§5) before any other action.
