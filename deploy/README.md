# Deployment templates

OS-specific service templates for `ao2-cp-server`. Each platform expects the
binary to live at a stable path with a token file owned by root/Administrator.

| Platform | Template | Install path |
|---|---|---|
| Linux (systemd) | [`linux/ao2-cp-server.service`](linux/ao2-cp-server.service) | `/etc/systemd/system/ao2-cp-server.service` |
| Linux env file  | [`linux/ao2-cp-server.env.example`](linux/ao2-cp-server.env.example) | `/etc/ao2-cp-server.env` (mode `0600`) |
| macOS (launchd) | [`macos/com.uesugitorachiyo.ao2-cp-server.plist`](macos/com.uesugitorachiyo.ao2-cp-server.plist) | `~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist` |
| Windows (NSSM)  | [`windows/Install-Ao2CpServerService.ps1`](windows/Install-Ao2CpServerService.ps1) | run as Administrator; installs service `ao2-cp-server` |

## TLS reverse-proxy templates

`ao2-cp-server` intentionally has no native TLS — it binds 127.0.0.1 and
relies on a reverse proxy for TLS termination, rate limiting, and access
control. Two drop-in templates are provided.

| Proxy | Template | Install path |
|---|---|---|
| Caddy 2 | [`caddy/Caddyfile.example`](caddy/Caddyfile.example) | `/etc/caddy/Caddyfile` (or import via `/etc/caddy/conf.d/`) |
| Nginx   | [`nginx/ao2-cp-server.conf.example`](nginx/ao2-cp-server.conf.example) | `/etc/nginx/conf.d/ao2-cp-server.conf` |

Both templates ship with rate-limit directives (120 req/min per IP for
`/api/v1/*`, 600 req/min for the cheap `/healthz` probe) and a
defense-in-depth header strip that blocks `OPENAI_API_KEY` /
`ANTHROPIC_API_KEY` headers from reaching the upstream, complementing the
server-side preflight that already refuses to start with those keys in its
environment.

The control-plane's bearer-token middleware still enforces authentication on
the upstream — the proxy rate-limit is defense-in-depth against credential
spraying and accidental fan-out from a single misconfigured client.

### Prometheus scraping

`/api/v1/metrics` exposes a Prometheus exposition v0.0.4 endpoint
(request counters by method × status class, request duration sum + count,
in-flight gauge, storage index gauge, and audit-log counters:
`ao2_cp_audit_log_appended_total`, `ao2_cp_audit_log_rotated_total`,
`ao2_cp_audit_log_persistence_errors_total`,
`ao2_cp_audit_log_dropped_total`, plus the gauges
`ao2_cp_audit_log_file_bytes` and
`ao2_cp_audit_log_oldest_resident_age_seconds`). Like the rest of
`/api/v1/*` it is bearer-token gated. Suggested alerts:

- `rate(ao2_cp_audit_log_persistence_errors_total[5m]) > 0` — silent
  persistence breakage (file rotation/write failure), pairs with the
  `persistence.last_error` peek on `/api/v1/status`.
- `rate(ao2_cp_audit_log_dropped_total[5m]) > 0` — ring buffer is
  evicting entries faster than the operator can consume them; raise
  `AO2_CP_AUDIT_LOG_CAPACITY` or enable NDJSON persistence.
- `ao2_cp_audit_log_file_bytes / <AO2_CP_AUDIT_LOG_MAX_BYTES> > 0.8`
  — predictive: the live NDJSON file is within 20 % of its
  rotation threshold but rotation has not yet fired. Catches stuck
  rotations before the file consumes the disk volume.
- `ao2_cp_audit_log_oldest_resident_age_seconds < <retention_target>` —
  the ring buffer's retention horizon has shrunk below the operator's
  target. Raise `AO2_CP_AUDIT_LOG_CAPACITY` or enable NDJSON
  persistence to extend history beyond the in-memory buffer.

### Live audit-log stream (SSE)

`GET /api/v1/audit-log/stream` opens a Server-Sent Events tail of the
audit-log ring buffer (`Content-Type: text/event-stream`). Each entry
is delivered as:

```
event: audit-log
id: <timestamp_unix_micros>
data: {"timestamp_unix_micros":...,"method":"GET","path":"/healthz",...}
```

Like the JSON surface it is bearer-token gated and accepts the same
filter query params (`method`, `status`, `status_class`, `path_prefix`,
`authenticated`). To resume after a transient disconnect, pass either
`?last_event_id=<micros>` or the standard `Last-Event-ID` request
header — the server replays buffered entries strictly newer than the
supplied id before the live tail begins. A 15 s keepalive comment is
emitted to keep reverse proxies from idling the connection out.

The stream is intentionally lossy: when the in-process broadcast
channel overflows under burst load, the server emits a single
`event: lagged` notice carrying the dropped count. Clients should
respond by polling `/api/v1/audit-log?since_unix_micros=<last_id>` to
backfill the gap, then reconnect to the live tail.

Reverse proxies must disable response buffering on this path (nginx:
`proxy_buffering off`; Caddy: `flush_interval -1`) — without it, the
SSE events are queued until the connection closes.

Configure Prometheus with:

```yaml
scrape_configs:
  - job_name: ao2-control-plane
    scheme: https
    metrics_path: /api/v1/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/ao2-cp-token
    static_configs:
      - targets: ['ao2-cp.example.com:443']
```

The token file should be the same `AO2_CP_API_TOKEN` value used by the
service, mode `0600 root:prometheus` (or equivalent). Rotating the token
requires updating both `/etc/ao2-cp-server.env` (or platform equivalent)
and the Prometheus credentials file in lockstep.

## Cross-cutting rules

- **Bind localhost only.** `--bind 127.0.0.1:8744`. Terminate TLS at a reverse
  proxy or LAN/VPN — v0.1 has no native TLS.
- **Token rotation.** Generate with `openssl rand -hex 32`. Store in
  `/etc/ao2-cp-server.env` (Linux), launchd `EnvironmentVariables` (macOS),
  or NSSM `AppEnvironmentExtra` (Windows). NEVER pass the token on the
  command line — it leaks to `ps` / `Get-Process`.
- **Forbidden env vars.** Server preflight refuses to start if
  `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is in the process environment.
  The Linux unit uses `PassEnvironment=` (empty) to block inheritance; the
  Windows installer rejects install if the machine scope has either set.
- **File-descriptor headroom.** All three templates set NOFILE/NumberOfFiles
  to 65536 to match the cargo-test ulimit step and absorb 500-concurrent
  burst load.
- **Data dir is the entire state.** Backup with `tar -czf` of the data
  directory (Linux/macOS) or `Compress-Archive` (Windows). No transactional
  database to snapshot.

See [`docs/runbooks/operations.md`](../docs/runbooks/operations.md) for
day-to-day operator procedures (start/stop, log inspection, token rotation,
upgrade, backup, restore, prune).

See [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) for the narrative install
guide that references these templates.
