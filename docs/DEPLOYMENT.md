# Deployment — ao2-control-plane v0.1

## Local (Mac/Linux/Windows)

```bash
cargo build --release -p ao2-cp-server
export AO2_CP_API_TOKEN=$(openssl rand -hex 16)
export AO2_CP_LOG_LEVEL=info
./target/release/ao2-cp-server --bind 127.0.0.1:8744 --data-dir ~/ao2-cp-data
```

## systemd (Linux)

Use the canonical template at
[`deploy/linux/ao2-cp-server.service`](../deploy/linux/ao2-cp-server.service)
(hardened with `PrivateTmp`, `ProtectKernelTunables`, `RestrictAddressFamilies`,
`LimitNOFILE=65536`, and `PassEnvironment=` to block forbidden env-var
inheritance). Companion env example at
[`deploy/linux/ao2-cp-server.env.example`](../deploy/linux/ao2-cp-server.env.example).

```bash
sudo install -m 0644 deploy/linux/ao2-cp-server.service /etc/systemd/system/ao2-cp-server.service
sudo install -m 0600 deploy/linux/ao2-cp-server.env.example /etc/ao2-cp-server.env
sudoedit /etc/ao2-cp-server.env   # paste a fresh `openssl rand -hex 32` token

sudo useradd --system --home /var/lib/ao2-cp-server --shell /usr/sbin/nologin ao2cp
sudo install -d -m 0750 -o ao2cp -g ao2cp /var/lib/ao2-cp-server/data
sudo install -m 0755 -o root -g root target/release/ao2-cp-server /usr/local/bin/ao2-cp-server

sudo systemctl daemon-reload
sudo systemctl enable --now ao2-cp-server
sudo journalctl -fu ao2-cp-server
```

## launchd (macOS)

Use the canonical template at
[`deploy/macos/com.uesugitorachiyo.ao2-cp-server.plist`](../deploy/macos/com.uesugitorachiyo.ao2-cp-server.plist).
The plist *must* live under `~/Library/LaunchAgents/` — launchd with TCC
sandboxing will silently refuse to execute binaries that resolve through
`~/Documents/` or other protected user directories.

```bash
install -m 0755 target/release/ao2-cp-server /usr/local/bin/ao2-cp-server
install -d -m 0700 /var/log/ao2-cp-server
install -m 0600 deploy/macos/com.uesugitorachiyo.ao2-cp-server.plist \
  ~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist
# Edit the installed copy: replace REPLACE_ME_ABSOLUTE_DATA_DIR and
# REPLACE_ME_FRESH_RANDOM_TOKEN (`openssl rand -hex 32`).
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.uesugitorachiyo.ao2-cp-server.plist
```

## Windows (NSSM)

NSSM 2.24+ is required (https://nssm.cc/download). The installer script wraps
all `nssm set` calls and refuses to install if a forbidden env var
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) is present in the machine scope.

```powershell
# As Administrator
$tokenFile = "C:\ProgramData\ao2-control-plane\token.txt"
New-Item -ItemType Directory "C:\ProgramData\ao2-control-plane" -Force | Out-Null
(openssl rand -hex 32) | Out-File -Encoding ascii -NoNewline $tokenFile
icacls $tokenFile /inheritance:r /grant:r "SYSTEM:F" "BUILTIN\Administrators:F"

.\deploy\windows\Install-Ao2CpServerService.ps1 `
  -BinaryPath "C:\Program Files\ao2-control-plane\bin\ao2-cp-server.exe" `
  -TokenFile  $tokenFile
```

Logs land under `C:\ProgramData\ao2-control-plane\logs\` with NSSM-native
rotation (10 MB cap, keep 5).

## Reverse proxy

`ao2-cp-server` has no native TLS — it binds 127.0.0.1 and relies on a
reverse proxy. Two drop-in templates ship in `deploy/`:

- [`deploy/caddy/Caddyfile.example`](../deploy/caddy/Caddyfile.example) —
  Caddy 2 with automatic Let's Encrypt + optional rate-limit plugin
  (120 req/min per IP for `/api/v1/*`, 600 req/min for `/healthz`).
- [`deploy/nginx/ao2-cp-server.conf.example`](../deploy/nginx/ao2-cp-server.conf.example) —
  Nginx with `limit_req_zone` + per-IP connection cap + HSTS + provider-key
  header strip.

Minimal Caddy (no rate-limit plugin required):

```Caddyfile
cp.example.com {
    reverse_proxy 127.0.0.1:8744
}
```

Caddy auto-provisions TLS via Let's Encrypt.

## Backups

`data/` is the entire state. Backup with:
```bash
tar -czf ao2-cp-data-$(date +%Y%m%d).tar.gz -C /var/lib/ao2-cp-server data
```

Bundle files are immutable (content-addressed). `index.jsonl` is append-only. No transactional state to capture.

## Retention

Before pruning, take a backup or snapshot of `data/`, then run a dry report:

```bash
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/report?keep_latest=25"
curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/prune?keep_latest=25"
```

The prune endpoint is dry-run unless `execute=true` is supplied. Execution
removes only old `ao2-control-plane` bundle files and matching signature
sidecars, then rewrites the local `index.jsonl` to remove the pruned observer
copies. It does not reach into AO2 repositories or mutate AO2 run evidence.

## Provider Registry Observer

The control plane can store AO2 provider/plugin registry snapshots as
observer-only evidence:

```bash
ao2 provider registry --json > /tmp/ao2-provider-registry.json
curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  --data-binary @/tmp/ao2-provider-registry.json \
  "http://127.0.0.1:8744/api/v1/provider/registry"
ao2 provider registry \
  --control-plane-url http://127.0.0.1:8744 \
  --api-token-env AO2_CP_API_TOKEN \
  --signing-key .release-signing/ao2-release-signing-key.pem \
  --signer-id ao2-provider-registry \
  --json
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/provider/registry/dashboard"
```

The signed CLI form posts to `/api/v1/provider/registry/signed`; the control
plane verifies the RSA/SHA-256 sidecar, stores it beside the registry snapshot,
and renders detail pages with links to evidence and memory observer dashboards.
These endpoints only store and render registry metadata. They cannot approve,
mutate, close, or execute AO2 runs or provider adapters.

## Upgrading

Stop server → replace binary → start server. The orphan sweep on startup will reconcile any in-flight write that crashed. Detailed per-platform upgrade commands live in [`docs/runbooks/operations.md` §4](runbooks/operations.md).

## Operator runbook

Day-to-day service operations — token rotation, log inspection, backup,
restore, pruning, troubleshooting — are documented in
[`docs/runbooks/operations.md`](runbooks/operations.md).
