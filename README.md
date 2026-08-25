# AO2 Control Plane

[![Latest release](https://img.shields.io/github/v/release/uesugitorachiyo/ao2-control-plane?include_prereleases&label=latest%20release)](https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.19)

AO2 Control Plane stores and serves completed AO2 evidence. It verifies signed
bundles, writes content-addressed records, and exposes authenticated APIs and
dashboards. It does not execute AO2 workflows or approve their results.

## Role In AO

- **Inputs:** Signed AO2 evidence packs, acceptance bundles, control-plane
  bundles, and memory exports.
- **Outputs:** Verified records, read APIs, dashboards, audit logs, and
  retention reports.
- **Upstream:** AO2.
- **Downstream:** AO Command and operators reviewing completed work.

See the [AO Architecture guide](https://github.com/uesugitorachiyo/ao-architecture)
and the
[AO2 Control Plane component page](https://github.com/uesugitorachiyo/ao-architecture/blob/main/components/ao2-control-plane.md)
for the cross-repository flow.

## Quick Start

Install the published `v0.1.19` archive for your platform. These commands use
a temporary directory, install only beneath it, bind only to loopback, and
stop after the health check. The control plane remains an observer: it does not
execute AO2 workflows or approve their results.

### macOS (Apple Silicon)

```bash
workdir="$(mktemp -d)"
cd "$workdir"
curl -fLO https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/ao2-control-plane-0.1.19-macos-aarch64.tar.gz
curl -fLO https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/SHA256SUMS
grep '  ao2-control-plane-0.1.19-macos-aarch64.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf ao2-control-plane-0.1.19-macos-aarch64.tar.gz
export AO2_CP_INSTALL_DIR="$PWD/install"
sh ./install.sh
"$AO2_CP_INSTALL_DIR/ao2-cp-server" --version
export AO2_CP_API_TOKEN="$(openssl rand -hex 16)"
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  "$AO2_CP_INSTALL_DIR/ao2-cp-server" --bind 127.0.0.1:18745 --data-dir "$PWD/data" >server.log 2>&1 &
server_pid=$!
curl -fsS --retry 10 --retry-connrefused http://127.0.0.1:18745/healthz
kill "$server_pid"
```

### Linux x86_64

```bash
workdir="$(mktemp -d)"
cd "$workdir"
curl -fLO https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/ao2-control-plane-0.1.19-linux-x86_64.tar.gz
curl -fLO https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/SHA256SUMS
grep '  ao2-control-plane-0.1.19-linux-x86_64.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf ao2-control-plane-0.1.19-linux-x86_64.tar.gz
export AO2_CP_INSTALL_DIR="$PWD/install"
sh ./install.sh
"$AO2_CP_INSTALL_DIR/ao2-cp-server" --version
export AO2_CP_API_TOKEN="$(openssl rand -hex 16)"
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  "$AO2_CP_INSTALL_DIR/ao2-cp-server" --bind 127.0.0.1:18745 --data-dir "$PWD/data" >server.log 2>&1 &
server_pid=$!
curl -fsS --retry 10 --retry-connrefused http://127.0.0.1:18745/healthz
kill "$server_pid"
```

### Windows x86_64

```powershell
$workdir = Join-Path ([IO.Path]::GetTempPath()) ("ao2-control-plane-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workdir | Out-Null
Set-Location $workdir
$archive = "ao2-control-plane-0.1.19-windows-x86_64.tar.gz"
Invoke-WebRequest "https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/$archive" -OutFile $archive
Invoke-WebRequest "https://github.com/uesugitorachiyo/ao2-control-plane/releases/download/v0.1.19/SHA256SUMS" -OutFile SHA256SUMS
$expected = ((Get-Content SHA256SUMS | Where-Object { $_ -match "  $([regex]::Escape($archive))$" }) -split "\s+")[0].ToLowerInvariant()
if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne $expected) { throw "archive checksum mismatch" }
tar -xzf $archive
$env:AO2_CP_INSTALL_DIR = Join-Path $PWD "install"
.\install.ps1
& (Join-Path $env:AO2_CP_INSTALL_DIR "ao2-cp-server.exe") --version
$env:AO2_CP_API_TOKEN = [guid]::NewGuid().ToString("N")
Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
$server = Start-Process -FilePath (Join-Path $env:AO2_CP_INSTALL_DIR "ao2-cp-server.exe") -ArgumentList @("--bind", "127.0.0.1:18745", "--data-dir", (Join-Path $PWD "data")) -PassThru
$health = $null
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    if ($server.HasExited) { throw "control plane exited before health check" }
    try {
        $health = Invoke-RestMethod http://127.0.0.1:18745/healthz
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $health) { throw "control plane health check timed out" }
Stop-Process -Id $server.Id
```

For a repeatable local development observer on `127.0.0.1:18745`, use
`scripts/start-long-lived-dev.sh`. To build from source instead, pin the same
release tag rather than cloning moving `main`:

```bash
git clone --depth 1 --branch v0.1.19 https://github.com/uesugitorachiyo/ao2-control-plane
cd ao2-control-plane
cargo build --release -p ao2-cp-server
```

## Common Endpoints

All `/api/v1/*` routes require
`Authorization: Bearer $AO2_CP_API_TOKEN`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness and version check |
| `GET` | `/readyz` | Token and storage readiness check |
| `POST` | `/api/v1/evidence-pack/signed` | Ingest a signed AO2 evidence pack |
| `GET` | `/api/v1/evidence-pack/dashboard` | Review stored evidence packs |
| `POST` | `/api/v1/memory/export/signed` | Ingest a signed AO2 memory export |
| `GET` | `/api/v1/ci/evidence-index` | Review the CI evidence index |

The [full endpoint and operator reference](REFERENCE.md) documents every route,
release-evidence bridge, dashboard, cache rule, and observer contract.

## Documentation

- [Deployment](docs/DEPLOYMENT.md)
- [Security](docs/SECURITY.md)
- [Operations](docs/runbooks/operations.md)
- [Long-Lived Development](docs/runbooks/long-lived-dev.md)
- [Release Smoke](docs/runbooks/release-smoke.md)
- [Storage Retention](docs/runbooks/storage-retention.md)
- [Branch Protection](docs/runbooks/branch-protection.md)
- [Public Export Evidence](docs/public-export-evidence.md)
- [Full Reference](REFERENCE.md)

## Configuration

| Environment variable | Default | Required |
| --- | --- | --- |
| `AO2_CP_BIND` | `127.0.0.1:8744` | No |
| `AO2_CP_DATA_DIR` | `./data` | No |
| `AO2_CP_API_TOKEN` | None | Yes |
| `AO2_CP_LOG_LEVEL` | `info` | No |
| `AO2_CP_MAX_BODY_BYTES` | `10485760` | No |

The full reference lists audit-log and retention settings.

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/run-workspace-tests.py
```

Release packaging and cross-platform smoke commands are documented in
[Release Smoke](docs/runbooks/release-smoke.md).

## Security Boundary

- Bearer-token authentication protects every `/api/v1/*` endpoint.
- The server refuses to start when provider API-key environment variables are
  present.
- Signed uploads fail closed when signature verification fails.
- Observer records cannot approve, modify, or close AO2 runs.
- The server does not provide native TLS; deploy it behind a trusted reverse
  proxy or private network.

## License

AO2 Control Plane is licensed under Apache 2.0.
