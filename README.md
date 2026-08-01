# AO2 Control Plane

[![Latest release](https://img.shields.io/github/v/release/uesugitorachiyo/ao2-control-plane?include_prereleases&label=latest%20release)](https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.18)

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

```bash
git clone https://github.com/uesugitorachiyo/ao2-control-plane
cd ao2-control-plane
cargo build --release -p ao2-cp-server
export AO2_CP_API_TOKEN="$(openssl rand -hex 16)"
./target/release/ao2-cp-server --data-dir ./data
```

For a repeatable local observer on `127.0.0.1:18745`:

```bash
scripts/start-long-lived-dev.sh
```

The bootstrap stores its token in a mode-`0600` file and prints token-free
health metadata.

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
