# Security Model — ao2-control-plane v0.1

## Threat model

This server stores evidence bundles produced by local `ao2` CLIs. It is NOT in the trusted execution path. Bundles are content-addressed (SHA-256 over AO2 canonical JSON v1 / `ao2-canonical-v1`), so:

- **Tampering with stored bundles is detectable** (GET re-verifies digest).
- **Replay of legitimate bundles is harmless** (POST is idempotent by sha256).
- **The server cannot fabricate bundles** (it has no signing key).

## Authentication

Bearer token, configured via `AO2_CP_API_TOKEN`. Authenticated `/api/v1/*`
endpoints require an `Authorization: Bearer <token>` header. The only query-token
exception is `/api/v1/audit-log/stream`: its browser SSE client may use
`?token=<token>` because `EventSource` cannot set an Authorization header. Do
not use query tokens on any other endpoint.

`/healthz` is unauthenticated.

Server refuses to start without a token.

## Forbidden environment

The server refuses to start if `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` are present in its environment. The server makes no provider calls; their presence indicates a misconfigured deployment. Exit code 78 (EX_CONFIG).

## Provider registry snapshots

`/api/v1/provider/registry` accepts unsigned `ao2.provider-plugin-registry.v1`
snapshots produced by the local AO2 CLI. `/api/v1/provider/registry/signed`
accepts the same snapshot wrapped in
`ao2.cp-provider-registry-signed-upload.v1` with an RSA/SHA-256 signature
sidecar. The server validates that the snapshot declares
`trust_boundary.execution_owner=ao2-local-cli`, verifies the signature when
present, and stores the snapshot as content-addressed observer evidence. These
endpoints do not execute providers, approve AO2 digests, or close AO2 runs.

## TLS

Out of scope for v0.1. Operators must:
- Bind to `127.0.0.1` for local-only use (default), OR
- Terminate TLS at a reverse proxy (caddy / nginx / tailscale funnel), OR
- Restrict the port to a private network (LAN / VPN)

Do not bind to `0.0.0.0` over the public internet without TLS.

## Rate limiting

Not implemented in v0.1. If exposed to untrusted clients, add at the reverse proxy.

## Dependency advisories

`cargo audit` runs in CI on pull requests and pushes to main (see the `audit` job in
`.github/workflows/ci.yml`). The current suppression list and per-advisory
disposition rationale live in `docs/security/advisory-dispositions.md`.
Adding a new ignore requires updating both files in the same PR.

## Reporting vulnerabilities

Open a private security advisory on GitHub or email the maintainer directly. Do not file public issues for security bugs.
