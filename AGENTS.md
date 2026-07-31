# AO2 Control Plane Agent Instructions

## Status And Role

AO2 Control Plane is the active read-only observer and evidence service for completed AO2 work. It verifies signed inputs, stores content-addressed records, and serves authenticated APIs, dashboards, audit logs, and retention readbacks.

The control plane does not execute or alter AO2 runs, issue approvals, close evaluators, decide policy, authorize release, or turn observer readback into mutation authority.

## Sources Of Truth

- [docs/SECURITY.md](docs/SECURITY.md) defines authentication, secret handling, signed-input validation, and deployment trust boundaries.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/runbooks/operations.md](docs/runbooks/operations.md), and [docs/runbooks/storage-retention.md](docs/runbooks/storage-retention.md) define operator, service, and retention behavior.
- `crates/ao2-cp-schema/`, `crates/ao2-cp-storage/`, and `crates/ao2-cp-server/` own schema, persistence, and API implementation respectively. [REFERENCE.md](REFERENCE.md) is the current endpoint reference.
- `scripts/run-workspace-tests.py` and [`.github/workflows/ci.yml`](.github/workflows/ci.yml) define broad tests and hosted gates.

## Ownership And Boundaries

- Accept only schema-valid, signature-valid, size-bounded evidence whose source, digest, provenance, and authority flags agree. Unknown, malformed, stale, mismatched, or over-authority inputs must fail closed.
- Preserve content addressing, storage integrity, migration compatibility, audit ordering, retention provenance, and replay determinism. Readback never approves or mutates its producer.
- Protect `AO2_CP_API_TOKEN` and signing material. Do not record bearer values, provider keys, credentials, account identifiers, private endpoints, raw environment values, or unredacted uploads.
- Treat `docs/releases/`, `docs/release/`, release-train records, committed fixtures, and public-export evidence as historical or producer-owned. Never rewrite them to obtain a readiness or publication claim.
- Keep binaries, data directories, caches, generated dashboards, logs, packages, and test artifacts under ignored `target/`, `data/`, or `dist/`.
- Deployment, live service changes, release, publication, credentials, permissions, direct-main writes, and any AO2 mutation require separate explicit operator authority. A deployment file or readiness result is not authorization.

## Working Method

- Change the smallest owned observer surface and preserve read-only semantics, strict schemas, exact provenance, redaction, authentication, auditability, and rollback.
- Add negative tests for invalid signatures, digest drift, path escape, replay inconsistency, migration failure, token leakage, stale evidence, and claims of approval or mutation.
- Use the nested instructions for server, storage, and deployment scopes; keep their critical non-authority boundaries represented here.
- Update this file in the same pull request when durable commands, architecture, ownership, or authority boundaries change.

## Verification

- Server/API changes: `cargo test -p ao2-cp-server`.
- Storage/migration changes: `cargo test -p ao2-cp-storage`.
- Schema changes: `cargo test -p ao2-cp-schema`.
- Run `cargo fmt --all -- --check`, `python3 scripts/run-workspace-tests.py`, and `cargo clippy --workspace --all-targets -- -D warnings` as the full local gate.
- Run release packaging, multi-host smoke, post-release, or deployment commands only with separate authority; never use real tokens for instruction validation.
- For instruction changes run `python3 ../ao-architecture/scripts/verify_agent_instruction_layout.py --workspace-root .. --repository ao2-control-plane`. Always run `git diff --check`.

## Evidence And Completion

- Record source heads, commands and exits, schema versions, signatures or digests, migration state, audit provenance, and relevant artifact hashes. Report skipped, unavailable, or failed checks explicitly.
- Completion requires focused and broad gates, green pull-request CI, clean synchronized `main`, and task-branch cleanup. Observer success grants no release, approval, or AO2 authority.
