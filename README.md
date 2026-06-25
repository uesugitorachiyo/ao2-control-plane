# ao2-control-plane

[![Latest release](https://img.shields.io/github/v/release/uesugitorachiyo/ao2-control-plane?include_prereleases&label=latest%20release)](https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.13)

Optional server layer for AO2 evidence ingest. Receives signed acceptance bundles, control-plane bundles, AO2 memory exports, and signed AO2 evidence packs from local `ao2` CLIs, stores them as content-addressed flat files, and exposes authenticated read APIs.

This server is an observer: it does not approve AO2 runs, execute providers, or own evaluator closure.

## AO Stack Architecture

This repository is part of the AO agent orchestration stack. Start with the
central architecture guide at
[uesugitorachiyo/ao-architecture](https://github.com/uesugitorachiyo/ao-architecture);
the ao2-control-plane-specific architecture page is
[ao2-control-plane](https://github.com/uesugitorachiyo/ao-architecture/tree/main/ao2-control-plane).

## Successor Boundary

AO2-first control-plane evidence replaces the deprecated standalone control-plane
path for active AO work. This repository is the home for typed state, evidence
readback, retention, release readiness observation, and authenticated operator
views. Execution and evaluator closure remain in
[`ao2`](https://github.com/uesugitorachiyo/ao2).

Some stored evidence schemas and route-owner strings still contain historical
`factory-v3` or `Hermes` labels. Treat those as compatibility labels for
already-published evidence contracts, not active repository dependencies. The
active production stack is AO2-first and is validated by the active-stack
handoff readback against `ao2`, `ao2-control-plane`, `ao-foundry`, `ao-forge`,
`ao-command`, and `ao-covenant`.

Likewise, `operator-release` schema, artifact, workflow, and route names are
AO2 release-evidence compatibility labels, not references to the deprecated `ao-operator` repository.
New active-stack work must not reintroduce `ao-operator` or route release
authority through this observer service.

## What it does

`ao2-control-plane` turns AO2's local evidence into a durable, authenticated
operator view. AO2 still runs locally and owns evaluator closure; the control
plane receives completed evidence after the fact, verifies it, stores it, and
makes it easier to inspect.

Today it is useful as a read-only evidence archive and audit viewer:

- ingest signed AO2 evidence packs, memory exports, acceptance bundles, and
  control-plane bundles;
- verify detached signatures, canonical digests, and stored sidecars;
- keep evidence in content-addressed flat-file storage;
- expose authenticated APIs and HTML dashboards for signed packs, source
  classes, verdicts, signer metadata, and gate-attention views;
- support backup/restore drills, storage-retention reports, dry-run pruning,
  and release support-bundle verification;
- provide cross-platform release archive smokes for Ubuntu, macOS, and
  Windows.

That makes it possible to answer operator questions without digging through
local run directories:

- What ran?
- What evidence was published?
- Who or what signed it?
- Which gates need attention?
- Is the stored evidence still digest-valid?
- Can the evidence archive be restored and verified later?

## Operations Cockpit Direction

The current UI is intentionally read-only. The next product direction is an
AO2 operations cockpit built from real evidence rather than manually maintained
task cards.

The intended cockpit surfaces are:

- a live run timeline for AO2 and Pulse activity;
- an overnight Pulse report summarizing completed iterations, failures,
  generated tasks, and publish attempts;
- a gate-attention inbox for failed, rejected, unsigned, unverified, or missing
  evidence;
- a release-readiness board for AO2 and `ao2-control-plane` CI, smoke, artifact,
  and ship/no-ship status;
- an evidence-backed process board where cards come from AO2 packets, run
  summaries, and gate results.

This is different from a generic Kanban board: the useful unit is not a manual
task note, but a card backed by evidence that can be opened, verified, and
audited.

## License

`ao2-control-plane` is licensed under `Apache-2.0`. See `LICENSE`.

## Quickstart

```bash
git clone https://github.com/uesugitorachiyo/ao2-control-plane
cd ao2-control-plane
cargo build --release -p ao2-cp-server

export AO2_CP_API_TOKEN=$(openssl rand -hex 16)
./target/release/ao2-cp-server --data-dir ./data
```

For a repeatable local dev observer on `127.0.0.1:18745`, use the token-safe
bootstrap:

```bash
scripts/start-long-lived-dev.sh
```

The script initializes `target/long-lived-control-plane/`, creates or reuses a
`0600` token file, starts `ao2-cp-server`, and prints only token-free health
metadata.

Package and smoke an installed local release archive:

```bash
cargo build --release -p ao2-cp-server
scripts/package-local.sh --out-dir dist --version 0.1.13 --binary target/release/ao2-cp-server
AO2_CP_ARCHIVE=dist/ao2-control-plane-0.1.13-macos-aarch64.tar.gz \
  AO2_CP_SMOKE_JSON=target/release-smoke/latest-release-smoke.json \
  scripts/smoke-release-archive.sh
```

Windows archive smoke uses the PowerShell harness and validates the `.exe`
manifest, installer checksum, installed binary, health endpoint, and acceptance
dashboard:

```powershell
cargo build --release -p ao2-cp-server
bash scripts/package-local.sh --out-dir dist --version 0.1.13 --binary target/release/ao2-cp-server.exe --target-label windows-x86_64
$env:AO2_CP_ARCHIVE="dist/ao2-control-plane-0.1.13-windows-x86_64.tar.gz"
$env:AO2_CP_SMOKE_JSON="target/release-smoke/latest-windows-release-smoke.json"
./scripts/smoke-release-archive.ps1
```

The archive contains `bin/ao2-cp-server` or `bin/ao2-cp-server.exe`, `install.sh`,
`install.ps1`, `SHA256SUMS`, and `RELEASE-MANIFEST.json`. The manifest records
the server binary SHA-256 plus the Python and PowerShell offline support-bundle
verifier paths, SHA-256 values, and token-free commands. The smoke installs
from the archive, starts the installed server, posts provider-pilot acceptance
fixtures, and verifies the acceptance dashboard source-class counts. CI runs
format, clippy, tests, packaging, and installed release smokes across Ubuntu,
macOS, and Windows.

## Install From Public Release

The current public release is
[`v0.1.13`](https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.13).
It publishes Linux, macOS, and Windows archives plus token-free promotion
summary evidence. Download and verify it with:

```bash
mkdir -p dist-release
gh release download v0.1.13 --repo uesugitorachiyo/ao2-control-plane \
  --pattern ao2-control-plane-0.1.13-macos-aarch64.tar.gz \
  --pattern SHA256SUMS \
  --dir dist-release
(cd dist-release && grep 'ao2-control-plane-0.1.13-macos-aarch64.tar.gz' SHA256SUMS | shasum -a 256 -c -)
```

Or run the repository verifier, which downloads all published prerelease assets
and verifies every file listed in `SHA256SUMS`:

```bash
scripts/release-download-verify.sh
```

CI also runs the same verifier as the `Release publication closure` job and
uploads `ao2-control-plane-release-publication-closure`. Its
`summary.json` uses schema `ao2.cp-release-publication-closure.v1`, records the
downloaded release assets and checksums, and prints
`control_plane_release_publication_closure=passed` when the published assets are
downloadable, checksum-valid, and include at least one
`ao2-control-plane-*.tar.gz` release archive. This is read-only release
evidence: it does not approve AO2 runs, mutate AO artifacts, mutate GitHub
releases, or include credential material.

`Post Release Verification` in
`.github/workflows/post-release-verification.yml` can also be dispatched
manually and runs weekly on Ubuntu, macOS, and Windows. It re-runs the same
read-only verifier against the public release and uploads
`ao2-control-plane-post-release-verification-ubuntu`,
`ao2-control-plane-post-release-verification-macos`, and
`ao2-control-plane-post-release-verification-windows` evidence artifacts. Each
artifact contains an `ao2.cp-release-publication-closure.v1` summary proving
the published release remains downloadable and checksum-valid without mutating
GitHub releases or AO2 artifacts.

The same `Post Release Verification` workflow also runs
`AO2 release evidence hosted bridge drift monitor` on Ubuntu. That job
downloads AO2's latest successful `ao2-operator-release-evidence-bundle` from
GitHub Actions, starts the local control-plane server, verifies the
`ao2.cp-operator-release-evidence-bridge-smoke.v1` JSON/HTML readback path, and
uploads `ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke`.
This is a read-only drift monitor for the hosted AO2 release evidence bridge:
it can download public GitHub Actions artifacts, but it does not approve
releases, store credentials, publish tags, or mutate AO2 artifacts.

CI also runs `Release asset parity audit`, which uploads
`ao2-control-plane-release-asset-parity-audit`. Its `summary.json` uses schema
`ao2.cp-release-asset-parity-audit.v1` and compares the public release assets,
`SHA256SUMS`, and local release notes against the stable three-target archive
contract: Linux x86_64, macOS aarch64, and Windows x86_64. The default audit is
advisory and prints `control_plane_release_asset_parity=attention` when a
stable release is downloadable but incomplete, or when release-note archive
hashes drift from `SHA256SUMS`; set `AO2_CP_RELEASE_ASSET_PARITY_STRICT=1` when
the release publication workflow is ready to make those gaps fail the gate. The
audit is read-only: it does not approve AO2 runs, mutate AO artifacts, mutate
GitHub releases, or include credential material.

```bash
scripts/release-asset-parity-audit.sh
AO2_CP_RELEASE_ASSET_PARITY_STRICT=1 scripts/release-asset-parity-audit.sh
```

CI also runs `Public release pair verification`, which uploads
`ao2-control-plane-public-release-pair-verification`. Its `summary.json` uses
schema `ao2.cp-public-release-pair-verification.v1` and verifies the current
AO2 stable release (`v0.4.80`) and control-plane release (`v0.1.13`) as one
public release pair. Those stable defaults are read from
`docs/release/release-train.json`, which also records the next candidate train
(`v0.4.81` / `v0.1.14`). The verifier reads GitHub release metadata and
`SHA256SUMS` only; it checks common Linux x86_64, macOS aarch64, and Windows
x86_64 coverage, AO2 provenance/readiness assets, control-plane promotion
summary evidence, and checksum coverage for the published control-plane
evidence summary. It prints
`control_plane_public_release_pair_verification=passed` when the pair is
complete. It is read-only: it does not download large archives, approve AO2
runs, mutate AO artifacts, mutate GitHub releases, or include credential
material.

`Post Release Verification` also runs this verifier in strict mode on its
weekly/manual schedule and uploads
`ao2-control-plane-post-release-pair-verification`. That scheduled artifact is
the drift monitor for the public AO2/control-plane release pair: if a public
release asset, provenance sidecar, checksum entry, common platform, or
control-plane `summary.json` checksum disappears after merge, the scheduled
workflow fails instead of leaving the gap hidden until the next PR.

```bash
scripts/public_release_pair_verify.py \
  --summary-json target/public-release-pair-verification/summary.json
```

The script and CI wiring are guarded by `tests/test_public_release_pair_verify.py`.

CI also runs `AO2 stable promotion evidence index readback`, which downloads
AO2's latest successful `ao2-stable-promotion-evidence-index` artifact from the
`Stable Promotion Evidence Index` workflow and emits
`ao2.cp-ao2-stable-promotion-evidence-index-readback.v1`. This is the
control-plane readback for AO2's stable-promotion closure: it requires the
producer summary schema `ao2.stable-promotion-evidence-index.v1`, passed
artifact-size budget audit, post-release verification gate, public pair digest
audit, and stable release evidence packet. The command prints
`control_plane_ao2_stable_promotion_evidence_index_readback=passed` only when
the producer index is complete and its read-only trust boundary is intact:

```bash
scripts/verify_ao2_stable_promotion_evidence_index.py \
  --out-json target/ao2-stable-promotion-evidence-index-readback/summary.json
```

The script is guarded by
`tests/test_ao2_stable_promotion_evidence_index_readback.py`. It may download a
GitHub Actions artifact for readback, but it does not approve releases, mutate
AO2 artifacts, mutate GitHub releases, or allow provider API keys.

CI also runs `AO2 RSI claim-readiness readback`, which checks out AO2, runs
`npm run rsi:claim-readiness`, and emits
`ao2.cp-ao2-rsi-claim-readiness-readback.v1`. This is the control-plane
readback for AO2's local RSI claim boundary: it requires the producer schema
`ao2.rsi-claim-readiness-audit.v1`, `bounded_governed_rsi` allowed,
`full_autonomous_self_mutating_rsi` denied, and the missing full-claim evidence
blockers for mutation authority, rollback evidence, live self-change evidence,
observer readback, and Covenant claim-publish approval. The command prints
`control_plane_ao2_rsi_claim_readiness_readback=passed` only when the boundary
is enforced and the observer trust boundary remains read-only:

```bash
scripts/verify_ao2_rsi_claim_readiness.py \
  --claim-summary-json ../ao2/target/rsi-claim-readiness/latest/summary.json \
  --out-json target/ao2-rsi-claim-readiness-readback/summary.json
```

The script is guarded by `tests/test_ao2_rsi_claim_readiness_readback.py`. The
CI job uses explicit `Checkout AO2` and `npm run rsi:claim-readiness` steps and
uploads `ao2-control-plane-ao2-rsi-claim-readiness-readback`. It does not
approve RSI claims, mutate AO2 artifacts, mutate GitHub repositories, write
observer storage, or allow provider API keys.

CI also runs `AO2 RSI self-change dry-run readback`, which checks out AO2, runs
`npm run rsi:self-change-dry-run`, and emits
`ao2.cp-ao2-rsi-self-change-dry-run-readback.v1`. This is the control-plane
readback for AO2's governed self-change dry-run evidence: it requires the
producer schema `ao2.rsi-governed-self-change-dry-run.v1`, status
`dry_run_evidence_ready`, change class `verification_path_hardening`, a proposed
patch artifact, a rollback patch artifact, `planned_not_executed` rollback
status, `rollback_rehearsal` mode `executed_in_temporary_workspace`, and a
boundary that still denies `full_autonomous_self_mutating_rsi`.
The command prints
`control_plane_ao2_rsi_self_change_dry_run_readback=passed` only when the
observer remains read-only and confirms it did not apply AO2 patches:

```bash
scripts/verify_ao2_rsi_self_change_dry_run.py \
  --self-change-summary-json ../ao2/target/rsi-self-change-dry-run/latest/summary.json \
  --out-json target/ao2-rsi-self-change-dry-run-readback/summary.json
```

The script is guarded by
`tests/test_ao2_rsi_self_change_dry_run_readback.py`. The CI job uses explicit
`Checkout AO2` and `npm run rsi:self-change-dry-run` steps and uploads
`ao2-control-plane-ao2-rsi-self-change-dry-run-readback`. It does not approve
RSI claims, mutate AO2 artifacts, apply AO2 patches, mutate GitHub repositories,
write observer storage, or allow provider API keys.

CI also runs `AO2 dual-repo public approval closure readback`, which downloads
AO2's latest successful `ao2-dual-repo-public-approval-closure` artifact from
the `Dual Repo Public Approval Closure` workflow and emits
`ao2.cp-ao2-dual-repo-public-approval-closure-readback.v1`. This is the
control-plane readback for AO2's final public release go/no-go packet: it
requires the producer schema `ao2.dual-repo-public-approval-closure.v1`,
`release_go_no_go=go`, no producer failures, the AO2 checklist closure source,
the control-plane public release pair verification source, and the
control-plane AO2 stable promotion evidence readback source. The command prints
`control_plane_ao2_dual_repo_public_approval_closure_readback=passed` only when
the closure is complete and its trust boundary still shows the control plane
does not approve releases, mutate AO2 artifacts, mutate GitHub releases, or
allow provider API keys:

```bash
scripts/verify_ao2_dual_repo_public_approval_closure.py \
  --out-json target/ao2-dual-repo-public-approval-closure-readback/summary.json
```

The script is guarded by
`tests/test_ao2_dual_repo_public_approval_closure_readback.py`.

CI also runs `Active stack release handoff readback`, which consumes AO
Foundry's `examples/readiness/active-stack-readiness.ledger.json` and AO
Covenant's generated `covenant policy spine --json` output. It emits
`ao2.cp-active-stack-release-handoff-readback.v1` and prints
`control_plane_active_stack_release_handoff_readback=passed` only when the
active stack contains `ao2`, `ao2-control-plane`, `ao-foundry`, `ao-forge`,
`ao-command`, and `ao-covenant`; the Foundry release handoff includes
`foundry-release-candidate`, `forge-release-candidate-handoff`,
`covenant-policy-spine`, and `signed-smoke-release-gate`; and the Covenant
policy spine remains `ao2-first`.

```bash
scripts/verify_active_stack_release_handoff.py \
  --foundry-ledger ../ao-foundry/examples/readiness/active-stack-readiness.ledger.json \
  --covenant-policy-spine target/active-stack-release-handoff-readback/covenant-policy-spine.json \
  --out-json target/active-stack-release-handoff-readback/summary.json
```

The CI job uses explicit `Checkout AO Foundry` and `Checkout AO Covenant` steps,
generates the policy-spine JSON from AO Covenant, and uploads
`ao2-control-plane-active-stack-release-handoff-readback`. The script is guarded
by `tests/test_active_stack_release_handoff_readback.py` and remains read-only:
it does not approve releases, mutate AO2 artifacts, mutate GitHub releases,
write observer storage, or allow provider API keys.

The server can also expose the same producer summary as an authenticated
read-only operator surface. Set
`AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY` to the downloaded
`summary.json`; `/api/v1/release/stable-promotion-evidence.json` wraps the
`ao2.stable-promotion-evidence-index.v1` document in
`ao2.cp-stable-promotion-evidence-readback.v1`, and
`/api/v1/release/stable-promotion-evidence` renders the matching HTML view. Both
surfaces redact local paths and do not approve releases, store credentials,
publish tags, or mutate AO2 artifacts.

Release notes are generated from `SHA256SUMS` with
`scripts/generate_release_notes_from_checksums.py`, so archive hashes flow from
the published checksum manifest instead of a handwritten table:

```bash
python3 scripts/generate_release_notes_from_checksums.py \
  --version 0.1.13 \
  --tag v0.1.13 \
  --checksums dist-release/SHA256SUMS \
  --output docs/releases/v0.1.13-notes.md
```

The CI workflow also produces release-ready archive artifacts for all supported
targets on every pull request and `main` push. Open
<https://github.com/uesugitorachiyo/ao2-control-plane/actions> and download:

- `ao2-control-plane-release-archive-linux-x86_64`
- `ao2-control-plane-release-archive-macos-aarch64`
- `ao2-control-plane-release-archive-windows-x86_64`

`Release Promotion` in `.github/workflows/release-promotion.yml` is the
governed path for preparing the next control-plane release. It is manual and
uses `dry_run=true` by default for `v0.1.13`, building and smoking release
archives for Linux x86_64, macOS aarch64, and Windows x86_64 before assembling
the `ao2-control-plane-release-promotion-plan-<tag>` artifact. Before any
archive build starts, release promotion requires the latest successful
`Post Release Verification` run on `main` to expose all six baseline artifacts:
the Ubuntu, macOS, and Windows post-release verifier outputs,
`ao2-control-plane-post-release-pair-verification`, and
`ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke`, and
`ao2-control-plane-post-release-active-stack-release-handoff-readback`. The
preflight summary uses `ao2.cp-post-release-verification-baseline.v1` and is
embedded into the promotion plan. The baseline run must match the exact
promotion commit SHA, so stale post-release evidence from an older `main`
revision blocks promotion. That plan contains
`ao2.cp-release-promotion-plan.v1`, the consolidated `SHA256SUMS`, and release
notes generated from `SHA256SUMS` with the source commit and archive hashes.
`SHA256SUMS` covers the platform archives, `summary.json`, and
`post-release-baseline.json` evidence assets so post-release verification can
prove the release metadata did not drift. The plan records that AO2 release
acceptance remains owned by the factory-v3 evaluator closer and that the control
plane does not approve AO2 runs, mutate AO artifacts, or include credential
material. Publishing a GitHub release requires dispatching the workflow with
`dry_run=false`; the normal path only prepares evidence.

## Running tests

The public CI workflow runs on pull requests and pushes to `main`, and can also
be dispatched manually. Release archive smokes remain part of that CI pipeline,
while AO2 release approval stays outside this observer service.

`main` branch protection is documented in
[`docs/runbooks/branch-protection.md`](docs/runbooks/branch-protection.md).
Verify the live settings with `scripts/verify-branch-protection.sh`.
The same read-only verifier runs from
`.github/workflows/production-readiness-ops.yml` on manual dispatch and a daily
schedule. It reports `mode=full` with an admin-capable token and `mode=limited`
from GitHub Actions branch metadata when the built-in token cannot read the full
branch protection endpoint. The policy requires admin enforcement, linear history,
force-push protection, deletion protection, active branch rulesets without stale
required-check names, and the current CI, ingest, release archive, lint, audit,
and deny checks.

Before public-facing changes, run `scripts/check-public-repo-policy.sh` with the
license policy check. The scanner rejects tracked generated export artifacts,
private-key markers, high-confidence credential tokens, suspicious credential
assignments, private AO2 repository references, and machine-local paths outside
the redaction fixture/readback-test canary surface.

Two release-publication integration tests
(`audit_log_rotation_stays_well_formed_under_n500_burst_lane_bbb` and
`cockpit_count_matches_audit_log_under_concurrent_rejection_load_lane_ww`)
spawn 500 concurrent HTTP requests and exhaust the default file-descriptor
soft limit on Linux (1024) and macOS (256). Raise the soft limit before
running the full workspace test suite on those platforms:

```bash
ulimit -n 65536 && cargo test --workspace
```

Failure mode without the raise is `Os { code: 24, kind: Uncategorized,
message: "Too many open files" }` (EMFILE). Both Linux (hard cap
1,048,576) and macOS (hard cap unlimited for most users) allow the soft
limit raise without sudo. CI applies this same `ulimit` step automatically
in `.github/workflows/ci.yml`. Windows does not need the raise.

### Cross-OS smoke

`scripts/smoke-three-os.sh` is the fast dev-iteration cousin of
`scripts/smoke-three-os-release.sh`. It packages `git archive HEAD` into
a tarball, ships it to the Ubuntu (`AO2_CP_UBUNTU_SSH_TARGET`) and
Windows (`AO2_CP_WINDOWS_SSH_TARGET`, ProxyJump-capable) hosts, runs
`cargo test -p ao2-cp-server` on all three, and emits a single
`ao2.cp-smoke-three-os.v1` JSON summary at
`target/smoke-three-os/<ts>/summary.json`. Use it before pushing to
catch Windows or Linux drift early:

```bash
# Run all OSes with the full server test suite
scripts/smoke-three-os.sh

# Run a subset of tests only
scripts/smoke-three-os.sh --tests-only metrics_endpoint,status_endpoint

# Skip a host
scripts/smoke-three-os.sh --skip-windows
```

Exits 0 if every executed run passed, 1 if any failed, 2 on
orchestration error.

### PowerShell parity

A cross-OS PowerShell parity test for `Verify-ReleaseSupportBundle.ps1`
skips silently when `pwsh` (PowerShell 7+) is missing. To make a missing
`pwsh` fail loudly instead — for release-gate runs and dedicated
cross-OS smoke hosts — set `AO2_CP_REQUIRE_PWSH=1`:

```bash
AO2_CP_REQUIRE_PWSH=1 cargo test --release -p ao2-cp-server \
  --test release_packaging --test release_publication
```

Then in another terminal:

```bash
# Health check
curl http://127.0.0.1:8744/healthz

# Readiness check for operators / cron
curl http://127.0.0.1:8744/readyz

# Ingest a bundle produced by local ao2
curl -X POST \
  -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @~/Documents/ao2/target/provider-pilot-acceptance/v0.4.66/provider-pilot-acceptance.json \
  http://127.0.0.1:8744/api/v1/acceptance

# List
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  http://127.0.0.1:8744/api/v1/acceptance

# Ingest an AO2 memory export as read-only evidence
curl -X POST \
  -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @./memory-export.json \
  http://127.0.0.1:8744/api/v1/memory/export

# List ingested memory exports, or open the authenticated dashboard
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  http://127.0.0.1:8744/api/v1/memory/export
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  http://127.0.0.1:8744/api/v1/memory/export/dashboard
```

Signed memory exports produced by `ao2 memory export --signing-key ...` can be
published through `ao2 memory publish`; AO2 detects the `.json.sig` and
`memory-export-signing-public.pem` sidecars and posts a signed wrapper to
`/api/v1/memory/export/signed`. The signed wrapper includes the detached
signature bytes and public key PEM; the server verifies RSA/SHA-256 before
storing the export and rejects invalid signatures. Verification is implemented
with native Rust crypto, so production does not require an `openssl` executable
or temporary signature files.

Signed AO2 evidence packs can be posted to `/api/v1/evidence-pack/signed` as a
read-only observer feed. The control plane verifies the detached RSA/SHA-256
signature, stores the original `ao2.evidence-pack.v1` JSON by canonical digest,
and stores signature metadata as a sidecar. Open
`/api/v1/evidence-pack/dashboard` with the bearer token to review signed packs,
run IDs, verdicts, signer IDs, verification state, summary counters and verdict
counts for filtered views, and links to per-pack detail pages, raw packs, and
signature sidecars. The HTML dashboard mirrors the machine summary so operators
can scan total entries, gate-attention count, unverified signatures, and verdict
counts without copying bearer tokens into saved links. The detail page re-checks
the stored
evidence digest and sidecar identity before rendering signer, fingerprint, and
uploaded obligation-gate metadata. Use
`/api/v1/evidence-pack/dashboard?gate=attention` to list only packs whose
uploaded obligation gates failed, rejected, or still contain failed/unverified
rubric items. The dashboard also exposes saved read-only views for all signed
packs, gate attention, unverified signatures, and failed/rejected verdicts.
These endpoints observe completed AO2 evidence; they do not sit in AO2's local
trust path and cannot approve, modify, or close AO2 runs.
Local AO2 can publish to this endpoint with:

```bash
ao2 evidence publish \
  --evidence-pack .ao2/runs/<run-id>/evidence-pack/evidence-pack.json \
  --signing-key .release-signing/ao2-release-signing-key.pem \
  --signer-id local-operator \
  --control-plane-url http://127.0.0.1:8744 \
  --api-token-env AO2_CP_API_TOKEN \
  --json
```

The AO2 publish response includes authenticated dashboard/detail URLs and
signature fingerprint metadata. AO2 Workbench renders a local token-safe receipt
from that response so operators can inspect the stored digest and signer
fingerprint without placing the control-plane bearer token in a browser URL.

Storage retention is explicit and token protected. Use the report endpoint first
to estimate footprint and prune candidates without deleting anything:

```bash
curl -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/report?keep_latest=25"
```

The prune endpoint defaults to dry-run. It only removes old
`ao2-control-plane` observer copies and related signature sidecars; it never
touches local AO2 run directories, approvals, or trust-path artifacts. Add
`execute=true` only after reviewing the dry-run response:

```bash
curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/prune?keep_latest=25"

curl -X POST -H "Authorization: Bearer $AO2_CP_API_TOKEN" \
  "http://127.0.0.1:8744/api/v1/storage/prune?keep_latest=25&execute=true"
```

For out-of-band maintenance, the release archive ships `bin/ao2-cp-gc`
(`bin/ao2-cp-gc.exe` on Windows). It opens the same `--data-dir` the
server uses and applies the same count-based retention policy without
going through the HTTP API, so cron jobs can enforce bounded growth
without minting a bearer token. The binary always requires an explicit
mode (`--dry-run` or `--apply`) to avoid accidental deletion and emits
the prune result as JSON on stdout. See
[`docs/runbooks/storage-retention.md`](docs/runbooks/storage-retention.md)
for the operator runbook covering cross-OS scheduling examples.

```bash
ao2-cp-gc --data-dir ./data --keep-latest 100 --dry-run
ao2-cp-gc --data-dir ./data --keep-latest 100 --apply
```

The storage support-bundle contract is available at
`/api/v1/storage/support-bundle/contract.json`. It documents the stable
`ao2.cp-support-bundle.v1` consumer fields, including
`phase1_release_readiness.gap_summary`, `critical_path`, per-gap `gap_kind`,
read-only trust-boundary flags, portable endpoints, and digest-verification
expectations. Front ends should use this contract and the route index instead of
hard-coding support-bundle fields or bearer-token-bearing URLs.

Release support-bundle manifests at
`/api/v1/release/support-bundle/manifest.json` include a
`verifier_output_schema_sample` object. That sample is token-free and documents
the offline verifier JSON fields Hermes/factory-v3 can ingest after running
`python3 verify_release_support_bundle.py --json --checksums SHA256SUMS ...` on
macOS/Ubuntu or
`pwsh -File Verify-ReleaseSupportBundle.ps1 -Json -Checksums SHA256SUMS -Path ...`
on Windows. The sample is an observer contract only: it records digest/checksum
verification output, read-only trust-boundary fields, and secret-hygiene
constraints, but it does not approve releases or mutate AO2 artifacts.

AO2 Risky PR golden CI artifact manifests can be observed from the control
plane by setting `AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST` to AO2's generated
`artifact-manifest.json` path, for example
`../ao2/target/risky-pr-golden-ci/artifact-manifest.json` after the CI artifact
is downloaded locally. `/api/v1/risky-pr/golden/artifact-manifest.json` wraps the
`ao2.risky-pr-golden-artifact-manifest.v1` manifest in
`ao2.cp-risky-pr-golden-artifact-manifest-observer.v1` read-only metadata, and
`/api/v1/risky-pr/golden/artifact-manifest` renders the same artifact list as an
HTML operator view. These routes never store the manifest, expose bearer
material, approve releases, or mutate AO2 artifacts.

AO2 public release-train drill summaries can be observed the same way by
setting `AO2_CP_RELEASE_TRAIN_SUMMARY` to AO2's generated
`target/public-release-train-drill/latest/summary.json`. The
`/api/v1/release/train.json` route wraps the
`ao2.public-release-train-drill.v1` summary in
`ao2.cp-release-train-readback.v1` observer metadata, and
`/api/v1/release/train` renders a read-only operator dashboard. Both surfaces
redact local absolute paths and do not publish, approve, persist, or mutate AO2
release evidence.

AO2 release evidence bundles can be observed by setting
`AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY` to AO2's generated
`target/operator-release-evidence-bundle/latest/summary.json`. The
`/api/v1/release/operator-evidence.json` route wraps the
`ao2.operator-release-evidence-bundle.v1` summary in
`ao2.cp-operator-release-evidence-readback.v1` observer metadata, and
`/api/v1/release/operator-evidence` renders the same nine-check release
evidence set as an authenticated dashboard, including the AO2
`ao2-dual-public-release-smoke` task-board readback/dashboard schemas, the
`ao2-public-release-pair-digest-audit` full archive parity check, and read-only
trust-boundary fields. Both surfaces redact local absolute paths and remain
read-only: they do not approve releases, store credentials, publish tags, or
mutate AO2 artifacts.

AO2 release evidence bridge smoke proves the hosted AO2 artifact can be
consumed by this control plane. CI runs the fixture-backed smoke across Ubuntu,
macOS, and Windows:

```bash
cargo build --release -p ao2-cp-server
python3 scripts/smoke-operator-release-evidence-bridge.py \
  --summary crates/ao2-cp-server/tests/fixtures/operator-release-evidence-bundle-summary.json
```

For live AO2 release evidence verification, first run or wait for AO2's `Operator Release
Evidence Audit` workflow, then download the latest successful
`ao2-operator-release-evidence-bundle` artifact and exercise the readback
routes in one command:

```bash
cargo build --release -p ao2-cp-server
python3 scripts/smoke-operator-release-evidence-bridge.py \
  --download-latest-ao2-artifact
```

Both modes emit `ao2.cp-operator-release-evidence-bridge-smoke.v1` under
`target/operator-release-evidence-bridge-smoke/`, including token-free JSON and
HTML captures plus server logs.

CI also runs `AO2 release evidence hosted bridge smoke` on Ubuntu after
the three-OS fixture smoke passes. That gate downloads the latest successful
AO2 `ao2-operator-release-evidence-bundle` artifact from GitHub Actions, starts
the local control-plane server, verifies JSON/HTML readback, and uploads
`ao2-control-plane-operator-release-evidence-hosted-bridge-smoke`. It remains a
read-only release-readiness check: it can download GitHub Actions artifacts, but
it does not approve releases, store credentials, publish tags, or mutate AO2
artifacts.

For an end-to-end local bridge smoke, first generate the AO2-side bridge
manifest into this repository, then run the control-plane observer smoke:

```bash
(cd ../ao2 && npm run risky-pr:control-plane-bridge -- --control-plane-root ../ao2-control-plane)
scripts/smoke-risky-pr-golden-bridge.sh
```

The smoke starts a local `ao2-cp-server` with
`AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST` pointing at
`target/risky-pr-golden-control-plane-bridge/artifact-manifest.json`, fetches the
JSON and HTML observer endpoints with `Authorization: Bearer` headers only, and
writes a token-free `ao2.cp-risky-pr-golden-bridge-smoke.v1` summary under
`target/`. It is observer-only: it does not approve releases, mutate AO2
artifacts, persist the manifest, or allow provider API keys.

CI also runs a fixture-backed variant of this smoke across Ubuntu, macOS, and
Windows via `scripts/smoke-risky-pr-golden-bridge.py` and
`tests/fixtures/risky-pr-golden-artifact-manifest.json`. That fixture path keeps
the trust-boundary contract continuously checked on pull requests without
depending on a sibling AO2 checkout. Each CI job uploads the full smoke
evidence directory, including `summary.json`, the JSON/HTML observer captures,
and server stdout/stderr logs for triage.

CI also runs a fixture-backed release-train bridge smoke across Ubuntu, macOS,
and Windows via `scripts/smoke-release-train-bridge.py` and
`tests/fixtures/public-release-train-summary.json`. The smoke starts a local
server with `AO2_CP_RELEASE_TRAIN_SUMMARY`, fetches
`/api/v1/release/train.json` and `/api/v1/release/train`, verifies
`ao2.cp-release-train-readback.v1` over the AO2
`ao2.public-release-train-drill.v1` summary, and uploads the full token-free
evidence directory. The fixture carries the manifest-backed `next_patch`
targets so candidate rehearsal output can be observed before public release
assets exist. It checks that local absolute paths are redacted and that
the control plane remains a read-only observer with no release approval or
artifact mutation authority.

Operators can inspect the stable CI evidence contract from the authenticated
CI evidence index at `/api/v1/ci/evidence-index.json`, or the HTML view at
`/api/v1/ci/evidence-index`. The index schema is
`ao2.cp-ci-evidence-index.v1`; it lists the Risky PR golden bridge smoke,
release-train bridge smoke, ingest smoke, release archive smoke, and
backup/restore drill artifact families with schema versions and trust-boundary
metadata. It is read-only observer metadata and does not approve releases,
mutate AO2 artifacts, or embed bearer material. The route index also advertises
this under `portable_artifacts` as `ci_evidence_index` so schedulers and
dashboards can discover the HTML and JSON surfaces without hard-coding endpoint
paths.

## Endpoints

All `/api/v1/*` endpoints require `Authorization: Bearer $AO2_CP_API_TOKEN`.
`/` is a public local landing page, and `/healthz` plus `/readyz` are public
operational checks. The landing page links to authenticated dashboards but does
not embed bearer tokens; operators should inject the header from local tooling
instead of putting tokens in browser URLs.

For browser-friendly local review without putting the bearer token in a URL,
generate dashboard snapshots:

```bash
export AO2_CP_API_TOKEN="$(cat target/long-lived-control-plane/api-token)"
python3 scripts/cp_dashboard_snapshot.py \
  --base-url http://127.0.0.1:18745 \
  --out-dir target/cp-dashboard-snapshots/latest \
  --open
```

Windows PowerShell:

```powershell
$env:AO2_CP_API_TOKEN = Get-Content target\long-lived-control-plane\api-token
.\scripts\cp-dashboard-snapshot.ps1 `
  -BaseUrl http://127.0.0.1:18745 `
  -OutDir target\cp-dashboard-snapshots\latest `
  -Open
```

The helper sends `Authorization: Bearer` only as an HTTP header, writes local
HTML/JSON snapshots plus `manifest.json`, and fails closed if a response body
contains the bearer value. It is read-only observer tooling; it does not approve
releases, start providers, or mutate AO artifacts. The generated snapshot set
includes `ci-evidence-index.html` and `ci-evidence-index.json` so operators can
review the production-readiness CI evidence contract without browsing with a
bearer token.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Public local landing page with health links, authenticated dashboard links, and token-safe access guidance. |
| `GET` | `/healthz` | Public liveness check with server version. |
| `GET` | `/readyz` | Public readiness check for API-token configuration and writable storage. |
| `POST` | `/api/v1/acceptance` | Ingest signed provider acceptance evidence. |
| `GET` | `/api/v1/acceptance` | List acceptance evidence. |
| `GET` | `/api/v1/acceptance/dashboard` | Render an authenticated read-only provider-pilot acceptance dashboard. |
| `GET` | `/api/v1/acceptance/dashboard.json` | Fetch provider-pilot acceptance trend JSON for Hermes/front-end integrations. |
| `GET` | `/api/v1/acceptance/:sha` | Fetch original acceptance evidence by canonical SHA-256. |

The acceptance dashboard reports `source_class` per bundle plus live/fixture
counts. Live source class is derived from AO2-owned
`target/provider-pilot-acceptance` evidence or explicit `source_class: "live"`
metadata in the bundle; copied fixtures remain visible as fixture evidence.
Provider-readiness artifacts can be ingested unsigned at `/api/v1/provider/readiness` or as a detached RSA/SHA-256 signed observer upload at `/api/v1/provider/readiness/signed`. Signed uploads use schema `ao2.cp-provider-readiness-signed-upload.v1`, store the original `factory-v3/hermes-provider-phase1-readiness/v1` artifact by canonical digest, and retain a token-free signature sidecar at `/api/v1/provider/readiness/:sha/signature`. The detail and dashboard JSON surfaces expose signature verification state and signer metadata without putting bearer tokens in links. By default these signatures are `cryptographic-only` observer metadata using the uploaded public key as a non-authoritative trust anchor. Operators may set `AO2_CP_PROVIDER_READINESS_TRUSTED_KEY_SHA256S` (or `--provider-readiness-trusted-key-sha256s`) to a comma-separated allow-list of public-key SHA-256 digests; matching signed provider-readiness sidecars are then marked with `trust_policy.release_authoritative=true`, `verification_scope=cryptographic-and-pinned-key`, and a configured-key trust anchor while the control plane remains a read-only observer. Phase 1 support-bundle readiness treats a present but non-authoritative provider-readiness signature sidecar as an `untrusted_signature` blocking gap so observer-only upload-key signatures cannot be mistaken for release-authoritative evidence.

The Phase 1 promotion dashboard correlates the latest provider-readiness
artifact with live provider acceptance evidence and marks release-gate and
three-OS smoke proof as external AO2/factory-v3 requirements. It is observer
only; it cannot run the release gate or approve a promotion.
The Phase 1 promotion history endpoint lists recent checklists, signed
decisions, and three-OS smoke observer artifacts so Hermes/front-end surfaces can
audit promotion evidence over time without copying commands or mutating AO
artifacts. The gap report includes an observer-only `operator_action_queue` and
dependency-sorted `critical_path` so Hermes can show which governed
factory-v3/evaluator-closer step is ready to start without approving or mutating
AO2 artifacts. It also exposes a newest-first `timeline` array that normalizes
each artifact kind, SHA-256, raw URL, decision signature URL/verified flag, and
read-only trust-boundary flags for queue surfaces that need one chronologically
ordered audit stream. The storage support-bundle also includes the history
endpoint in its operator handoff links and summarizes available
provider-readiness, Phase 1 decision, and release-evaluator signature sidecars
with only sanitized verification fields (algorithm, verified flag, signer id,
public-key digest, trust anchor, scope, and raw sidecar URL). It never embeds
uploaded public-key PEM material or bearer-token-bearing URLs, so Hermes and AO
Operator dashboards can discover the promotion audit trail from one authenticated
read-only bundle.

AO2 release-publication summaries can be posted to
`/api/v1/release/publication` after the governed release workflow has shipped a
tag. The release dashboard observes publication state, provenance tag match,
download verification, rollback status, release doctor status, and archive
targets without entering the release trust path. AO2 owns evaluator closure and
release acceptance. AO2 materializes closure evidence separately after it
compares release-readiness inputs with the control-plane observer state. The
control plane may observe the surrounding signed evidence, but it must not
produce or approve that evaluator decision.
When running `scripts/smoke-three-os-release.sh` for a Phase 1 release
candidate, set `AO2_CP_RELEASE_CANDIDATE_VERSION` to the AO2 candidate version
under review. The smoke summary keeps that separate from `AO2_CP_VERSION`, which
is the control-plane component/package version. Release handoff and readiness
surfaces use the candidate version to block cross-candidate evidence mixups.
The release support bundle also includes embedded `ao2.cp-release-assembly.v1`
and `ao2.cp-release-evaluator-decision-dashboard.v1` sections. The assembly is
the portable same-candidate manifest for operators: it records the release
candidate version, required artifact SHA-256 values, provider acceptance
candidate versions, candidate correlation status, and the fact that factory-v3
evaluator-closer remains the release acceptance owner. The evaluator-decision
section is a read-only observer copy of the Factory v3 evaluator-closer dashboard
so offline handoff reviewers can verify final release acceptance context without
granting the control plane approval authority. Its
`portable_bundle_manifest.integrity` block records AO2 Control Plane canonical
JSON SHA-256 digests for each embedded support-bundle surface so offline macOS,
Ubuntu, and Windows reviewers can verify copied or archived surfaces with the
same project canonicalizer without contacting the read-only control plane again.
Operators can also open `/api/v1/release/support-bundle/manifest.json` for a
compact scheduler-safe index containing the bundle filename, canonical bundle
digest, surface check summary, download/verification links, and explicit
read-only handoff metadata without embedding bearer tokens. Open
`/api/v1/release/support-bundle/verify` for an
authenticated read-only HTML verification view, or
`/api/v1/release/support-bundle/verify.json` for the machine-readable digest
check result. Exported bundle copies can be verified offline without a server:

```bash
python3 scripts/fetch_release_support_handoff.py \
  --base-url http://127.0.0.1:8744 \
  --out-dir target/release-handoff \
  --keep-latest 7
python3 scripts/verify_release_support_bundle.py target/release-handoff/release-support-bundle.json
python3 scripts/verify_release_support_bundle.py --json target/release-handoff/release-support-bundle.json
python3 scripts/verify_release_support_bundle.py --checksums target/release-handoff/SHA256SUMS target/release-handoff/release-support-bundle.json
pwsh -File scripts/Verify-ReleaseSupportBundle.ps1 -Path target/release-handoff/release-support-bundle.json
pwsh -File scripts/Verify-ReleaseSupportBundle.ps1 -Json -Path target/release-handoff/release-support-bundle.json
pwsh -File scripts/Verify-ReleaseSupportBundle.ps1 -Checksums target/release-handoff/SHA256SUMS -Path target/release-handoff/release-support-bundle.json
```

`tests/fixtures/release-support-bundle-contract-v1.json` is the mirrored
AO2/control-plane release-support contract fixture. AO2 verifies the same
bundle shape with `ao2 release support-bundle-verify`; ao2-control-plane
verifies this copy with the offline verifier above so producer and consumer
schema drift is caught in tests. CI's `Release support fixture parity with AO2`
job checks out both public repos, compares the mirrored fixture byte-for-byte,
and uploads `ao2-control-plane-release-support-fixture-parity` with SHA-256
evidence.

When the mirrored fixture or a strict CI evidence family requirement changes,
open AO2 and ao2-control-plane PRs with the same branch name in both
repositories. The parity jobs check out the matching peer branch when present;
using different branch names makes each PR compare against the other repository's
old `main` fixture and creates a false circular failure.

The helper fetches `/api/v1/release/support-bundle/handoff.json`, the portable bundle, checksums, verifier JSON, and manifest JSON into the output directory. It reads the bearer value from `AO2_CP_AUTH_VALUE`, writes a sanitized `fetch-summary.json`, and records `auth_value_stored=false`; do not paste bearer values into command-line arguments or committed artifacts.

The offline verifier requires exactly the eight required surfaces (CI evidence
index, install verification, assembly, readiness, handoff, cockpit, evaluator
decision, and storage support), matching manifest and integrity digests,
expected JSON paths, and a read-only trust boundary. The optional JSON mode is
intended for Hermes/scheduler ingestion: it preserves the verifier exit code,
includes `failures` on rejection, and repeats `control_plane_role=read_only_observer` plus
`release_acceptance_owner=factory-v3 evaluator-closer` so automation does not
mistake the observer check for release approval. When `--checksums` / `-Checksums`
is provided, the verifier also confirms the canonical bundle digest is present
in the downloaded `SHA256SUMS` file and emits `checksum_verified` in JSON output.
The PowerShell path supports Windows PowerShell 5.1 and PowerShell 7+.

| `POST` | `/api/v1/control-plane/bundle` | Ingest fleet/control-plane bundle evidence. |
| `GET` | `/api/v1/control-plane/bundle` | List fleet/control-plane bundle evidence. |
| `GET` | `/api/v1/control-plane/bundle/:sha` | Fetch original fleet/control-plane bundle by canonical SHA-256. |
| `GET` | `/api/v1/control-plane/routes.json` | Fetch the token-free route index for Hermes/front-end discovery of read-only observer, portable download, signed evidence/memory, and factory-v3 evaluator-owned surfaces. The index includes a `portable_artifacts` section that groups the CI evidence index, gap reports, and support bundles with JSON, HTML, download, checksum, manifest, and verification links so schedulers do not need to infer handoff surfaces from the full route list. The index is regression-tested against frontend-relevant static routes to reduce discovery drift without placing credentials in URLs. |
| `GET` | `/api/v1/ci/evidence-index` | Render an authenticated read-only HTML index of production-readiness CI evidence families, including bridge, ingest, release archive, backup/restore, and stable-promotion readback artifacts. |
| `GET` | `/api/v1/ci/evidence-index.json` | Fetch the machine-readable `ao2.cp-ci-evidence-index.v1` contract for CI evidence artifact names, schema versions, and read-only trust-boundary metadata. |
| `POST` | `/api/v1/evidence-pack/signed` | Verify and ingest a signed `ao2.evidence-pack.v1` observer wrapper, storing signature metadata as a sidecar. |
| `GET` | `/api/v1/evidence-pack` | List ingested AO2 evidence packs. |
| `GET` | `/api/v1/evidence-pack/dashboard` | Render an authenticated read-only dashboard for signed AO2 evidence packs. |
| `GET` | `/api/v1/evidence-pack/:sha/detail` | Render an authenticated read-only detail page for one signed AO2 evidence pack. |
| `GET` | `/api/v1/evidence-pack/:sha/detail.json` | Fetch structured read-only detail JSON for one signed AO2 evidence pack. |
| `GET` | `/api/v1/evidence-pack/run/:run_id/latest` | Fetch structured detail JSON for the newest signed evidence pack matching a run id. |
| `GET` | `/api/v1/evidence-pack/:sha/signature` | Fetch signed evidence-pack sidecar metadata by evidence-pack SHA-256, after sidecar identity validation. |
| `GET` | `/api/v1/evidence-pack/:sha` | Fetch original AO2 evidence pack by canonical SHA-256. |
| `POST` | `/api/v1/memory/export` | Ingest an `ao2.memory-export.v1` export as read-only evidence. |
| `POST` | `/api/v1/memory/export/signed` | Verify and ingest a signed memory export wrapper, storing signature metadata as a sidecar. |
| `GET` | `/api/v1/memory/export` | List ingested AO2 memory exports. |
| `GET` | `/api/v1/memory/export/dashboard` | Render an authenticated HTML dashboard of memory exports. |
| `GET` | `/api/v1/memory/export/:sha/signature` | Fetch signed-export sidecar metadata by export SHA-256. |
| `GET` | `/api/v1/memory/export/:sha` | Fetch original AO2 memory export by canonical SHA-256. |
| `GET` | `/api/v1/phase1/promotion/dashboard` | Render an authenticated read-only Phase 1 promotion checklist across readiness, acceptance, release-gate, and three-OS smoke proof. |
| `GET` | `/api/v1/phase1/promotion/dashboard.json` | Fetch the Phase 1 promotion checklist as JSON for Hermes/front-end integrations. |
| `GET` | `/api/v1/phase1/promotion/operator-panel` | Render a read-only Phase 1 operator panel that mirrors Hermes/factory promotion posture without approving or mutating AO artifacts. |
| `GET` | `/api/v1/phase1/promotion/operator-panel.json` | Fetch the Phase 1 operator panel as JSON for front ends and support bundles. |
| `GET` | `/api/v1/phase1/promotion/operator-support-bundle.json` | Fetch the portable read-only Phase 1 operator support bundle. The bundle embeds dashboard, gap report, operator panel, promotion history, newest-first promotion timeline, and per-entry canonical timeline digests for offline evaluator handoff without moving approval into the observer. |
| `GET` | `/api/v1/phase1/promotion/operator-support-bundle/download` | Download the same operator support bundle with attachment headers, deterministic observer timestamp, digest header, and read-only observer metadata. |
| `GET` | `/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS` | Download token-free SHA-256 checksums for the operator support bundle. |
| `POST` | `/api/v1/phase1/promotion/operator-support-bundle/verify` | Render read-only HTML verification for a submitted operator support bundle by recomputing embedded promotion timeline canonical digests and comparing them with `timeline_integrity`. This does not ingest, approve, or mutate AO artifacts. |
| `POST` | `/api/v1/phase1/promotion/operator-support-bundle/verify.json` | Fetch machine-readable verification for a submitted operator support bundle, including per-entry expected/actual canonical SHA-256 values and tamper/mismatch counts. |
| `GET` | `/api/v1/phase1/promotion/gap-report.json` | Fetch only the machine-readable Phase 1 blocking gap report for schedulers and operator handoff artifacts. |
| `GET` | `/api/v1/phase1/promotion/gap-report/download` | Download the same gap report with attachment headers, digest header, and read-only observer metadata. |
| `GET` | `/api/v1/phase1/promotion/gap-report/SHA256SUMS` | Download token-free SHA-256 checksums for the portable gap report. |
| `GET` | `/api/v1/phase1/promotion/portable-manifest` | Render an authenticated HTML manifest of portable Phase 1 observer artifacts, digests, and download/checksum links without approving or mutating AO artifacts. |
| `GET` | `/api/v1/phase1/promotion/portable-manifest.json` | Fetch the machine-readable portable Phase 1 manifest for Hermes/factory-v3 handoff bundles, including digest scope and trust-boundary metadata. |
| `GET` | `/api/v1/phase1/promotion/portable-manifest/download` | Download the same portable manifest with attachment headers, a SHA-256 header, deterministic observer timestamp, and read-only observer metadata. |
| `GET` | `/api/v1/phase1/promotion/portable-manifest/SHA256SUMS` | Download token-free SHA-256 checksums for the portable Phase 1 manifest itself. |
| `GET` | `/api/v1/phase1/promotion/history.json` | Fetch recent Phase 1 checklists, signed decisions, and three-OS smoke proof as read-only promotion history. |
| `GET` | `/api/v1/risky-pr/golden/artifact-manifest` | Render an authenticated read-only HTML view of AO2's Risky PR golden CI artifact manifest configured by `AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST`. |
| `GET` | `/api/v1/risky-pr/golden/artifact-manifest.json` | Fetch the machine-readable `ao2.cp-risky-pr-golden-artifact-manifest-observer.v1` wrapper around AO2's generated artifact manifest without storing or mutating AO2 evidence. |
| `GET` | `/api/v1/release/cockpit` | Render an authenticated read-only release cockpit that correlates release publication, Phase 1, provider registry, readiness, acceptance, storage observer surfaces, and latest provider acceptance details. |
| `GET` | `/api/v1/release/cockpit.json` | Fetch the release cockpit as JSON for Hermes/front-end integrations, including detailed latest Codex/Claude provider acceptance summaries and raw evidence links. |
| `GET` | `/api/v1/release/handoff` | Render an authenticated read-only Phase 1 release-candidate handoff panel for operators and Hermes front ends. |
| `GET` | `/api/v1/release/handoff.json` | Fetch a read-only Phase 1 release-candidate handoff package for Hermes/factory-v3, correlating cockpit, signed decision, live provider acceptance, and three-OS evidence without approving or mutating AO artifacts. |
| `GET` | `/api/v1/release/train` | Render an authenticated read-only AO2 public release-train drill readback configured by `AO2_CP_RELEASE_TRAIN_SUMMARY`, with local paths redacted and no release approval authority. |
| `GET` | `/api/v1/release/train.json` | Fetch the machine-readable `ao2.cp-release-train-readback.v1` wrapper around AO2's `ao2.public-release-train-drill.v1` summary without storing, publishing, or mutating AO2 evidence. |
| `GET` | `/api/v1/release/operator-evidence` | Render an authenticated read-only AO2 operator release evidence dashboard configured by `AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY`, with local paths redacted and no release approval authority. |
| `GET` | `/api/v1/release/operator-evidence.json` | Fetch the machine-readable `ao2.cp-operator-release-evidence-readback.v1` wrapper around AO2's `ao2.operator-release-evidence-bundle.v1` summary without storing, publishing, or mutating AO2 evidence. |
| `GET` | `/api/v1/release/stable-promotion-evidence` | Render an authenticated read-only AO2 stable-promotion evidence dashboard configured by `AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY`, with blockers, required evidence families, trust boundary, and local paths redacted. |
| `GET` | `/api/v1/release/stable-promotion-evidence.json` | Fetch the machine-readable `ao2.cp-stable-promotion-evidence-readback.v1` wrapper around AO2's `ao2.stable-promotion-evidence-index.v1` summary without storing, publishing, approving, or mutating AO2 evidence. |
| `GET` | `/api/v1/release/readiness` | Render an authenticated read-only release-readiness verdict that summarizes handoff gates and explicitly defers acceptance to factory-v3 evaluator-closer. |
| `GET` | `/api/v1/release/readiness.json` | Fetch the machine-readable release-readiness verdict for Hermes/factory-v3 checklists without approving or mutating AO artifacts. |
| `GET` | `/api/v1/release/support-bundle.json` | Fetch the portable read-only release support bundle, including embedded same-candidate `release_assembly` and evaluator-decision dashboard surfaces for offline factory-v3 evaluator-closer review. |
| `GET` | `/api/v1/release/support-bundle/manifest.json` | Fetch a compact scheduler-safe support-bundle manifest with filename, canonical digest, surface check summary, and download/verification links. |
| `GET` | `/api/v1/release/support-bundle/download` | Download the same portable release support bundle with `Content-Disposition`, canonical bundle digest, and read-only observer headers for cross-platform operator handoff. |
| `GET` | `/api/v1/release/support-bundle/verify` | Render an authenticated read-only HTML verification view for release support-bundle embedded surface digests and trust-boundary posture. |
| `GET` | `/api/v1/release/support-bundle/verify.json` | Fetch the machine-readable release support-bundle embedded surface digest verification result. |
| `POST` | `/api/v1/provider/registry` | Ingest AO2 provider/plugin registry evidence as read-only observer data. |
| `POST` | `/api/v1/provider/registry/signed` | Verify and ingest a signed AO2 provider/plugin registry, storing signature metadata as a sidecar. |
| `GET` | `/api/v1/provider/registry` | List ingested provider registry artifacts. |
| `GET` | `/api/v1/provider/registry/latest` | Fetch the newest raw provider registry artifact by canonical SHA-256. |
| `GET` | `/api/v1/provider/registry/dashboard` | Render an authenticated read-only provider registry dashboard. |
| `GET` | `/api/v1/provider/registry/dashboard.json` | Fetch provider registry posture as JSON, including latest signature state, provider guards, and operator links. |
| `GET` | `/api/v1/provider/registry/:sha/detail` | Render authenticated provider registry detail with signature and evidence links. |
| `GET` | `/api/v1/provider/registry/:sha/detail.json` | Fetch provider registry detail as JSON. |
| `GET` | `/api/v1/provider/registry/:sha/signature` | Fetch signed registry sidecar metadata by registry SHA-256. |
| `GET` | `/api/v1/provider/registry/:sha` | Fetch one raw provider registry artifact by canonical SHA-256. |
| `POST` | `/api/v1/provider/readiness` | Ingest Hermes/AO2 Phase 1 provider readiness evidence as read-only observer data. |
| `GET` | `/api/v1/provider/readiness` | List ingested provider readiness artifacts. |
| `GET` | `/api/v1/provider/readiness/latest` | Fetch the newest provider readiness artifact by canonical SHA-256. |
| `GET` | `/api/v1/provider/readiness/dashboard` | Render an authenticated read-only provider readiness dashboard. |
| `GET` | `/api/v1/provider/readiness/dashboard.json` | Fetch the provider readiness dashboard as JSON for Hermes/front-end integrations, including readiness trend totals, Phase 1 blockers, and safe next actions. |
| `GET` | `/api/v1/provider/readiness/support-bundle.json` | Fetch the portable read-only provider readiness support bundle for operator/evaluator handoff. |
| `GET` | `/api/v1/provider/readiness/support-bundle/download` | Download the provider readiness support bundle with attachment headers and read-only observer metadata. |
| `GET` | `/api/v1/provider/readiness/support-bundle/SHA256SUMS` | Download token-free SHA-256 checksums for the provider readiness support bundle. |
| `GET` | `/api/v1/provider/readiness/:sha/detail` | Render authenticated detail for one provider readiness artifact with evidence/memory links. |
| `GET` | `/api/v1/provider/readiness/:sha/detail.json` | Fetch provider readiness detail as JSON. |
| `GET` | `/api/v1/provider/readiness/:sha` | Fetch one raw provider readiness artifact by canonical SHA-256. |
| `POST` | `/api/v1/release/publication` | Ingest an `ao2.release-publication-summary.v1` observer artifact after a governed release ship. |
| `GET` | `/api/v1/release/publication/latest` | Fetch the newest release-publication summary by canonical SHA-256. |
| `GET` | `/api/v1/release/publication/dashboard` | Render an authenticated read-only release-publication dashboard. |
| `GET` | `/api/v1/release/publication/dashboard.json` | Fetch release publication state, provenance, rollback, and archive health for Hermes/front-end integrations. |
| `GET` | `/api/v1/release/publication/:sha` | Fetch one raw release-publication summary by canonical SHA-256. |
| `POST` | `/api/v1/release/evaluator-decision` | Ingest a `factory-v3/ao2-release-evaluator-decision/v1` evaluator-closer decision as read-only observer data. |
| `GET` | `/api/v1/release/evaluator-decision/latest` | Fetch the newest evaluator-closer release decision by canonical SHA-256. |
| `GET` | `/api/v1/release/evaluator-decision/dashboard` | Render an authenticated read-only evaluator decision dashboard without approving the release. |
| `GET` | `/api/v1/release/evaluator-decision/dashboard.json` | Fetch evaluator decision state, blockers, release tag, and trust-boundary fields for Hermes/front-end integrations. |
| `GET` | `/api/v1/release/evaluator-decision/:sha` | Fetch one raw evaluator-closer release decision by canonical SHA-256. |
| `GET` | `/api/v1/storage/report?keep_latest=N` | Report storage footprint and prune candidates without deleting observer copies. |
| `GET` | `/api/v1/storage/dashboard` | Render the authenticated read-only storage dashboard. |
| `GET` | `/api/v1/storage/dashboard.json` | Fetch storage dashboard JSON for Hermes/front-end observer surfaces. |
| `GET` | `/api/v1/storage/support-bundle.json` | Fetch the storage support bundle manifest for portable observer-retention review. |
| `GET` | `/api/v1/storage/support-bundle/download` | Download the storage support bundle with attachment headers and digest metadata. |
| `GET` | `/api/v1/storage/support-bundle/contract.json` | Fetch the token-free support-bundle consumer contract for stable Phase 1 readiness fields, gap classification, trust-boundary flags, and portable endpoints. |
| `GET` | `/api/v1/storage/support-bundle/SHA256SUMS` | Download token-free storage support bundle checksums. |
| `POST` | `/api/v1/storage/prune?keep_latest=N` | Dry-run storage pruning. Add `execute=true` to delete old observer copies and rewrite the control-plane index. |
| `GET` | `/api/v1/metrics` | Prometheus exposition v0.0.4 — request counters by method × status_class, request duration sum/count, in-flight gauge, storage index gauge, audit-log counters (`ao2_cp_audit_log_appended_total`, `..._rotated_total`, `..._persistence_errors_total`, `..._dropped_total`), and audit-log gauges (`ao2_cp_audit_log_file_bytes`, `ao2_cp_audit_log_oldest_resident_age_seconds`). See [`deploy/README.md`](deploy/README.md#prometheus-scraping) for scrape config. |
| `GET` | `/api/v1/status` | Structured `ao2.cp-status.v1` JSON — build info (version, target, profile), storage stats (index entries, on-disk bytes), retention pressure pct, request totals + error rate + in-flight, process uptime, and an `audit_log` block (`capacity`, `buffered`, `total_appended_since_boot`, `persistence.{enabled,path,last_error,rotation.{max_bytes,count,last_rotated_unix_micros}}`). Token-gated dashboard view of liveness/readiness data. |
| `GET` | `/api/v1/audit-log` | Bounded ring buffer of recent requests as `ao2.cp-audit-log.v1` JSON. Query params: `limit`, `since_unix_micros`, `method`, `status`, `status_class`, `path_prefix`, `authenticated`. Bearer-token value is never copied into entries. Buffer capacity is `AO2_CP_AUDIT_LOG_CAPACITY` (default 1024). |
| `GET` | `/api/v1/audit-log/dashboard` | Render an authenticated read-only HTML dashboard of the audit-log ring buffer: capacity/buffered cards, persistence + rotation panels, the same query filters as the JSON surface, a status-class-coloured recent-request table, and an explicit trust-boundary footer. Same query params as `/api/v1/audit-log`. |
| `GET` | `/api/v1/audit-log/dashboard.json` | Fetch the same dashboard payload as `ao2.cp-audit-log-dashboard.v1` JSON for Hermes/front-end integrations — `links`, `trust_boundary`, `buffer` telemetry (capacity, buffered, total_appended_since_boot, persistence + rotation), and the filtered recent entries. Same query params as `/api/v1/audit-log`. Bearer-token value is never copied into the response. |
| `GET` | `/api/v1/audit-log/stream` | Server-Sent Events tail of audit-log entries (`event: audit-log`, `id: <timestamp_unix_micros>`, JSON `data:` payload). Accepts the same filter query params as `/api/v1/audit-log` (`method`, `status`, `status_class`, `path_prefix`, `authenticated`); also accepts `last_event_id=<micros>` or the standard `Last-Event-ID` request header to replay buffered entries strictly newer than the supplied id before the live tail begins. Bearer-token gated; emits a 15 s keepalive comment to keep proxies honest. Lossy under load — a `event: lagged` notice tells clients to backfill via `/api/v1/audit-log?since_unix_micros=...`. |

### Structured access log

Every HTTP request emits exactly one JSON line to stderr (via the
`ao2_cp_server::access` tracing target) with fields: `method`, `path`,
`status`, `duration_micros`, `auth_attempted`, `authenticated`. The
bearer token value is never recorded — only the presence of the
`Authorization` header and the resulting status. Use `RUST_LOG` to
control verbosity; e.g. `RUST_LOG=ao2_cp_server::access=info` to keep
only the request log.

### Audit-log operator endpoint

The same request metadata recorded by the access-log middleware is
also appended to a bounded in-process ring buffer surfaced by
`GET /api/v1/audit-log` (token-gated). Operators get a queryable
newest-first view over HTTPS with filters by method, status, status
class, path prefix, authentication outcome, and a wall-clock
`since_unix_micros` boundary — no stderr grep required. The buffer
capacity (`AO2_CP_AUDIT_LOG_CAPACITY`, default `1024`) caps resident
memory at ~200 KiB; appends past capacity evict the oldest entry.

For audit history that survives restart, set `AO2_CP_AUDIT_LOG_FILE`
to a writable path. Each entry is then mirrored to that file as
newline-delimited JSON (one entry per line, flushed on every append)
in addition to the ring buffer. The file is opened append-only —
existing history is preserved across restart, and `tail -f` works
out of the box. Persistence is independent of the ring-buffer
capacity: setting capacity to `0` keeps zero in memory but still
appends every entry to disk if a file path is configured.

For bounded growth, set `AO2_CP_AUDIT_LOG_MAX_BYTES=<bytes>`. Once
the live file grows past the threshold, it is renamed to
`<path>.1` (replacing any prior sidecar) and a fresh file is
opened at the original path. There is only **one historical
generation** — no `.2`, no compression, no time-based rotation.
Operators who want richer retention pipe the live NDJSON file into
their own log shipper (`logrotate`, `vector`, `fluent-bit`); the
built-in rotation exists to guarantee disk-usage stays bounded
when no shipper is configured, not to be a fully-featured log
manager. Rotation state is reported alongside other persistence
telemetry under `audit_log.persistence.rotation` on both
`/api/v1/status` and `/api/v1/audit-log`:

- `rotation.max_bytes` — configured threshold, or `null` when
  rotation is disabled and the file grows without bound.
- `rotation.count` — total rotations since boot. Spikes above
  the operator's expected cadence indicate runaway traffic or a
  too-small threshold; zero across a busy interval indicates the
  threshold has never been reached.
- `rotation.last_rotated_unix_micros` — wall-clock micros of the
  most recent rotation, or `null` if none has occurred this
  process lifetime.

A read-only HTML view of the same buffer is available at
`GET /api/v1/audit-log/dashboard` and its machine-readable twin at
`/api/v1/audit-log/dashboard.json` (schema
`ao2.cp-audit-log-dashboard.v1`). The HTML surface accepts the same
query filters as `/api/v1/audit-log` (`limit`, `since_unix_micros`,
`method`, `status`, `status_class`, `path_prefix`, `authenticated`)
and renders four telemetry cards (ring buffer, persistence, rotation,
filtering) plus a status-class-coloured table of the filtered recent
entries. The JSON twin emits the identical telemetry under a `buffer`
block alongside `links`, `trust_boundary`, and `entries` so Hermes
can poll either surface. Path strings rendered into the HTML are
HTML-escaped at write time; raw query strings drive percent-decoded
audit-log entries but never reach the rendered HTML body, so an
attacker cannot smuggle a `<script>` tag through a crafted URL.

Shared implementation in `crates/ao2-cp-server/src/audit_log.rs` and
`handlers/audit_log.rs`; regression coverage in
`tests/audit_log_endpoint.rs` (14 tests covering auth, ordering,
filters, bounded-eviction, bearer-token redaction, NDJSON
persistence, persistence-across-restart, size-based rotation, the
new HTML + JSON dashboard surfaces, and HTML-injection defence
through the dashboard).

#### NDJSON shipper integration helper

For operators piping the audit-log NDJSON into Vector, Fluent Bit,
NXLog, or a `logrotate`-managed rolling archive, ship the
`scripts/ship-audit-log.sh` (Mac/Linux) and
`scripts/ship-audit-log.ps1` (Windows) helpers. Both read the live
NDJSON file (and optionally the rotated `<path>.1` sidecar) and copy
it to stdout, ready to be piped into the downstream shipper. The
helpers discover the persistence path by reading
`/api/v1/status` with the configured bearer (set
`AO2_CP_API_TOKEN` or pass `--token`/`-Token`); operators who
already know the path can pass `--path`/`-Path` directly and
skip the round-trip. With `--follow`/`-Follow` the helpers tail
the live file with `tail -F` (bash) or `Get-Content -Wait`
(PowerShell) so they keep producing across rotation events
without operator intervention. The bearer is forwarded only as
an `Authorization` header on the status round-trip; it is never
written to stdout or stderr, and the audit-log NDJSON itself
already redacts bearer values at write time.

Example: pipe authenticated audit-log NDJSON into Vector on Linux:

```
AO2_CP_API_TOKEN=$(cat /etc/ao2-cp/token) \
  scripts/ship-audit-log.sh --include-rotated --follow \
  | vector --quiet -c /etc/vector/audit-log.toml
```

Example: pipe the live file into a Fluent Bit `stdin` input on
Windows (PowerShell):

```
$env:AO2_CP_API_TOKEN = Get-Content C:\ao2-cp\token
.\scripts\ship-audit-log.ps1 -IncludeRotated -Follow `
  | C:\fluent-bit\bin\fluent-bit.exe -i stdin -o stdout
```

Regression coverage in
`crates/ao2-cp-server/tests/audit_log_shipper.rs` (4 cross-OS
integration tests: live-file streaming with bearer redaction,
rotated-sidecar prefix, bearer-missing rejection, and the
`--path`/`-Path` override that skips the status round-trip).
The same test logic runs on bash (Mac/Linux) and PowerShell
(Windows), so `scripts/smoke-three-os.sh` exercises both
helpers byte-identically.

#### Audit-log rotation drill

To prove the bounded-growth path on a host, run the portable rotation
drill. It starts an ephemeral CP with `AO2_CP_AUDIT_LOG_FILE` and a
small `AO2_CP_AUDIT_LOG_MAX_BYTES`, drives authenticated observer
traffic, then verifies `/api/v1/status`, `/api/v1/metrics`, the live
NDJSON file, and the rotated `.1` sidecar:

```bash
cargo build -p ao2-cp-server
scripts/cp-audit-log-rotation-drill.sh \
  --server-bin target/debug/ao2-cp-server \
  --work-dir target/audit-log-rotation-drill/manual \
  --out target/audit-log-rotation-drill/manual/rotation-report.json
```

On Windows, use `scripts/cp-audit-log-rotation-drill.ps1` with the
same server binary, work directory, and output path. The report schema
is `ao2.cp-audit-log-rotation-drill.v1`; it is read-only observer
evidence and does not include bearer-token values.

#### Periodic health snapshot helper

For nightly or cron-driven evidence, use
`scripts/cp-health-snapshot.sh` on Mac/Linux or
`scripts/cp-health-snapshot.ps1` on Windows. Both call the shared
`scripts/cp_health_snapshot.py` implementation, read
`/api/v1/healthz/extended` with `--api-token-env`, scan local log
files for ERROR/WARN/PANIC counters, and emit
`ao2.cp-health-snapshot.v1` JSON:

```bash
AO2_CP_API_TOKEN="$(cat /etc/ao2-cp/token)" \
  scripts/cp-health-snapshot.sh \
    --base-url http://127.0.0.1:8744 \
    --api-token-env AO2_CP_API_TOKEN \
    --log-dir /var/log/ao2-cp-server \
    --out /var/log/ao2-cp-server/health-snapshot.json
```

The snapshot is read-only observer evidence. It does not mutate AO
artifacts, does not include bearer-token values, and records log
finding counts only, not raw log lines.

#### Disaster-recovery restore drill

Before depending on a long-lived control-plane backup, run the portable
restore drill. It starts an ephemeral CP, ingests fixture evidence,
archives the content-addressed data directory, restores it into a fresh
directory, and verifies restored readback is byte-identical by SHA:

```bash
cargo build -p ao2-cp-server
scripts/cp-dr-restore-drill.sh \
  --server-bin target/debug/ao2-cp-server \
  --work-dir target/dr-restore-drill/manual \
  --out target/dr-restore-drill/manual/dr-restore-report.json
```

On Windows, use `scripts/cp-dr-restore-drill.ps1` with the same
server binary, work directory, and output path. The report schema is
`ao2.cp-dr-restore-drill.v1`; it is read-only observer evidence and
does not include bearer-token values.

Both `/api/v1/status` and `/api/v1/audit-log` expose the same
audit-log telemetry block so a dashboard can poll either surface:

- `capacity` — configured ring-buffer slots.
- `buffered` — currently resident entries (post-eviction).
- `total_appended_since_boot` — monotonic count of every append
  this process has performed since startup; survives ring eviction
  and lets dashboards estimate request rate without keeping every
  entry resident.
- `persistence.enabled` — whether `AO2_CP_AUDIT_LOG_FILE` is set.
- `persistence.path` — configured file path, or `null` when
  persistence is disabled.
- `persistence.last_error` — most recent persistence write/serialise
  error message (non-clearing peek), or `null` when there has been
  no failure since boot. Use this on a dashboard panel to surface
  silent persistence breakage (e.g. `ENOSPC`) without the operator
  having to grep stderr.

### Content-addressed observer caching

Every content-addressed `GET /api/v1/…/:sha` endpoint supports a
strong RFC-7232 ETag (`"<sha>"`), `Cache-Control: public, max-age=60,
must-revalidate`, an `If-None-Match` short-circuit returning `304`
without re-reading the body, and a parallel `HEAD` route emitting only
headers. The 304 path avoids the disk read entirely. Endpoints
covered: `/acceptance/:sha`, `/control-plane/bundle/:sha`,
`/evidence-pack/:sha`, `/memory/export/:sha`,
`/phase1/promotion/{checklist,decision,three-os-smoke}/:sha`,
`/provider/readiness/:sha`, `/provider/registry/{latest,:sha}`,
`/release/{publication,evaluator-decision}/:sha`. Shared
implementation lives in `crates/ao2-cp-server/src/handlers/caching.rs`
and is regression-tested by `tests/observer_caching.rs` (10 tests, one
per endpoint × four properties) and `tests/provider_registry_caching.rs`.

See also `docs/superpowers/specs/2026-05-19-ao2-control-plane-v01-design.md`.

## Configuration

| Env var | Flag | Default | Required |
|---|---|---|---|
| `AO2_CP_BIND` | `--bind` | `127.0.0.1:8744` | no |
| `AO2_CP_DATA_DIR` | `--data-dir` | `./data` | no |
| `AO2_CP_API_TOKEN` | `--api-token` | — | **yes** |
| `AO2_CP_LOG_LEVEL` | `--log-level` | `info` | no |
| `AO2_CP_MAX_BODY_BYTES` | `--max-body-bytes` | `10485760` | no |
| `AO2_CP_AUDIT_LOG_CAPACITY` | `--audit-log-capacity` | `1024` | no |
| `AO2_CP_AUDIT_LOG_FILE` | `--audit-log-file` | _(unset)_ | no |
| `AO2_CP_AUDIT_LOG_MAX_BYTES` | `--audit-log-max-bytes` | _(unset, no rotation)_ | no |

## Security

See `docs/SECURITY.md`. Highlights:
- Bearer-token auth on all `/api/v1/*` endpoints
- Server refuses to start if `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is set (forbidden-env preflight)
- Content-addressed storage (SHA-256 over AO2 canonical JSON v1 / `ao2-canonical-v1`) — tampering is detectable on GET
- Signed memory exports and evidence-pack observer uploads fail closed unless the detached RSA/SHA-256 signature verifies against the supplied public key
- Evidence-pack observer endpoints are read-only and remain outside the AO2 local trust path
- Release-publication observer endpoints are read-only and cannot approve or mutate releases
- Storage pruning is opt-in, token protected, dry-run by default, and scoped to `ao2-control-plane` observer copies
- Native signature verification keeps the same behavior on macOS, Ubuntu, and Windows without shelling out
- No native TLS in v0.1; terminate at a reverse proxy or LAN/VPN. Drop-in Caddy and nginx templates (with TLS + per-IP rate limiting + provider-key header strip) ship in [`deploy/caddy/Caddyfile.example`](deploy/caddy/Caddyfile.example) and [`deploy/nginx/ao2-cp-server.conf.example`](deploy/nginx/ao2-cp-server.conf.example).

## Status

v0.1 — see GitHub releases.

## License

Apache-2.0
