# Runbook: release smoke triage

Audience: release operators triaging a failing three-OS release smoke
or a downgraded `candidate_correlation` / `candidate_correlation_parity`
verdict on cockpit / handoff / readiness.

Trust boundary: this runbook is **read-only**. The control plane never
mutates AO artifacts, never approves a release, and never embeds bearer
tokens / provider keys / cookies / credentials in shell commands or
status output. Every step below is a JSON read or a script invocation
against locally-checked-out evidence — there is no path here that
writes back to AO.

---

## AO2 risky PR golden bridge smoke

Use `scripts/smoke-risky-pr-golden-bridge.sh` when validating that AO2's Risky
PR golden CI artifact manifest can be observed by the control plane without
crossing the release-approval trust boundary. The script starts a local
`ao2-cp-server`, points `AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST` at
`target/risky-pr-golden-control-plane-bridge/artifact-manifest.json`, and fetches
both `/api/v1/risky-pr/golden/artifact-manifest.json` and
`/api/v1/risky-pr/golden/artifact-manifest` with the bearer token carried only in
the `Authorization: Bearer` header.

```sh
(cd ../ao2 && npm run risky-pr:control-plane-bridge -- --control-plane-root ../ao2-control-plane)
scripts/smoke-risky-pr-golden-bridge.sh
```

Expected output is a token-free summary path and
`risky_pr_golden_bridge_smoke=passed`. The summary schema is
`ao2.cp-risky-pr-golden-bridge-smoke.v1`. This is still a read-only observer
check: `control_plane_approves_release=false`, `mutates_ao_artifacts=false`, no
provider API keys are allowed, and no bearer material is written into URLs,
HTML, JSON, or status output.

Pull-request CI runs the same trust-boundary check with
`scripts/smoke-risky-pr-golden-bridge.py` against
`tests/fixtures/risky-pr-golden-artifact-manifest.json` on Ubuntu, macOS, and
Windows. Use the CI fixture result to verify cross-OS behavior; use the AO2
bridge command above when validating a freshly generated AO2 artifact manifest.
The CI artifact is the full smoke evidence directory: `summary.json`, captured
JSON/HTML observer responses, and server stdout/stderr logs.

The authenticated CI evidence index at `/api/v1/ci/evidence-index.json`
summarizes the stable production-readiness artifact families under
`ao2.cp-ci-evidence-index.v1`: Risky PR golden bridge smoke, release-train
bridge smoke, ingest smoke, release archive smoke, and backup/restore drill. Use
it as the operator-facing map from CI job names to artifact names and schema
versions before downloading individual GitHub Actions artifacts.

## Control-plane release publication closure

Use `scripts/release-download-verify.sh` to verify the public
`ao2-control-plane` prerelease without mutating GitHub releases or AO2
artifacts. The script downloads the configured release tag, verifies every asset
listed in `SHA256SUMS`, and can emit a token-free closure summary:

```sh
AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON=target/release-publication-closure/summary.json \
  scripts/release-download-verify.sh
```

Expected output includes `control_plane_release_publication_closure=passed`. The
summary schema is `ao2.cp-release-publication-closure.v1`; it lists downloaded
asset names, sizes, SHA-256 digests, the checksum manifest path, and a
trust-boundary block showing `control_plane_approves_release=false`,
`mutates_ao_artifacts=false`, `mutates_github_releases=false`, and
`credential_material_included=false`.

Pull-request CI runs the same check in the `Release publication closure` job and
uploads the `ao2-control-plane-release-publication-closure` artifact. Use that
hosted artifact as the control-plane counterpart to AO2's release-publication
closure evidence when checking whether both repositories have public,
downloadable, checksum-valid release assets.

`Post Release Verification` in
`.github/workflows/post-release-verification.yml` can be dispatched manually and
also runs weekly. It runs the same read-only release verifier on Ubuntu, macOS,
and Windows, then uploads per-OS evidence artifacts:
`ao2-control-plane-post-release-verification-ubuntu`,
`ao2-control-plane-post-release-verification-macos`, and
`ao2-control-plane-post-release-verification-windows`. Each artifact includes an
`ao2.cp-release-publication-closure.v1` `summary.json` with
`checksum_verified=true` and trust-boundary values showing the verifier does not
approve AO2 runs, mutate AO artifacts, mutate GitHub releases, or include
credential material.

## Control-plane release asset parity audit

Use `scripts/release-asset-parity-audit.sh` to verify that the public
`ao2-control-plane` stable release assets, `SHA256SUMS`, and local release notes
agree on the expected release surface. The expected platform archives are Linux
x86_64, macOS aarch64, and Windows x86_64, plus the release-support and
release-train evidence JSON assets published beside the archive files.

```sh
scripts/release-asset-parity-audit.sh
AO2_CP_RELEASE_ASSET_PARITY_STRICT=1 scripts/release-asset-parity-audit.sh
```

Release notes are generated from `SHA256SUMS`; generate or repair the local
release-notes hash table from the checksum manifest instead of editing archive
hashes by hand:

```sh
python3 scripts/generate_release_notes_from_checksums.py \
  --version 0.1.13 \
  --tag v0.1.13 \
  --checksums dist-release/SHA256SUMS \
  --output docs/releases/v0.1.13-notes.md
```

Expected output is `control_plane_release_asset_parity=passed` for a complete
stable release, or `control_plane_release_asset_parity=attention` when the
release is checksum-valid but missing platform archives or release-note parity.
The summary schema is `ao2.cp-release-asset-parity-audit.v1`; it lists published
assets, checksum entries, release-note archive names and hashes, missing assets,
release-note checksum drift, and the read-only trust boundary. Default CI keeps
this audit advisory so a known partial public release remains visible without
blocking unrelated PRs. Use `AO2_CP_RELEASE_ASSET_PARITY_STRICT=1` in the
release-publication path once the Linux and Windows archives are attached to the
stable release.

Pull-request CI runs the audit in the `Release asset parity audit` job and
uploads `ao2-control-plane-release-asset-parity-audit` for operator review.

## AO2/control-plane public release pair verification

Use `scripts/public_release_pair_verify.py` to verify that the public AO2 stable
release and public control-plane release still form a complete production
release pair. The verifier reads GitHub release metadata and `SHA256SUMS`
manifests only; it does not download large archives, upload assets, edit
releases, approve AO2 runs, or mutate AO artifacts.

```sh
scripts/public_release_pair_verify.py \
  --summary-json target/public-release-pair-verification/summary.json
```

Expected output includes
`control_plane_public_release_pair_verification=passed`. The summary schema is
`ao2.cp-public-release-pair-verification.v1`; it records AO2 `v0.4.80`,
control-plane `v0.1.13`, their common Linux x86_64, macOS aarch64, and Windows
x86_64 release coverage, AO2's provenance/readiness assets, the control-plane
promotion summary evidence, checksum coverage for `summary.json`, and a
read-only trust boundary. Use `--strict` in release-promotion or stable-channel
gates when missing public assets or missing evidence checksum entries should
fail immediately instead of producing an advisory `attention` summary.

If a historical release has `summary.json` uploaded but not listed in
`SHA256SUMS`, repair only the checksum manifest: download `summary.json`,
append its SHA-256 as `summary.json`, re-upload `SHA256SUMS`, and rerun this
verifier plus `scripts/release-download-verify.sh`.

Pull-request CI runs the same check in the `Public release pair verification`
job and uploads `ao2-control-plane-public-release-pair-verification`. Use that
artifact when reviewing whether AO2 and the control plane are releasable
together, not just individually. The script and CI wiring are guarded by
`tests/test_public_release_pair_verify.py`.

## AO2 release train bridge smoke

Use the release train bridge smoke to verify that AO2's public
`ao2.public-release-train-drill.v1` summary can be read back through the
control plane as `ao2.cp-release-train-readback.v1`. Pull-request CI runs the
fixture-backed `scripts/smoke-release-train-bridge.py` path on Ubuntu, macOS,
and Windows using `tests/fixtures/public-release-train-summary.json`.

The smoke starts a local `ao2-cp-server`, sets
`AO2_CP_RELEASE_TRAIN_SUMMARY`, and fetches both
`/api/v1/release/train.json` and `/api/v1/release/train` with the bearer token
carried only in the `Authorization: Bearer` header. The evidence directory
contains `summary.json`, `release-train-readback.json`,
`release-train-readback.html`, and server stdout/stderr logs. Expected output
is `release_train_bridge_smoke=passed`.

This check is read-only: `control_plane_approves_release=false`,
`mutates_ao_artifacts=false`, `mutates_observer_storage=false`, no provider API
keys are allowed, bearer material is not printed, and local absolute paths from
the source summary are redacted before JSON/HTML readback.

## 1. The two parity verdicts

Operators see two related-but-independent verdicts on every
release-publication-shaped surface (cockpit, handoff, readiness,
publication dashboard, assembly support bundle, phase-1 operator panel,
phase-1 promotion dashboard, phase-1 portable manifest):

| Field                              | Source                                                              | Computed how                                                                       | Possible values                                       |
|------------------------------------|---------------------------------------------------------------------|------------------------------------------------------------------------------------|-------------------------------------------------------|
| `candidate_correlation`            | Server-computed from five ingestion sources                         | `candidate_correlation_value()` inspects release_version/tag, three-OS smoke version, evaluator version/tag, codex version, claude version | `matched`, `mismatched`, `missing`                    |
| `candidate_correlation_parity`     | Lifted off the most recent three-OS smoke ingestion (Lane Q)         | `scripts/smoke-three-os-release.sh` `compute_parity()` aggregates per-OS smoke logs | `matched`, `mismatched`, `missing`, `drift`, `unknown` |

Both verdicts are registered as hard readiness gates (correlation since
Lane J, parity since Lane S). A downgrade on either gate flips
readiness from `ready` to `attention` and adds a blocker line.

The two verdicts answer different questions:

- `candidate_correlation` answers: *do the five canonical evidence
  sources name the same release?*
- `candidate_correlation_parity` answers: *did the three OSes that
  smoke-tested this release independently agree on what
  candidate_correlation should be?*

Lane T proved by existence proof that the two verdicts can disagree:
canonical version evidence can align across all five sources
(`candidate_correlation=matched`) while the three per-OS smokes
disagreed on candidate_correlation (`candidate_correlation_parity=drift`).
Treat both as load-bearing gates.

---

## 2. Triage by parity verdict

### 2.1 `candidate_correlation_parity=drift`

A drift verdict means the three OSes produced different
`candidate_correlation` values when their per-OS smokes ran. Examples:
macOS reported `matched`, Ubuntu reported `mismatched`, Windows
reported `matched`.

Most likely root causes (in observed-frequency order):

1. **One OS pulled a stale archive.** A per-OS smoke that resolved an
   older `release_candidate_version` than the other two will report
   `mismatched`. Check the `version` and `release_candidate_version`
   fields on each per-OS smoke summary.
2. **One OS pulled stale evaluator / acceptance evidence.** The smoke
   verifies its own ingested evidence against the locally-resolved
   release version. If an SSH-driven Ubuntu or Windows smoke ran
   against a different `~/.ao2-cp/` state than the macOS local smoke,
   it can land at a different verdict even with an identical archive.
3. **Genuinely tampered archive.** A drift verdict that survives a
   re-run on all three OSes against a known-good archive is the
   strongest signal we have today that the archive itself differs
   across the three machines.

#### Triage commands

The orchestrator host writes per-OS smoke output to
`target/three-os-release-smoke/<timestamp>/`. The relevant files:

```
target/three-os-release-smoke/<timestamp>/
├── summary.json            # aggregator output: candidate_correlation_parity + per-target candidate_correlation_status
├── report.md               # human-readable summary with per-OS verdicts
├── macos.log               # macOS smoke stdout (includes candidate_correlation_status=<status>)
├── ubuntu.log              # Ubuntu smoke stdout (same trailer)
├── windows.log             # Windows smoke stdout (same trailer)
├── ubuntu-command.sh       # SSH command file that produced ubuntu.log
└── windows-command.ps1     # SSH command file that produced windows.log
```

Start with the top-level verdict and the three per-target verdicts:

```sh
jq '{
  parity: .candidate_correlation_parity,
  macos: .targets.macos.candidate_correlation_status,
  ubuntu: .targets.ubuntu.candidate_correlation_status,
  windows: .targets.windows.candidate_correlation_status
}' target/three-os-release-smoke/<timestamp>/summary.json
```

Then read the `candidate_correlation_status=<value>` trailer line on
each per-OS log to confirm where the disagreement came from. Each
per-OS smoke emits its verdict on stdout via this exact format, so:

```sh
grep '^candidate_correlation_status=' target/three-os-release-smoke/<timestamp>/macos.log
grep '^candidate_correlation_status=' target/three-os-release-smoke/<timestamp>/ubuntu.log
grep '^candidate_correlation_status=' target/three-os-release-smoke/<timestamp>/windows.log
```

If two OSes agree on `matched` and a third reports `mismatched`, the
third is the suspect. Read that OS's log from the top and look for the
five ingestion endpoints (`/api/v1/release/publication`,
`/api/v1/phase1/promotion/three-os-smoke`,
`/api/v1/release/evaluator-decision`, `/api/v1/acceptance` for codex,
`/api/v1/acceptance` for claude). The mismatch will be in whichever
ingestion source reports a different version than the others.

### 2.2 `candidate_correlation_parity=mismatched`

All three OSes ran their smokes and all three reported the *same*
non-matched verdict (e.g., all three reported `mismatched`). This is
typically a canonical-evidence issue, not an OS-isolation issue. Treat
it as if `candidate_correlation` itself was the failing gate and
triage from the five ingestion sources upstream.

### 2.3 `candidate_correlation_parity=missing`

No three-OS smoke has been ingested by this control-plane instance, or
the most recently ingested smoke was malformed. The `parity=missing`
default is intentional (Lane R) — a downgraded server that lost its
smoke ingestion MUST NOT silently default to `matched`.

Recovery: run the three-OS smoke and re-ingest. The smoke writes to
`target/three-os-release-smoke/<timestamp>/summary.json` and emits the
JSON via the aggregator's `POST /api/v1/phase1/promotion/three-os-smoke`
trailing call.

### 2.4 `candidate_correlation_parity=unknown`

The smoke ran but at least one per-OS log did not emit a parseable
`candidate_correlation_status=<value>` trailer line. The aggregator's
`compute_parity()` returns `unknown` when it cannot extract one of the
three per-target statuses. Read each per-OS log from the bottom and
confirm the trailer line was emitted; the most common cause is the
per-OS smoke exiting before reaching the cross-surface parity check.

### 2.5 `candidate_correlation_content_hash_parity=drift`

A second, independent parity gate added in Lane V. Where
`candidate_correlation_parity` compares only the single
`candidate_correlation_status` *string* across OSes,
`candidate_correlation_content_hash_parity` compares a sha256 of the
**full normalized `.candidate_correlation` subtree** (status,
blockers array, anything else nested under that key) from each per-OS
cockpit. A content-hash drift can fire while status-level parity
reports `matched` — for example, when all three OSes agree on
`status=matched` but one OS's `blockers` array contains an extra
warning that the others don't.

The aggregator fetches each per-OS `release-cockpit.json` back to
the orchestrator host (`cp` for macOS, `scp` over the BatchMode=yes
SSH targets for Ubuntu and Windows) and writes them under
`target/three-os-release-smoke/<timestamp>/fetched-<os>/release-cockpit.json`.
Diff-by-hand workflow:

```sh
SMOKE_ROOT=target/three-os-release-smoke/<timestamp>
for os in macos ubuntu windows; do
  echo "=== $os ==="
  jq -cS '.candidate_correlation' "$SMOKE_ROOT/fetched-$os/release-cockpit.json"
done
```

The OS whose normalized output differs from the other two is the
suspect. Diff pairwise to localize which field drifted:

```sh
diff <(jq -cS '.candidate_correlation' "$SMOKE_ROOT/fetched-macos/release-cockpit.json") \
     <(jq -cS '.candidate_correlation' "$SMOKE_ROOT/fetched-ubuntu/release-cockpit.json")
```

Most likely root causes (in observed-frequency order):

1. **One OS's local server picked up extra evidence the others didn't.**
   A blockers-array entry from a stale evidence source on one machine
   that wasn't cleaned up between smoke runs.
2. **Schema-version skew across OSes.** A newer server build on one
   machine added a field to `.candidate_correlation` that the older
   build on another machine doesn't emit yet. This typically
   coincides with `version` mismatch on each per-OS smoke summary.
3. **Genuinely tampered server on one OS.** A content-hash drift
   that reproduces across multiple smoke runs against the same
   archive is a strong signal of host-level compromise on the
   dissenting OS.

### 2.6 `candidate_correlation_content_hash_parity=unknown`

The fetch step failed for at least one OS (`scp` couldn't reach the
remote, `jq` or `sha256sum`/`shasum` was missing from PATH on the
orchestrator, or the per-OS cockpit was malformed). Read the
aggregator stdout for the line
`candidate_correlation_content_hash_parity=unknown (macos=<hash> ubuntu=<hash> windows=<hash>)`
to see which OS landed at `missing` vs. `unknown` and triage from
that machine's smoke log.

---

## 3. Triage by `candidate_correlation` verdict

(For completeness — these predate the parity gate, but operators still
hit them often enough to belong in the same runbook.)

### 3.1 `candidate_correlation=mismatched`

At least one of the five canonical evidence sources reports a
`release_candidate_version` (or release tag, codex/claude provider
version) that disagrees with the others. The `blockers` array on the
cockpit / handoff / readiness JSON spells out which fields disagreed.

### 3.2 `candidate_correlation=missing`

At least one of the five sources has not been ingested. The blockers
array names the missing source(s).

---

## 4. Reference: the Lane T test as a worked example

The integration test
`candidate_correlation_parity_gate_fires_independently_when_three_os_smoke_reports_drift`
in `crates/ao2-cp-server/tests/release_publication.rs` POSTs an
exact-shape fixture where:

- `release_publication_fixture()` reports `release_candidate_version=0.4.79`
- `release_evaluator_decision_fixture()` reports `release.version=0.4.79`
- The codex and claude acceptance fixtures both pin
  `release_candidate_version=0.4.79`
- The three-OS smoke fixture reports
  `release_candidate_version=0.4.79` (so the canonical chain agrees)
- The smoke's per-target `candidate_correlation_status` values are
  `{macos: matched, ubuntu: mismatched, windows: matched}`
- The aggregator-computed `candidate_correlation_parity` is `drift`

The expected post-ingestion state:

- `candidate_correlation=matched` (canonical evidence aligns)
- `candidate_correlation_parity=drift`
- `gate_results[candidate_correlation].status=passed`
- `gate_results[candidate_correlation_parity].status=blocked`
- `readiness.status != "ready"`
- `blockers` includes a line mentioning `candidate_correlation_parity`
- cockpit HTML renders `warn">drift` in the Three-OS smoke parity row

If a real-world drift looks like this, the triage path is: re-run the
Ubuntu smoke in isolation (since it's the dissenting OS) and confirm
whether the disagreement is reproducible. A reproducible disagreement
points at section 2.1 root cause 1 or 2; a non-reproducible
disagreement points at root cause 3 (genuinely tampered archive) and
should be escalated.

---

## 5. Triage by ingestion-time rejection (Lane KK + LL + MM + QQ)

The control plane will refuse to record a three-OS release smoke
artifact if it fails server-side validation. The 422 response body
carries the reason, but the request is otherwise transient — operators
should start at the cockpit / handoff / readiness HTML instead of
trying to capture the response body live.

### 5.1 Where to look first

All three operator-facing HTML surfaces — `/api/v1/release/cockpit`,
`/api/v1/release/handoff`, `/api/v1/release/readiness` — now render a
**Rejected Smoke Ingestions** section (Lane MM on cockpit, Lane QQ on
the other two). The section is the durable audit trail surface:

- **Total rejected: 0 (ok-styled).** No tampering attempts observed
  since the storage root was provisioned. The forensic-record layer
  is reachable; nothing further to do.
- **Total rejected: N >= 1 (warn-styled).** Each row corresponds to
  one append to the Lane LL audit log
  `<storage-root>/rejected-three-os-smoke.jsonl`. The most recent
  timestamp + rejection reason render directly on the HTML.

### 5.2 Reading the audit log

The audit log lives at `<storage-root>/rejected-three-os-smoke.jsonl`
(append-only JSON-lines, schema `ao2.cp-rejected-three-os-smoke.v1`).
Each record carries only an allowlist of fields:

- `timestamp_utc` — when the 422 was returned
- `rejection_reason` — the server diagnostic that named the constraint
- `body_sha256` + `body_size_bytes` — fingerprint of the rejected
  payload (the raw body is NEVER persisted)
- `posted_summary` — strict allowlist: `schema`, `status`, `version`,
  `release_candidate_version`, `source_commit_short` (12 chars only),
  `source_dirty`, `candidate_correlation_parity`,
  `surface_content_hash_parity`, per-target `status` strings

Authorization tokens, provider keys, cookies, and credentials cannot
leak via the audit log because they're not on the allowlist.

### 5.3 Triage by Lane KK rejection reason

#### `three-OS release smoke source_commit must be a 40-char lowercase hex git sha1; got "<value>"`

The aggregator (`scripts/smoke-three-os-release.sh`) always emits
`source_commit="$(git rev-parse HEAD)"`, which is unconditionally a
40-char lowercase hex SHA. A 422 here means the ingestion was either:

1. **Hand-crafted** with a placeholder (`"unknown"`, `"TODO"`,
   `"fake"`) — operator was testing the ingestion path. Re-run the
   real aggregator.
2. **Short SHA** (39 chars or fewer) — the orchestrator was running
   in a shallow clone where `git rev-parse` returned a truncated
   value. Re-clone with full depth and re-run.
3. **Uppercase hex** — never emitted by `git rev-parse` on any
   supported platform. If you see this in the audit log, treat it as
   a genuinely tampered ingestion and escalate.

#### `three-OS release smoke top-level status disagrees with server-side recomputation from per-target evidence: posted=passed, recomputed=failed (all_targets_passed=true, source_dirty=true)`

The orchestrator emitted `source_dirty=true` (the source tree had
uncommitted changes) but still claimed `status=passed`. Lane KK's
tightened recomputation requires `all_targets_passed && !source_dirty`
for `recomputed=passed`. Triage:

1. **The aggregator was run from a dirty worktree.** Stash or commit
   the local changes, then re-run the aggregator. The `source_dirty`
   flag will flip to `false` and ingestion will succeed.
2. **The orchestrator's reporting is lying about dirtiness.** Check
   `git status` on the orchestrator host. If clean, the dirty bit was
   injected — escalate as tampered.

#### `three-OS release smoke top-level status disagrees with server-side recomputation from per-target evidence: posted=passed, recomputed=failed (all_targets_passed=false, source_dirty=false)`

The aggregator claims `status=passed` but at least one per-target
status is not `passed`. This is the original Lane DD rejection;
read the `target_statuses` block in the audit log to see which OS
disagreed.

### 5.4 Triage by Lane W / Lane AA / Lane DD rejection

Other 422 ingestion reasons predate Lane KK but still surface in the
same audit log:

- `candidate_correlation_parity` disagrees with server recomputation
  → Lane W: the aggregator's parity verdict and the per-OS trailer
  verdicts don't match. Read the per-OS smoke logs to find the dissent.
- `surface_content_hash_parity` cell value outside the allowlist → Lane
  CC2: a future field was emitted by the aggregator before being
  registered in the server's allowlist. Update the allowlist if the
  field is legitimate; otherwise treat as tampered.

### 5.5 When to escalate

A single rejection with a known root cause (operator-typed
placeholder, dirty worktree) is benign — fix and re-run. Multiple
rejections within a short window with rejection reasons that don't
match any operator-induced cause should be escalated. The audit log's
`timestamp_utc` lets operators trace the burst pattern; the
`body_sha256` lets them dedupe identical retries.

---

## 6. Where the gates are enforced

| Layer                          | File                                                                          | Purpose                                                                       |
|--------------------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| Server-side computation        | `crates/ao2-cp-server/src/handlers/release_publication.rs`                    | `candidate_correlation_value()` and `release_readiness_gate()` registration   |
| Server-side parity recomputation | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `validate_three_os_release_smoke()` | Rejects ingestion when posted `candidate_correlation_parity` disagrees with the recomputation (Lane W) |
| Smoke aggregator (status parity) | `scripts/smoke-three-os-release.sh` `compute_parity()` + `extract_correlation_status()` | Computes `candidate_correlation_parity` from per-OS logs                       |
| Smoke aggregator (content hash)  | `scripts/smoke-three-os-release.sh` `compute_correlation_content_hash()` + `compute_content_hash_parity()` + `fetch_*_artifact()` | Computes `candidate_correlation_content_hash_parity` from fetched per-OS cockpits (Lane V) |
| Smoke per-OS (bash)            | `scripts/smoke-release-archive.sh`                                            | Emits `candidate_correlation_status=<value>` trailer per OS                   |
| Smoke per-OS (PowerShell)      | `scripts/smoke-release-archive.ps1`                                           | Windows-side mirror of the bash smoke                                          |
| Offline support-bundle verifier | `scripts/verify_release_support_bundle.py` + `scripts/Verify-ReleaseSupportBundle.ps1` | Re-asserts `candidate_correlation` on every release-publication-shaped surface |
| Negative-path tests            | `crates/ao2-cp-server/tests/release_publication.rs`                           | `cockpit_handoff_readiness_default_..._missing` and `..._fires_independently_..._drift` |
| Tampered-ingestion test        | `crates/ao2-cp-server/tests/phase1_promotion.rs`                              | `three_os_release_smoke_ingestion_rejects_tampered_top_level_parity` (Lane W)  |
| Source-string parity test      | `crates/ao2-cp-server/tests/release_packaging.rs`                             | Asserts bash and PowerShell smokes / verifiers / runbook stay in lockstep      |
| Source-commit format + dirty-bit ingestion gate (Lane KK) | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `validate_three_os_release_smoke()` | Rejects ingestion if `source_commit` is not a 40-char lowercase hex SHA, or if `source_dirty=true` paired with `status=passed` |
| Rejected-smoke audit log (Lane LL) | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `append_rejected_smoke_audit()` | Appends a redacted forensic record at `<storage-root>/rejected-three-os-smoke.jsonl` for every 422 ingestion |
| Audit-count operator surface (Lane MM + QQ) | `crates/ao2-cp-server/src/handlers/release_publication.rs` `render_rejected_smoke_audit_section()` | Surfaces the Lane LL count + latest rejection reason on the cockpit / handoff / readiness HTML |
| Per-target source-commit emission (Lane OO) | `scripts/smoke-three-os-release.sh` `extract_source_commit_at_target()` + `compute_source_commit_drift()` | Aggregates each per-OS run's `source_commit_at_target` (read from the `.source-commit` record embedded in `source.tgz`) into a top-level `source_commit_per_target` block + `source_commit_per_target_drift` boolean |
| Source-commit cross-OS evidence agreement (Lane PP-server) | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `validate_three_os_release_smoke()` | Rejects ingestion when any per-target `source_commit_at_target` disagrees with the top-level `source_commit` (orchestrator HEAD drift between packaging and execution) |
| Cross-bundle byte-identity offline verifier (Lane NN) | `scripts/verify_release_support_bundle.py --compare-against PATH` + `scripts/Verify-ReleaseSupportBundle.ps1 -CompareAgainst` | Diffs two release-candidate support bundles offline, surfacing verdict drift across aggregate parity verdicts + per-surface `candidate_correlation.status` + `schema_version` |
| Audit-log rotation budget visibility (Lane VV) | `crates/ao2-cp-server/src/handlers/release_publication.rs` `render_rejected_smoke_audit_section()` (size row) | Surfaces `audit_log_size_bytes` / `audit_log_cap_bytes` on the cockpit / handoff / readiness HTML so operators can see how close the Lane UU 1 MiB rotation cap is without shelling into the storage root |
| Audit-log size cap with FIFO eviction (Lane UU) | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `append_rejected_smoke_audit()` (cap-check + rotation block) | Caps the audit log at 1 MiB (1048576 bytes); when an append would cross the cap, evicts oldest records FIFO until the new tail fits, preserving the newest forensic evidence |
| Audit-log concurrent-write protection (Lane WW-rotation) | `crates/ao2-cp-server/src/handlers/phase1_promotion.rs` `REJECTED_SMOKE_AUDIT_WRITER_LOCK` process-global tokio mutex | Serializes the read-projection-write region inside `append_rejected_smoke_audit` so concurrent appends never see each other's stale view; reader path (`rejected_smoke_audit_summary`) stays lock-free because `tokio::fs::write` is atomic |
| Audit-log rotation budget JSON pass-through (Lane XX) | `crates/ao2-cp-server/src/handlers/release_publication.rs` `release_cockpit_json` / `release_candidate_handoff_json` / `release_readiness_json` `rejected_smoke_audit` block | Surfaces the same 5-field rotation-budget shape on the JSON endpoints that the HTML renderer surfaces, so monitoring scrapers can alert without parsing HTML |
| Audit-log rotation alert rules (Lane XX-doc) | `docs/runbooks/release-smoke.md` section 9.6 + `scripts/package-local.sh` README heredoc (Lane AAA) | Documents the two recommended Prometheus expressions: rotation-imminent (`audit_log_size_bytes / audit_log_cap_bytes > 0.75`) and tampering-attempt spike (`increase(count[1m]) > 10`) |
| Offline verifier audit-log byte-identity + cross-bundle drift (Lane ZZ) | `scripts/verify_release_support_bundle.py` + `scripts/Verify-ReleaseSupportBundle.ps1` `rejected_smoke_audit` hash + `--compare-against` / `-CompareAgainst` | Hashes `rejected_smoke_audit` across cockpit/handoff/readiness within a bundle (within-bundle byte-identity) and surfaces rotation-budget drift across two bundles (cross-bundle); drift is NOT folded into `verdict_parity` because between-captures activity is legitimate |
| On-call triage pointer (Lane EEE) | `crates/ao2-cp-server/src/handlers/release_publication.rs` `render_rejected_smoke_audit_section()` (triage row) | Surfaces a brief "see runbook section 9.9 for tampering-burst triage" pointer with the load-bearing framing ("tampering event, not audit-log corruption") on the cockpit / handoff / readiness HTML so an operator paged at 3 AM lands on the triage section without knowing the runbook section number |
| Cross-surface on-call meta-parity (Lane HHH) | `crates/ao2-cp-server/tests/release_packaging.rs` `on_call_triage_surfaces_agree_on_load_bearing_literals_lane_hhh` | Asserts the cockpit HTML renderer, the runbook (release-smoke.md), and the support-bundle README (package-local.sh heredoc) all reference identical mutex name + worked-example test name + framing anchor + section-9.9 pointer, catching cross-surface drift on rename |
| Audit-log concurrent-burst regression detection (Lane BBB + FFF) | `crates/ao2-cp-server/tests/release_publication.rs` `audit_log_rotation_burst_invariants` helper + Lane WW count-matching test | Exercises the audit-log append path at N=50 / N=200 / N=500 concurrent rejections with wall-clock-budget assertions that surface lock-starvation regressions before the count/size invariants would |
| Section-6 row structural parity (Lane KKK + LLL + MMM) | `crates/ao2-cp-server/tests/release_packaging.rs` `section_6_table_rows_bind_every_lane_label_to_existing_source_pointer_lane_kkk` + `section_6_lane_labels_trace_back_to_workspace_source_lane_lll` + `section_6_row_identifier_tokens_exist_in_referenced_files_lane_mmm` | Tridirectional structural binding for this very table: (KKK) every row mentioning a `Lane XX` label must reference at least one existing workspace path; (LLL) every `Lane XX` label in section 6 must also appear OUTSIDE section 6 in `crates/`, `scripts/`, or `docs/runbooks/`; (MMM) every backtick-wrapped `IDENT()` or `SCREAMING_SNAKE_CASE` token following a file-path segment in the same row must exist as a literal in that file, so a future identifier rename surfaces here instead of leaving the runbook with a stale source pointer |
| README heredoc structural parity (Lane NNN) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_heredoc_lane_labels_and_section_pointers_resolve_in_runbook_lane_nnn` | Cross-binds the `scripts/package-local.sh` README.txt heredoc to this runbook: every `Lane XX` label in the README must also appear in `docs/runbooks/release-smoke.md`, and every numbered section pointer (single section "section 9.6" or range "sections 9.5-9.10") must resolve to an actual `## N.` or `### N.M` header — a future runbook section rename or README label drift fails here before shipping inside the release archive |
| README heredoc identifier-existence binding (Lane OOO) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_heredoc_identifier_tokens_exist_in_workspace_source_lane_ooo` | Extends Lane NNN with identifier-level binding: every `snake_case` test/function name and `SCREAMING_SNAKE_CASE` constant token in the `scripts/package-local.sh` README.txt heredoc must exist as a literal somewhere under `crates/` or `scripts/`, so a future rename of e.g. `audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation` or `REJECTED_SMOKE_AUDIT_WRITER_LOCK` surfaces here before the stale README ships inside the release archive |
| Section-6 header + column-count floor (Lane PPP) | `crates/ao2-cp-server/tests/release_packaging.rs` `section_6_header_literal_and_column_count_floor_lane_ppp` | Pins the table skeleton: the first non-blank line after the section heading must be exactly the 3-column header `\| Layer \| File \| Purpose \|` (whitespace-normalized), the separator row must contain only `-` / `:` cells, and every data row must split into exactly 3 cells — a future regression that flattens columns, renames a header, or strips the header surfaces here before Lane KKK/LLL/MMM's content-level floors run |
| README handoff command/flag parity (Lane QQQ) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_handoff_commands_bind_to_actual_cli_flag_declarations_lane_qqq` | Cross-binds the operator-facing handoff commands embedded in the `scripts/package-local.sh` README heredoc to the actual CLI declarations: every `--xxx-yyy` long flag mentioned after `fetch_release_support_handoff.py` must be declared via `parser.add_argument` in that Python script, and every `-Xxx` PowerShell flag after `Fetch-ReleaseSupportHandoff.ps1` must appear as a `$Xxx` param in the PowerShell script — a future CLI flag rename surfaces here before operators hit "unknown flag" runtime errors |
| README env-var name parity (Lane RRR) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_env_var_names_bind_to_install_and_handoff_scripts_lane_rrr` | Cross-binds every `AO2_CP_xxx` environment variable mentioned in the README heredoc to an actual consumer under `scripts/` (with the README portion masked out so the binding is not trivially self-satisfied); additionally pins `AO2_CP_INSTALL_DIR` to be consumed by BOTH the embedded `install.sh` and `install.ps1` heredocs so a Unix-only or Windows-only rename surfaces immediately |
| README route-literal parity (Lane SSS) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_api_v1_routes_bind_to_axum_router_declarations_lane_sss` | Cross-binds every `/api/v1/...` HTTP endpoint mentioned in the README heredoc (operator landing flow steps 1-5: phase1 operator-panel, phase1 dashboard, release cockpit, release publication/dashboard, release readiness, release handoff) to an actual `.route(...)` declaration in `crates/ao2-cp-server/src/server.rs`; also pins the `nest("/api/v1", ...)` mount itself — a future route rename surfaces here before operators copy-pasting the README URL hit a 404 |
| README verify-bundle CLI parity (Lane TTT) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_verify_bundle_invocations_bind_to_actual_cli_declarations_lane_ttt` | Extends Lane QQQ to the second pair of CLIs invoked from the README: `verify_release_support_bundle.py` (hand-rolled argv parser) and `Verify-ReleaseSupportBundle.ps1`. Every `--xxx-yyy` long flag in a README Python invocation must appear as a `"<flag>"` literal in the script; every `-Xxx` flag in a PowerShell invocation must be declared as `$Xxx` in the param block; and `-Path` must be `Mandatory=$true` since the README always supplies it |
| README archive-contents parity (Lane UUU) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_archive_filenames_appear_in_tar_arglist_lane_uuu` | Cross-binds bare script filenames (no slash, ending in `.py` / `.ps1` / `.sh`) referenced in the README heredoc to the `tar -czf "$ARCHIVE" ...` argument list in `scripts/package-local.sh`. Directory-prefixed repo paths like `scripts/smoke-three-os-release.sh` are correctly excluded. A future build-script regression that drops e.g. `install.sh` from the tar arglist surfaces here before operators copy-pasting the README hit "file not found" |
| Install heredoc binary-name parity (Lane VVV) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_bind_to_cargo_toml_bin_name_lane_vvv` | Cross-binds the binary name in the install.sh and install.ps1 heredocs (`BINARY_NAME="<name>"` / `$BinaryName = "<name>.exe"` plus their `bin/<name>` SHA256SUMS lookups) to the first `[[bin]] name = "..."` entry in `crates/ao2-cp-server/Cargo.toml`, AND to the `target/release/<name>` build path + `BINARY_NAME=` assignments in `scripts/package-local.sh`. A future `[[bin]]` rename surfaces here before the installer silently looks for a binary that's no longer in the archive |
| README port-literal parity (Lane WWW) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_base_url_literal_binds_to_config_default_bind_lane_www` | Cross-binds the `http://<host:port>` origin embedded in every README handoff command (`--base-url` / `-BaseUrl`) to the canonical `default_value = "..."` literal on the `AO2_CP_BIND` clap arg in `crates/ao2-cp-server/src/config.rs`. A future move of the default-bind port (e.g., 8744 → 8745) surfaces here before operators copy-pasting from the README land on "connection refused" |
| Smoke aggregator function-name parity (Lane XXX) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_aggregator_function_refs_in_runbook_resolve_to_definitions_lane_xxx` | Cross-binds every backtick `<func>()` reference in the runbook whose name starts with `compute_` / `extract_` / `fetch_` / `validate_` to an actual function definition in either `scripts/smoke-three-os-release.sh` (for shell-aggregator names) or `crates/ao2-cp-server/src/handlers/` (for Rust `validate_*` names). Extends Lane MMM's row-internal binding to ALL such references in the runbook prose, not just section-6 rows; an aggregator rename surfaces immediately |
| Alert-rule metric-name parity (Lane YYY) | `crates/ao2-cp-server/tests/release_packaging.rs` `alert_rule_metric_names_bind_to_handler_json_keys_lane_yyy` | Cross-binds the documented Prometheus alert expressions (`audit_log_size_bytes / audit_log_cap_bytes > 0.75`, `increase(count[1m]) > 10`) in the runbook + README to the actual JSON-key literals emitted by `crates/ao2-cp-server/src/handlers/release_publication.rs` or `phase1_promotion.rs`. A metric-name rename surfaces here before on-call operators silently lose paging on rotation pressure or tampering bursts |
| Rotation-budget JSON shape parity (Lane ZZZ) | `crates/ao2-cp-server/tests/release_packaging.rs` `rejected_smoke_audit_json_shape_binds_to_handler_keys_lane_zzz` | Cross-binds the documented 5-field `rejected_smoke_audit` JSON shape in runbook section 9.5 (`count`, `latest_timestamp_utc`, `latest_rejection_reason`, `audit_log_size_bytes`, `audit_log_cap_bytes`) and the Lane UU `1048576` cap literal to actual `"<key>"` JSON-key literals in `crates/ao2-cp-server/src/handlers/release_publication.rs` + `phase1_promotion.rs`. A future JSON-shape drift surfaces here before monitor scrapers that depend on stable keys silently lose their hooks |
| Install heredoc SHA256SUMS line-shape parity (Lane AAAA) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_sha256sums_line_shape_binds_to_write_shape_lane_aaaa` | Cross-binds the canonical SHA256SUMS write shape `printf "%s  bin/%s\n" "$binary_sha" "$BINARY_NAME"` in `scripts/package-local.sh` against both parse shapes in the embedded installers: install.sh `awk '$2 == "bin/<name>" { print $1 }' SHA256SUMS` and install.ps1 `-match "bin/<name>.exe$"` + `($_ -split "\s+")[0]`. A future column reorder, separator change, or `[[bin]]` rename without lockstep parser update surfaces here before the archive ships with a parse that silently fails |
| Release-readiness gate registration parity (Lane BBBB) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_readiness_gate_registration_binds_to_downstream_anchors_lane_bbbb` | Cross-binds the canonical `let gate_results = vec![release_readiness_gate(...)...]` registration in `release_publication.rs` against three structural invariants: (1) gate IDs unique within the vec, (2) `"gate_results": gate_results` JSON wire-out emission present, (3) every HTML cockpit `gate_row("<id>", ...)` entry must trace back to a registered gate ID. A future duplicate, dropped wire-out, or orphan UI row surfaces here before operators see a confusing or empty readiness summary |
| README threat-model claim parity (Lane CCCC) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_threat_model_claims_bind_to_trust_boundary_emission_lane_cccc` | Cross-binds the operator-facing README threat-model claim phrases ("read-only observer", "does not approve", "never mutates", "factory-v3 evaluator-closer", "does not start providers") in the `scripts/package-local.sh` README heredoc against the matching JSON-literal emission in `fn trust_boundary() -> serde_json::Value` (`"role": "read_only_observer"`, `"mutates_ao_artifacts": false`, `"control_plane_approves_release": false`, `"release_acceptance_owner": "factory-v3 evaluator-closer"`). A future contract weakening (flipping a bool, renaming a key, dropping a claim) silently breaks the README's promise to operators |
| Smoke aggregator step-order parity (Lane DDDD) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_aggregator_step_order_matches_dependency_pipeline_lane_dddd` | Cross-binds the linear top-level execution order of `scripts/smoke-three-os-release.sh` against the dependency pipeline: `run_macos` → `extract_correlation_status` (×3) → `compute_parity` → `fetch_<os>_artifact` (×3) → `compute_content_hash_parity`. Extends Lane XXX's function-name SET binding with an orthogonal ORDER constraint. A future reorder (e.g., computing parity before all extracts run, or computing content-hash parity before fetches complete) yields silent `unknown` verdicts even when the data is intact |
| Installer fail-closed step-order parity (Lane EEEE) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_perform_checksum_before_copy_lane_eeee` | Cross-binds the security-load-bearing fail-closed order in install.sh and install.ps1: `expected=$(awk ...)` → `if [ -z "$expected" ]` → `actual=$(sha256sum/shasum ...)` → `if [ "$actual" != "$expected" ]` → `cp "bin/$BINARY_NAME" ...` (and PowerShell equivalents). A future regression that moves `cp` / `Copy-Item` before the mismatch check leaves an unverified binary at `$INSTALL_DIR` even when SHA256 validation would have failed; Lane EEEE pins the offset ordering of all five steps in each heredoc |
| Support-bundle surface-ID JSON-literal parity (Lane FFFF) | `crates/ao2-cp-server/tests/release_packaging.rs` `support_bundle_surface_ids_bind_to_json_literal_emission_lane_ffff` | Cross-binds the canonical `const SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS: [&str; 6] = [...]` array in `crates/ao2-cp-server/src/handlers/release_publication.rs` against (1) every `"id": "<surface_id>"` JSON literal in the bundle-manifest builder and (2) every `"<surface_id>":` JSON-key literal in the `integrity.surface_sha256` map. A future rename of `release_cockpit` → `release_cockpit_v2` in the const without updating the JSON-literal builder silently breaks every consumer that filters surfaces on `"id"` |
| Schema-version const emission parity (Lane HHHH) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_schema_consts_bind_to_schema_version_emission_lane_hhhh` | Parses every `const *_SCHEMA: &str = "..."` declaration at the top of `crates/ao2-cp-server/src/handlers/release_publication.rs` (outside the `#[cfg(test)]` module) and asserts each is referenced in at least one `"schema_version": <CONST>` JSON-literal emission line, plus declared names AND values are pairwise unique. A future deletion of an emission site that leaves the const declaration intact would silently advertise a schema label nothing actually stamps; a duplicate value would let consumers conflate distinct resources under one schema string. Floor: >= 8 schema consts |
| Install heredoc default install dir parity (Lane IIII) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_default_install_dir_binds_to_readme_lane_iiii` | Cross-binds the silent default install directory in the install.sh heredoc (`INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-<default>}}"`) and the install.ps1 heredoc (`} else { Join-Path $env:USERPROFILE ".local\bin" }`) against the README.txt example commands, asserting (1) the Unix default literal appears in the README, (2) every `$env:` root the PowerShell default uses also appears in the README's Windows install example, and (3) the defaults are either $HOME-rooted/absolute (Unix) or rooted under $env:USERPROFILE / $env:LOCALAPPDATA (Windows) — never cwd-relative, never elevation-required. A future quiet flip of either default without updating the README leaves operators copy-pasting from the shipped README into a different directory than the silent default lands the binary at |
| Release route → handler fn parity (Lane JJJJ) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_routes_bind_to_handler_fns_lane_jjjj` | Parses every `.route("/release/...", <method>(handlers::release_publication::<fn>))` declaration in `crates/ao2-cp-server/src/server.rs` and asserts (1) the handler `fn` exists in `handlers/release_publication.rs`, (2) `.json` route suffix iff `_json` handler suffix (catches HTML-vs-JSON content-negotiation regressions), (3) route paths are pairwise unique (axum panics at startup on duplicates; static catch beats deploy-time crash). Floor: >= 25 release routes — catches accidental router truncation. Symmetric to Lane SSS (README routes → .route() existence) but for the second half: route → handler resolution |
| README workspace-path parity (Lane KKKK) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_workspace_path_claims_resolve_to_real_files_lane_kkkk` | Scans the README.txt heredoc inside `scripts/package-local.sh` for tokens that look like workspace-rooted source paths (first segment in {crates, docs, scripts, tests}; ends in a source extension `.rs / .sh / .py / .ps1 / .md / .toml / .yaml / .yml / .json / .jsonl`; contains at least one `/`). Asserts each resolves to a real file on disk under the workspace root. Floor: >= 3 paths — catches a regression that drops drill-in references back to vague prose. Symmetric to Lane UUU (bare filenames → tar arglist) and Lane OOO (snake_case identifiers → workspace) but for the third axis: directory-rooted workspace paths |
| README operator-landing numbered-list parity (Lane LLLL) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_operator_landing_flow_numbered_list_lane_llll` | Parses the README's `Operator landing flow` numbered list and asserts (1) numbering is consecutive starting at 1 with no gaps / duplicates / skips (the order communicates the intended triage progression), (2) every `/api/v1/...` path mentioned in the numbered list resolves to a real `.route(...)` declaration in `crates/ao2-cp-server/src/server.rs` (a 404 from the documented triage entry point is the worst possible operator UX), and (3) the list has >= 5 numbered entries citing >= 5 `/api/v1/...` paths. A future regression that renumbers, skips, drops a path, or returns to vague prose surfaces here before operators chase a dead URL or follow a misleading triage order |
| Install heredoc permission-step parity (Lane MMMM) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_permission_step_parity_lane_mmmm` | Pins three load-bearing post-copy steps in the install heredocs: (1) install.sh must contain `chmod 755 "$INSTALL_DIR/$BINARY_NAME"` AFTER the cp step (a future quiet removal would leave the binary at the umask-default mode and break execution under stricter umasks), (2) the printf `ao2_control_plane_installed=...` confirmation line in install.sh must come AFTER chmod (otherwise the success line lands before the binary is actually permissioned), (3) install.ps1 must contain the matching `Copy-Item` step AND the matching `Write-Output "ao2_control_plane_installed=..."` confirmation (asymmetric operator feedback silently breaks any cross-OS install verification script). Complements Lane EEEE (checksum-before-copy fail-closed order) by pinning the post-copy permission and confirmation contract |
| HTML CSS class parity (Lane NNNN) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_publication_html_css_class_parity_lane_nnnn` | Cross-binds the embedded `<style>` rules (`.ok{...}`, `.warn{...}`, `.bad{...}`) in `crates/ao2-cp-server/src/handlers/release_publication.rs` HTML pages to the dynamic class assignments (`class=\"ok\"`, `class=\"warn\"`, `class=\"bad\"`). Asserts (1) the three status-styling classes are defined, (2) every defined class is referenced at least once as a static `class=\"<name>\"` literal (catches dead CSS after a refactor that removed the dynamic branch), (3) every static `class=\"<word>\"` literal has a matching `.<word>{...}` rule (catches a typo that would leave operators with unstyled status text). Floor: >= 3 status classes |
| HTML title / heading parity (Lane OOOO) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_publication_html_title_h1_parity_lane_oooo` | Extracts every `<title>...</title>` and `<h1>...</h1>` literal from `crates/ao2-cp-server/src/handlers/release_publication.rs` and asserts (1) the file renders >= 6 HTML pages, (2) `<title>` count equals `<h1>` count (mismatch indicates a stray tag from a botched merge), (3) each title/h1 pair matches verbatim by source order (catches a rename of one without the other), (4) every title starts with the `AO2 ` branding prefix, (5) titles are pairwise unique (no two tabs share a label). A future rename of either side without lockstep update would split the operator's mental model between browser tab label and page header |
| Section-6 row uniqueness parity (Lane PPPP) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_smoke_section_6_rows_are_unique_lane_pppp` | Cross-axis to Lane III (which asserts every shipped lane has a section-6 row AND a test fn reference, but does not assert uniqueness). Walks section 6, collects every `(Lane XXXX)` label and every backtick-quoted snake_case test fn name, and asserts (1) >= 10 lane labels present (floor preventing accidental truncation), (2) lane labels are pairwise unique (catches a botched rebase that re-shipped a row, or a copy-paste typo where two cascades claimed the same Lane XXXX identifier), (3) >= 10 test fn references present, (4) test fn names are pairwise unique (catches a renamed-test row that left its old reference behind so the new row is not actually carrying a unique binding). The orthogonal axis to Lane III: III asserts presence, PPPP asserts uniqueness |
| HTML footer-link parity (Lane QQQQ) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_publication_html_footer_link_parity_lane_qqqq` | Slices the terminal `<p><a href="...">...</a> · ...</p>` footer from every HTML page rendered by `crates/ao2-cp-server/src/handlers/release_publication.rs` (the `<p>` block immediately preceding `</main></body></html>`). Asserts (1) >= 6 HTML pages render with a footer, (2) each footer has >= 2 anchor links (a single-link footer is no longer a navigation surface), (3) each anchor's text body is non-empty (catches a footer like `<a href="/api/v1/foo"></a>` after a rename that dropped the link label), (4) >= 4 static `/api/v1/...` hrefs aggregated across footers (floor against an accidental rewrite to template-only hrefs), (5) every static href resolves to a real `.route(...)` declaration in `server.rs` after stripping the `/api/v1` prefix and any query string. Template `{var}` hrefs are deferred to Lane JJJJ which binds the computed values back to the route table. A footer href that 404s is the worst possible cross-page navigation regression: operators on one surface can no longer hop to the next |
| Smoke aggregator log-line shape parity (Lane RRRR) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_aggregator_log_line_shape_parity_lane_rrrr` | Binds the `<key>=<value>` log-line shape across the aggregator (`scripts/smoke-three-os-release.sh`) and the per-OS smoke scripts (`scripts/smoke-release-archive.sh`, `scripts/smoke-release-archive.ps1`). Scans the aggregator for `grep -E '^<key>='` consumer patterns, scans the .sh emitter for `printf "<key>=%s\n"` lines, scans the .ps1 emitter for `Write-Output "<key>=$<var>"` lines, then asserts (1) aggregator consumes >= 2 keys, (2) per-OS scripts each emit >= 10 keys, (3) the .sh emit-key set EQUALS the .ps1 emit-key set (cross-OS parity — neither variant may quietly drop a key), (4) every aggregator-consumed key is emitted by BOTH per-OS scripts. A future quiet rename of an emitter key, a delimiter swap (`:` instead of `=`), or an asymmetric emit between .sh and .ps1 would silently break ingestion: the aggregator would fall back to "unknown" on the affected OS without crashing, and downstream evidence would lose the per-OS fact. Lane RRRR closes that gap |
| Provider-acceptance JSON shape parity (Lane SSSS) | `crates/ao2-cp-server/tests/release_packaging.rs` `provider_acceptance_json_shape_parity_lane_ssss` | Binds the per-provider acceptance JSON shape across the renderer and the emitter in `crates/ao2-cp-server/src/handlers/release_publication.rs`. Locates every `let acceptance_row = ...` closure (currently two: handoff + cockpit), extracts every `json_str(&entry, "<key>")` and `entry.get("<key>")` read in each, locates `compact_acceptance_for_handoff`, extracts every `"<key>":` JSON literal write, then asserts (1) >= 2 acceptance_row closures present, (2) every closure reads >= 4 keys, (3) `status`/`source_class`/`run_id` present in every reader (these drive the per-provider columns AND `provider_acceptance_is_live_passed`), (4) all reader closures read the SAME key set (cockpit + handoff present the same per-provider columns and must agree), (5) emitter writes >= 6 keys, (6) `status`/`source_class`/`run_id`/`score`/`raw_url` present in the emitter, (7) every reader-read key is also an emitter-written key (reader is a subset of emitter). A renamed JSON key in the emitter without a matching renderer update would leave blank table cells where operators expect provider run IDs and scores |
| Section-6 row count parity (Lane TTTT) | `crates/ao2-cp-server/tests/release_packaging.rs` `section_6_row_count_binds_to_4_letter_lane_test_fn_count_lane_tttt` | Closes the count-axis gap between Lane III (every shipped 4-letter lane has a section-6 row + test fn ref) and Lane PPPP (no two rows share the same Lane label or test fn name). Lane TTTT extracts every 4-letter `(Lane XXXX)` row label from section 6's column 1, and every 4-letter `fn <name>_lane_<xxxx>(` test fn definition in release_packaging.rs (excluding matches inside `//` comment lines), then asserts (1) >= 15 of each, (2) lowercased label set EQUALS test fn suffix set. A brand-new test fn `fn foo_lane_uuuu(...)` added without a matching section-6 row, or a section-6 row whose test was deleted, surfaces here even when no human ran the manual Lane III enrollment step |
| README heredoc lane coverage (Lane UUUU) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_heredoc_lane_mentions_bind_to_runbook_coverage_lane_uuuu` | Binds the lane labels mentioned in the release-archive README heredoc (`scripts/package-local.sh` `cat > "$STAGE/README.txt" <<'TXT' ... TXT` block) to lane labels present somewhere in this runbook. Extracts every `Lane <X>` token where `<X>` is uppercase ASCII letters with optional `-<lowercase>` suffix from both surfaces, then asserts (1) README references >= 5 distinct lanes (floor against an accidental README truncation that drops triage anchors), (2) every README-mentioned lane appears somewhere in `docs/runbooks/release-smoke.md`. A future README update that pivots to a new triage anchor without backfilling the runbook would leave operators consulting the offline release-archive README on a dead pointer (the archive ships the README at package time so post-ship runbook drift can't be fixed in place) |
| Install heredoc artifact-ref parity (Lane VVVV) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_artifact_refs_bind_to_tar_arglist_lane_vvvv` | Cross-axis to Lane UUU (README archive-contents ↔ tar arglist). Lane VVVV binds the install scripts themselves: every relative-path file reference in the install.sh and install.ps1 heredocs (e.g., `SHA256SUMS`, `bin/$BINARY_NAME`, `Join-Path "bin" $BinaryName`) must resolve to a tar arglist entry, with directory-prefix matching for entries like `bin/` covering `bin/<file>`. Asserts (1) install.sh references >= 2 distinct archive paths, (2) install.ps1 references >= 2, (3) tar arglist enumerates >= 5 entries, (4) every install heredoc file reference resolves to a tar arglist entry (literal or parent-directory match). An install script referencing a file the tar arglist doesn't ship would yield an install-time `file not found` regression at the checksum step — the worst failure mode because the binary is never executed |
| Install heredoc env-var symmetry + clap separation (Lane WWWW) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_env_var_symmetry_and_clap_separation_lane_wwww` | Two cross-OS install-time invariants. **Symmetry**: install.sh and install.ps1 must reference the IDENTICAL set of `AO2_*` env vars — a mismatch means the Mac/Linux operator can override the install via some env var the Windows operator cannot, an asymmetric install UX. **Clap separation**: server-runtime env vars declared with clap `env = "AO2_..."` attributes in `src/config.rs` (currently AO2_CP_BIND, AO2_CP_DATA_DIR, AO2_CP_API_TOKEN, AO2_CP_LOG_LEVEL, AO2_CP_MAX_BODY_BYTES, AO2_CP_PROVIDER_READINESS_TRUSTED_KEY_SHA256S) MUST NOT appear in either install heredoc; install-time and server-runtime env namespaces must stay disjoint so the install script never silently collides with the server's own config namespace. Floors: install.sh AND install.ps1 each reference >= 1 install-time env var; clap declares >= 3 server-runtime env vars. Asserts (1) install.sh env set EQUALS install.ps1 env set, (2) install.sh env ∩ clap env is empty, (3) install.ps1 env ∩ clap env is empty |
| Aggregator JSON key ↔ handler read parity (Lane XXXX) | `crates/ao2-cp-server/tests/release_packaging.rs` `aggregator_json_keys_bind_to_handler_reads_lane_xxxx` | Extends Lane RRRR (aggregator log-line shape ↔ per-OS emitter) one hop further: the JSON keys the aggregator EMITS into its output JSON (via the Python heredocs in `scripts/smoke-three-os-release.sh`) must be READ by at least one handler (`crates/ao2-cp-server/src/handlers/phase1_promotion.rs` or `release_publication.rs`). Pins four load-bearing cross-OS verdict / drift keys explicitly read by handler `json_str(...)` or `.get(...)` calls: `candidate_correlation_status`, `candidate_correlation_parity`, `source_commit_per_target_drift`, `source_commit`. Floor: aggregator emits >= 10 distinct keys total. Intentionally NOT pinned: `candidate_correlation_content_hash_parity` (handlers compute their own `surface_content_hash_parity`) and `source_commit_at_target` (read via parent `source_commit_per_target` dict iteration, not named lookup). A future quiet rename on either end of the pinned keys would silently break the cross-OS verdict pipeline: the handler reads `null`, downstream parity verdicts degrade to `unknown`, and no test crashes — Lane XXXX catches that before merge |
| HTML render fn ↔ route registration parity (Lane YYYY) | `crates/ao2-cp-server/tests/release_packaging.rs` `html_render_fns_bind_to_route_registration_lane_yyyy` | Narrows Lane JJJJ (general route ↔ handler fn parity) to specifically the HTML render surface: every `pub (async) fn <name>(...)` in `crates/ao2-cp-server/src/handlers/release_publication.rs` whose body terminates with `</main></body></html>` (the canonical HTML page-end marker) MUST appear in server.rs as `release_publication::<name>` inside a `.route(...)` declaration. Algorithm: strip `#[cfg(test)]` tail, walk each `</main></body></html>` occurrence backwards to find the enclosing `pub (async) fn`, collect distinct fn names, assert each is referenced in server.rs. Floor: >= 6 HTML render fns. Catches orphan HTML pages (rendered but never served via a route) and stale route registrations (route names a fn that no longer renders HTML) — both surfaces of the dead-code class that Lane JJJJ's broad route binding can miss when narrowed to HTML pages specifically |
| Cargo workspace member parity (Lane ZZZZ) | `crates/ao2-cp-server/tests/release_packaging.rs` `cargo_workspace_members_bind_to_real_crate_dirs_lane_zzzz` | Binds the top-level `Cargo.toml`'s `[workspace] members = [...]` array against on-disk crate dirs across three invariants: (1) every declared member resolves to a real directory containing a `Cargo.toml` — a phantom member breaks `cargo build` workspace-wide before any code runs, (2) each member's declared crate name (`name = "..."` in its own Cargo.toml) matches its enclosing directory's basename modulo Cargo's `-`/`_` interchange — drift here makes directory-resolving tooling diverge from package-name-resolving tooling, (3) every `crates/<dir>/Cargo.toml` on disk is enrolled as a member — an orphan crate is silently skipped by `cargo test --workspace` so CI greens on a crate that may no longer compile. Floor: >= 2 workspace members. Foundational binding that catches the structural drift class no other lane covers: a deleted crate left in members, a renamed crate not re-enrolled, or a new crate that compiles in isolation but is invisible to workspace-wide CI |
| Workspace dependency unification parity (Lane AAAAA) | `crates/ao2-cp-server/tests/release_packaging.rs` `member_cargo_tomls_unify_via_workspace_dependencies_lane_aaaaa` | Binds member-crate `[dependencies]` and `[dev-dependencies]` entries against the top-level `[workspace.dependencies]` block: every shared dep name MUST be referenced via `<dep>.workspace = true` (shorthand) or `<dep> = { workspace = true }` (inline). A direct version pin in a member silently shadows the workspace version — a future `cargo update -p tokio` against the workspace declaration would no longer affect the shadowing member, behavior fragments across crates, and a security-driven version bump can leave one member unpatched. Path-dep entries (intra-workspace crates like `ao2-cp-schema = { path = "..." }`) are correctly exempt since they are not declared in `[workspace.dependencies]`. Floors: workspace declares >= 5 deps; each member crate shares >= 3 deps with the workspace block. Catches a shadow-version pin, a botched merge that converted a `.workspace = true` line back to a direct version literal, or a partial migration that left one member out of sync with the unified pin |
| Install heredoc shebang + strict-mode parity (Lane BBBBB) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_shebang_and_strict_mode_parity_lane_bbbbb` | Two security-load-bearing invariants on the install scripts shipped in the release archive (the `cat > "$STAGE/install.{sh,ps1}"` heredocs in `scripts/package-local.sh`): (1) install.sh's body must begin with a `#!` shebang on the first non-empty line AND must declare `set -eu` (or stricter like `set -euo pipefail`) — without `-e`, a checksum-mismatch exit-1 branch followed by `cp` silently installs an unverified binary; without `-u`, an unset `$INSTALL_DIR` expands empty and `cp` writes to `/${BINARY_NAME}` on the root filesystem, (2) install.ps1's body must declare `$ErrorActionPreference = "Stop"` — without it, non-terminating cmdlet errors (a permission-denied Copy-Item under a strict ACL) print red text and continue executing, the installer reports `ao2_control_plane_installed=...` even though the binary copy silently failed. Orthogonal to Lane EEEE (checksum-before-copy order): EEEE pins the order of steps, BBBBB pins the meta-condition that step failures actually abort the script — without BBBBB, the EEEE-correct order could pass while the failure branches silently return nonzero and the install proceeds anyway |
| Cargo.lock workspace-coverage parity (Lane CCCCC) | `crates/ao2-cp-server/tests/release_packaging.rs` `cargo_lock_workspace_path_sources_match_members_lane_ccccc` | Cross-axis to Lane ZZZZ (workspace members ↔ on-disk dirs): ZZZZ binds the Cargo.toml-side declaration, CCCCC binds the Cargo.lock-side reflection. Two invariants: (1) every declared workspace member's crate name must appear as a path-source `[[package]]` entry in Cargo.lock (no `source =` line — path sources are implicit). A stale lockfile missing a new member breaks `cargo build --frozen` in CI / release builds before any code runs. (2) Conversely, every Cargo.lock path-source entry must be a declared workspace member — an orphan path-source from a deleted crate inflates the lockfile with a phantom that pins a transitive dep version no longer in the live graph, defeating lockfile-diff review. Together with Lane ZZZZ, pins all three corners of the (members declaration, on-disk dir, lockfile entry) triangle |
| Tar arglist ↔ stage-area write parity (Lane DDDDD) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_tar_arglist_binds_to_stage_writes_lane_ddddd` | Binds the `tar -czf "$ARCHIVE" <args>...` arglist in `scripts/package-local.sh` against the script's own staging logic: every entry in the arglist MUST have at least one matching `"$STAGE/<entry>"` write step earlier in the script (`cp ... "$STAGE/<entry>"`, `cat > "$STAGE/<entry>"`, `printf ... > "$STAGE/<entry>"`, `python3 - "$STAGE/<entry>"`, or `mkdir -p "$STAGE/<entry>"` + a `"$STAGE/<entry>/..."` populator). If a tar arg has no matching write, the tar step fails at archive time with `file not found` — but only AFTER the build has already spent minutes producing the release binary; the operator sees a wasted-build error at the worst possible moment. Lane DDDDD catches this at the script-structure level. Cross-axis to Lane VVVV (install heredoc artifact refs ↔ tar arglist) and Lane UUU (README archive contents ↔ tar arglist): VVVV binds the install scripts TO tar, UUU binds the README claims TO tar, DDDDD binds the script's own staging logic — the SOURCE of the arglist — to tar. Floor: >= 5 tar arglist entries |
| Handler module declaration parity (Lane EEEEE) | `crates/ao2-cp-server/tests/release_packaging.rs` `handler_module_declarations_bind_to_real_files_lane_eeeee` | Binds `crates/ao2-cp-server/src/handlers/mod.rs` against the `.rs` files in `handlers/`. Two invariants: (1) every `pub mod <name>;` declaration must resolve to `handlers/<name>.rs` or `handlers/<name>/mod.rs` on disk — Rust's compiler enforces this, but Lane EEEEE surfaces the failure at the meta-parity level with a precise message before `cargo build` produces the lower-context module-not-found error, (2) every `.rs` file under `handlers/` (excluding mod.rs itself) must be declared as a `pub mod` in mod.rs — an orphan handler file is silently dead code, `cargo build` succeeds without it, and a future contributor reading the handler source has no way to know it's never wired in. Floor: >= 6 declared handler submodules. Catches the structural drift class where a renamed handler file leaves the mod declaration pointing at a phantom, or a new handler file is created without registration |
| HTML page doctype + charset parity (Lane FFFFF) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_publication_html_doctype_and_charset_parity_lane_fffff` | Pins two structural HTML header invariants on every page rendered by `crates/ao2-cp-server/src/handlers/release_publication.rs` (the `format!` templates terminating in `</main></body></html>`): (1) the template MUST begin with `<!doctype html>` (case-insensitive) — without it, browsers fall back to "quirks mode" with legacy box-model CSS, table border-collapse handled inconsistently, and font-size resolution that differs from what the embedded `<style>` was written against; a future regression that strips the doctype produces no test failure until an operator complains about a misaligned column, (2) the template MUST declare `<meta charset="utf-8">` (case-insensitive) — without an explicit charset, operator-facing strings containing `·` (footer separator) or `→` (error messages) render as mojibake on a browser whose locale default is not UTF-8. Floor: >= 6 HTML pages (symmetric to Lane YYYY). Orthogonal to Lane NNNN (CSS class), Lane OOOO (`<title>`/`<h1>`), and Lane YYYY (render fn ↔ route): FFFFF pins the structural HTML header invariants that every page must satisfy regardless of which fn produced it |
| Schema version semver-suffix parity (Lane GGGGG) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_schema_const_values_end_with_v_n_suffix_lane_ggggg` | Pins the version-suffix convention on every `const *_SCHEMA: &str = "<value>";` declared in `crates/ao2-cp-server/src/handlers/release_publication.rs`. Each `<value>` MUST end with either `.v<digits>` (dotted-tail convention — `ao2.release-publication-summary.v1`) or `/v<digits>` (slash-tail convention — `factory-v3/ao2-release-evaluator-decision/v1`); the digit run MUST be a bare positive integer with N >= 1 (no v0, no patch numbers, no suffixes); and the suffix MUST be at the very END of the schema string (no version embedded mid-string, no `.v1/extra`). Floor: >= 8 schema consts. Why this matters: downstream verifiers (`verify_release_support_bundle.py`, `Verify-ReleaseSupportBundle.ps1`, the AO2 attest tooling) key off the suffix to route a payload to the matching JSON schema. A schema string emitted without a version suffix is silently treated as v0 (legacy) or rejected; either way the operator sees an opaque "schema mismatch" error with no version context, no migration path, and no debuggable signal. A regression — a rename that drops the suffix, a refactor that switches from `.v1` to `_v1`, or a new schema introduced without a version tag — surfaces here before downstream verifiers fail with that low-context error. Cross-axis to Lane HHHH (RELEASE_*_SCHEMA const → JSON literal emission parity): HHHH binds the const NAME to the emitted JSON; GGGGG binds the const VALUE to the semver suffix convention |
| Install heredoc verify-before-copy checksum flow parity (Lane HHHHH) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_verify_before_copy_checksum_flow_parity_lane_hhhhh` | Pins the verify-then-copy safety ordering in both `install.sh` and `install.ps1` heredocs generated by `scripts/package-local.sh`. Three invariants: (1) install.sh `if [ "$actual" != "$expected" ]` checksum mismatch check + `exit 1` must appear BEFORE the `cp "bin/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"` copy step (verify-then-copy); (2) install.ps1 `if ($Actual -ne $Expected...)` mismatch check + `throw` must appear BEFORE the `Copy-Item ... $InstallDir` copy step (verify-then-copy parity on Windows); (3) both scripts must emit the literal string `"checksum mismatch"` on verification failure (operator-facing message parity — oncall grep logs for this exact phrase across Unix and Windows). Why this matters: a regression that swaps the order to copy-then-verify creates a TOCTOU-like window where a corrupted or tampered binary already sits in `$INSTALL_DIR/$BINARY_NAME` at the moment the script aborts; the user's previously-working install is now overwritten by a bad binary AND the script exits with error, leaving the user in a worse state than if they hadn't run the script. Cross-axis to Lane AAAA (SHA256SUMS line-shape parity): AAAA binds the file format; HHHHH binds the install script's USE of that file (verify-first ordering + fail-closed semantics). Cross-axis to Lane MMMM (install heredoc chmod ordering): MMMM binds chmod-after-cp; HHHHH binds verify-before-cp — together the flow is verify → cp → chmod → confirmation |
| Install heredoc SHA256 algorithm + case-normalization parity (Lane IIIII) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_sha256_algorithm_and_case_normalization_parity_lane_iiiii` | Pins the cross-platform hash-computation correctness layer in both install heredocs. Four invariants for install.sh: (1) must invoke `sha256sum` (Linux primary — GNU coreutils tool); (2) must fall back to `shasum -a 256` (Mac fallback — macOS ships shasum but not sha256sum; without this branch the script fails on stock macOS with "command not found" before any verification can happen); (3) the portability branch must be gated by `command -v sha256sum >/dev/null 2>&1` (probe-then-invoke; a bare `if sha256sum` invocation pollutes stderr on macOS); (4) install.sh must use `awk '{ print $1 }'` to extract the hash column from BOTH branches (>= 2 occurrences for the two if/else branches; without column extraction the comparison includes the trailing filename and always reports mismatch). PowerShell side: install.ps1 must use `Get-FileHash -Algorithm SHA256` (the built-in PowerShell cmdlet; Windows ships no sha256sum binary) AND must call `.ToLowerInvariant()` on at least one side of the hash comparison. SHA256SUMS is canonical lowercase-hex (Lane AAAA); Get-FileHash returns uppercase by default. Without normalization every Windows install fails with "checksum mismatch" even on a correct binary — a particularly vicious bug because the operator's binary IS correct and the install script lies. Cross-axis to Lane HHHHH (verify-before-copy ordering): HHHHH binds ORDERING; IIIII binds CORRECTNESS — even with the right ordering, a non-normalized hash on Windows reports false positives. Cross-axis to Lane AAAA (SHA256SUMS line shape lowercase-hex format): AAAA binds the file format; IIIII binds the install scripts to consume that lowercase-hex format correctly across all three platforms |
| Install heredoc cwd-to-script-dir parity (Lane JJJJJ) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_cwd_to_script_dir_parity_lane_jjjjj` | Pins the precondition that makes every relative file read in the install heredocs work regardless of where the operator invokes the script. Two invariants: (1) install.sh must contain `cd "$(dirname -- "$0")"` (POSIX-portable way to change cwd to the script's own directory; `--` guards against script paths starting with `-`); (2) install.ps1 must contain `Set-Location -LiteralPath $PSScriptRoot` (PowerShell equivalent; `$PSScriptRoot` resolves to the directory containing the running script; `-LiteralPath` prevents wildcard interpretation if the path contains brackets). Ordering invariants: both cwd-fix lines must appear EARLY — strictly before any `SHA256SUMS` read AND before any `bin/$BINARY_NAME` / `Join-Path "bin"` read. Why this matters: the release archive is extracted to a temp directory of the operator's choosing; they may invoke `sh install.sh` from any directory (home, /tmp, parent of extracted dir). Without cwd-fix, every relative read resolves against the operator's pwd, not the archive dir — the script aborts with "No such file or directory" (sh) or "Cannot find path" (PowerShell) on the FIRST read, before verification can even begin, with no hint to the operator that the fix is `cd` into the extracted dir first. Cross-axis to Lane HHHHH (verify-before-copy) and Lane IIIII (SHA256 algorithm): HHHHH/IIIII assume the script can READ SHA256SUMS and the binary. JJJJJ pins the precondition that makes those reads possible across macOS / Ubuntu / Windows regardless of operator pwd |
| Install heredoc INSTALL_DIR mkdir-with-parents parity (Lane KKKKK) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_install_dir_mkdir_with_parents_parity_lane_kkkkk` | Pins the install-directory creation step in both heredocs. Two invariants: (1) install.sh must contain `mkdir -p "$INSTALL_DIR"` — the `-p` flag tells mkdir to create intermediate parent directories AND to suppress "already exists" errors on re-install. Without it, install on a fresh user account fails because `$HOME/.local` may not exist yet (only the leaf `bin` is typically missing, but a plain `mkdir "$INSTALL_DIR"` fails if ANY intermediate is missing). (2) install.ps1 must contain `New-Item -ItemType Directory -Force -Path $InstallDir` — the PowerShell equivalent; the `-Force` flag is critical, creating parents AND suppressing the "already exists" error (without `-Force`, New-Item fails noisily if the dir exists OR if intermediate dirs are missing). Ordering invariants: both mkdir calls must precede the `cp` / `Copy-Item` step (a copy-first ordering fails with "no such directory" on every fresh install; Copy-Item does NOT auto-create the parent on its own). Cross-axis to Lane HHHHH (verify-before-copy) and Lane JJJJJ (cwd-to-script-dir): HHHHH/JJJJJ pin the verify SOURCE path; KKKKK pins the DESTINATION path. Together they ensure both ends of the cp step are valid before the binary moves |
| README docs/ path-claim parity (Lane LLLLL) | `crates/ao2-cp-server/tests/release_packaging.rs` `readme_docs_path_claims_resolve_to_real_files_lane_lllll` | Pins doc-path references in the README.txt heredoc. The README tells operators where to find authoritative triage guidance (e.g., `Operator triage: read docs/runbooks/release-smoke.md for ...`). Every `docs/<path>.md` token in README.txt MUST resolve to a real file under the workspace root. Specifically: the `docs/runbooks/release-smoke.md` operator-landing pointer MUST be referenced (mandatory breadcrumb). Floor: >= 1 distinct `docs/<path>.md` claim. Why this matters: the operator extracts the release archive, reads README.txt, and follows the breadcrumb during an incident. A typoed or renamed path lands them on "file not found" exactly when they need triage guidance most. Lane KKKK binds workspace-path claims (`crates/...` paths in README); Lane LLLLL is orthogonal: it binds doc-path claims (`docs/...` paths in README). Cross-axis to Lane III (per-row binding) and Lane TTTT (row count ↔ test fn count): LLLLL extends the README→reality binding from code paths to doc paths |
| Forbidden-env preflight contract parity (Lane MMMMM) | `crates/ao2-cp-server/tests/release_packaging.rs` `forbidden_env_preflight_contract_parity_lane_mmmmm` | Pins the runtime enforcement of the "No API-key provider authentication" trust boundary. Six invariants in `crates/ao2-cp-server/src/config.rs` + `main.rs`: (1) `check_env: bool` clap arg declared in config.rs (the test-vs-production gate); (2) the forbidden-env scan enumerates BOTH `OPENAI_API_KEY` AND `ANTHROPIC_API_KEY` (no one-provider escape hatch); (3) the scan is guarded by `if raw.check_env { ... }` (tests can opt out, production opts in); (4) `ConfigError::ForbiddenEnv` variant exists with the operator-facing message `"forbidden env var present:"` (log-greppable structured error); (5) `from_real_env()` AUTOMATICALLY pushes `--check-env` so the production entry point never bypasses the preflight; (6) main.rs calls `Config::from_real_env()` and does NOT call `Config::parse_from(std::env::args_os())` (which would skip the auto-push and silently disable the boundary). Why this matters: the control plane MUST refuse to start if a provider API key is present in the environment — otherwise a misconfigured operator host could leak the key into request logs, error traces, or proxied calls. A regression in ANY of these six dimensions silently disables the trust boundary. Cross-axis to Lane CCCC (README threat-model ↔ handler emission): CCCC binds the documented threats to their emission in HTML; MMMMM binds one of those threats (provider key in env) to its runtime enforcement at startup |
| Package-local STAGE-dir trap cleanup parity (Lane NNNNN) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_stage_dir_trap_cleanup_parity_lane_nnnnn` | Pins the staging-dir cleanup contract in `scripts/package-local.sh`. Four invariants: (1) the script creates `STAGE=$(mktemp -d)` (canonical POSIX-portable temp dir); (2) the cleanup body must `rm -rf "$STAGE"` (full removal, not just newest entry); (3) the trap MUST be `trap cleanup EXIT` so cleanup runs on EVERY exit path — normal success, script error, OR signal (a `trap cleanup ERR` alone misses normal exit; a `trap cleanup INT` alone misses script-internal errors); (4) the trap registration MUST appear BEFORE the first STAGE write (the first `"$STAGE/...` reference or `mkdir -p "$STAGE"` step). Why this matters: without the trap, a partial-failure script run leaves stale `stage.XXXXXX` dirs in /tmp. Over many runs /tmp fills with build artifacts containing the release binary (which can include build-host paths, expanded macro debug info, and timing-sensitive build state). On a shared developer host this accumulates indefinitely. Ordering invariant on (4) is load-bearing: a script abort between `mktemp` and `trap` installation leaves a stale dir; installing the trap FIRST ensures every exit path cleans up. Cross-axis to Lane DDDDD (tar arglist ↔ stage writes): DDDDD binds the arglist to staging steps; NNNNN binds the staging dir itself to cleanup — together they ensure the staging surface is both correct AND ephemeral |
| Package-local script shebang + strict-mode parity (Lane OOOOO) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_script_shebang_and_strict_mode_parity_lane_ooooo` | Pins the script-level shebang + strict-mode invariants on `scripts/package-local.sh` itself (the orchestrator script that EMITS the install heredocs). Four invariants: (1) the file's first byte MUST be `#` (start of `#!` shebang); (2) the first line MUST be exactly `#!/usr/bin/env sh` — `#!/bin/sh` is not guaranteed on every BSD/macOS variant and `#!/bin/bash` reduces cross-platform portability; (3) `set -eu` (or stricter like `set -euo pipefail`) MUST appear on a line by itself somewhere in the file; (4) the `set -eu` line MUST appear within the first 5 lines so the fail-fast property is in effect from the very first command. Why this matters: package-local.sh is the script CI invokes to build the release tarball. Without `-e`, a failed `cargo build --release` step proceeds to the tar arglist and CI sees a `file not found` error MINUTES after the actual root cause. Without `-u`, a typo'd `$STAGE_DIR` (instead of `$STAGE`) expands to empty and `cp` writes to the wrong location. Cross-axis to Lane BBBBB (install heredoc shebang + strict-mode): BBBBB binds the install heredocs (`install.sh`, `install.ps1`) — the scripts that get WRITTEN by package-local.sh and SHIPPED in the release archive; OOOOO is the orthogonal script-level analog binding the orchestrator script that PRODUCES those heredocs |
| Package-local default VERSION ↔ workspace version parity (Lane PPPPP) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_default_version_matches_workspace_version_lane_ppppp` | Pins the release-label-vs-binary integrity contract. `scripts/package-local.sh` declares `VERSION="<x.y.z>"` near the top — the default release tag applied to the output archive name (e.g., `ao2-control-plane-0.1.0-macos-aarch64.tar.gz`) when the operator doesn't pass `--version`. The top-level `Cargo.toml` declares `[workspace.package] version = "<x.y.z>"` — the version every member crate inherits via `version.workspace = true`. These two MUST be byte-equal. Why this matters: without the binding, a workspace bump (`0.1.0` → `0.2.0`) that misses the script produces release archives labeled `0.1.0` containing `0.2.0` binaries. Operators following README's "latest" pointer download a `0.1.0` tarball expecting older code and silently get newer behavior — an integrity gap that defeats the entire release labelling system. Floor: VERSION must be a semver-ish string (digits + dot) to prevent empty-string archive names like `ao2-control-plane--macos-aarch64.tar.gz`. Cross-axis to Lane ZZZZ (workspace member ↔ crate dir): ZZZZ binds workspace identity at the structural level (members resolve to real dirs); PPPPP binds workspace identity at the release-label level (script default tag matches the manifest version) |
| Package-local default BINARY release-profile parity (Lane QQQQQ) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_default_binary_is_release_profile_lane_qqqqq` | Pins the four invariants on `scripts/package-local.sh`'s default `BINARY="<path>"` declaration. (1) MUST reference `target/release/` — cargo's release-profile output dir; a regression to `target/debug/` ships a debug binary (10x larger, unstripped symbols leak build-host paths, 10x slower, panic backtraces include source paths). (2) MUST NOT contain `target/debug/` — defensive deny twin of (1) catching partial regressions like `target/debug-release/`. (3) MUST end with `/ao2-cp-server` (no `.exe` suffix on the default; the script's later `case *windows*) BINARY_NAME="ao2-cp-server.exe";;` block handles Windows). A misspelled binary name means cargo's actual output isn't found and the script exits with `missing ao2-control-plane binary`. (4) MUST be `$ROOT`-relative (start with `$ROOT/`) — an absolute path like `/Users/<author>/Documents/...` only works on the original author's machine; on every other operator's host the script exits at the preflight check. Why this matters: this is the load-bearing pointer from the orchestrator script to the cargo build output; any drift here breaks the entire release pipeline on either CI or operator hosts. Cross-axis to Lane EEEEE (handler module ↔ file existence): EEEEE binds source files; QQQQQ binds binary artifacts |
| Package-local cp source paths ↔ real-file parity (Lane RRRRR) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_cp_source_paths_resolve_to_real_files_lane_rrrrr` | Pins every `cp "$ROOT/<path>" "$STAGE/..."` line in `scripts/package-local.sh`. Two invariants: (1) every captured `<path>` MUST resolve to a real file under the workspace root (renamed or deleted ancillary scripts like `verify_release_support_bundle.py` → `verify-release-support-bundle.py` don't fail at cargo build — they only fail at package-local.sh runtime with `cp: cannot stat '...'`, after CI already spent minutes building the release binary); (2) floor: at least 4 such `cp "$ROOT/..."` lines (the four observed: verify_release_support_bundle.py, Verify-ReleaseSupportBundle.ps1, fetch_release_support_handoff.py, Fetch-ReleaseSupportHandoff.ps1) — catches the regression where a future refactor consolidates support scripts and silently drops one from the release archive. Cross-axis to Lane DDDDD (tar arglist ↔ stage writes) and Lane QQQQQ (BINARY default path): DDDDD binds the tar arglist to stage writes (downstream); RRRRR binds stage writes back to real source files in `$ROOT` (upstream). QQQQQ binds the BINARY artifact path; RRRRR is the parallel binding for ancillary support files staged from `$ROOT`. Together they ensure every file in the release archive traces back to a real workspace file |
| Workspace package metadata unification parity (Lane SSSSS) | `crates/ao2-cp-server/tests/release_packaging.rs` `member_cargo_tomls_unify_via_workspace_package_metadata_lane_sssss` | Pins every workspace member crate's `[package]` table to declare core metadata fields (`version`, `edition`, `license`) via `.workspace = true` (or the equivalent `<field> = { workspace = true }` form) rather than re-declaring concrete values in each member manifest. Why this matters: when `edition`/`version`/`license` are duplicated across member manifests with explicit values, a bump in one member but not the others produces a workspace where (a) `edition = "2021"` in member A but `edition = "2018"` in member B means a function moved between them stops compiling (different prelude); (b) `version = "0.1.0"` in member A but `"0.2.0"` in member B means the workspace version (Lane PPPPP) only binds to member A and release archives mislabel member B's content; (c) `license = "MIT OR Apache-2.0"` in member A but `"MIT"` in member B is a legal compliance violation — the workspace claims dual-licensing but a member crate only ships under one license. Floor: >= 3 workspace members checked (matches Lane ZZZZ member floor). Cross-axis to Lane AAAAA (workspace.dependencies unification): AAAAA binds `[workspace.dependencies]` ↔ member `[dependencies]`; SSSSS binds `[workspace.package]` ↔ member `[package]`. Together they ensure ALL workspace-level metadata propagates uniformly to every member crate |
| Workspace.dependencies semver-ish version string parity (Lane TTTTT) | `crates/ao2-cp-server/tests/release_packaging.rs` `workspace_dependencies_have_semver_version_strings_lane_ttttt` | Pins every entry in `[workspace.dependencies]` (the workspace's top-level third-party dep block) to a semver-ish version string. Each entry — `<name> = "<version>"` (short form) or `<name> = { version = "<version>", features = [...] }` (long form) — MUST have a non-empty version that starts with a digit. Three regressions caught: (1) bare wildcard `<name> = "*"` — cargo resolves to the registry's latest at build time, producing irreproducible builds; (2) empty version `<name> = { features = [...] }` — same irreproducibility problem; (3) git-only deps `<name> = { git = "..." }` without a tag/rev pin — moving-target builds. Floor: >= 10 dependencies enumerated (current count ~22; catches over-aggressive refactor). Cross-axis to Lane AAAAA (workspace.dependencies ↔ member inheritance), Lane SSSSS (workspace.package ↔ member inheritance), and Lane CCCCC (Cargo.lock workspace coverage): AAAAA + SSSSS bind workspace metadata TO members; TTTTT binds the workspace metadata to its OWN integrity contract (versions are pinned, not wildcarded). CCCCC's reproducible-build guarantee depends on TTTTT's version-pinning floor — a wildcarded dep undoes Cargo.lock's pinning at the next cargo update |
| Smoke-three-os AO2_CP_VERSION ↔ workspace version parity (Lane UUUUU) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_three_os_default_version_matches_workspace_version_lane_uuuuu` | Pins `scripts/smoke-three-os-release.sh`'s `AO2_CP_VERSION="${AO2_CP_VERSION:-<x.y.z>}"` default fallback to the top-level `Cargo.toml` `[workspace.package] version`. Two invariants: (1) the smoke script must declare an env-overridable `AO2_CP_VERSION` near the top with a `${AO2_CP_VERSION:-<x.y.z>}` default form; (2) the default `<x.y.z>` MUST byte-equal `[workspace.package] version`. Why this matters: the three-OS smoke orchestrates release artifact verification across macOS/Linux/Windows. Lane PPPPP binds `package-local.sh`'s VERSION to the workspace; without UUUUU, a workspace bump could pass PPPPP (package-local updated) but fail at three-OS smoke time because the smoke script's hardcoded default still references the old version — the smoke builds a `<workspace_version>` archive and then verifies against the stale `<smoke_version>`. Every per-host verification step fails with version-mismatch, AFTER the slow build + cross-host transfer. Cross-axis to Lane PPPPP: PPPPP binds the release PRODUCTION script's default version; UUUUU binds the release VERIFICATION script's default version. Together they ensure the workspace version propagates to both the production path and the verification path |
| HTML render fn read-only-observer trust-boundary disclaimer parity (Lane VVVVV) | `crates/ao2-cp-server/tests/release_packaging.rs` `html_render_fns_carry_read_only_observer_disclaimer_lane_vvvvv` | Pins every operator-facing HTML render template in `crates/ao2-cp-server/src/handlers/release_publication.rs` to carry the load-bearing trust-boundary disclaimer. Two anchor phrases pinned per template: (1) `read-only` (case-insensitive) — every page must lead with the read-only posture so the operator immediately sees the trust boundary; (2) `AO artifacts` OR `AO2 artifacts` — every page must explicitly state it does not mutate AO/AO2 artifacts. Floor: >= 7 HTML render templates (each `format!("<!doctype html>...", ...)` body); current count is 8. Why this matters: the control plane is a READ-ONLY observer; it does NOT approve releases and does NOT mutate AO artifacts. Without the per-template pin, an operator landing on any of the pages (via direct URL, runbook link, or cockpit link) could misread the page as authoritative for approval — a security-critical regression. Cross-axis to Lane CCCC (README threat-model ↔ handler emissions) and Lane YYYY (HTML render fn ↔ route registration): CCCC binds the broad threat-model surface; VVVVV is the tighter per-template binding that EVERY HTML render carries the load-bearing trust-boundary phrase. YYYY binds render fn ↔ route; VVVVV binds render fn ↔ disclaimer content. Together they ensure every operator-reachable HTML page is BOTH routed (YYYY) AND attests to its read-only posture (VVVVV) |
| Runbook section heading number ordering parity (Lane WWWWW) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_smoke_runbook_section_headings_form_contiguous_sequence_lane_wwwww` | Pins `docs/runbooks/release-smoke.md`'s `## N.` numbered top-level section headings to form a contiguous `1..=N` sequence in order. Three invariants: (1) every line matching `^## <digits>.` MUST parse cleanly (no `## 1A.` typos, no `## 01.` zero-padded variants); (2) the captured integer sequence MUST be contiguous `1..=N` (no gaps, no duplicates, no reordering); (3) floor: N >= 9 numbered sections (current count: parity verdicts, triage by verdict, triage by candidate_correlation, Lane T worked example, ingestion-time rejection, where the gates are enforced, offline candidate comparison, Lane PP-server rejection triage, rotation-budget reading). Why this matters: the numbered sections form a load-bearing structural navigation surface. Prometheus alerts, cockpit cross-references, and oncall pages all link to specific section numbers — a gap (`1, 2, 3, 5`) breaks every "see section 4" cross-ref; a duplicate (`1, 2, 3, 3`) confuses operators following a numbered link; a reorder means top-to-bottom readers encounter sections out of logical order. Cross-axis to Lane TTTT (section-6 row count ↔ test fn count) and Lane SSSS (section-6 row uniqueness): TTTT + SSSS bind the section-6 ENFORCEMENT TABLE's internal consistency; WWWWW binds the TOP-LEVEL numbered section structure of the runbook itself. Together they ensure the runbook's structural navigation surface is internally consistent at both levels |
| Package-local sha256sum/shasum cross-platform fallback parity (Lane XXXXX) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_sha256_has_cross_platform_fallback_lane_xxxxx` | Pins `scripts/package-local.sh` to compute every SHA-256 hash via the cross-platform `if command -v sha256sum >/dev/null 2>&1; then sha256sum ... else shasum -a 256 ... fi` guarded pattern. Three invariants: (1) floor: >= 2 guarded blocks (current count: one for staging hashes — binary + 4 ancillary scripts; one for the archive hash); (2) each guarded block MUST have a matching `else` branch with at least one `shasum -a 256` invocation; (3) every bare `sha256sum` invocation (excluding the `command -v sha256sum` portability test itself) MUST live inside the `then` body of a guarded block. Why this matters: POSIX SH doesn't standardize a SHA-256 CLI — Linux distros ship `sha256sum` (GNU coreutils); macOS ships `shasum -a 256` (Perl). A naive bare `sha256sum` call works on Ubuntu/Linux CI but breaks on macOS with `command not found` AFTER minutes of release-build work. Without the binding, a future refactor that consolidates the two blocks (e.g., into a single `sha256sum $files` multi-arg invocation) silently breaks the macOS release path. Cross-axis to Lane OOOOO (script shebang + strict-mode): OOOOO ensures the script fails-fast on errors; XXXXX ensures the specific call pattern that ACTUALLY DEPENDS on host portability is itself portably written. OOOOO catches "this script crashed silently"; XXXXX catches "this script will crash silently on macOS" |
| Package-local README.txt heredoc trust-boundary disclaimer parity (Lane YYYYY) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_readme_heredoc_trust_boundary_disclaimer_lane_yyyyy` | Pins `scripts/package-local.sh`'s `README.txt` heredoc body to carry the load-bearing read-only-observer trust-boundary disclaimer. Six invariants: (1) the heredoc start marker `cat > "$STAGE/README.txt" <<'TXT'` MUST exist; (2) the closing `TXT` terminator MUST exist after the start; (3-6) the heredoc body MUST contain the four anchor phrases — `read-only observer` (load-bearing role descriptor), `does not start providers` (provider-lifecycle non-mutation claim), `does not approve AO2 runs` (release/AO2 non-approval claim), `never mutates AO2 artifacts` (broader non-mutation pledge); floor: heredoc body >= 100 lines (current count ~210). Why this matters: the README.txt is what an operator reads FIRST after extracting the release archive — typically before launching the server. If a future refactor strips the read-only-observer disclaimer (consolidation, "we already say it on the live HTML" reasoning), an operator extracting the archive could reasonably misread the tool as a production / approval-authority tool rather than a read-only observer — a security-critical regression. Cross-axis to Lane VVVVV (live HTML trust-boundary disclaimer) and Lane CCCC (README threat-model ↔ handler emissions): VVVVV covers the RUNNING-SERVER HTML surface; CCCC covers the REPO-ROOT README; YYYYY covers the SHIPPED-IN-ARCHIVE README.txt. All three operator-doc surfaces (live HTML, repo README, archive README) must carry the load-bearing trust-boundary disclaimer |
| Release-manifest python heredoc trust_boundary keys parity (Lane ZZZZZ) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_release_manifest_trust_boundary_keys_lane_zzzzz` | Pins `scripts/package-local.sh`'s `python3 - "$STAGE/RELEASE-MANIFEST.json" ... <<'PY' ... PY` python heredoc body to declare the machine-readable trust-boundary attestation. Six invariants: (1) the heredoc start marker MUST exist; (2) the closing `PY` terminator MUST exist after the start; (3) the heredoc body MUST contain the literal JSON key `"trust_boundary"`; (4) the heredoc body MUST contain the literal JSON key `"support_bundle_trust_boundary"` (the offline-verifier-scoped key); (5) the heredoc body MUST contain the literal value prefix `"read-only observer` (the value disclaimer); (6) floor: >= 2 occurrences of `"trust_boundary"` JSON key (one top-level scoping the control plane, one nested under `release_support_handoff_fetcher.phase1_portable_handoff`). Why this matters: the RELEASE-MANIFEST.json is the structured trust-boundary attestation shipped in every release archive — offline verifiers and downstream automation consume the `trust_boundary` key programmatically. If a future refactor strips the key (cleanup, consolidation), the machine-readable attestation is silently lost even when the human-readable README.txt still says "read-only observer". Cross-axis to Lane VVVVV (live HTML disclaimer) and Lane YYYYY (README.txt human-readable disclaimer): VVVVV covers the RUNNING-SERVER surface; YYYYY covers the OFFLINE HUMAN-READABLE doc; ZZZZZ covers the MACHINE-READABLE attestation. All three operator-facing surfaces (live HTML, human-readable text, machine-readable JSON) must carry the trust-boundary contract |
| Release-manifest schema_version semver-suffix parity (Lane AAAAAA) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_release_manifest_schema_version_semver_suffix_lane_aaaaaa` | Pins the `"schema_version"` JSON literal in `scripts/package-local.sh`'s RELEASE-MANIFEST.json python heredoc to match the `<dotted-namespace>.v<positive-integer>` semver-suffix pattern (the same pattern enforced by Lane GGGGG for the handler `RELEASE_*_SCHEMA` consts). Three invariants: (1) the python heredoc body declares a top-level `"schema_version"` JSON key; (2) the value matches `"<namespace>.v<N>"` — at least 2 `.` separators in the value, the final dotted segment starts with `v` followed by ASCII digits with no leading zero, and N >= 1; (3) the namespace prefix starts with `ao2-control-plane` (the bound product identifier). Why this matters: schema_version is the downstream-consumed identifier that offline verifiers (verify_release_support_bundle.py / Verify-ReleaseSupportBundle.ps1) and CI orchestration use to dispatch by schema version. A regression that drops the `v<N>` suffix, adds a non-monotonic suffix (`v01`, `v1a`), or collapses the namespace silently breaks verifier integer-comparison logic. Cross-axis to Lane GGGGG (handler `RELEASE_*_SCHEMA` const `.v<N>` suffix parity): GGGGG binds the IN-PROCESS handler const strings; AAAAAA binds the OUT-OF-PROCESS python-heredoc literal. Both running-handler and offline-archive emissions follow the same schema-versioning contract |
| Package-local archive filename format parity (Lane BBBBBB) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_local_archive_filename_format_lane_bbbbbb` | Pins the canonical release archive filename in `scripts/package-local.sh`: `ARCHIVE="$OUT_DIR/ao2-control-plane-$VERSION-$TARGET_LABEL.tar.gz"`. Six invariants: (1) exactly one top-level `ARCHIVE=` assignment (not multiple — the canonical name has a single definition point; heredoc-interior assignments are filtered out via heredoc-state tracking); (2) value starts with `$OUT_DIR/` (operator-configured output dir, not hardcoded); (3) value contains `ao2-control-plane-` (product-name prefix); (4) value contains `$VERSION` (version substitution — without it, two releases at different versions overwrite each other in $OUT_DIR); (5) value contains `$TARGET_LABEL` (OS+arch substitution — without it, macOS/Linux/Windows releases collide); (6) value ends with `.tar.gz` (gzip-compressed tar suffix — a regression to `.tar` ships uncompressed; `.tar.bz2`/`.tar.xz` breaks the smoke aggregator's `tar -xzf` extraction). Why this matters: the archive filename is the contract between release production (this script) and release verification (smoke aggregator + README + operators). A drift silently breaks cross-OS smoke verification AFTER the build completes — at the worst possible moment. Cross-axis to Lane PPPPP (VERSION ↔ workspace) and Lane QQQQQ (BINARY ↔ release-profile): PPPPP/QQQQQ bind the INPUTS to the archive emission; BBBBBB binds the OUTPUT — the canonical filename consumed by the verification chain |
| Smoke aggregator shebang + strict-mode parity (Lane CCCCCC) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_three_os_shebang_and_strict_mode_parity_lane_cccccc` | Pins `scripts/smoke-three-os-release.sh`'s shebang + strict-mode declaration. Four invariants: (1) file's first byte is `#` (start of `#!` shebang); (2) first line is exactly `#!/usr/bin/env bash` (env-based for cross-distro portability; the smoke depends on bash-specific features `${BASH_SOURCE[0]}` and `-o pipefail`); (3) `set -euo pipefail` (or equivalent: `set -eu -o pipefail`, `set -e -u -o pipefail`) declared on a line by itself; (4) the strict-mode line appears within the first 5 lines (a strict-mode declared later is useless because preceding lines already ran without it). Why this matters: the smoke aggregator SSH/SCP-orchestrates per-host archive verification across macOS/Ubuntu/Windows. Without `-e`, a failed `ssh`/`scp`/`tar -xzf` step proceeds to the cross-OS verdict computation, which reports `matched` when a per-host step actually failed silently. Without `-u`, a typo'd `$AO2_CP_VERISION` expands to empty and `$AO2_CP_VERSION-$TARGET_LABEL.tar.gz` becomes `-macos.tar.gz`. Without `-o pipefail`, a failed `cat smoke.log` piped to `jq ...` returns jq's exit code only (zero if jq succeeded on empty stdin). Cross-axis to Lane OOOOO (package-local.sh shebang + strict-mode): OOOOO binds the release PRODUCTION script (POSIX sh, `#!/usr/bin/env sh` + `set -eu`); CCCCCC binds the release VERIFICATION script (bash, `#!/usr/bin/env bash` + `set -euo pipefail`). Together they ensure both critical release-path scripts fail-fast on errors |
| Install heredoc ao2_control_plane_installed= literal symmetry parity (Lane DDDDDD) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_ao2_control_plane_installed_literal_symmetry_parity_lane_dddddd` | Pins the cross-OS install-confirmation literal contract across the install.sh and install.ps1 heredocs in `scripts/package-local.sh`. Seven invariants: (1) install.sh emits the literal `ao2_control_plane_installed=` byte-string; (2) install.ps1 emits the same literal byte-string (byte-identical); (3) install.sh uses `printf "ao2_control_plane_installed=%s\n"` (NOT `echo` — non-portable across dash/BSD/GNU; missing `\n` concatenates with stderr leaks); (4) install.ps1 uses `Write-Output "ao2_control_plane_installed=...` (NOT `Write-Host` — Write-Host bypasses stdout and `install.ps1 > install.log` captures nothing); (5) install.sh value is the full `$INSTALL_DIR/$BINARY_NAME` path (operator-facing where-binary-landed context, not just the bin name); (6) install.ps1 value uses `$(Join-Path $InstallDir $BinaryName)` (PowerShell's portable path-joining helper that normalizes separators per OS, not naive string concat which can double-separator); (7) floor: exactly ONE confirmation line per script (no double-emission breaking single-line `grep -E '^ao2_control_plane_installed='` parsers). Cross-axis to Lane MMMM (chmod-after-cp + Write-Output existence): MMMM binds the ORDERING and EXISTENCE of the post-copy steps; DDDDDD binds the LITERAL CONTRACT — byte-identical key name, correct emission mechanism, full-path value, and single-emission floor. Without DDDDDD, a typo'd `ao2_control_plan_installed=` on one OS only, or a Write-Host refactor, silently breaks cross-OS install verification while MMMM's ordering checks pass |
| Per-host smoke shebang + strict-mode parity (Lane EEEEEE) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_release_archive_per_host_shebang_and_strict_mode_parity_lane_eeeeee` | Pins shebang + strict-mode invariants on the per-host smoke scripts `scripts/smoke-release-archive.sh` and `scripts/smoke-release-archive.ps1`. Five invariants: (1) .sh first byte is `#` (shebang start); (2) .sh first line is exactly `#!/usr/bin/env bash` (uses bash-only `${BASH_SOURCE[0]}` array variable — a regression to `#!/usr/bin/env sh` silently breaks on Ubuntu where /bin/sh is dash); (3) .sh declares `set -euo pipefail` (or equivalent) within first 5 lines; (4) .ps1 declares `$ErrorActionPreference = "Stop"` within first 5 lines (without it, failed Copy-Item / Get-FileHash print red text and continue, masking step failures); (5) .ps1 first non-empty line IS the $ErrorActionPreference declaration (no executable code precedes it, eliminating the strict-mode window). Why this matters: the smoke verification chain has three scripts — Lane CCCCCC binds the aggregator (smoke-three-os-release.sh); EEEEEE binds the per-host scripts the aggregator invokes via SSH/SCP. A silent step failure in either per-host script that doesn't propagate (failed `tar -xzf`, masked `cp` exit code) leaves the aggregator with stale data which it then aggregates into "all green" — masking the very regression smoke was supposed to catch. Cross-axis to Lane CCCCCC (smoke aggregator) and Lane OOOOO (package-local.sh emitter): together they pin fail-fast semantics across every script in the release production + verification chain |
| Install heredoc BINARY_NAME .exe cross-OS suffix parity (Lane FFFFFF) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_binary_name_exe_suffix_cross_os_parity_lane_ffffff` | Pins the cross-OS binary-filename contract between install.sh's `BINARY_NAME="ao2-cp-server"` (no .exe) and install.ps1's `$BinaryName = "ao2-cp-server.exe"` (.exe). Five invariants: (1) install.sh contains EXACTLY ONE top-level `BINARY_NAME="<v>"` assignment; (2) install.ps1 contains EXACTLY ONE top-level `$BinaryName = "<v>"` assignment; (3) install.sh value does NOT end with `.exe` (unix convention; a `.exe` suffix on unix would break `command -v <basename>` lookups); (4) install.ps1 value DOES end with `.exe` (Windows kernel requires the suffix to treat as executable); (5) install.ps1 value EQUALS install.sh value + the literal `.exe` (the cross-OS contract — Windows form is unix form + .exe, nothing else differs). Why this matters: a rename of either binary without lockstep update silently ships a Windows install referencing a non-existent file, or a unix install pointing at a different binary than `cargo build --release` produces. Both are install-time silent failures with low-context error messages ("file not found"). Cross-axis to Lane VVV (install heredoc bin/ binary-name parity) which binds the path-prefix; FFFFFF binds the .exe-suffix transform |
| Smoke aggregator exit-code fail-loud parity (Lane GGGGGG) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_three_os_exit_code_fail_loud_parity_lane_gggggg` | Pins fail-loud exit semantics on `scripts/smoke-three-os-release.sh`. Three invariants: (1) every `exit <N>` statement MUST have N >= 1 (no `exit 0` early-success branches — success is fall-through to end-of-script; an explicit `exit 0` mid-body short-circuits later parity checks while reporting clean exit); (2) floor: >= 5 `exit 1` statements (the aggregator has multiple parity-drift surfaces — cockpit content-hash, readiness content-hash, publication-dashboard content-hash, assembly content-hash, assembly-blockers content-hash); (3) every `exit <non-zero>` line MUST be preceded within 3 prior lines by an `echo ... >&2` (stderr-redirected error message); without diagnostic text the CI / operator sees a non-zero exit code with no debugging surface. Why this matters: the aggregator IS the cross-OS verifier; an exit-code regression that masks per-host drift (via `exit 0` short-circuit) silently breaks the verification chain — even with strict-mode (Lane CCCCCC) intact. Cross-axis to Lane CCCCCC (smoke aggregator shebang + strict-mode): CCCCCC pins fail-fast on step failure; GGGGGG pins fail-loud on parity drift. Together they ensure the aggregator can never report green on a broken release |
| Install heredoc AO2_CP_* env-var ↔ README reverse-documentation parity (Lane HHHHHH) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredocs_ao2_cp_env_vars_documented_in_readme_lane_hhhhhh` | Inverse-direction binding to Lane RRR. RRR pins README → scripts (every AO2_CP_* env var in README is referenced in some script). HHHHHH pins scripts → README (every AO2_CP_* env var the install heredocs actually consume MUST appear in the README.txt heredoc as operator-facing documentation). Three invariants: (1) floor: install heredocs reference >= 1 AO2_CP_* env var; (2) every AO2_CP_* var in install.sh heredoc is in README; (3) every AO2_CP_* var in install.ps1 heredoc is in README. Scoped to the canonical AO2_CP namespace; the legacy non-prefixed aliases (e.g., AO2_INSTALL_DIR) are intentionally excluded as backwards-compat fallbacks. Why this matters: without HHHHHH, an install heredoc can quietly consume a new operator-override env var without the README documenting it; operators run the install command thinking only the documented vars apply, while the heredoc silently honors an undocumented override from their environment — a configuration-leak surface |
| Smoke aggregator summary JSON schema semver-suffix parity (Lane IIIIII) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_three_os_summary_schema_semver_suffix_lane_iiiiii` | Pins the smoke aggregator's summary JSON schema key. Three invariants: (1) the python heredoc inside `scripts/smoke-three-os-release.sh` that emits the summary MUST declare a `"schema":` JSON key; (2) the value MUST match `<dotted-namespace>.v<N>` where N is a positive integer with no leading zero; (3) the namespace MUST start with the `ao2-control-plane` org prefix. The aggregator is located by content match (the heredoc that contains `"schema":`) rather than file ordinal, so script refactors that move it don't silently bypass the lane. Why this matters: this lane closes a parity trinity with Lane GGGGG (handler schema-version consts) and Lane AAAAAA (RELEASE-MANIFEST.json schema_version). All three carry the `<namespace>.v<N>` convention so downstream readiness/cockpit tooling can gate breaking changes monotonically; an unenforced schema key in the smoke aggregator would let a breaking summary payload change ship under the same `"schema"` label, silently breaking the readiness-refresh pipeline (which would parse the JSON fine but fail version-gate logic downstream). Cross-axis fail-fast also reinforces Lane GGGGGG (exit-code fail-loud) and Lane CCCCCC (aggregator strict-mode): all three pin the aggregator's contract surface, but IIIIII pins the payload, not the script behavior |
| Install heredoc cd-to-script-dir precedence parity (Lane JJJJJJ) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_cd_to_script_dir_precedence_lane_jjjjjj` | Pins that both install heredocs cd into the script's own directory BEFORE any relative-path reference. Per-script invariants: (1) install.sh body contains exactly one cd-to-dirname statement; (2) install.ps1 body contains exactly one Set-Location to PSScriptRoot statement; (3) the cd-equivalent appears BEFORE the first reference to `bin/` or the archive's checksum manifest in the same heredoc body. Why this matters: without this binding, an operator who invokes the install heredoc from a directory other than the unpacked archive root sees the install fail silently — every relative path lookup resolves against the invocation cwd, not the script dir. On Unix this is also a confused-deputy surface: if a malicious local checksum manifest happened to exist in the operator's cwd, the install would verify against attacker-controlled checksums. The exactly-one count protects against refactor accidents where a second cd would muddle the working dir; the precedence check protects against the bug where a cd is present but appears after a relative-path reference. Cross-axis to Lane BBBBB (install heredoc shebang + strict-mode), DDDDDD (install heredoc installed-literal symmetry), FFFFFF (install heredoc BINARY_NAME .exe cross-OS), and HHHHHH (install heredoc env-var README documentation): JJJJJJ pins the install heredoc's working directory contract |
| Release script EXIT trap cleanup parity (Lane KKKKKK) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_script_exit_trap_cleanup_parity_lane_kkkkkk` | Pins that every release-pipeline script that allocates non-trivial ephemeral resources installs an EXIT trap to clean them up. Per-script invariants: (1) `scripts/package-local.sh` installs `trap cleanup EXIT` AND its cleanup body removes the mktemp staging directory; (2) `scripts/smoke-release-archive.sh` installs `trap cleanup EXIT` AND its cleanup body kills the background server process; (3) `scripts/smoke-three-os-release.sh` installs a `trap ... EXIT` (uses an inline trap to remove the working-tree commit file). Floor: at least 3 trap declarations across the three scripts. Why this matters: strict-mode (Lanes OOOOO/CCCCCC/EEEEEE) makes early exit the common case — every unchecked failure triggers it. Without EXIT traps, the CI host (or the operator's laptop) leaks tempdirs in `$TMPDIR` and zombie ao2-cp-server processes bound to chosen ports, masking subsequent failures and bloating disk usage. The cleanup-body content check protects against decorative traps (a `trap cleanup EXIT` paired with an empty cleanup body that doesn't actually remove anything). Cross-axis to Lane OOOOO/CCCCCC/EEEEEE (script strict-mode): strict-mode makes early exits common; KKKKKK ensures those exits don't leak |
| RELEASE-MANIFEST.json auth_value_stored=False security parity (Lane LLLLLL) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_manifest_auth_value_stored_false_parity_lane_llllll` | Security-critical trust-boundary invariant. The python heredoc in `scripts/package-local.sh` that emits RELEASE-MANIFEST.json declares one or more `auth_value_stored` keys (one per documented handoff command that takes an auth env var); each MUST carry the Python literal `False`, never `True`. Three invariants: (1) floor — at least one such key exists in the manifest heredoc; (2) the heredoc MUST NOT contain the literal `auth_value_stored": True` shape; (3) the count of `auth_value_stored": False` MUST equal the total count of `auth_value_stored` (so no occurrence escapes the pin via reformatting variants). The manifest heredoc is located by content match (the heredoc that declares the `ao2-control-plane.release-manifest.v1` schema_version) so refactors that move it don't bypass the lane. Why this matters: the `auth_value_stored` key documents to the release-archive consumer that the manifest itself does NOT store the operator's auth value; flipping it to True would either be a false claim (the archive misrepresents its contents) or accurate (the auth value got baked into the archive — a credential-leak in the publicly distributed artifact). Cross-axis to Lane ZZZZZ (RELEASE-MANIFEST.json python heredoc trust_boundary keys parity) and Lane VVVVV (HTML render fn read-only-observer disclaimer): all three pin different facets of the trust-boundary contract — ZZZZZ pins the declarative `trust_boundary` text key, VVVVV pins the operator-facing HTML disclaimer, LLLLLL pins the boolean credential-storage claim |
| RELEASE-MANIFEST.json binary_path = bin/binary cross-field parity (Lane MMMMMM) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_manifest_binary_path_bin_prefix_parity_lane_mmmmmm` | Pins the cross-field tie between two related keys in the manifest python heredoc: the `binary` value and the `binary_path` value. Three invariants: (1) the heredoc declares a `"binary":` key with a Python expression value (not a string literal — both fields interpolate from argv); (2) the heredoc declares a `"binary_path":` key whose value is an f-string starting with `f"bin/{`; (3) the expression inside the f-string's braces MUST string-match the bare expression assigned to `binary`. The manifest heredoc is located by content match (same `ao2-control-plane.release-manifest.v1` anchor as Lanes AAAAAA / LLLLLL). Why this matters: the install heredocs and offline verifiers read both fields independently; a refactor that updates one argv index but forgets the other can ship a manifest where binary=X but binary_path=bin/Y — silently corrupting the install. Tying both to the same source expression makes that drift impossible. Cross-axis to Lane VVV (install heredoc → bin/binary name parity): VVV pins the install-script side, MMMMMM pins the manifest side; together they ensure the install script and the manifest both point at the same binary, regardless of which side a downstream tool reads from |
| Install heredoc checksum mismatch error message parity (Lane NNNNNN) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_checksum_mismatch_error_parity_lane_nnnnnn` | Pins cross-OS error-message parity on the install heredocs' hash-divergence path. Four invariants: (1) install.sh emits the literal phrase `checksum mismatch` in a stderr-redirected echo; (2) the echo is followed within 5 lines by a non-zero exit; (3) install.ps1 emits the same literal phrase in a `throw` statement (the only PowerShell mechanism that respects $ErrorActionPreference = "Stop" and aborts the script); (4) both diagnostics include the `bin/` prefix in the file reference (e.g., `checksum mismatch for bin/$BINARY_NAME`). Why this matters: operator triage runbooks grep logs for the literal `checksum mismatch` phrase to route supply-chain incidents to on-call. A refactor to `hash mismatch` / `checksum failure` would break every runbook entry filtering by this string, AND would split the Unix and Windows operator's symptom strings for what is functionally the same incident. The non-zero exit + throw checks protect against the more dangerous failure mode: a refactor that drops `exit 1` from install.sh (or replaces `throw` with `Write-Warning` in install.ps1) lets the install proceed past verification and copies a tampered binary into the operator's PATH — a supply-chain drift surface. Cross-axis to Lane DDDDDD (install heredoc installed-literal symmetry): DDDDDD pins the success-path stdout message; NNNNNN pins the failure-path stderr message. Both surfaces have parity contracts |
| Manifest offline_support_bundle_verifiers path-command parity (Lane OOOOOO) | `crates/ao2-cp-server/tests/release_packaging.rs` `release_manifest_offline_verifiers_path_command_parity_lane_oooooo` | Pins that each entry in RELEASE-MANIFEST.json `offline_support_bundle_verifiers` has its `command` string reference the literal `path` value, and both verifier commands reference the same shared bundle filename. Four invariants: (1) the manifest heredoc declares an `offline_support_bundle_verifiers` key; (2) both `python` and `powershell` child verifier entries exist; (3) for each (path, command) pair, the command string contains the path value as a substring; (4) both verifier commands reference the shared bundle filename `release-support-bundle.json`. The manifest heredoc is located by content match (same `ao2-control-plane.release-manifest.v1` anchor as Lanes AAAAAA / LLLLLL / MMMMMM). Why this matters: the manifest documents the offline-verification command line for operators on either OS; if the documented `path` says one filename but the documented `command` invokes a different one, operators running the command from the runbook get a `file not found` error while believing the manifest told them the right thing. The shared-bundle-filename check (invariant 4) prevents the symmetric drift where the two verifiers expect different bundle names — Mac/Linux passes `release-support-bundle.json` and Windows passes `support-bundle.json`, splitting the cross-OS runbook entry. Cross-axis to Lane RRRRR (package-local.sh cp source paths ↔ real-file parity): RRRRR pins that the verifier file is copied into the stage area at the right name; OOOOOO pins that the manifest documents that name correctly to operators |
| Install heredoc sha256sum/shasum cross-platform fallback parity (Lane PPPPPP) | `crates/ao2-cp-server/tests/release_packaging.rs` `install_heredoc_sha256sum_shasum_cross_platform_fallback_parity_lane_pppppp` | Pins that install.sh probes for the GNU coreutils hash binary first and falls back to the macOS shasum wrapper, while install.ps1 uses the PowerShell-native hash cmdlet and never references unix hash tools. Five invariants: (1) install.sh contains `command -v sha256sum`; (2) install.sh contains `shasum -a 256`; (3) the probe appears strictly before the fallback (gating semantics); (4) install.ps1 contains `Get-FileHash -Algorithm SHA256`; (5) install.ps1 contains neither `sha256sum` nor `shasum -a 256`. Why this matters: install.sh runs on Linux (where the GNU coreutils binary is the default hash tool) AND macOS (where it is absent and the Perl-script wrapper ships with the OS). Inverting the probe/fallback ordering means Linux installs unconditionally try the macOS tool, and the default OS path errors before checksumming. Dropping the fallback means the macOS install path hits a generic command-not-found and skips checksum verification entirely — a supply-chain drift surface. The install.ps1 absence checks (invariant 5) prevent the symmetric pollution where a copy-paste from install.sh leaks a unix-only command into the PowerShell heredoc, silently breaking the Windows install path. Cross-axis to Lane XXXXX (package-local.sh emitter-side checksum block shape parity): XXXXX pins the emitter side of the fallback ordering on the packaging script itself; PPPPPP pins the installed-side ordering on the install.sh heredoc that the packaging script writes into archives shipped to operators |
| Package README.txt auth credential lifecycle parity (Lane QQQQQQ) | `crates/ao2-cp-server/tests/release_packaging.rs` `package_readme_auth_credential_lifecycle_parity_lane_qqqqqq` | Pins the operator-facing README.txt heredoc credential lifecycle for both support-bundle fetch flows and both shell families. Six invariants: (1) exactly two Unix `export AO2_CP_AUTH_VALUE=` lines (simple bundle + Phase 1 portable handoff); (2) exactly two Unix `unset AO2_CP_AUTH_VALUE` cleanup lines; (3) exactly two PowerShell `$env:AO2_CP_AUTH_VALUE=` lines; (4) exactly two `Remove-Item Env:\AO2_CP_AUTH_VALUE` cleanup lines; (5) every Unix export is followed by its cleanup before the next export; (6) every PowerShell set is followed by its cleanup before the next set. Why this matters: the README recipe handles bearer-token header values. If a cleanup line disappears, an operator who copy-pastes the documented flow leaves the token in their shell environment and leaks it into later child processes, logs, or diagnostics. Cross-axis to Lane ZZZZZ and LLLLLL: those lanes pin the manifest's trust-boundary/auth_value_stored declaration; QQQQQQ pins that the human runbook recipe actually satisfies the declaration by clearing the credential after use |
| Smoke aggregator markdown report section structure parity (Lane RRRRRR) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_aggregator_markdown_report_section_structure_parity_lane_rrrrrr` | Pins that the smoke-three-os-release.sh markdown report has all five mandatory H2 sections in canonical order and that the Trust-boundary section carries the load-bearing security keywords. Six invariants: (1) the markdown-writing block exists (anchored by the `} >"$report_md"` close); (2) the H1 title appears; (3) all five H2 sections appear (Results, Logs, Remote command files, Trust boundary, Rerun commands); (4) they appear in canonical order; (5) the Trust-boundary section contains the role keyword `read_only_observer`; (6) the Trust-boundary section contains the approval-owner identity `factory-v3 evaluator-closer`. Why this matters: the markdown report is the primary triage surface that doesn't need jq — on-call operators read it first, and post-mortem reviewers consult it later. Dropping the Trust-boundary section silently weakens the operator-facing security commitment in the very document incident reviewers reference. Reordering jumbles operator navigation: on-call playbooks reference sections by position. Cross-axis to Lane VVVVV (HTML render fn trust-boundary disclaimer parity) and Lane ZZZZZ (manifest trust-boundary key parity): VVVVV pins the HTML disclaimer surface, ZZZZZ pins the manifest JSON surface, RRRRRR pins the third operator-facing surface — the smoke aggregator's markdown report. All three surfaces must agree on the role and approval owner |
| Smoke aggregator secret redaction pattern parity (Lane SSSSSS) | `crates/ao2-cp-server/tests/release_packaging.rs` `smoke_aggregator_secret_redaction_pattern_parity_lane_ssssss` | Pins that BOTH redaction sites in scripts/smoke-three-os-release.sh share the same four secret-pattern markers. The script runs two independent redaction passes — one over the JSON-emitting heredoc's per-OS log tails (the `SECRET_PATTERNS = [` list), and one over the markdown failure-excerpt fenced code block (the inline `for pat in [` python -c invocation). Eight invariants: both passes must each contain the four canonical markers (case-insensitive bearer-token pattern containing `authorization`, the local-OAuth token `AO2_CP_API_TOKEN`, and the two provider API keys `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`). Why this matters: the script's two-site duplication is fragile by construction. If a new secret pattern is added to one redactor and not the other, the same log-tail content gets full redaction in one operator-facing surface (the JSON summary) and partial redaction in the other (the markdown report). Operators reading the report would still see the secret even though the JSON summary is clean — credential leakage in whichever surface lags behind. Cross-axis to existing redaction tests for the support-bundle verifier and bundle handler: together they form the defense-in-depth secret-redaction surface that no single edit can fully bypass |
| SECURITY.md source-code claim parity (Lane TTTTTT) | `crates/ao2-cp-server/tests/release_packaging.rs` `security_md_claims_bind_to_source_code_lane_tttttt` | Pins that load-bearing factual claims in docs/SECURITY.md trace back to actual source code literals. Seven invariants: (1) the doc mentions Exit code 78 AND src/main.rs calls exit(78); (2 + 3) the doc names both provider-registry schema identifiers AND src/handlers/provider_registry.rs declares both; (4) the doc names the `ao2-local-cli` execution-owner literal AND the handler validates it; (5) the doc names `AO2_CP_API_TOKEN` AND src/config.rs reads it; (6 + 7) the doc lists `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` as forbidden envs AND src/config.rs refuses them. Why this matters: docs/SECURITY.md is the security-posture declaration that operators, reviewers, and integrators read to understand the trust model. If any claim drifts from the implementation, the doc becomes a misleading contract: operators read one behavior, the server does another. Integrators relying on the exit-code claim (CI pipelines parsing exit codes) silently break. Cross-axis to Lane CCCC (README threat-model → handler emission parity): CCCC pins the README threat-model section; TTTTTT pins the SECURITY.md document — both operator-facing security surfaces, both must trace to implementation |
| DEPLOYMENT.md flag and endpoint parity (Lane UUUUUU) | `crates/ao2-cp-server/tests/release_packaging.rs` `deployment_md_flags_and_endpoints_bind_to_source_lane_uuuuuu` | Pins that load-bearing operator-recipe surfaces in docs/DEPLOYMENT.md trace back to actual clap-derived flags and registered endpoint paths. Seven invariants: (1) the doc references `--bind` AND src/config.rs declares the bind field; (2) the doc references `--data-dir` AND src/config.rs declares data_dir; (3) the doc references `AO2_CP_LOG_LEVEL` AND src/config.rs reads it; (4-7) each of the four documented endpoint paths (`/api/v1/storage/report`, `/api/v1/storage/prune`, `/api/v1/provider/registry`, `/api/v1/provider/registry/dashboard`) appears in src/route_catalog.rs. Why this matters: DEPLOYMENT.md is the operator's deploy guide. It hands out systemd unit fragments, curl recipes, and command lines that operators copy-paste into their environment. If a flag is renamed, an env var removed, or an endpoint route moved without the doc keeping pace, operators following the documented recipe land on clap errors or 404s — the most expensive form of documentation drift because it surfaces during deployment, not development. Cross-axis to Lane WWW (README port literal parity): WWW pins the 8744 port literal across surfaces; UUUUUU pins the CLI flags and endpoint paths that flank it — together they cover the full deploy-recipe surface |
| Manifest outputs arrays bind to fetcher outputs parity (Lane VVVVVV) | `crates/ao2-cp-server/tests/release_packaging.rs` `manifest_outputs_arrays_bind_to_fetcher_outputs_lane_vvvvvv` | Pins that every file name declared in the manifest python heredoc's two `outputs` arrays (the standard `release_support_handoff_fetcher.outputs` flow and the `phase1_portable_handoff.outputs` flow) also appears in the fetcher script. Eleven invariants — five standard-flow file names (`release-support-verifier-handoff.json`, `release-support-bundle.json`, `SHA256SUMS`, `release-support-bundle-verify.json`, `release-support-bundle-manifest.json`) and six Phase 1 file names (`phase1-portable-manifest.json`, `ao2-phase1-operator-support-bundle.json`, `ao2-phase1-gap-report.json`, `phase1-SHA256SUMS`, `phase1-portable-manifest-verify-upload.json`, `phase1-portable-manifest-verification.json`) — must each be pinned in both the heredoc in `scripts/package-local.sh` AND in `scripts/fetch_release_support_handoff.py`. Why this matters: the manifest's `outputs` arrays are the contract operators use to know which files to expect on disk after running the documented fetcher command. If a file name is in the manifest but not in the fetcher, operators waste triage time looking for a missing file. If the fetcher writes a file the manifest doesn't list, operators don't know the bundle's full surface. Either drift breaks the manifest-as-truth contract. Cross-axis to Lane OOOOOO (manifest verifier path↔command parity): OOOOOO pins that documented verifier commands reference documented paths; VVVVVV pins that documented output files map to files the fetcher actually writes — together they close the manifest's claims-vs-reality loop |
| Server Cargo.toml [[bin]] and [lib] declarations bind to sources (Lane WWWWWW) | `crates/ao2-cp-server/tests/release_packaging.rs` `server_cargo_toml_bin_and_lib_declarations_bind_to_sources_lane_wwwwww` | Pins that the server crate's Cargo.toml sub-structure ties cleanly back to the package name, the source files on disk, and the package-script binary literal. Seven invariants: (1) `crates/ao2-cp-server/Cargo.toml` declares the package name literal; (2) the [[bin]] block declares the same name (so cargo produces a binary whose filename matches every downstream surface); (3) the [[bin]] block declares the path literal pointing at the main entry source; (4) the entry source file exists on disk; (5) the [lib] block declares the snake_case lib name (so downstream `use` imports resolve); (6) the [lib] block declares the lib source path AND the lib source file exists on disk; (7) `scripts/package-local.sh` declares the matching binary-name literal. Why this matters: if the [[bin]] name diverges from the package name, cargo produces a binary with the wrong filename and every downstream literal (package script, install heredoc, README) silently picks up the wrong file or fails to find it. If the [lib] name diverges from snake_case of the package name, every downstream `use ao2_cp_server::...` import breaks — including this crate's own integration tests. If a source path drifts from the actual file location, cargo build fails outright; pinning the literals catches the subtler refactor-without-update case. Cross-axis to Lane VVV (install heredoc → bin/ binary name parity): VVV pins that install heredocs reference the binary filename; WWWWWW pins the Cargo declaration that produces that filename — together they close the loop from build artifact through tar archive into install heredoc |
| Route catalog entries bind to server route registrations (Lane XXXXXX) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_entries_bind_to_server_route_registrations_lane_xxxxxx` | Pins that every `RouteMetadata` path entry in `crates/ao2-cp-server/src/route_catalog.rs` has a matching `.route("<suffix>", ...)` registration in `crates/ao2-cp-server/src/server.rs`. The catalog is the central inventory the public route-index endpoint emits; for each catalog entry the test strips the `/api/v1` prefix and asserts the suffix appears as a quoted route literal in the axum router. A defensive floor on catalog-entry count (≥100, currently 115) prevents future refactors from stripping entries and passing the per-path check vacuously. Why this matters: the catalog is operator-facing truth about which API surfaces exist. If a route is in the catalog but not registered in the axum router, the route-index endpoint claims a path the server doesn't actually serve — operators curl what the inventory advertises and get 404. If a route is registered but missing from the catalog, integrators see a route in code that isn't visible via the inventory — a security-visibility gap where new surfaces ship without making it into the documented attack-surface enumeration. Cross-axis to Lane SSS (README → axum router declaration parity): SSS pins docs↔router; XXXXXX pins catalog↔router; together with Lane UUUUUU (DEPLOYMENT.md endpoints) they form a docs/catalog/router triangle. Cross-axis to Lane JJJJ (release routes ↔ handler fn parity): JJJJ pins that release-publication routes wire to handler fns; XXXXXX pins that ALL routes (not just release) in the catalog wire to axum registration |
| Server route registrations bind to route catalog entries (Lane YYYYYY) | `crates/ao2-cp-server/tests/release_packaging.rs` `server_route_registrations_bind_to_route_catalog_entries_lane_yyyyyy` | Reverse parity to Lane XXXXXX: pins that every `.route("<path>", ...)` registration in `crates/ao2-cp-server/src/server.rs` has a matching `path: "/api/v1<path>"` entry in `crates/ao2-cp-server/src/route_catalog.rs`. The test scans server.rs for every `.route(` opener, extracts the first quoted argument, prepends the `/api/v1` mount prefix, and asserts the full path appears in the catalog. A defensive floor on extracted-route count (≥90) catches parser regressions. Why this matters: the public route-index endpoint enumerates the attack surface from the catalog. If a new route is added to server.rs but the catalog isn't updated, the route ships and serves requests but the inventory hides it — operators and security reviewers enumerating routes via the endpoint silently miss the new surface. Together XXXXXX and YYYYYY form a bidirectional invariant: neither direction alone catches all drift cases. Cross-axis to Lane JJJJ (release routes ↔ handler fn parity): JJJJ pins router↔handler; YYYYYY pins router↔catalog; together with XXXXXX the chain catalog→router→handler is fully observable in both directions |
| Mutating routes use POST not GET CSRF safety (Lane ZZZZZZ) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_mutating_routes_use_post_not_get_lane_zzzzzz` | Pins a structural CSRF-safety invariant on `crates/ao2-cp-server/src/route_catalog.rs`: every RouteMetadata block with `mutates_observer_storage: true` MUST declare a method other than GET. The test parses each RouteMetadata block, extracts its method and mutation flag, and fails with the offending path if any mutating route is declared as GET. A defensive floor on parsed-block count (≥100) catches parser regressions. Why this matters: a GET endpoint that mutates state is a classic CSRF attack vector. Any cross-origin HTML page can embed `<img src="<mutating-get-url>">` or `<script src="...">` and trigger the mutation just by being loaded — no JavaScript required, no operator interaction required, just an authenticated session that the browser sends automatically with the request. The structural defense is method-based: state-changing operations use POST/PUT/DELETE because browsers treat these as 'unsafe' methods, requiring explicit form/fetch invocation. The auth middleware in `crates/ao2-cp-server/src/auth.rs` provides the bearer-token check; this lane adds a second defense layer — even if auth were bypassed, the method-vs-mutation invariant means a CSRF GET request can't actually change state. Cross-axis to Lane YYYYYY: YYYYYY pins router→catalog visibility; ZZZZZZ pins catalog method safety; together they cover both visibility and safety for the full mutation surface |
| Route catalog category field enum-shape parity (Lane AAAAAAA) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_category_field_enum_shape_lane_aaaaaaa` | Pins that every RouteMetadata entry's `category` value in `crates/ao2-cp-server/src/route_catalog.rs` belongs to a canonical allowed-set of category literals defined inside the test (currently 21 distinct values covering storage, provider, release, phase1, and observer groupings). The test parses each RouteMetadata block, extracts the `category` field, and fails if any value is outside the allowed-set; a defensive floor on parsed-block count (≥100) and allowed-set size (≥20) catches parser regressions and accidental list strip-outs. Why this matters: the catalog drives dashboard grouping and the operator-facing route inventory, and downstream code filters route lists by exact `category` value. A typo (e.g. `storage-observer` → `stoarge-observer`) silently creates a new one-route group that splits the dashboard visual grouping, breaks category-filtered views, and slips past code review because the catalog file is large. To introduce a legitimate new category, both the canonical set in the test AND the new RouteMetadata entry must be updated in the same change — the test fails loud until both sides match. Cross-axis to Lane XXXXXX/YYYYYY: those lanes pin route IDENTITY parity (catalog↔server); AAAAAAA pins route METADATA-FIELD parity within the catalog — together the route surface is locked at both the identity and the field-value level |
| Route catalog method field enum parity (Lane BBBBBBB) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_method_field_enum_parity_lane_bbbbbbb` | Pins that every RouteMetadata entry's `method` value in `crates/ao2-cp-server/src/route_catalog.rs` is one of the canonical uppercase HTTP verbs (GET / POST / PUT / DELETE / PATCH). The test parses each RouteMetadata block, extracts the `method` field, and fails if any value is outside the allowed-set; a defensive floor on parsed-block count (≥100) and allowed-set size (≥5) catches parser regressions. Why this matters: a typo like `Get` or `POST ` (trailing space) silently breaks exact-string method filtering in dashboards and operator tooling, and may mislead operators about what HTTP verb the endpoint actually accepts (server.rs registrations are case-folded by axum but the catalog is a public-facing literal contract). The fixed-case enum also defends Lane ZZZZZZ's CSRF check: if a future entry uses lowercase, ZZZZZZ's case-insensitive comparison still catches the CSRF violation, but BBBBBBB catches the typo earlier so operators and reviewers always see canonical methods. To introduce a new verb (e.g. PATCH for partial-resource updates), update both the canonical set in this test AND the new RouteMetadata entry in the same change. Cross-axis to Lane AAAAAAA: AAAAAAA pins the category enum; BBBBBBB pins the method enum — together they cover both string-field shapes in the catalog |
| Route catalog owner field membership parity (Lane CCCCCCC) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_owner_field_membership_lane_ccccccc` | Pins that every RouteMetadata entry's `owner` value in `crates/ao2-cp-server/src/route_catalog.rs` belongs to a canonical set of trust-boundary owner literals (currently 5: ao2-control-plane observer, factory-v3 evaluator-closer, ao2 signed evidence boundary, ao2 signed memory boundary, factory-v3 Hermes watchdog). The test parses each RouteMetadata block, extracts the `owner` field, and fails if any value is outside the allowed-set; defensive floors on parsed-block count (≥100) and allowed-set size (≥5) catch parser regressions and accidental owner-set strip-outs. Why this matters: the `owner` field declares the trust-boundary identity responsible for endpoint behavior. A fabricated owner literal silently introduces a sixth trust-boundary identity that the cockpit HTML disclaimer doesn't render, the smoke report markdown doesn't list, and the manifest JSON doesn't pin — fragmenting the operator-facing trust model across surfaces. To introduce a new owner, update the canonical set here AND the cockpit disclaimer + smoke report markdown + manifest JSON owner surfaces in the same change. Cross-axis to Lane VVVVV (HTML disclaimer trust-boundary language): VVVVV pins the operator-visible disclaimer literals; CCCCCCC pins the every-route owner declaration — together the trust-boundary identity surface stays coherent across UI and data. Closes the route_catalog string-field enum trilogy (category / method / owner) |
| Route catalog download flag implications parity (Lane DDDDDDD) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_download_flag_implications_lane_ddddddd` | Pins three semantic implications of `download: true` on every RouteMetadata entry in `crates/ao2-cp-server/src/route_catalog.rs`: every download-flagged route MUST also have `portable: true` (cross-OS-safe artifact), `method: "GET"` (downloads are reads), and `mutates_observer_storage: false` (downloads cannot mutate state). The test parses each RouteMetadata block, filters to those with `download: true`, and asserts all three paired-flag invariants; defensive floors on parsed-block count (≥100) and download-flagged-count (≥8 — release-support bundle + SHA256SUMS + portable manifest + phase1 variants) catch parser regressions and accidental contract strip-outs. Why this matters: the `download` flag tells the dashboard to render a download widget and tells operators they can save the response to disk. A `download: true` paired with `mutates: true` looks like a safe download but actually changes state behind the scenes — a hidden side-effect. A `download: true` paired with `method: POST` smells like a side-effect under a read label. A `download: true` paired with `portable: false` ships an artifact operators cannot use on the OS they ran the install on. Cross-axis to Lane ZZZZZZ (mutating-route CSRF safety): ZZZZZZ catches `mutates+GET`; DDDDDDD catches `download+POST`, `download+mutates`, and `download+non-portable` — together they cover the four highest-risk flag combinations on the route catalog |
| Route catalog download path naming convention parity (Lane EEEEEEE) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_download_path_naming_convention_lane_eeeeeee` | Pins that every `download: true` entry's `path` in `crates/ao2-cp-server/src/route_catalog.rs` ends with either `/download` (canonical "fetch the artifact" suffix) or `/SHA256SUMS` (canonical "fetch the checksum file" suffix). The test parses each RouteMetadata block, filters to entries with `download: true`, extracts the path, and asserts the suffix matches one of the two canonical forms; defensive floors on parsed-block count (≥100) and download-flagged-count (≥8) catch parser regressions. Why this matters: operator runbooks reference download URLs by suffix convention ("hit `<bundle-url>/download` to fetch, `<bundle-url>/SHA256SUMS` to verify"), and the convention is what lets operators predict the URL for a download from any category. A future endpoint that declares `download: true` but uses `/raw`, `/fetch`, or `/get-file` as the suffix breaks every runbook entry filtering by suffix and forces operators to look up the exact URL per-category. Cross-axis to Lane DDDDDDD: DDDDDDD pins what `download: true` implies about FLAGS; EEEEEEE pins what it implies about PATH SHAPE — together they pin the full operator-facing contract behind the download flag |
| Route catalog portable flag non-mutating implication parity (Lane FFFFFFF) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_portable_implies_non_mutating_lane_fffffff` | Pins that every RouteMetadata entry in `crates/ao2-cp-server/src/route_catalog.rs` with `portable: true` also declares `mutates_observer_storage: false`. The test parses each RouteMetadata block, filters to entries with `portable: true`, and asserts the non-mutating flag invariant; defensive floors on parsed-block count (≥100) and portable-flagged-count (≥40) catch parser regressions and accidental portable-surface strip-outs. Why this matters: the `portable` flag means the artifact or operation is designed to be taken offline. A portable download produces a bundle operators can ship to air-gapped machines; a portable verify endpoint is safe to run repeatedly without source-of-truth changes. A `portable: true` paired with `mutates: true` breaks the idempotent-offline contract — an operator copying the bundle to a remote machine expects safe-to-re-run behavior, not state mutation on the source side. Cross-axis to Lane DDDDDDD/EEEEEEE (download flag axes): DDDDDDD/EEEEEEE cover the download subset of portable; FFFFFFF covers the full portable surface including portable-but-not-download routes (POST verifiers). Cross-axis to Lane ZZZZZZ (CSRF): ZZZZZZ catches mutating GET; FFFFFFF catches mutating-but-portable (any method) — together they cover the full mutation-vs-safety contract |
| RouteMetadata struct and to_json schema parity (Lane GGGGGGG) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_struct_and_to_json_schema_lane_ggggggg` | Pins two surfaces in lockstep on `crates/ao2-cp-server/src/route_catalog.rs`: (1) the `pub struct RouteMetadata` declaration must list exactly the 7 known fields with their canonical types (method, path, category, owner are `&'static str`; download, portable, mutates_observer_storage are `bool`); (2) the `to_json()` impl body must emit those 7 dynamic fields PLUS 4 trust-boundary constant keys with their canonical values: `auth_required: true`, `control_plane_role: "read-only-observer"`, `mutates_ao_artifacts: false`, `control_plane_approves_release: false`. The test reads the struct declaration block and the to_json() function body, asserts each required line/literal, and pins the field count at exactly 7. Why this matters: the route-index endpoint (`/api/v1/route-index` + `/api/v1/control-plane/routes.json`) is the canonical machine-readable inventory of every observer API surface. Operator audit tooling, dashboard rendering, and integration tests all parse this JSON; a renamed field, a dropped trust-boundary key, or a flipped constant value (e.g. `mutates_ao_artifacts` accidentally set to true during a refactor) silently changes the operator-consumed JSON contract and breaks downstream consumers OR — worse — quietly weakens the per-route trust-boundary commitment. To add a new field requires updating the struct declaration AND every RouteMetadata block initializer AND the to_json() body AND this test's `required_fields` list in the same change. Cross-axis to Lane CCCCCCC (owner) + Lane VVVVV (HTML disclaimer): all three encode the trust-boundary commitment on different operator-facing surfaces; drift on any fails loud at test time |
| Handler SCHEMA constants canonical shape parity (Lane HHHHHHH) | `crates/ao2-cp-server/tests/release_packaging.rs` `handler_schema_constants_have_canonical_shape_lane_hhhhhhh` | Pins workspace-wide that every `const <NAME>_SCHEMA: &str = "..."` declaration across `crates/ao2-cp-server/src/handlers/*.rs` (excluding `mod.rs`) follows the canonical `ao2.<family-id>.v<N>` shape: the literal MUST start with the `ao2.` prefix AND end with `.v<digits>` (semver-major suffix). The test discovers handler files programmatically, scans each line for `const ` + `_SCHEMA: &str` pattern, extracts the quoted literal, and asserts both invariants. Defensive floors on discovered handler-file count (≥8) and schema-constant count (≥30; today around 41) catch wholesale strip-outs. Why this matters: schema literals are emitted in JSON responses (`schema`, `schema_version`) and serve as the machine-readable identity of every observer surface — operator audit tooling, integration tests, and the support-bundle verifier all filter on these literals. A typo like `oa2.foo.v1` (transposed prefix) or `ao2.foo` (missing semver suffix) silently breaks downstream schema dispatch — payload looks identical, consumer no longer recognizes the family. Lane GGGGG pinned the semver-suffix invariant on a single file's release schemas; HHHHHHH scales that invariant to every handler module in the workspace, catching new schemas introduced anywhere. Cross-axis to Lane GGGGG (single-file release schema semver) + Lane IIIIII (smoke aggregator JSON output schema semver): together they lock the full schema-naming taxonomy across internal handlers AND external smoke-aggregator outputs |
| Route catalog method-path tuple uniqueness parity (Lane IIIIIII) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_method_path_tuples_are_unique_lane_iiiiiii` | Pins that every (method, path) tuple in `crates/ao2-cp-server/src/route_catalog.rs` appears at most once across the ROUTES table. The test parses each RouteMetadata block, extracts its `method` and `path` fields, builds a HashMap keyed on the (method, path) tuple, and reports every duplicate pair; a defensive floor on parsed-block count (≥100) catches parser regressions where the block-extractor breaks silently. Why this matters: HTTP routing semantics require (method, path) uniqueness — a duplicate either silently shadows one of the entries at axum's router level (later registration wins, earlier handler becomes unreachable) OR fragments the `/api/v1/control-plane/routes.json` route inventory into two JSON rows that appear to be distinct observer surfaces but share a single handler, breaking operator audit tooling and the trust-boundary route-count contract. Cross-axis to Lane XXXXXX (catalog↔server.rs forward parity) and Lane YYYYYY (reverse parity): XXXXXX/YYYYYY pin every catalog entry to its server.rs registration in both directions, but neither catches duplicates INTERNAL to the catalog — both duplicate rows would map to the SAME server.rs registration, so bidirectional parity passes silently. Lane IIIIIII closes that gap structurally inside the catalog so the route-inventory contract stays normalized |
| Route catalog path canonical-prefix parity (Lane JJJJJJJ) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_paths_use_canonical_prefix_lane_jjjjjjj` | Pins two URL-contract invariants on every `path` field in `crates/ao2-cp-server/src/route_catalog.rs`: (1) every path MUST start with the canonical `/api/v1/` versioned prefix; (2) no path may end with a trailing slash. The test parses each RouteMetadata block, extracts the `path` field, and asserts both invariants; a defensive floor on parsed-block count (≥100) catches parser regressions. Why this matters: the versioned `/api/v1/` prefix is the operator contract advertised in the README, in the route-inventory endpoint, and in the install.sh handoff documentation; a new route added under `/admin/`, `/v2/`, `/healthz`, or a bare segment silently introduces a second API surface that escapes the versioning convention and breaks operator URL prediction. Trailing-slash drift is even more insidious: axum treats `/foo` and `/foo/` as distinct routes, so a trailing slash on one entry but not another silently fragments the URL space — an operator hitting the documented `/foo` URL gets a 404 while the catalog appears to declare the route. Cross-axis to Lane EEEEEEE (download path SUFFIX): EEEEEEE pins what download-flagged paths must END with; JJJJJJJ pins what EVERY path must START with — together the URL shape is locked at both ends. Cross-axis to Lane IIIIIII (tuple uniqueness): IIIIIII catches duplicate pairs; JJJJJJJ catches a new entry that uses a fundamentally different URL scheme |
| Route catalog category coverage parity (Lane KKKKKKK) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_category_coverage_parity_lane_kkkkkkk` | Reverse of Lane AAAAAAA. AAAAAAA pins forward: every CATALOG category must appear in the canonical allowed-set. KKKKKKK pins reverse: every allowed-set category MUST appear in at least one RouteMetadata block in `crates/ao2-cp-server/src/route_catalog.rs`. The test re-declares the same canonical set (kept structurally identical to AAAAAAA), parses every RouteMetadata block, collects the set of used categories, and reports any allowed category that has zero uses. Why this matters: a "dangling" allowed category — present in the schema but used by no route — silently weakens Lane AAAAAAA's invariant. When an operator removes the last route in a category (deprecation, refactor) but forgets to trim the allowed-set, the schema permits a value that no route declares; downstream code filtering by category gets unexpectedly empty groups, and operator-facing dashboards may reserve a section for a surface that no longer exists. AAAAAAA + KKKKKKK together form a bijection: the catalog's actual category SET and the canonical allowed SET are forced to be identical — neither dangling categories nor undeclared categories can slip through. To remove a category, REMOVE all RouteMetadata entries first AND THEN trim BOTH the AAAAAAA and KKKKKKK canonical sets in the same change |
| Route catalog owner coverage parity (Lane LLLLLLL) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_owner_coverage_parity_lane_lllllll` | Reverse of Lane CCCCCCC. CCCCCCC pins forward: every CATALOG owner must appear in the canonical 5-identity allowed-set. LLLLLLL pins reverse: every allowed-set owner MUST appear in at least one RouteMetadata block in `crates/ao2-cp-server/src/route_catalog.rs`. The test re-declares the same canonical 5-owner set (kept structurally identical to CCCCCCC), parses every RouteMetadata block, collects the set of used owners, and reports any allowed owner that has zero uses. Why this matters: the owner reverse-coverage check is even more security-relevant than category reverse-coverage — a dangling allowed owner silently broadcasts a false trust-boundary surface. Operators reading the cockpit HTML disclaimer or the smoke report markdown see the identity listed as a trust party, but if no route actually delegates work to that identity, the disclaimer is misleading. The trust-boundary surface MUST be exactly the set of identities actively reachable from the route catalog. Cross-axis to Lane CCCCCCC (forward) and Lane VVVVV (HTML disclaimer): CCCCCCC + LLLLLLL form a bijection on the per-route owner declarations; VVVVV pins the operator-visible HTML disclaimer — together the trust-boundary identity surface stays coherent and never misrepresents reachable parties. To remove an owner: REMOVE all RouteMetadata entries first AND trim BOTH the CCCCCCC and LLLLLLL canonical sets in the same change |
| Route catalog path :param snake_case naming parity (Lane MMMMMMM) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_path_params_use_snake_case_lane_mmmmmmm` | Pins that every `:<name>` path-parameter placeholder appearing in a `path: "..."` field inside `crates/ao2-cp-server/src/route_catalog.rs` follows snake_case ASCII naming (`^[a-z][a-z0-9_]*$`). The test parses each RouteMetadata block, splits the path on `/`, finds every segment starting with `:`, and asserts the suffix matches the snake_case pattern. Defensive floors on parsed-block count (≥100) and observed-param-count (≥2; today the catalog uses `:sha` and `:run_id`) catch parser regressions. Why this matters: axum captures the param name verbatim into the Rust handler's extractor argument; a mixed naming convention (`:RunId` PascalCase, `:run-id` kebab-case, `:runId` camelCase) silently fragments URL-param semantics across the catalog. Operators predicting URLs from runbook references get confused by mixed conventions, and the convention divergence may cascade into Rust handler signatures — a `:run-id` placeholder would even fail to compile (hyphen is not valid in a Rust identifier). Cross-axis to Lane JJJJJJJ (path prefix + no-trailing-slash): JJJJJJJ pins the OUTER shape of every path (prefix + slash hygiene); MMMMMMM pins the INNER shape of dynamic segments — together they cover both the static and the parametric parts of the URL contract |
| HTML page title AO2 operator-anchor parity (Lane NNNNNNN) | `crates/ao2-cp-server/tests/release_packaging.rs` `html_page_titles_contain_ao2_operator_anchor_lane_nnnnnnn` | Pins that every `<title>...</title>` literal across `crates/ao2-cp-server/src/handlers/*.rs` (excluding `mod.rs`) contains the substring "AO2" (case-sensitive). The test scans each handler file for `<title>...</title>` spans, extracts the title text, and asserts the AO2 anchor; defensive floor on discovered-title-count (≥20; today's count is 23) catches handler-strip-out or parser regressions. Why this matters: the browser tab title is the operator's FIRST identification surface — when six tabs are open during release triage, the title is the navigation cue. A page that ships without the AO2 anchor (e.g. just "Release Cockpit" or "Storage" without prefix) silently drops tab-level product identification — the operator can't tell at a glance whether the tab is an AO2 control-plane page or an unrelated dashboard with similar terminology. Tab confusion on release-day triage is a real cost: an operator may click into the wrong tab and act on data not from the control plane. Cross-axis to Lane VVVVV (HTML body trust-boundary disclaimer): VVVVV pins the BODY's operator-visible disclaimer; NNNNNNN pins the TAB-TITLE's operator-visible product anchor — together every operator-facing page is identifiable as part of the AO2 control plane both inside (body) and outside (tab title) |
| HTML page title uniqueness parity (Lane OOOOOOO) | `crates/ao2-cp-server/tests/release_packaging.rs` `html_page_titles_are_unique_lane_ooooooo` | Pins that every `<title>...</title>` literal across `crates/ao2-cp-server/src/handlers/*.rs` (excluding `mod.rs`) is UNIQUE — no two handler pages share the same browser-tab title. The test scans each handler file for `<title>...</title>` spans, collects all titles into a `HashMap<String, Vec<String>>` (title → files that use it), and reports any title with more than one source file as a duplicate. Defensive floor on discovered-title-count (≥20; today's count is 23) catches handler-strip-out or parser regressions. Why this matters: when an operator triaging release readiness has multiple cockpit tabs open during release-day triage, the tab title is the primary disambiguation cue — if two operator-facing pages share the same `<title>` (e.g. both saying "AO2 Release") the operator cannot tell from the tab strip which is which and must click into each to disambiguate, doubling the cognitive load and slowing recovery during incidents. Today's 23 titles are already distinct ("AO2 Release Cockpit", "AO2 Release Readiness", etc.) — this lane locks the invariant in. Cross-axis to Lane NNNNNNN (HTML title operator-anchor): NNNNNNN pins WHAT every title must contain (AO2 anchor); OOOOOOO pins that every title must be UNIQUE — together every operator-facing page is both identifiable as part of the AO2 control plane (NNNNNNN) AND distinguishable from sibling pages on the tab strip (OOOOOOO) |
| Route catalog category kebab-case naming parity (Lane PPPPPPP) | `crates/ao2-cp-server/tests/release_packaging.rs` `route_catalog_categories_use_kebab_case_lane_ppppppp` | Pins that every `category: "..."` field in `crates/ao2-cp-server/src/route_catalog.rs` follows ASCII kebab-case naming (`^[a-z][a-z0-9-]*$`). Defensive floor on discovered category count (≥100) catches parser regressions or route-catalog strip-outs. Why this matters: category strings surface in operator triage paths — runbook cross-references, cockpit HTML class names, smoke-aggregator JSON keys, support-bundle filters, and downstream jq/grep/alert recipes. A mixed convention (`snake_case_category`, `CamelCaseCategory`, or `mixed-Case-Category`) fragments the operator mental model and forces every downstream consumer to normalize defensively. Cross-axis to Lane AAAAAAA (category membership enum) and Lane KKKKKKK (category coverage): those lanes pin WHICH category values are valid and used; PPPPPPP pins HOW they are spelled. Cross-axis to Lane MMMMMMM (path-param snake_case): route taxonomy strings use kebab-case, while code-facing path parameter identifiers use snake_case. |

Any future regression in any of these layers will surface as a failing
test in the workspace.

---

## 7. Comparing two release candidates offline (Lane NN)

When two operators each hold a different release-candidate support
bundle (e.g., `0.4.79` and `0.4.80`) and want to know whether the
verdict surface has drifted between them, run the offline verifier
with `--compare-against` (Python) or `-CompareAgainst` (PowerShell).
This is a read-only operation; the verifiers never reach the network.

### 7.1 Where to get the bundles

Each release candidate publishes a portable support bundle
(`release-support-bundle.json`) alongside the binary archive
(`ao2-control-plane-<version>-<target>.tar.gz`). On a published
release the bundle is committed under the AO2 release artifacts;
on a smoked-not-yet-released candidate the bundle is under
`<smoke-root>/release-support-bundle.json`. The two paths feed the
verifier directly; no other transformation is required.

### 7.2 Invoke the verifier

Python (macOS, Ubuntu, Windows with Python on PATH):

```
python3 scripts/verify_release_support_bundle.py \
  /path/to/primary-bundle.json \
  --compare-against /path/to/compare-bundle.json
```

PowerShell (Windows, or any OS with `pwsh`):

```
pwsh -NoProfile -File scripts/Verify-ReleaseSupportBundle.ps1 \
  -BundlePath /path/to/primary-bundle.json \
  -CompareAgainst /path/to/compare-bundle.json
```

Both scripts produce the same JSON summary on stdout with a
`comparison_against` object.

### 7.3 Interpreting the comparison

The `comparison_against` block has four operator-relevant fields:

```json
{
  "comparison_against": {
    "verdict_parity": true | false,
    "verdict_diffs": [
      {"surface": "release_readiness",
       "field": "candidate_correlation_parity",
       "primary": "matched", "compare": "drift"}
    ],
    "correlation_status_diffs": [
      {"surface": "release_handoff",
       "primary": "matched", "compare": "mismatched"}
    ],
    "primary_bundle_sha256": "...",
    "compare_bundle_sha256": "...",
    "bundle_sha256_match": false
  }
}
```

- `verdict_parity=true` + empty diff arrays + non-zero exit on
  bundle_sha256 mismatch → the two bundles agree on every operator-
  visible verdict (they tested the same release cleanly). The
  bundle SHAs legitimately differ because builds carry timestamps.
- `verdict_parity=false` + populated `verdict_diffs` → a parity
  verdict (cockpit, handoff, or readiness) flipped between the two
  bundles. Read the surface + field to identify which gate
  diverged.
- `correlation_status_diffs` populated → a single surface's
  `candidate_correlation.status` differs between bundles. Triage
  by reading the `.candidate_correlation` block on each bundle
  (the verifier emits the per-bundle paths in the summary).
- `comparison_schema_version_drift` failure marker → the two
  bundles were produced from different schema generations. Treat
  as a build-pipeline drift, not a release-content drift.

### 7.4 Exit code semantics

- Drift on verdict_parity or correlation_status fields → exit 1.
- `bundle_sha256` differing alone → does NOT fail exit (builds
  legitimately differ).
- `--compare-against` pointing at a non-JSON or missing file →
  emits `comparison_against.load_error` and the
  `comparison_against: failed to load` failure marker; exits non-
  zero.

Automation pipelines surface drift via:

```
python3 scripts/verify_release_support_bundle.py PRIMARY \
  --compare-against COMPARE || alert-on-drift
```

### 7.5 Why this is not a server-side check

The cross-bundle comparison is intentionally offline. Server-side
ingestion validates one bundle at a time (Lane W, Lane DD, Lane KK,
Lane PP-server) without cross-bundle context. Cross-bundle drift is
a release-management workflow that lives ahead of (not inside) the
ingestion path; the offline verifier is the artifact operators
share between themselves before pushing a candidate to AO.

---

## 8. Triage by Lane PP-server rejection (source_commit_per_target drift)

A bundle that survives Lane KK + Lane DD + Lane W can still be
rejected on Lane PP-server when the per-target `source_commit_at_target`
values disagree with the top-level `source_commit`. The diagnostic
shape:

```
three-OS release smoke source_commit_per_target drift: top-level source_commit=<sha> disagrees with per-target source_commit_at_target (ubuntu=<other-sha>); orchestrator HEAD drifted between packaging and execution
```

### 8.1 What this means

The aggregator packages `source.tgz` once and embeds a
`.source-commit` JSON record (the result of `git rev-parse HEAD` at
packaging time). Each per-target smoke reads that record and emits
the value as `source_commit_at_target` in its log. The aggregator
collects those values back to the top-level summary as
`source_commit_per_target`. A 422 on this gate means one or more
per-target values disagree with the orchestrator's top-level
`source_commit`.

### 8.2 Triage steps

1. **Read the dissenting target** from the diagnostic string. The
   diagnostic names every dissenting target with its observed value
   (`ubuntu=<sha>`, `windows=<sha>`, etc.).
2. **Did the orchestrator's HEAD advance during the smoke?** Run
   `git log --since="<smoke-start-time>" --until="<smoke-end-time>"`
   on the orchestrator host. A non-empty result means a commit
   landed during the smoke — the next smoke from a clean checkout
   will pass.
3. **Is the dissenting target running against a stale source.tgz?**
   On the remote target host, check the contents of
   `<remote-root>/run/.source-commit`. If it doesn't match the
   orchestrator's HEAD at packaging time, the remote runner picked
   up an old tarball. Clean the remote run directory and re-run.
4. **All `source_commit_at_target` values match each other but
   disagree with top-level?** This means the orchestrator's
   `git rev-parse HEAD` returned a different value than the one
   embedded in `source.tgz` (impossible with the current aggregator
   ordering). Escalate as a packaging-pipeline anomaly.

### 8.3 Recovery

The honest recovery is always the same: re-run
`scripts/smoke-three-os-release.sh` from a clean checkout. The
orchestrator now emits the same `source_commit` everywhere because
the working tree settled.

### 8.4 Why an honest drift report is still rejected

The aggregator's `compute_source_commit_drift()` returns `true` when
it observes drift; the smoke summary surfaces that boolean on
`source_commit_per_target_drift`. Lane PP-server rejects the bundle
even when this boolean is honestly `true` because the bundle's
release-evidence guarantee is unreliable in that state: the operator
cannot tell whether the divergent target tested the labelled commit.
Re-running from a clean checkout is faster than re-validating
post-hoc.

---

## 9. Reading the audit-log rotation budget (Lane VV)

The Lane LL forensic audit log at
`<storage-root>/rejected-three-os-smoke.jsonl` rotates at 1 MiB
under Lane UU's FIFO eviction policy — older records are dropped
to keep the file under cap. Rotation emits no persistent counter,
so the cockpit / handoff / readiness HTML surfaces the two raw
signals operators need to infer rotation state without shell
access. The new `Audit log size` row sits inside the existing
`Rejected Smoke Ingestions` section.

### 9.1 What the row looks like

```html
<dt>Audit log size</dt>
<dd class="ok"><code>838860</code> / <code>1048576</code> bytes (Lane UU rotation cap)</dd>
```

- `audit_log_size_bytes` — current on-disk size of the audit log.
- `audit_log_cap_bytes` — the Lane UU rotation threshold (1 MiB =
  `1048576` bytes).
- `class="ok"` while size < 75% of cap (`786432` bytes).
- `class="warn"` once size >= 75% of cap.

### 9.2 Triage by row state

| Row state                                    | Operator interpretation                                                                                                         | Action                                                                                                                                                 |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ok`, size = 0                               | Fresh control plane or no rejections yet                                                                                        | Positive evidence the audit trail is reachable. No action.                                                                                              |
| `ok`, size < 75% of cap                      | Stable population, no rotation imminent                                                                                         | No action.                                                                                                                                              |
| `warn`, size >= 75% of cap                   | Rotation imminent — the next rejection burst will drop older records                                                            | Capture the audit log tail BEFORE the next 422 if a forensic investigation is open; copy the file to a separate location for analysis.                  |
| Size dropped after a known rejection burst   | Rotation just happened — older records were evicted                                                                             | Compare on-disk record count against an external counter (e.g., Prometheus exporter from Lane WW once shipped). Older records are not recoverable.      |

### 9.3 Why a raw (size, cap) pair instead of a counter

A `rotated_records_dropped: N` counter would seem more direct, but
it has two failure modes the raw signals avoid:

1. **Counter / file consistency window.** A counter must be
   persisted somewhere; a crash between the rotation and the
   counter write produces inconsistent state.
2. **Migration cost when policy changes.** A future bump of the
   rotation cap (or a switch to time-based rotation) would
   invalidate the counter's semantics; the raw signals stay
   meaningful under any policy.

The raw signals also generalize: an external monitor can compute
`size / cap > 0.75` and page the operator without parsing the HTML.

### 9.4 Where this is enforced

The renderer reads the two fields from `rejected_smoke_audit_summary`
in `crates/ao2-cp-server/src/handlers/phase1_promotion.rs`. The
warn-class threshold (75%) is pinned by the
`cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv`
behavioral test. A future change to either the cap or the
threshold surfaces there as a deliberate test update.

### 9.5 Reading the rotation budget from JSON (Lane XX)

External monitors (Prometheus exporters, oncall dashboards) consume
the rotation budget without parsing HTML by polling any of the
three JSON endpoints:

- `/api/v1/release/cockpit.json`
- `/api/v1/release/handoff.json`
- `/api/v1/release/readiness.json`

Each returns a top-level `rejected_smoke_audit` object with the
same shape:

```json
{
  "rejected_smoke_audit": {
    "count": 0,
    "latest_timestamp_utc": null,
    "latest_rejection_reason": null,
    "audit_log_size_bytes": 0,
    "audit_log_cap_bytes": 1048576
  }
}
```

The keys are always present even pre-rejection; `latest_*` fields
are JSON `null` until the first 422 lands. A monitor can rely on
the stable shape — never a missing key.

### 9.6 Recommended alert rules

A two-rule alert that maps directly to the HTML class transitions:

| Rule | Expression | Fires when |
|---|---|---|
| Rotation imminent | `audit_log_size_bytes / audit_log_cap_bytes > 0.75` | Lane VV warn-class transition; older records will be evicted on the next rejection burst |
| Tampering attempt spike | `increase(count[1m]) > 10` | More than 10 rejections within 1 minute — possible coordinated tampering or a misbehaving client |

The two signals are complementary: the first answers "is the
audit trail healthy?" and the second answers "is something
attacking us?". A monitor that fires only on the first rule may
miss a slow tampering pattern that stays below 75% but accumulates
record-by-record over hours.

### 9.7 Cross-surface JSON consistency

The same `rejected_smoke_audit` object appears identically on all
three JSON endpoints. A monitor pointing at any of them sees the
same numbers — no need to poll multiple endpoints to triangulate.
The pass-through is enforced by the
`cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx`
behavioral test, which asserts the shape on all three surfaces
pre- and post-rejection.

### 9.8 Offline-verifier audits (Lane ZZ)

The Lane XX server-side pass-through proves the three JSON surfaces
agree at render time. The Lane ZZ offline verifier (Python +
PowerShell) audits the property again at bundle-acceptance time
through two complementary checks:

**Within-bundle byte-identity.** Both verifiers hash the
`rejected_smoke_audit` object on each of the three operator-triage
surfaces (cockpit, handoff, readiness) and assert byte-identity.
A tampered offline bundle could bump cockpit's `count` to mask
rejected tampering attempts visible to the operator on the
dashboard while leaving handoff/readiness untouched — the
per-surface shape check still passes (each remains a valid
five-field object), but the byte-identity hash flags the drift.
The failure marker is
`rejected_smoke_audit_cross_surface_byte_identity` and the
diagnostic names all three triage surfaces so an operator who
lands on the failure knows where to begin triage. The check
parallels Lane FF (candidate_correlation) and Lane HH (aggregate
parity verdicts).

**Cross-bundle rotation-budget drift.** When the verifier is invoked
with `--compare-against PATH` (Python) or `-CompareAgainst PATH`
(PowerShell), it collects each surface's `count`, `audit_log_size_bytes`,
and `audit_log_cap_bytes` from both bundles and surfaces drift as
`comparison_audit_log_rotation_budget_drift` failures plus a
structured `audit_budget_diffs` array in the comparison report.
The drift is explicitly **NOT** folded into `verdict_parity` because
legitimate between-captures activity should not fail the verdict
gate — operators read the signal and decide whether it's expected
(activity between captures), suspicious (audit-log tampering), or
operationally interesting (a rotation cap change at the server).

The end-to-end behavioral test is
`release_support_bundle_audit_log_byte_identity_and_cross_bundle_drift_lane_zz`
in `crates/ao2-cp-server/tests/release_packaging.rs`. It drives the
Python verifier with clean, tampered, and later-rotation bundles
and asserts the exact Lane ZZ failure markers + report shape; when
pwsh is on PATH it runs the PowerShell verifier against the same
inputs and asserts the same failures, enforcing runtime cross-OS
parity beyond the source-string parity check.

### 9.9 Concurrent-write protection (Lane WW-rotation)

On-call note: if you've been paged because of a sustained
tampering burst (`rejected_smoke_audit.count` climbing 10+/min for
several minutes — Lane XX-doc alert rule 2), the audit log itself
is integrity-safe under concurrent rejection load. The
`append_rejected_smoke_audit` function in
`crates/ao2-cp-server/src/handlers/phase1_promotion.rs` acquires
a process-global `tokio::sync::Mutex<()>` (named
`REJECTED_SMOKE_AUDIT_WRITER_LOCK`) at the top of every append and
holds it for the entire read-projection-write region. The mutex
prevents the rotation race that would otherwise let two concurrent
rotations both read the file, both project a size that doesn't see
each other's new record, and both write — silently losing the
first writer's record and briefly pushing the file above the cap.

The lock is held only across local I/O — no network calls, no DB
calls — so tail-latency impact is bounded by file size. The
summary reader path (`rejected_smoke_audit_summary`) stays
lock-free because `tokio::fs::write` (truncate + write) is atomic
relative to a fresh `read_to_string`: a reader either sees the
pre-rotation file or the post-rotation file, never a partial.

The contract is pinned by
`audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation`
in `crates/ao2-cp-server/tests/release_publication.rs`. The test
pre-fills the audit log to ~990 KiB, fires 50 concurrent tampered
POSTs (each of which crosses the 1 MiB cap), and asserts four
invariants: file size <= cap, every record is valid JSON, cockpit
count matches on-disk line count, and at least one record
survives.

What this means for triage: a tampering-burst alert points at a
**tampering event**, not at audit-log corruption. The audit log
itself is safe — read it. If `rejected_smoke_audit.count` shows a
spike that matches the alert window, the cap is intact, and every
line parses as JSON, then the surge is real and the upstream
factory-v3 evaluator-closer needs the rejection reasons + source
commits to triage the attacker's intent. No action required on
the control plane's audit log.

### 9.10 On-call triage pointer on cockpit/handoff/readiness HTML (Lane EEE)

The "Rejected Smoke Ingestions" section on the cockpit, handoff,
and release-readiness HTML surfaces renders a small **On-call
triage** row right next to the audit-log size row:

```html
<dt>On-call triage</dt>
<dd>See release-smoke runbook section 9.9 for tampering-burst triage (a burst is a tampering event, not audit-log corruption).</dd>
```

The pointer collapses a navigation step for the on-call operator
paged at 3 AM on a Lane XX-doc rule-2 burst alert: instead of
discovering the runbook section number from the alert metadata
(or the support-bundle README's audit-log section), the operator
sees the load-bearing framing ("tampering event, not audit-log
corruption") and the runbook section number ("9.9") right on the
cockpit row they're already looking at.

The pointer is **static** — it renders identically pre-rejection
and post-rejection, with count=0 and count>=1. The framing is
load-bearing regardless of the count: the alert fires on burst
*rate*, not absolute count, so an on-call landing on a count-0
surface (after a rotation) still benefits from the framing
because the burst that triggered the page may have already
rolled out of the post-rotation window.

The contract is pinned by `cockpit_html_surfaces_rejected_smoke_audit_count_lane_mm`
(extended) and `handoff_and_readiness_html_mirror_rejected_smoke_audit_section_lane_qq`
(extended) in `crates/ao2-cp-server/tests/release_publication.rs`.
Both tests bind three literals: `"On-call triage"`,
`"runbook section 9.9"`, and `"tampering event, not audit-log
corruption"`. If any of these strings drifts in the renderer,
both tests fail.
