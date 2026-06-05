# Storage retention — operator runbook

`ao2-cp-gc` is the operator-facing companion to `ao2-cp-server`. It
applies the same count-based retention policy as the
`/api/v1/storage/prune` endpoint, but runs as a one-shot CLI against
the on-disk data directory. Cron jobs can enforce bounded growth
without minting a bearer token.

Audit-log NDJSON bounded growth is separate from content-addressed
bundle retention. Configure `AO2_CP_AUDIT_LOG_MAX_BYTES` for the live
audit-log file and prove it with
`scripts/cp-audit-log-rotation-drill.sh` or
`scripts/cp-audit-log-rotation-drill.ps1`. The drill emits
`ao2.cp-audit-log-rotation-drill.v1` read-only observer evidence and
does not mutate AO artifacts.

## Trust boundary

`ao2-cp-gc` only deletes content-addressed observer evidence on a
per-kind LRU basis (keep the `N` most recent entries per prunable
kind, plus their related-kind signature sidecars). It does NOT:

- approve AO2 digests, close AO2 runs, or execute provider plugins;
- modify the schema, signature, or trust-policy of any retained
  artifact;
- expose any network surface (no listener, no auth);
- touch any path outside `--data-dir`.

It is a maintenance tool for the flat-file store, analogous to log
rotation.

## Usage

```text
ao2-cp-gc --data-dir <PATH> --keep-latest <N> --dry-run
ao2-cp-gc --data-dir <PATH> --keep-latest <N> --apply
```

`--dry-run` and `--apply` are mutually exclusive and one is required:
the binary exits `64` (`EX_USAGE`) if neither is passed, so cron jobs
will not silently delete on operator typos.

The binary emits the prune result as JSON on stdout. Fields match
`/api/v1/storage/prune`'s response:

```json
{
  "schema_version": "ao2.cp-storage-prune.v1",
  "dry_run": true,
  "keep_latest": 100,
  "pruned": [ /* RetentionCandidate, oldest-first */ ],
  "retained_index_entries": 412,
  "reclaimed_bytes": 17829
}
```

`schema_version` is identical to the HTTP API's, so monitor pipelines
that already parse the HTTP response do not need a second parser.

## Scheduling examples

The same `--data-dir` the running server uses is safe — the prune
rewrites the index atomically and removes bundle files in place. No
server downtime required.

### macOS / Ubuntu (cron)

```cron
# Daily at 03:30 local, keep the 200 newest entries per prunable kind
30 3 * * * /usr/local/bin/ao2-cp-gc --data-dir /var/lib/ao2-cp/data --keep-latest 200 --apply >> /var/log/ao2-cp-gc.log 2>&1
```

### macOS (launchd)

A dedicated `LaunchAgent` plist can wrap the same command. Reuse the
deploy template at `deploy/launchd/com.ao2cp.server.plist` as a
starting point and adjust `ProgramArguments` plus `StartCalendarInterval`.

### Windows (Task Scheduler)

```powershell
schtasks /Create /TN "ao2-cp-gc daily" /TR "C:\\Program Files\\ao2-cp\\ao2-cp-gc.exe --data-dir C:\\ProgramData\\ao2-cp\\data --keep-latest 200 --apply" /SC DAILY /ST 03:30
```

### Bounded-growth invariant under load

The CI `gc_smoke` integration test (`crates/ao2-cp-server/tests/gc_smoke.rs`)
runs on every push for all three OS in the release-smoke matrix. It
asserts:

- `--dry-run` reports candidates without deleting anything.
- `--apply` deletes the `N` oldest entries per kind, removes their
  related-kind signature sidecars, and rewrites the on-disk index.
- A second `--apply` with the same policy is a no-op (idempotence —
  the operator-facing bounded-growth invariant).
- `--keep-latest` above the population count keeps everything.

Any drift in `Storage::prune_retention` semantics flips this red on
Mac, Ubuntu, and Windows simultaneously.

## Choosing `--keep-latest`

The control plane stores 13 prunable primary kinds plus their
signature sidecars. Each retained entry includes the primary bundle
file and (where applicable) a separate signature bundle file. Typical
operator targets:

- **Light load** (single tenant, low publish rate): `--keep-latest
  100`. Roughly 13 × 100 ≈ 1.3K primary bundles + sidecars.
- **Heavy load** (multiple tenants, frequent publishes): `--keep-latest
  500` to retain a longer triage window.
- **Compliance retention**: schedule a periodic snapshot of
  `--data-dir` to cold storage; `ao2-cp-gc` is for live-server disk
  bounds only.

`/api/v1/storage/report?keep_latest=<N>` is the source of truth for
sizing — run it before changing `--keep-latest` in production.

## Failure modes

| Exit | Cause |
| --- | --- |
| `0` | Success (dry-run or apply). |
| `2` | Clap argument error (e.g. `--dry-run --apply` together). |
| `64` | `EX_USAGE` — neither `--dry-run` nor `--apply` was passed. |
| `70` | `EX_SOFTWARE` — runtime or storage error (see stderr). |

stderr is operator-readable. stdout is JSON suitable for piping into
`jq` or a log aggregator.
