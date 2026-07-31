# AO2 Control Plane Storage Instructions

## Scope

This crate owns content-addressed persistence, indexes, migrations, retention metadata, integrity checks, and replayable reads.

## Rules

- Bind records to verified content digests and source provenance; never accept caller-supplied identity without recomputing and comparing it.
- Make migrations explicit, versioned, testable, and safe for existing records. Reject unknown versions and incomplete or partially applied state.
- Preserve atomic writes, index/data agreement, audit ordering, retention decisions, and deterministic replay. A replay reconstructs observer state only; it cannot advance AO2.
- Detect corruption, collisions, traversal, symlinks, missing blobs, and provenance drift before returning a successful read.
- Do not silently delete, rewrite, or fabricate historical records. Retention cleanup requires its documented operator boundary and auditable result.
- Storage tests: `cargo test -p ao2-cp-storage`. Follow with repository-wide format, workspace-test, and Clippy gates.
