# Public Export Evidence

## Scope

This folder is a clean-copy public export for the `ao2-control-plane`
repository. It was created without private git history.

## Source Baseline

- Source repository: `ao2-control-plane`
- Code export baseline commit: `cb17771de4ae05a72454a797edb3babe0621ef8c`
- Export strategy: clean copy, no private git history

## Included Surface

- Rust workspace, deploy assets, public docs, runbooks, scripts, fixtures, and tests
- Public README and license files
- Public CI workflow

## Excluded Surface

- Private git history and generated runtime data
- Private release/status artifacts
- Local absolute paths, private AO2 links, secrets, signing keys, and bearer tokens

## Verification

- `cargo fmt --all -- --check && cargo test --workspace`: PASS
- `bash scripts/check-public-export.sh`: PASS before initial public git commit
- `bash scripts/check-public-repo-policy.sh`: tracked-file public repository
  policy gate for generated artifacts, credential material, private-key markers,
  private AO2 references, and machine-local paths outside redaction canaries.
- Digest-pinned fixture metadata was refreshed after public path/repo scrubbing so readback tests continue to verify exact public-export bytes.

## Publication Status

No GitHub remote or push was configured during this export. Public publication
still requires operator approval.
