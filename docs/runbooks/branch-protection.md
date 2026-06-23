# Branch Protection

`ao2-control-plane` protects `main` with strict required status checks, admin
enforcement, required linear history, force-push protection, and branch deletion
protection.

The required status checks are:

- `Cargo audit`
- `Cargo deny (bans + licenses + sources)`
- `Ingest smoke (macos-aarch64)`
- `Ingest smoke (ubuntu-x86_64)`
- `Ingest smoke (windows-x86_64)`
- `Lint (fmt + clippy)`
- `Release archive smoke (macos-aarch64)`
- `Release archive smoke (ubuntu-x86_64)`
- `Release archive smoke (windows-x86_64)`
- `Test (macos-latest)`
- `Test (ubuntu-latest)`
- `Test (windows-latest)`

Verify the live policy with:

```sh
scripts/verify-branch-protection.sh
```

The verifier is read-only. It does not push, merge, edit repository settings, or
mutate branch protection.

When the token can read the full branch protection endpoint, the verifier runs in
`mode=full` and checks strict status checks, admin enforcement, linear history,
force-push protection, deletion protection, and required check names. When
GitHub Actions restricts the built-in token from that endpoint, the verifier
falls back to `mode=limited` through branch metadata and still checks that
`main` is protected for everyone with the required CI matrix contexts.

The same verifier also runs from
`.github/workflows/production-readiness-ops.yml` on manual dispatch and a daily
schedule, using the repository-scoped `GITHUB_TOKEN` as `GH_TOKEN`.
