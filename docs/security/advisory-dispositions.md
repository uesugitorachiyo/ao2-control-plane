# Advisory Dispositions

This document records the explicit risk disposition for every RustSec
advisory that affects a dependency in ao2-control-plane's resolved
dependency graph (`Cargo.lock`). Each entry must give the advisory id,
the affected crate + version, the exposure analysis specific to this
codebase, and the disposition (mitigate / suppress / accept).

`cargo audit` is wired into the `audit` CI job (see
`.github/workflows/ci.yml`). Suppressions are passed via `--ignore`
flags so the suppression list lives in CI config alongside the
rationale here. Adding a new ignore requires updating both this file
and the workflow in the same PR.

## RUSTSEC-2023-0071 — rsa 0.9.x Marvin Attack

| Field | Value |
| --- | --- |
| Advisory | RUSTSEC-2023-0071 |
| Crate | rsa 0.9.10 |
| Severity | 5.9 (medium) |
| Date | 2023-11-22 |
| Upstream fix | None available (as of 2026-05-26) |
| URL | <https://rustsec.org/advisories/RUSTSEC-2023-0071> |

### Vulnerability summary

The Marvin Attack is a timing sidechannel in the `rsa` crate's RSA
**decryption** primitive (PKCS#1 v1.5 padding). An attacker who can
submit ciphertexts and observe decryption-time variance over the
network can recover plaintext bits (Bleichenbacher-class oracle).
There is no upstream fix because constant-time RSA in pure Rust is an
unsolved problem; the maintainers track this in
`rsa/issues/19`.

### Exposure analysis in ao2-control-plane

ao2-control-plane uses the `rsa` crate **only** for signature
verification of evidence uploads. The call sites are:

- `crates/ao2-cp-server/src/handlers/memory.rs`
- `crates/ao2-cp-server/src/handlers/evidence_pack.rs`
- `crates/ao2-cp-server/src/handlers/provider_readiness.rs`
- `crates/ao2-cp-server/src/handlers/provider_registry.rs`
- `crates/ao2-cp-server/src/handlers/release_publication.rs`
- `crates/ao2-cp-server/src/handlers/phase1_promotion.rs`

Every site imports `rsa::pkcs1v15::VerifyingKey` (or `pss::VerifyingKey`)
plus `signature::Verifier`. The call is `verifying_key.verify(&payload,
&signature)`. None of the handlers decrypt RSA-encrypted ciphertext.
The server holds no RSA private keys.

The Marvin Attack vector requires:

1. An RSA *decryption* operation (private-key path), and
2. The attacker controlling the ciphertext, and
3. The attacker observing decryption-time variance.

None of these conditions are reachable through ao2-control-plane.
Signature verification is a public-key modexp — the timing signal the
attack exploits does not exist in the verify path.

### Disposition: suppress with `--ignore`

CI passes `--ignore RUSTSEC-2023-0071` to `cargo audit`. The
suppression is narrow (single advisory id) and the workflow comment
points back here.

### Trip-wire for revisiting

Re-evaluate this disposition if any of the following become true:

- The `rsa` crate gains a decryption call site in ao2-control-plane.
  This is enforced by **Lane VVVVVVV**
  (`crates/ao2-cp-server/tests/release_packaging.rs::no_rsa_decryption_call_sites_lane_vvvvvvv`):
  the test walks `crates/*/src/` plus `crates/*/build.rs` and fails CI
  on any reference to `DecryptingKey`, `rsa::oaep`, `Pkcs1v15Encrypt`,
  `Oaep::new`, or `.decrypt(`. A future PR that introduces RSA
  decryption cannot land without explicitly addressing this disposition.
- `rsa` ships an upstream fix; remove the ignore and bump the version.
- A new advisory affects `signature::Verifier` itself.
