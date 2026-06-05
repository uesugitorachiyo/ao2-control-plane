//! K16: Detached project-start bundle verification observer lineage.
//!
//! Codex C17 (`ao2 d2c8efd feat(factory): verify detached project-start
//! bundles`) ships the `ao2 factory project-start-bundle-verify` command
//! that emits `ao2.factory-project-start-bundle-verification.v1` over a
//! relocated project-start handoff `.tgz` archive. The verifier is
//! fail-closed on manifest, SHA256SUMS, internal-digest, review-to-rubric
//! digest, review-to-project-run digest, signature, secret-scan, and
//! trust-boundary checks — so a Hermes operator or evaluator-closer can
//! observe whether the handoff bundle independently re-verifies after
//! cross-OS transfer without re-running the producer.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The verifier verdict declares `ao2.factory-project-start-bundle-verification.v1`,
//!    `status=accepted`, and preserves the seven-field observer-safe
//!    `trust_boundary` verbatim.
//!
//! 2. The verifier `bundle_sha256` matches the project-start handoff
//!    bundle's self-declared `sha256` — the same digest the K10 bundle
//!    chain already covers — so observers can correlate the verifier
//!    verdict back to the bundle artifact without unpacking the archive.
//!
//! 3. The verifier `checks` block lists all twelve fail-closed checks
//!    (manifest, sha256sums, project-start, project-run, acceptance
//!    rubric + signature, project acceptance review + signature, review
//!    -> rubric digest, review -> project-run digest, secret scan, trust
//!    boundary) and every check is `true` for an accepted verdict.
//!
//! 4. An accepted verdict implies `failure_count=0` and `failures=[]` —
//!    the verifier never claims `accepted` with non-empty failures.
//!
//! 5. The verifier threads K13 (rubric) + K14 (review) lineage by
//!    asserting `review_rubric_digest_matches=true` and
//!    `review_project_run_digest_matches=true` as observer-readable
//!    booleans inside the detached verifier output. K13 → K14 lineage
//!    now reaches detached verification.
//!
//! 6. The verifier explicitly reports `secret_scan_passed=true` and
//!    `trust_boundary_verified=true` — secret hygiene and trust-boundary
//!    invariants are enforced inside the detached verifier, not just by
//!    the producer.
//!
//! 7. `files_checked` accounts for the bundle's manifest + SHA256SUMS
//!    sidecars on top of the labeled `artifact_count`, so an observer
//!    can sanity-check that the verifier inspected the manifest and
//!    checksum entries (not just the labeled artifacts).

use serde_json::Value;

const VERIFICATION_JSON: &str = include_str!(
    "fixtures/detached-bundle-verification/factory-project-start-bundle-verification.json"
);
const BUNDLE_JSON: &str =
    include_str!("fixtures/detached-bundle-verification/factory-project-start-bundle.json");

fn parse(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("fixture parses as JSON")
}

#[test]
fn verification_declares_schema_status_accepted_and_observer_safe_trust_boundary() {
    let v = parse(VERIFICATION_JSON);
    assert_eq!(
        v["schema_version"].as_str(),
        Some("ao2.factory-project-start-bundle-verification.v1"),
        "verifier verdict must declare K16 schema"
    );
    assert_eq!(
        v["status"].as_str(),
        Some("accepted"),
        "verifier verdict status must be accepted for a clean bundle"
    );
    assert_eq!(
        v["failure_count"].as_u64(),
        Some(0),
        "accepted verdict must have failure_count=0"
    );

    let tb = &v["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(
        tb["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_oracle_only"));
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        tb["provider_auth"].as_str(),
        Some("local OAuth CLI only; API-key provider auth forbidden")
    );
}

#[test]
fn verification_bundle_sha256_matches_project_start_bundle_self_sha() {
    let v = parse(VERIFICATION_JSON);
    let bundle = parse(BUNDLE_JSON);

    let verifier_sha = v["bundle_sha256"]
        .as_str()
        .expect("verifier.bundle_sha256 must be a string");
    assert_eq!(
        verifier_sha.len(),
        64,
        "verifier.bundle_sha256 must be a 64-hex digest"
    );

    let bundle_self_sha = bundle["sha256"]
        .as_str()
        .expect("bundle.sha256 must be a string");
    assert_eq!(
        verifier_sha, bundle_self_sha,
        "verifier.bundle_sha256 must match the project-start bundle's self-declared sha256 \
         so observers can correlate the verifier verdict back to the K10 bundle digest"
    );

    let verifier_artifact_count = v["artifact_count"]
        .as_u64()
        .expect("verifier.artifact_count is integer");
    let bundle_artifact_count = bundle["artifact_count"]
        .as_u64()
        .expect("bundle.artifact_count is integer");
    assert_eq!(
        verifier_artifact_count, bundle_artifact_count,
        "verifier.artifact_count must match the bundle's artifact_count"
    );
}

#[test]
fn verification_lists_all_twelve_fail_closed_checks_true_for_accept() {
    let v = parse(VERIFICATION_JSON);
    let checks = &v["checks"];

    for required_check in [
        "manifest_verified",
        "sha256sums_verified",
        "project_start_verified",
        "project_run_verified",
        "acceptance_rubric_verified",
        "acceptance_rubric_signature_verified",
        "project_acceptance_review_verified",
        "project_acceptance_review_signature_verified",
        "review_rubric_digest_matches",
        "review_project_run_digest_matches",
        "secret_scan_passed",
        "trust_boundary_verified",
    ] {
        assert_eq!(
            checks[required_check].as_bool(),
            Some(true),
            "checks.{} must be present and true for an accepted verdict \
             (fail-closed surface visible to control-plane observer)",
            required_check
        );
    }
}

#[test]
fn verification_failure_count_zero_and_failures_empty_for_accept() {
    let v = parse(VERIFICATION_JSON);
    assert_eq!(
        v["failure_count"].as_u64(),
        Some(0),
        "accepted verdict must have failure_count=0"
    );
    let failures = v["failures"]
        .as_array()
        .expect("verifier.failures must be an array even when empty");
    assert!(
        failures.is_empty(),
        "accepted verdict must have failures=[], got {} entries",
        failures.len()
    );
}

#[test]
fn verification_threads_k13_k14_rubric_and_review_digest_matches() {
    let v = parse(VERIFICATION_JSON);
    let checks = &v["checks"];

    // K13 → K16: the detached verifier independently re-verifies that the
    // signed acceptance rubric inside the bundle matches the rubric the
    // review claims it applied (review.rubric_sha256 == sha256(rubric
    // bytes)). This is the K13 rubric digest lineage threaded into the
    // detached verifier as an observer-readable boolean.
    assert_eq!(
        checks["review_rubric_digest_matches"].as_bool(),
        Some(true),
        "review_rubric_digest_matches must be true — K13 rubric lineage \
         must be re-verified by the detached verifier, not trusted blindly"
    );

    // K14 → K16: the detached verifier independently re-verifies that the
    // signed acceptance review inside the bundle pins the project-run
    // bytes the bundle ships (review.project_run_sha256 == sha256(run
    // bytes)). This is the K14 project-run digest lineage threaded into
    // the detached verifier.
    assert_eq!(
        checks["review_project_run_digest_matches"].as_bool(),
        Some(true),
        "review_project_run_digest_matches must be true — K14 review-to-run \
         lineage must be re-verified by the detached verifier"
    );

    // Signature checks are part of the same lineage: rubric and review
    // signatures must verify independently inside the detached verifier.
    assert_eq!(
        checks["acceptance_rubric_signature_verified"].as_bool(),
        Some(true),
        "acceptance rubric signature must verify inside the detached verifier"
    );
    assert_eq!(
        checks["project_acceptance_review_signature_verified"].as_bool(),
        Some(true),
        "project acceptance review signature must verify inside the detached verifier"
    );
}

#[test]
fn verification_secret_scan_and_trust_boundary_checks_pass_for_accept() {
    let v = parse(VERIFICATION_JSON);
    let checks = &v["checks"];

    // The detached verifier owns secret hygiene independently — observers
    // can rely on this boolean rather than re-scanning artifacts inside
    // the control plane.
    assert_eq!(
        checks["secret_scan_passed"].as_bool(),
        Some(true),
        "secret_scan_passed must be true inside the detached verifier"
    );

    // Trust-boundary verification is itself a check: the verifier
    // confirms every embedded artifact still carries the seven-field
    // observer-safe boundary, so any drift inside the bundle would flip
    // this boolean and fail the verdict.
    assert_eq!(
        checks["trust_boundary_verified"].as_bool(),
        Some(true),
        "trust_boundary_verified must be true — the detached verifier \
         enforces the observer-safe trust boundary on every embedded artifact"
    );
}

#[test]
fn verification_files_checked_accounts_for_artifact_count_plus_manifest_extras() {
    let v = parse(VERIFICATION_JSON);

    let artifact_count = v["artifact_count"]
        .as_u64()
        .expect("artifact_count is integer");
    let files_checked = v["files_checked"]
        .as_u64()
        .expect("files_checked is integer");

    // The verifier walks labeled artifacts AND the bundle sidecars
    // (manifest.json + SHA256SUMS at minimum), so files_checked must be
    // strictly greater than artifact_count. Observers can sanity-check
    // that the verifier inspected the manifest and checksum entries —
    // not just the labeled artifacts — by reading this invariant.
    assert!(
        files_checked > artifact_count,
        "files_checked ({}) must exceed artifact_count ({}) — the verifier \
         must inspect bundle manifest + SHA256SUMS sidecars on top of the \
         labeled artifacts",
        files_checked,
        artifact_count
    );
    assert!(
        files_checked >= artifact_count + 2,
        "files_checked ({}) must exceed artifact_count ({}) by at least 2 \
         (manifest.json + SHA256SUMS sidecars)",
        files_checked,
        artifact_count
    );
}
