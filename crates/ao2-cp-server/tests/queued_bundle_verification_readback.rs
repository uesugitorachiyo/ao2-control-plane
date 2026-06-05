//! K17: Queue-persisted bundle verification observer lineage.
//!
//! Codex C18 (`ao2 9a74561 feat(factory): verify queued project-start
//! bundles`) makes queue-run-next automatically run the detached
//! `ao2.factory-project-start-bundle-verification.v1` verifier against
//! the freshly generated project-start handoff bundle and persist the
//! verdict on the completed queue entry. Queue execution fails closed
//! if the detached verifier rejects.
//!
//! The persisted entry now carries five new C18-contributed fields on
//! the queue-run-next `entry` object alongside the K10-K15 surface:
//!
//!   - `entry.project_start_bundle_verification` (path to verifier verdict JSON)
//!   - `entry.project_start_bundle_verification_sha256` (sha256 of verifier file bytes)
//!   - `entry.project_start_bundle_verification_status` (verdict status, e.g. "accepted")
//!   - `entry.project_start_bundle_verification_checks` (flat copy of the 12 checks)
//!   - `entry.project_start_bundle_verification_result` (full embedded
//!     verifier object — schema_version, status, bundle_sha256, checks,
//!     trust_boundary)
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The queue-run-next entry threads all five verification fields,
//!    declares `project_start_bundle_verification_status=accepted`, and
//!    preserves the seven-field observer-safe `trust_boundary` verbatim
//!    on the embedded verifier result. The C18 parity-checklist
//!    contribution `ao2_queue_verifies_project_start_handoff_bundle=true`
//!    is also asserted.
//!
//! 2. The embedded `project_start_bundle_verification_result` declares
//!    K16's `ao2.factory-project-start-bundle-verification.v1` schema
//!    with `status=accepted` and `failure_count=0` — the queue path
//!    reuses K16's verifier verdict schema, not a parallel variant.
//!
//! 3. **K17 verifier file digest lineage**: `sha256(verifier file
//!    bytes) == entry.project_start_bundle_verification_sha256` —
//!    observers can detect tamper on the persisted verifier verdict
//!    without re-parsing it.
//!
//! 4. **K17 verifier-to-bundle digest binding**:
//!    `entry.project_start_bundle_verification_result.bundle_sha256 ==
//!    entry.project_start_bundle_sha256` — the queue-persisted verifier
//!    verdict applies to the same project-start handoff bundle the
//!    entry shipped, not a stale or substituted artifact.
//!
//! 5. The flat `entry.project_start_bundle_verification_checks` mirrors
//!    `entry.project_start_bundle_verification_result.checks` field-by-
//!    field with all twelve fail-closed booleans true for accept — so
//!    queue observers can ack the verdict from the flat block without
//!    dereferencing the embedded result.
//!
//! 6. `entry.project_start_bundle_verification_status` matches
//!    `entry.project_start_bundle_verification_result.status` — top-
//!    level status and embedded result status cannot drift.
//!
//! 7. The K10-K15 surface is preserved alongside the new verifier
//!    fields: `project_start_bundle`, `project_start_bundle_sha256`,
//!    `project_acceptance_review`, `project_acceptance_review_sha256`,
//!    the `hermes_queue_handoff` block, and the queue entry schema are
//!    all still present, so C18 does not break the existing observer
//!    surface.

use serde_json::Value;
use sha2::{Digest, Sha256};

const VERIFIER_JSON: &str = include_str!(
    "fixtures/queued-bundle-verification/factory-project-start-bundle-verification.json"
);
const QUEUE_RUN_NEXT_JSON: &str =
    include_str!("fixtures/queued-bundle-verification/factory-queue-project-start-run-next.json");

fn parse(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("fixture parses as JSON")
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn queue_entry_threads_verification_fields_with_observer_safe_trust_boundary() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    assert!(
        entry["project_start_bundle_verification"]
            .as_str()
            .is_some(),
        "entry.project_start_bundle_verification must be a path"
    );
    assert!(
        entry["project_start_bundle_verification_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "entry.project_start_bundle_verification_sha256 must be a 64-hex digest"
    );
    assert_eq!(
        entry["project_start_bundle_verification_status"].as_str(),
        Some("accepted"),
        "entry.project_start_bundle_verification_status must be accepted"
    );
    assert!(
        entry["project_start_bundle_verification_checks"].is_object(),
        "entry.project_start_bundle_verification_checks must be a flat object"
    );
    assert!(
        entry["project_start_bundle_verification_result"].is_object(),
        "entry.project_start_bundle_verification_result must be the full embedded verifier object"
    );

    // C18 parity-checklist contribution: queue now verifies bundles.
    assert_eq!(
        entry["parity_checklist_progress"]["ao2_queue_verifies_project_start_handoff_bundle"]
            .as_bool(),
        Some(true),
        "parity_checklist_progress.ao2_queue_verifies_project_start_handoff_bundle must be true \
         after C18 — queue now auto-runs detached bundle verification"
    );

    // Trust boundary on the embedded verifier result must be seven-field observer-safe.
    let tb = &entry["project_start_bundle_verification_result"]["trust_boundary"];
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
fn queue_entry_embedded_verification_result_declares_k16_schema_and_accept_status() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let result = &run_next["entry"]["project_start_bundle_verification_result"];

    assert_eq!(
        result["schema_version"].as_str(),
        Some("ao2.factory-project-start-bundle-verification.v1"),
        "queue-persisted verifier result must declare K16 verifier schema — \
         the queue path reuses K16's verdict, not a parallel variant"
    );
    assert_eq!(
        result["status"].as_str(),
        Some("accepted"),
        "embedded verifier result status must be accepted for a clean queue run"
    );
    assert_eq!(
        result["failure_count"].as_u64(),
        Some(0),
        "accepted verdict must have failure_count=0"
    );
    let failures = result["failures"]
        .as_array()
        .expect("verifier result failures must be an array");
    assert!(
        failures.is_empty(),
        "accepted verdict must have failures=[], got {} entries",
        failures.len()
    );
}

#[test]
fn queue_entry_verification_sha256_matches_verifier_file_bytes() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry_verifier_sha = run_next["entry"]["project_start_bundle_verification_sha256"]
        .as_str()
        .expect("entry.project_start_bundle_verification_sha256 is hex");

    let verifier_file_sha = hex_sha256(VERIFIER_JSON.as_bytes());

    assert_eq!(
        entry_verifier_sha, verifier_file_sha,
        "entry.project_start_bundle_verification_sha256 must equal sha256(verifier file bytes) \
         — K17 verifier file digest lineage; tamper on the persisted verifier verdict file is \
         detectable from the queue entry alone without re-parsing the verdict"
    );
}

#[test]
fn queue_entry_verification_bundle_sha256_matches_entry_project_start_bundle_sha256() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    let entry_bundle_sha = entry["project_start_bundle_sha256"]
        .as_str()
        .expect("entry.project_start_bundle_sha256 is hex");

    let result_bundle_sha = entry["project_start_bundle_verification_result"]["bundle_sha256"]
        .as_str()
        .expect("entry.project_start_bundle_verification_result.bundle_sha256 is hex");

    assert_eq!(
        result_bundle_sha, entry_bundle_sha,
        "verifier_result.bundle_sha256 must equal entry.project_start_bundle_sha256 — \
         the queue-persisted verifier verdict must apply to the same project-start handoff \
         bundle the queue entry shipped, not a stale or substituted artifact"
    );

    // The standalone verifier fixture (the actual file on disk) must
    // also agree on bundle_sha256 with the queue-embedded verifier
    // result — observers must not be able to substitute a different
    // verdict file with the same persisted sha but a different
    // bundle_sha256 claim.
    let standalone = parse(VERIFIER_JSON);
    assert_eq!(
        standalone["bundle_sha256"].as_str(),
        Some(entry_bundle_sha),
        "standalone verifier file bundle_sha256 must agree with the queue entry's \
         bundle_sha256 — verifier file and queue entry must agree on what was verified"
    );
}

#[test]
fn queue_entry_verification_checks_mirror_embedded_result_checks() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    let flat_checks = &entry["project_start_bundle_verification_checks"];
    let result_checks = &entry["project_start_bundle_verification_result"]["checks"];

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
            flat_checks[required_check].as_bool(),
            Some(true),
            "flat checks.{} must be present and true for an accepted verdict",
            required_check
        );
        assert_eq!(
            flat_checks[required_check], result_checks[required_check],
            "flat checks.{} must mirror embedded verifier_result.checks.{} field-by-field — \
             queue observers must be able to ack the verdict from the flat block without \
             dereferencing the embedded result",
            required_check, required_check
        );
    }
}

#[test]
fn queue_entry_verification_status_matches_embedded_result_status() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    let top_status = entry["project_start_bundle_verification_status"]
        .as_str()
        .expect("entry.project_start_bundle_verification_status is string");
    let embedded_status = entry["project_start_bundle_verification_result"]["status"]
        .as_str()
        .expect("entry.project_start_bundle_verification_result.status is string");

    assert_eq!(
        top_status, embedded_status,
        "entry.project_start_bundle_verification_status must equal the embedded \
         verifier_result.status — top-level status and embedded result status cannot drift, \
         so observers can rely on either path to read the verdict"
    );
    assert_eq!(
        top_status, "accepted",
        "for a clean queue run, the persisted verdict status must be accepted"
    );
}

#[test]
fn queue_entry_preserves_k10_k15_artifacts_and_review_threading_alongside_verification() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    // K10 surface: project_start_bundle path + sha256.
    assert!(
        entry["project_start_bundle"].as_str().is_some(),
        "K10 entry.project_start_bundle must still be a path after C18"
    );
    assert!(
        entry["project_start_bundle_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "K10 entry.project_start_bundle_sha256 must still be a 64-hex digest after C18"
    );

    // K11 surface: hermes_queue_handoff block.
    assert_eq!(
        entry["hermes_queue_handoff"]["schema_version"].as_str(),
        Some("ao2.hermes-project-start-handoff.v1"),
        "K11 hermes_queue_handoff schema must still be present after C18"
    );
    assert_eq!(
        entry["hermes_queue_handoff"]["project_start_bundle_sha256"].as_str(),
        entry["project_start_bundle_sha256"].as_str(),
        "K11 hermes_queue_handoff bundle digest must still agree with the entry's bundle digest"
    );

    // K12 surface: queue-entry schema declaration on the entry envelope.
    assert_eq!(
        run_next["claimed_entry"]["schema_version"].as_str(),
        Some("ao2.factory-project-start-workbench-queue-entry.v1"),
        "K12 queue-entry schema must still be declared on claimed_entry after C18"
    );

    // K15 surface: review threading (path + sha + status + decision).
    assert!(
        entry["project_acceptance_review"].as_str().is_some(),
        "K15 entry.project_acceptance_review must still be a path after C18"
    );
    assert!(
        entry["project_acceptance_review_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "K15 entry.project_acceptance_review_sha256 must still be a 64-hex digest after C18"
    );
    assert_eq!(
        entry["project_acceptance_review_status"].as_str(),
        Some("accepted"),
        "K15 entry.project_acceptance_review_status must still be accepted after C18"
    );
    assert_eq!(
        entry["project_acceptance_review_recommended_decision"].as_str(),
        Some("accept"),
        "K15 entry.project_acceptance_review_recommended_decision must still be accept after C18"
    );

    // Execution contract on the entry must still preserve the
    // seven-field observer-safe boundary verbatim (separate from the
    // verifier result trust_boundary — both must hold).
    let ec = &entry["execution_contract"];
    assert_eq!(ec["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(ec["mutates_ao_artifacts"].as_bool(), Some(false));
    assert_eq!(
        ec["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(
        ec["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );
    assert_eq!(ec["factory_v3_role"].as_str(), Some("parity_oracle_only"));
    assert_eq!(ec["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        ec["provider_auth"].as_str(),
        Some("local OAuth CLI only; API-key provider auth forbidden")
    );
}
