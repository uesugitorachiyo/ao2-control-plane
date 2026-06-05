//! K19: Queue-persisted project-start operator summary observer lineage.
//!
//! Codex C20 (`ao2 621f37f feat(factory): summarize queued
//! project-start handoffs`) makes the AO2 queue-run-next path
//! automatically generate the K18 operator summary
//! (`ao2.factory-project-start-operator-summary.v1`) on a successful
//! queued project-start completion, and persists the summary's path,
//! Markdown sidecar path, sha256, status, flat checks, and full
//! embedded result on the completed queue entry. Queue execution
//! fails closed if summary generation cannot bind the verified bundle.
//!
//! The persisted entry carries six C20-contributed fields alongside
//! the K10-K18 surface:
//!
//!   - `entry.project_start_operator_summary` (path to summary JSON)
//!   - `entry.project_start_operator_summary_markdown` (path to .md sidecar)
//!   - `entry.project_start_operator_summary_sha256` (sha256 of summary JSON bytes)
//!   - `entry.project_start_operator_summary_status` ("accepted")
//!   - `entry.project_start_operator_summary_checks` (flat 4-boolean copy)
//!   - `entry.project_start_operator_summary_result` (full K18 schema embedded)
//!
//! A new parity-checklist boolean
//! `parity_checklist_progress.ao2_queue_summarizes_project_start_handoff=true`
//! sits alongside K17's `ao2_queue_verifies_project_start_handoff_bundle=true`.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The queue-run-next entry threads all six C20-contributed
//!    summary fields, declares
//!    `project_start_operator_summary_status=accepted`, asserts
//!    `parity_checklist_progress.ao2_queue_summarizes_project_start_handoff=true`,
//!    and preserves the seven-field observer-safe `trust_boundary`
//!    verbatim on the embedded summary result.
//!
//! 2. The embedded `project_start_operator_summary_result` declares
//!    K18's `ao2.factory-project-start-operator-summary.v1` schema
//!    with `status=accepted`, `project_status=accepted`,
//!    `bundle_verification_status=accepted`, and `failure_count=0` —
//!    the queue path reuses K18's summary schema, not a parallel
//!    variant.
//!
//! 3. **K19 summary file digest lineage**: `sha256(summary JSON
//!    bytes) == entry.project_start_operator_summary_sha256` —
//!    tamper on the persisted summary file is detectable from the
//!    queue entry alone.
//!
//! 4. **K18 digest binding survives queue persistence**: inside the
//!    embedded summary `result.artifacts`, every entry still
//!    satisfies `sha256 == expected_sha256`. The K18 fail-closed
//!    contract is preserved through the C20 queue persist path.
//!
//! 5. The flat `entry.project_start_operator_summary_checks` mirrors
//!    `entry.project_start_operator_summary_result.checks` field-by-
//!    field with all four fail-closed booleans
//!    (`bundle_digest_matches`, `bundle_verification_accepted`,
//!    `project_start_accepted`, `trust_boundary_verified`) true for
//!    accept.
//!
//! 6. `entry.project_start_operator_summary_status` matches the
//!    embedded `summary_result.status` — top-level and embedded
//!    statuses cannot drift.
//!
//! 7. The K10-K18 surface is preserved alongside the new summary
//!    fields: K10 bundle digest, K11 hermes_queue_handoff schema, K12
//!    queue-entry schema, K15 project_acceptance_review threading,
//!    K17 project_start_bundle_verification threading. The
//!    execution_contract trust boundary is also preserved.

use serde_json::Value;
use sha2::{Digest, Sha256};

const SUMMARY_JSON: &str =
    include_str!("fixtures/queued-operator-summary/factory-project-start-operator-summary.json");
const QUEUE_RUN_NEXT_JSON: &str =
    include_str!("fixtures/queued-operator-summary/factory-queue-project-start-run-next.json");

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
fn queue_entry_threads_operator_summary_fields_with_observer_safe_trust_boundary() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    assert!(
        entry["project_start_operator_summary"].as_str().is_some(),
        "entry.project_start_operator_summary must be a path"
    );
    assert!(
        entry["project_start_operator_summary_markdown"]
            .as_str()
            .is_some(),
        "entry.project_start_operator_summary_markdown must be a path to the .md sidecar"
    );
    assert!(
        entry["project_start_operator_summary_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "entry.project_start_operator_summary_sha256 must be a 64-hex digest"
    );
    assert_eq!(
        entry["project_start_operator_summary_status"].as_str(),
        Some("accepted"),
        "entry.project_start_operator_summary_status must be accepted"
    );
    assert!(
        entry["project_start_operator_summary_checks"].is_object(),
        "entry.project_start_operator_summary_checks must be a flat object"
    );
    assert!(
        entry["project_start_operator_summary_result"].is_object(),
        "entry.project_start_operator_summary_result must be the full embedded K18 summary"
    );

    // C20 parity-checklist contribution: queue now summarizes.
    assert_eq!(
        entry["parity_checklist_progress"]["ao2_queue_summarizes_project_start_handoff"].as_bool(),
        Some(true),
        "parity_checklist_progress.ao2_queue_summarizes_project_start_handoff must be true \
         after C20 — queue now auto-generates the K18 operator summary on completed entries"
    );
    // K17's parity boolean must still hold.
    assert_eq!(
        entry["parity_checklist_progress"]["ao2_queue_verifies_project_start_handoff_bundle"]
            .as_bool(),
        Some(true),
        "parity_checklist_progress.ao2_queue_verifies_project_start_handoff_bundle (K17) \
         must still hold after C20"
    );

    // Trust boundary on the embedded summary result.
    let tb = &entry["project_start_operator_summary_result"]["trust_boundary"];
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
fn queue_entry_embedded_summary_result_declares_k18_schema_and_accept_status() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let result = &run_next["entry"]["project_start_operator_summary_result"];

    assert_eq!(
        result["schema_version"].as_str(),
        Some("ao2.factory-project-start-operator-summary.v1"),
        "queue-persisted summary result must declare K18 summary schema — \
         the queue path reuses K18's summary, not a parallel variant"
    );
    assert_eq!(
        result["status"].as_str(),
        Some("accepted"),
        "embedded summary result status must be accepted"
    );
    assert_eq!(
        result["project_status"].as_str(),
        Some("accepted"),
        "embedded summary project_status must be accepted"
    );
    assert_eq!(
        result["bundle_verification_status"].as_str(),
        Some("accepted"),
        "embedded summary bundle_verification_status must be accepted"
    );
    assert_eq!(
        result["failure_count"].as_u64(),
        Some(0),
        "accepted summary must have failure_count=0"
    );
    let failures = result["failures"]
        .as_array()
        .expect("summary result failures must be an array");
    assert!(
        failures.is_empty(),
        "accepted summary must have failures=[], got {} entries",
        failures.len()
    );
}

#[test]
fn queue_entry_operator_summary_sha256_matches_summary_file_bytes() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry_summary_sha = run_next["entry"]["project_start_operator_summary_sha256"]
        .as_str()
        .expect("entry.project_start_operator_summary_sha256 is hex");

    let summary_file_sha = hex_sha256(SUMMARY_JSON.as_bytes());

    assert_eq!(
        entry_summary_sha, summary_file_sha,
        "entry.project_start_operator_summary_sha256 must equal sha256(summary file bytes) \
         — K19 summary file digest lineage; tamper on the persisted summary file is \
         detectable from the queue entry alone"
    );
}

#[test]
fn queue_entry_embedded_summary_preserves_k18_digest_binding_for_every_artifact() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let artifacts = run_next["entry"]["project_start_operator_summary_result"]["artifacts"]
        .as_object()
        .expect("embedded summary result.artifacts is object");

    for (label, entry) in artifacts {
        let actual = entry["sha256"].as_str().expect("artifact sha256 is string");
        let expected = entry["expected_sha256"]
            .as_str()
            .expect("artifact expected_sha256 is string");
        assert_eq!(
            actual, expected,
            "queue-persisted summary.artifacts.{}: sha256 ({}) must equal expected_sha256 \
             ({}) — K18 digest binding must survive queue persistence; the queue path \
             must not weaken the fail-closed contract",
            label, actual, expected
        );
    }
}

#[test]
fn queue_entry_operator_summary_checks_mirror_embedded_result_checks() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    let flat_checks = &entry["project_start_operator_summary_checks"];
    let result_checks = &entry["project_start_operator_summary_result"]["checks"];

    for required_check in [
        "bundle_digest_matches",
        "bundle_verification_accepted",
        "project_start_accepted",
        "trust_boundary_verified",
    ] {
        assert_eq!(
            flat_checks[required_check].as_bool(),
            Some(true),
            "flat checks.{} must be present and true for an accepted summary",
            required_check
        );
        assert_eq!(
            flat_checks[required_check], result_checks[required_check],
            "flat checks.{} must mirror embedded summary_result.checks.{} field-by-field \
             — queue observers must be able to ack the summary from the flat block",
            required_check, required_check
        );
    }
}

#[test]
fn queue_entry_operator_summary_status_matches_embedded_result_status() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    let top_status = entry["project_start_operator_summary_status"]
        .as_str()
        .expect("entry.project_start_operator_summary_status is string");
    let embedded_status = entry["project_start_operator_summary_result"]["status"]
        .as_str()
        .expect("entry.project_start_operator_summary_result.status is string");

    assert_eq!(
        top_status, embedded_status,
        "entry.project_start_operator_summary_status must equal the embedded \
         summary_result.status — top-level status and embedded result status cannot drift"
    );
    assert_eq!(
        top_status, "accepted",
        "for a clean queue run, the persisted summary status must be accepted"
    );
}

#[test]
fn queue_entry_preserves_k10_k17_surface_alongside_operator_summary() {
    let run_next = parse(QUEUE_RUN_NEXT_JSON);
    let entry = &run_next["entry"];

    // K10 surface: project_start_bundle path + sha256.
    assert!(
        entry["project_start_bundle"].as_str().is_some(),
        "K10 entry.project_start_bundle must still be a path after C20"
    );
    assert!(
        entry["project_start_bundle_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "K10 entry.project_start_bundle_sha256 must still be a 64-hex digest after C20"
    );

    // K11 surface: hermes_queue_handoff block.
    assert_eq!(
        entry["hermes_queue_handoff"]["schema_version"].as_str(),
        Some("ao2.hermes-project-start-handoff.v1"),
        "K11 hermes_queue_handoff schema must still be present after C20"
    );

    // K12 surface: queue-entry schema on claimed_entry.
    assert_eq!(
        run_next["claimed_entry"]["schema_version"].as_str(),
        Some("ao2.factory-project-start-workbench-queue-entry.v1"),
        "K12 queue-entry schema must still be declared on claimed_entry after C20"
    );

    // K15 surface: review threading.
    assert!(
        entry["project_acceptance_review"].as_str().is_some(),
        "K15 entry.project_acceptance_review must still be a path after C20"
    );
    assert_eq!(
        entry["project_acceptance_review_status"].as_str(),
        Some("accepted"),
        "K15 entry.project_acceptance_review_status must still be accepted after C20"
    );

    // K17 surface: verifier persistence on the entry.
    assert!(
        entry["project_start_bundle_verification"]
            .as_str()
            .is_some(),
        "K17 entry.project_start_bundle_verification must still be a path after C20"
    );
    assert!(
        entry["project_start_bundle_verification_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "K17 entry.project_start_bundle_verification_sha256 must still be 64-hex after C20"
    );
    assert_eq!(
        entry["project_start_bundle_verification_status"].as_str(),
        Some("accepted"),
        "K17 entry.project_start_bundle_verification_status must still be accepted after C20"
    );
    assert!(
        entry["project_start_bundle_verification_result"].is_object(),
        "K17 entry.project_start_bundle_verification_result must still be present after C20"
    );

    // Execution contract trust boundary.
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
