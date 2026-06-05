//! K20: Queue-status detail observer lineage.
//!
//! Codex C21 (`ao2 45e1a76 feat(factory): add queue status detail`)
//! ships `ao2.factory-queue-status.v1` — a read-only AO2-owned
//! single-record queue detail view returned by
//! `ao2 factory queue-status --target <repo> --run-id <run-id> --json`.
//! The intent is to give Hermes one polling surface for a completed
//! queued project-start without mutating the queue or AO artifacts.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The detail declares `ao2.factory-queue-status.v1`, mirrors the
//!    requested `run_id` and `status`, exposes `job_kind` and
//!    `queue_path`, and preserves the seven-field observer-safe
//!    `trust_boundary` verbatim.
//!
//! 2. The detail's top-level `status`/`run_id`/`job_kind` match the
//!    embedded `entry.status`/`entry.run_id`/`entry.job_kind` — Hermes
//!    cannot see a different verdict from the two surfaces.
//!
//! 3. The embedded queue entry carries the K19 surface intact: the
//!    six C20-contributed fields (`project_start_operator_summary`,
//!    `_markdown`, `_sha256`, `_status`, `_checks`, `_result`) still
//!    appear under `entry`, and `_status` mirrors `_result.status`.
//!
//! 4. **K20 summary-file digest lineage survives queue-status
//!    threading**: `sha256(operator-summary file bytes)` equals
//!    `entry.project_start_operator_summary_sha256`. C21 fails closed
//!    on this exact contract; observers must reproduce it from disk.
//!
//! 5. **K18 digest binding survives queue-status threading**: for
//!    every artifact in `entry._result.artifacts`, `sha256 ==
//!    expected_sha256`. The queue-status layer cannot rewrite
//!    artifact digests without breaking the chain.
//!
//! 6. The detail lists `parity_checklist_progress` with
//!    `ao2_queue_status_detail_is_read_only=true`,
//!    `factory_v3_drives_workflow=false`,
//!    `factory_v3_role="parity_oracle_only"`, and
//!    `control_plane_role="read_only_observer_after_signed_evidence"`;
//!    plus top-level `ao2_decision_owner="ao2-workbench-queue"` and a
//!    `continuity_contract` block.
//!
//! 7. The queue-status entry carries the replacement-packet handoff
//!    produced by AO2 after project-start closure. Control-plane observes
//!    the packet path, packet sha, archive path + sha, verifier path + sha,
//!    status, embedded result, and embedded verifier result without becoming
//!    a packet producer or release approver.
//!
//! 8. The status is terminal (not `queued`/`running`/`cancel_requested`)
//!    — C21 refuses to return a non-terminal entry. Observers see this
//!    invariant directly in the captured fixture.

use serde_json::Value;
use sha2::{Digest, Sha256};

const DETAIL_JSON: &str = include_str!("fixtures/queue-status-detail/factory-queue-status.json");
const SUMMARY_BYTES: &[u8] =
    include_bytes!("fixtures/queue-status-detail/factory-project-start-operator-summary.json");

fn parse(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("fixture parses as JSON")
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{:02x}", byte).expect("hex writer");
    }
    out
}

#[test]
fn queue_status_declares_schema_run_id_and_observer_safe_trust_boundary() {
    let d = parse(DETAIL_JSON);

    assert_eq!(
        d["schema_version"].as_str(),
        Some("ao2.factory-queue-status.v1"),
        "detail must declare K20 schema"
    );
    assert!(
        d["status"].as_str().is_some(),
        "detail must declare a status"
    );
    assert!(
        d["run_id"].as_str().is_some(),
        "detail must declare a run_id"
    );
    assert!(
        d["job_kind"].as_str().is_some(),
        "detail must declare a job_kind"
    );
    assert!(
        d["queue_path"].as_str().is_some(),
        "detail must declare a queue_path"
    );

    let tb = &d["trust_boundary"];
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
fn queue_status_top_level_status_run_id_job_kind_mirror_embedded_entry() {
    let d = parse(DETAIL_JSON);

    let top_status = d["status"].as_str().expect("top status is string");
    let entry_status = d["entry"]["status"].as_str().expect("entry status");
    assert_eq!(
        top_status, entry_status,
        "detail.status must mirror detail.entry.status — Hermes must not \
         see a different verdict between the two surfaces"
    );

    let top_run_id = d["run_id"].as_str().expect("top run_id");
    let entry_run_id = d["entry"]["run_id"].as_str().expect("entry run_id");
    assert_eq!(
        top_run_id, entry_run_id,
        "detail.run_id must mirror detail.entry.run_id"
    );

    let top_job_kind = d["job_kind"].as_str().expect("top job_kind");
    let entry_job_kind = d["entry"]["job_kind"].as_str().expect("entry job_kind");
    assert_eq!(
        top_job_kind, entry_job_kind,
        "detail.job_kind must mirror detail.entry.job_kind"
    );
}

#[test]
fn queue_status_entry_preserves_k19_six_summary_fields_with_mirroring() {
    let d = parse(DETAIL_JSON);
    let entry = &d["entry"];

    for required in [
        "project_start_operator_summary",
        "project_start_operator_summary_markdown",
        "project_start_operator_summary_sha256",
        "project_start_operator_summary_status",
        "project_start_operator_summary_checks",
        "project_start_operator_summary_result",
    ] {
        assert!(
            !entry[required].is_null(),
            "queue-status detail must preserve K19 field entry.{} across \
             queue-status threading",
            required
        );
    }

    // _status mirrors _result.status (K19 embedded-result mirroring
    // invariant survives queue-status).
    let flat_status = entry["project_start_operator_summary_status"]
        .as_str()
        .expect("summary status mirror is string");
    let result_status = entry["project_start_operator_summary_result"]["status"]
        .as_str()
        .expect("embedded result status is string");
    assert_eq!(
        flat_status, result_status,
        "entry.project_start_operator_summary_status must mirror \
         entry.project_start_operator_summary_result.status — K19 mirroring \
         contract must survive queue-status threading"
    );

    // _checks mirrors _result.checks four-true booleans.
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
            result_checks[required_check].as_bool(),
            "entry.project_start_operator_summary_checks.{} must mirror \
             entry.project_start_operator_summary_result.checks.{}",
            required_check,
            required_check
        );
        assert_eq!(
            flat_checks[required_check].as_bool(),
            Some(true),
            "checks.{} must be true for an accepted summary",
            required_check
        );
    }
}

#[test]
fn queue_status_summary_file_digest_binding_survives_queue_status_threading() {
    let d = parse(DETAIL_JSON);

    let actual_summary_sha = hex_sha256(SUMMARY_BYTES);
    let entry_summary_sha = d["entry"]["project_start_operator_summary_sha256"]
        .as_str()
        .expect("entry.project_start_operator_summary_sha256 is string");

    assert_eq!(
        actual_summary_sha, entry_summary_sha,
        "sha256(operator-summary file bytes) ({}) must equal \
         entry.project_start_operator_summary_sha256 ({}) — C21 fails \
         closed on this exact mismatch; observers must reproduce the \
         binding from disk",
        actual_summary_sha, entry_summary_sha
    );

    // Cross-check the summary file's own self-consistency (K18 digest
    // binding) so we know the file we hashed is the same file the
    // queue-status entry pinned.
    let summary: Value =
        serde_json::from_slice(SUMMARY_BYTES).expect("operator-summary fixture parses");
    assert_eq!(
        summary["schema_version"].as_str(),
        Some("ao2.factory-project-start-operator-summary.v1"),
        "the summary file pinned by queue-status must be the K18 schema"
    );
    assert_eq!(
        summary["status"].as_str(),
        Some("accepted"),
        "summary file pinned by queue-status must be accepted"
    );
}

#[test]
fn queue_status_embedded_summary_result_preserves_k18_digest_binding() {
    let d = parse(DETAIL_JSON);
    let artifacts = d["entry"]["project_start_operator_summary_result"]["artifacts"]
        .as_object()
        .expect("embedded summary result artifacts is object");
    assert!(
        !artifacts.is_empty(),
        "embedded summary result must list artifacts after queue-status threading"
    );

    for (label, entry) in artifacts {
        let actual = entry["sha256"].as_str().expect("artifact sha256 is string");
        let expected = entry["expected_sha256"]
            .as_str()
            .expect("artifact expected_sha256 is string");
        assert_eq!(
            actual, expected,
            "entry.project_start_operator_summary_result.artifacts.{}: \
             sha256 ({}) must equal expected_sha256 ({}) — K18 digest \
             binding must survive queue-status threading",
            label, actual, expected
        );
    }
}

#[test]
fn queue_status_carries_parity_checklist_continuity_and_decision_owner() {
    let d = parse(DETAIL_JSON);

    let checklist = &d["parity_checklist_progress"];
    assert_eq!(
        checklist["ao2_queue_status_detail_is_read_only"].as_bool(),
        Some(true),
        "parity_checklist_progress.ao2_queue_status_detail_is_read_only \
         must be true — C21's read-only contract surfaced to observers"
    );
    assert_eq!(
        checklist["factory_v3_drives_workflow"].as_bool(),
        Some(false),
        "factory_v3 must not drive the workflow"
    );
    assert_eq!(
        checklist["factory_v3_role"].as_str(),
        Some("parity_oracle_only")
    );
    assert_eq!(
        checklist["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(
        checklist["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );

    assert_eq!(
        d["ao2_decision_owner"].as_str(),
        Some("ao2-workbench-queue"),
        "queue-status detail must record the ao2 decision owner"
    );

    assert!(
        d["continuity_contract"].is_object(),
        "queue-status detail must echo the queue's continuity_contract block"
    );
}

#[test]
fn queue_status_entry_preserves_replacement_packet_handoff_read_only() {
    let d = parse(DETAIL_JSON);
    let entry = &d["entry"];

    for required in [
        "replacement_packet",
        "replacement_packet_sha256",
        "replacement_packet_archive",
        "replacement_packet_archive_sha256",
        "replacement_packet_status",
        "replacement_packet_result",
        "replacement_packet_verification",
        "replacement_packet_verification_sha256",
        "replacement_packet_verification_status",
        "replacement_packet_verification_checks",
        "replacement_packet_verification_result",
    ] {
        assert!(
            !entry[required].is_null(),
            "queue-status detail must preserve replacement packet handoff field entry.{required}"
        );
    }

    assert_eq!(
        entry["replacement_packet_status"].as_str(),
        Some("packaged"),
        "entry.replacement_packet_status must mirror a packaged AO2 replacement packet"
    );
    assert_eq!(
        entry["replacement_packet_result"]["schema_version"].as_str(),
        Some("ao2.factory-replacement-packet.v1"),
        "entry.replacement_packet_result must embed the AO2 packet schema"
    );
    assert_eq!(
        entry["replacement_packet_result"]["status"].as_str(),
        entry["replacement_packet_status"].as_str(),
        "replacement_packet_status must mirror replacement_packet_result.status"
    );

    let packet_tb = &entry["replacement_packet_result"]["trust_boundary"];
    assert_eq!(packet_tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        packet_tb["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );
    assert_eq!(
        packet_tb["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(
        packet_tb["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(packet_tb["mutates_ao_artifacts"].as_bool(), Some(false));

    assert_eq!(
        entry["replacement_packet_verification_status"].as_str(),
        Some("accepted"),
        "entry.replacement_packet_verification_status must expose the verifier verdict"
    );
    assert_eq!(
        entry["replacement_packet_verification_result"]["schema_version"].as_str(),
        Some("ao2.factory-replacement-packet-verification.v1"),
        "entry.replacement_packet_verification_result must embed the AO2 packet verifier schema"
    );
    assert_eq!(
        entry["replacement_packet_verification_result"]["status"].as_str(),
        entry["replacement_packet_verification_status"].as_str(),
        "replacement_packet_verification_status must mirror verifier result.status"
    );

    let verifier_checks = &entry["replacement_packet_verification_checks"];
    let verifier_result_checks = &entry["replacement_packet_verification_result"]["checks"];
    for check in [
        "manifest_verified",
        "checksums_verified",
        "packet_verified",
        "trust_boundary_verified",
        "secret_scan_passed",
        "ao2_replacement_driver_verified",
        "factory_v3_evaluator_closer_verified",
    ] {
        assert_eq!(
            verifier_checks[check].as_bool(),
            Some(true),
            "entry.replacement_packet_verification_checks.{check} must be true"
        );
        assert_eq!(
            verifier_checks[check], verifier_result_checks[check],
            "flat verifier check {check} must mirror the embedded verifier result"
        );
    }

    let archive_sha = entry["replacement_packet_archive_sha256"]
        .as_str()
        .expect("replacement_packet_archive_sha256 is string");
    assert_eq!(
        archive_sha.len(),
        64,
        "replacement_packet_archive_sha256 must be a 64-hex digest"
    );
}

#[test]
fn queue_status_returns_only_terminal_entries_and_observer_safe_surface() {
    let d = parse(DETAIL_JSON);

    // C21's fail-closed terminal-only contract: the detail must never
    // return an in-flight queue entry. Observers verify this by
    // checking the captured status is in the terminal set.
    let status = d["status"].as_str().expect("detail status is string");
    let terminal = [
        "accepted",
        "accepted_with_concerns",
        "rejected",
        "blocked",
        "failed",
        "completed",
        "cancelled",
    ];
    assert!(
        terminal.contains(&status),
        "queue-status detail status '{}' must be in the terminal set {:?} \
         — C21 refuses to return in-flight entries",
        status,
        terminal
    );

    // Sanity: the embedded entry's own status is the same terminal
    // value. (Top-level/entry mirroring is asserted elsewhere; this
    // check guards the terminal-set narrowing too.)
    let entry_status = d["entry"]["status"]
        .as_str()
        .expect("entry status is string");
    assert!(
        terminal.contains(&entry_status),
        "queue-status detail entry.status '{}' must be in the terminal set",
        entry_status
    );

    // Observer-safe surface: queue-status must not embed bearer tokens
    // or PEM material. The fixture was captured from a real smoke and
    // any leak would be visible in DETAIL_JSON.
    assert!(
        !DETAIL_JSON.contains("Bearer "),
        "queue-status detail must not embed bearer tokens"
    );
    assert!(
        !DETAIL_JSON.contains("BEGIN PRIVATE KEY"),
        "queue-status detail must not embed private key material"
    );
    assert!(
        !DETAIL_JSON.contains("BEGIN RSA PRIVATE KEY"),
        "queue-status detail must not embed RSA private key material"
    );
}
