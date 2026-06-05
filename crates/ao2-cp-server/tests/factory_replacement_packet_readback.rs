//! Read-only observer checks for AO2 factory replacement packets.
//!
//! AO2 produces `ao2.factory-replacement-packet.v1` as a single review handoff
//! over project-start queue status, closure packaging, closure verification,
//! operator summary, rubric, and acceptance review artifacts. The control plane
//! does not produce or approve the packet; it only validates the observer-safe
//! contract from fixture bytes.

use serde_json::Value;

const PACKET: &str =
    include_str!("fixtures/factory-replacement-packet/factory-replacement-packet.json");
const VERIFICATION: &str = include_str!(
    "fixtures/factory-replacement-packet/factory-replacement-packet-verification.json"
);

fn packet() -> Value {
    serde_json::from_str(PACKET).expect("factory replacement packet fixture parses")
}

fn verification() -> Value {
    serde_json::from_str(VERIFICATION)
        .expect("factory replacement packet verification fixture parses")
}

#[test]
fn replacement_packet_declares_observer_safe_trust_boundary() {
    let p = packet();

    assert_eq!(
        p["schema_version"].as_str(),
        Some("ao2.factory-replacement-packet.v1")
    );
    assert_eq!(p["status"].as_str(), Some("packaged"));
    assert!(p["run_id"].as_str().is_some());

    let tb = &p["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        tb["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );
    assert_eq!(
        tb["factory_v3_role"].as_str(),
        Some("evaluator_closer_and_sampling_auditor")
    );
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
    assert_eq!(
        tb["provider_auth"].as_str(),
        Some("local OAuth CLI only; API-key provider auth forbidden")
    );
}

#[test]
fn replacement_packet_summarizes_factory_v3_retirement_boundary() {
    let p = packet();
    let summary = &p["replacement_summary"];

    assert_eq!(
        summary["ao2_replaces_factory_v3_workflow_driver"].as_bool(),
        Some(true)
    );
    assert_eq!(
        summary["ao2_packet_role"].as_str(),
        Some("single_ao2_owned_review_handoff")
    );
    assert_eq!(
        summary["factory_v3_role"].as_str(),
        Some("evaluator_closer_and_sampling_auditor")
    );
    assert_eq!(
        summary["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(
        summary["hermes_role"].as_str(),
        Some("front_end_queue_cron_memory_bookkeeping")
    );
}

#[test]
fn replacement_packet_requires_accepted_queue_and_closure_checks() {
    let p = packet();
    let checks = &p["checks"];

    for key in [
        "queue_status_accepted",
        "latest_queue_status_accepted",
        "latest_selector_matches_run_id_selector",
        "closure_verification_accepted",
        "closure_checksums_verified",
        "closure_trust_boundary_verified",
        "project_start_operator_summary_accepted",
        "project_acceptance_review_accepted",
    ] {
        assert_eq!(
            checks[key].as_bool(),
            Some(true),
            "replacement packet check {key} must be true"
        );
    }
    assert_eq!(
        checks["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(checks["mutates_ao_artifacts"].as_bool(), Some(false));
}

#[test]
fn replacement_packet_lists_review_handoff_archive_manifest_without_secret_material() {
    let p = packet();

    assert!(
        p["archive"].as_str().is_some(),
        "replacement packet must expose the archive path for operator review"
    );
    assert_eq!(
        p["manifest_entry"].as_str(),
        Some("manifest.json"),
        "replacement packet must pin the archive manifest entry name"
    );
    assert_eq!(
        p["checksum_entry"].as_str(),
        Some("SHA256SUMS"),
        "replacement packet must pin the archive checksum entry name"
    );
    assert_eq!(
        p["packet_entry"].as_str(),
        Some("replacement-packet.json"),
        "replacement packet must pin the inner packet entry name"
    );
    assert!(
        p["artifact_count"]
            .as_u64()
            .is_some_and(|count| count >= 12),
        "replacement packet must package the full project-start review handoff"
    );
    assert!(
        p["sha256"].as_str().is_some_and(|sha| sha.len() == 64),
        "replacement packet must expose a 64-hex archive digest"
    );

    assert!(
        !PACKET.contains("Bearer "),
        "replacement packet fixture must not expose bearer tokens"
    );
    assert!(
        !PACKET.contains("BEGIN PRIVATE KEY"),
        "replacement packet fixture must not expose private keys"
    );
}

#[test]
fn replacement_packet_verification_is_observer_safe_and_fail_closed() {
    let report = verification();

    assert_eq!(
        report["schema_version"].as_str(),
        Some("ao2.factory-replacement-packet-verification.v1")
    );
    assert_eq!(report["status"].as_str(), Some("accepted"));
    assert_eq!(report["failure_count"].as_u64(), Some(0));
    assert!(report["run_id"].as_str().is_some());

    let checks = &report["checks"];
    for key in [
        "manifest_verified",
        "checksums_verified",
        "packet_verified",
        "trust_boundary_verified",
        "secret_scan_passed",
        "ao2_replacement_driver_verified",
        "factory_v3_evaluator_closer_verified",
    ] {
        assert_eq!(
            checks[key].as_bool(),
            Some(true),
            "replacement packet verification check {key} must be true"
        );
    }

    let tb = &report["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        tb["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );
    assert_eq!(
        tb["factory_v3_role"].as_str(),
        Some("evaluator_closer_and_sampling_auditor")
    );
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer_after_signed_evidence")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));

    assert!(
        !VERIFICATION.contains("Bearer "),
        "replacement packet verification fixture must not expose bearer tokens"
    );
    assert!(
        !VERIFICATION.contains("BEGIN PRIVATE KEY"),
        "replacement packet verification fixture must not expose private keys"
    );
}
