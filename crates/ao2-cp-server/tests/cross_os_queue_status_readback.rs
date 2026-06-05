//! K21: Cross-OS queue-status readback observer lineage.
//!
//! Codex C22 (`ao2 9618da4 test(factory): surface queue status in
//! smokes`) threads the K20 `ao2.factory-queue-status.v1` detail
//! surface into the operational smoke + morning cross-OS readback
//! pipelines. The local smoke and the Ubuntu/Windows nightly
//! readback now each write a `factory-queue-project-start-status.json`
//! detail artifact and surface four new fields on the project-run
//! summary so Hermes can confirm queue-status parity across
//! Mac/Ubuntu/Windows from one polled summary per host.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. Each platform's project-run summary declares the host-
//!    independent run-smoke schema `ao2.factory-project-run-smoke.v1`,
//!    a top-level `status` and `run_status`, and a flattened
//!    observer-safe trust-boundary surface (`control_plane_role`,
//!    `mutates_ao_artifacts`, `factory_v3_role`,
//!    `factory_v3_drives_workflow`, `release_acceptance_owner`,
//!    `control_plane_approves_release`).
//!
//! 2. Each platform's summary declares the four C22-contributed
//!    queue-status fields: `queued_project_start_queue_status`,
//!    `queued_project_start_queue_status_schema`,
//!    `queued_project_start_queue_status_read_only`, and
//!    `queued_project_start_queue_status_detail`.
//!
//! 3. **K21 cross-platform parity**: the queue-status schema,
//!    status, and read-only flag are byte-identical across
//!    Mac/Ubuntu/Windows. Hermes can poll any one host's summary and
//!    rely on platform-independent queue-status semantics.
//!
//! 4. Each platform's `queued_project_start_queue_status_detail` is a
//!    non-empty absolute path string pointing at a per-host
//!    `factory-queue-project-start-status.json`. The path-shape is
//!    platform-specific (POSIX vs Windows drive letter) but the field
//!    is always present and non-empty.
//!
//! 5. **K20 lineage survives cross-OS readback**: each platform
//!    summary still reports the K16 bundle-verification status, K18
//!    operator-summary status, and queued-flavor variants as
//!    `accepted`. The K20 queue-status surface is consistent with
//!    those upstream verdicts.
//!
//! 6. **K15 review-signature parity**: each platform reports
//!    `project_start_bundle_review_signature_verified=true` and the
//!    queued-flavor signature-verified flag as well, so the
//!    independently-signed queued review survives cross-OS readback.
//!
//! 7. **Replacement-packet parity**: each platform summary surfaces the
//!    AO2 replacement-packet path, status, archive digest, verifier path,
//!    verifier status, verifier trust-boundary checks, and AO2-driver
//!    verdict. This keeps Hermes on one summary record per host while
//!    control-plane remains a read-only observer.
//!
//! 8. The trust-boundary surface and queue-status fields contain no
//!    bearer tokens or PEM material on any platform.

use serde_json::Value;

const MACOS_SUMMARY: &str =
    include_str!("fixtures/cross-os-queue-status/macos-factory-project-run-summary.json");
const UBUNTU_SUMMARY: &str =
    include_str!("fixtures/cross-os-queue-status/ubuntu-factory-project-run-summary.json");
const WINDOWS_SUMMARY: &str =
    include_str!("fixtures/cross-os-queue-status/windows-factory-project-run-summary.json");

fn parse(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("fixture parses as JSON")
}

fn all_platforms() -> Vec<(&'static str, Value)> {
    vec![
        ("macos", parse(MACOS_SUMMARY)),
        ("ubuntu", parse(UBUNTU_SUMMARY)),
        ("windows", parse(WINDOWS_SUMMARY)),
    ]
}

#[test]
fn each_platform_summary_declares_schema_status_and_observer_safe_trust_boundary() {
    for (platform, s) in all_platforms() {
        assert_eq!(
            s["schema_version"].as_str(),
            Some("ao2.factory-project-run-smoke.v1"),
            "{}: summary must declare the run-smoke schema",
            platform
        );
        assert!(
            s["status"].as_str().is_some(),
            "{}: summary must declare a top-level status",
            platform
        );
        assert!(
            s["run_status"].as_str().is_some(),
            "{}: summary must declare a run_status",
            platform
        );
        assert_eq!(
            s["control_plane_role"].as_str(),
            Some("read_only_observer_after_signed_evidence"),
            "{}: control_plane_role must be observer-only",
            platform
        );
        assert_eq!(
            s["mutates_ao_artifacts"].as_bool(),
            Some(false),
            "{}: mutates_ao_artifacts must be false",
            platform
        );
        assert_eq!(
            s["control_plane_approves_release"].as_bool(),
            Some(false),
            "{}: control_plane_approves_release must be false",
            platform
        );
        assert_eq!(
            s["factory_v3_role"].as_str(),
            Some("parity_oracle_only"),
            "{}: factory_v3_role must be parity_oracle_only",
            platform
        );
        assert_eq!(
            s["factory_v3_drives_workflow"].as_bool(),
            Some(false),
            "{}: factory_v3_drives_workflow must be false",
            platform
        );
        assert_eq!(
            s["release_acceptance_owner"].as_str(),
            Some("factory-v3 evaluator-closer"),
            "{}: release_acceptance_owner must remain factory-v3 evaluator-closer",
            platform
        );
    }
}

#[test]
fn each_platform_summary_declares_four_queue_status_fields() {
    for (platform, s) in all_platforms() {
        for required in [
            "queued_project_start_queue_status",
            "queued_project_start_queue_status_schema",
            "queued_project_start_queue_status_read_only",
            "queued_project_start_queue_status_detail",
        ] {
            assert!(
                !s[required].is_null(),
                "{}: summary must declare C22 queue-status field '{}'",
                platform,
                required
            );
        }
    }
}

#[test]
fn queue_status_schema_status_and_read_only_flag_are_identical_across_platforms() {
    let platforms = all_platforms();

    // Capture the macOS reference values; they are the source of
    // truth for cross-OS parity.
    let (_, mac) = &platforms[0];
    let ref_schema = mac["queued_project_start_queue_status_schema"]
        .as_str()
        .expect("macos schema is string");
    let ref_status = mac["queued_project_start_queue_status"]
        .as_str()
        .expect("macos status is string");
    let ref_read_only = mac["queued_project_start_queue_status_read_only"]
        .as_bool()
        .expect("macos read_only is bool");

    assert_eq!(
        ref_schema, "ao2.factory-queue-status.v1",
        "reference schema must be the K20 schema"
    );
    assert_eq!(
        ref_status, "accepted",
        "reference status must be accepted for a clean smoke"
    );
    assert!(
        ref_read_only,
        "reference read_only flag must be true — C21's read-only contract"
    );

    // Every other platform must report byte-identical schema, status,
    // and read-only flag. Hermes can poll any one host's summary and
    // know the queue-status semantics are platform-independent.
    for (platform, s) in &platforms[1..] {
        assert_eq!(
            s["queued_project_start_queue_status_schema"].as_str(),
            Some(ref_schema),
            "{}: queue-status schema must match macOS reference '{}' \
             — cross-OS parity required for Hermes polling",
            platform,
            ref_schema
        );
        assert_eq!(
            s["queued_project_start_queue_status"].as_str(),
            Some(ref_status),
            "{}: queue-status status must match macOS reference '{}' \
             — cross-OS parity required",
            platform,
            ref_status
        );
        assert_eq!(
            s["queued_project_start_queue_status_read_only"].as_bool(),
            Some(ref_read_only),
            "{}: queue-status read_only flag must match macOS reference \
             {} — cross-OS parity required",
            platform,
            ref_read_only
        );
    }
}

#[test]
fn each_platform_detail_path_is_non_empty_and_points_at_queue_status_artifact() {
    for (platform, s) in all_platforms() {
        let detail = s["queued_project_start_queue_status_detail"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: queue-status _detail must be a string", platform));
        assert!(
            !detail.is_empty(),
            "{}: queue-status _detail must be non-empty",
            platform
        );
        assert!(
            detail.ends_with("factory-queue-project-start-status.json"),
            "{}: queue-status _detail '{}' must point at \
             factory-queue-project-start-status.json (path-shape is \
             platform-specific but the basename is invariant)",
            platform,
            detail
        );
    }
}

#[test]
fn k20_lineage_surfaces_remain_accepted_across_platforms() {
    for (platform, s) in all_platforms() {
        // K16 (bundle verification) → K18 (operator summary) → K19
        // (queue-persisted summary) → K20 (queue-status detail) lineage,
        // all flattened onto the run-smoke summary and visible on every
        // platform.
        for required_accept_field in [
            "queued_project_start_bundle_verification_status",
            "queued_project_start_operator_summary_status",
            "project_start_bundle_verification_status",
            "project_start_operator_summary_status",
            "queued_project_start_status",
            "project_start_status",
        ] {
            assert_eq!(
                s[required_accept_field].as_str(),
                Some("accepted"),
                "{}: {} must be 'accepted' for a clean cross-OS readback — \
                 the K20 queue-status surface is consistent with these \
                 upstream verdicts",
                platform,
                required_accept_field
            );
        }

        assert_eq!(
            s["queued_project_start_operator_summary_bundle_digest_matches"].as_bool(),
            Some(true),
            "{}: queued operator summary's bundle_digest_matches must be \
             true across cross-OS readback (K18 digest binding)",
            platform
        );
    }
}

#[test]
fn k15_review_signature_parity_holds_across_platforms() {
    for (platform, s) in all_platforms() {
        assert_eq!(
            s["project_start_bundle_review_signature_verified"].as_bool(),
            Some(true),
            "{}: project_start_bundle_review_signature_verified must be true \
             across cross-OS readback (K15 independently-signed review)",
            platform
        );
        assert_eq!(
            s["queued_project_start_bundle_review_signature_verified"].as_bool(),
            Some(true),
            "{}: queued_project_start_bundle_review_signature_verified must \
             be true across cross-OS readback (K15 queued-flavor signed review)",
            platform
        );
        assert_eq!(
            s["project_acceptance_review_signature_status"].as_str(),
            Some("signed"),
            "{}: project_acceptance_review_signature_status must be 'signed' \
             across cross-OS readback (K14 review signature)",
            platform
        );
    }
}

#[test]
fn replacement_packet_handoff_parity_holds_across_platforms() {
    for (platform, s) in all_platforms() {
        for required_field in [
            "queued_auto_replacement_packet",
            "queued_auto_replacement_packet_archive",
            "queued_auto_replacement_packet_status",
            "queued_auto_replacement_packet_verification",
            "queued_auto_replacement_packet_verification_status",
            "queued_auto_replacement_packet_verification_checksums_verified",
            "queued_auto_replacement_packet_verification_trust_boundary_verified",
            "queued_replacement_packet",
            "queued_replacement_packet_archive",
            "queued_replacement_packet_schema",
            "queued_replacement_packet_status",
            "queued_replacement_packet_sha256",
            "queued_replacement_packet_ao2_replaces_factory_v3_workflow_driver",
            "queued_replacement_packet_factory_v3_role",
            "queued_replacement_packet_verification",
            "queued_replacement_packet_verification_schema",
            "queued_replacement_packet_verification_status",
            "queued_replacement_packet_verification_checksums_verified",
            "queued_replacement_packet_verification_trust_boundary_verified",
            "queued_replacement_packet_verification_ao2_replacement_driver_verified",
            "queued_replacement_packet_verification_factory_v3_evaluator_closer_verified",
        ] {
            assert!(
                !s[required_field].is_null(),
                "{}: summary must declare replacement-packet field '{}'",
                platform,
                required_field
            );
        }

        assert_eq!(
            s["queued_auto_replacement_packet_status"].as_str(),
            Some("packaged"),
            "{}: auto replacement packet must be packaged",
            platform
        );
        assert_eq!(
            s["queued_auto_replacement_packet_verification_status"].as_str(),
            Some("accepted"),
            "{}: auto replacement packet verification must be accepted",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_schema"].as_str(),
            Some("ao2.factory-replacement-packet.v1"),
            "{}: replacement packet schema must be AO2-owned",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_status"].as_str(),
            Some("packaged"),
            "{}: replacement packet must be packaged",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_verification_schema"].as_str(),
            Some("ao2.factory-replacement-packet-verification.v1"),
            "{}: replacement packet verifier schema must be AO2-owned",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_verification_status"].as_str(),
            Some("accepted"),
            "{}: replacement packet verifier must be accepted",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_ao2_replaces_factory_v3_workflow_driver"].as_bool(),
            Some(true),
            "{}: AO2 must be the replacement workflow driver",
            platform
        );
        assert_eq!(
            s["queued_replacement_packet_factory_v3_role"].as_str(),
            Some("evaluator_closer_and_sampling_auditor"),
            "{}: factory-v3 must remain evaluator-closer/sampling auditor",
            platform
        );

        for boolean_field in [
            "queued_auto_replacement_packet_verification_checksums_verified",
            "queued_auto_replacement_packet_verification_trust_boundary_verified",
            "queued_replacement_packet_verification_checksums_verified",
            "queued_replacement_packet_verification_trust_boundary_verified",
            "queued_replacement_packet_verification_ao2_replacement_driver_verified",
            "queued_replacement_packet_verification_factory_v3_evaluator_closer_verified",
        ] {
            assert_eq!(
                s[boolean_field].as_bool(),
                Some(true),
                "{}: replacement packet verifier field '{}' must be true",
                platform,
                boolean_field
            );
        }

        assert!(
            s["queued_replacement_packet_sha256"]
                .as_str()
                .is_some_and(|sha| sha.len() == 64),
            "{}: replacement packet archive sha must be a 64-hex digest",
            platform
        );
    }
}

#[test]
fn cross_os_summaries_contain_no_bearer_or_pem_material() {
    for (platform, raw) in [
        ("macos", MACOS_SUMMARY),
        ("ubuntu", UBUNTU_SUMMARY),
        ("windows", WINDOWS_SUMMARY),
    ] {
        assert!(
            !raw.contains("Bearer "),
            "{}: cross-OS summary must not embed bearer tokens",
            platform
        );
        assert!(
            !raw.contains("BEGIN PRIVATE KEY"),
            "{}: cross-OS summary must not embed PKCS8 private key material",
            platform
        );
        assert!(
            !raw.contains("BEGIN RSA PRIVATE KEY"),
            "{}: cross-OS summary must not embed RSA private key material",
            platform
        );
        assert!(
            !raw.contains("ANTHROPIC_API_KEY"),
            "{}: cross-OS summary must not leak provider API-key env var",
            platform
        );
    }
}
