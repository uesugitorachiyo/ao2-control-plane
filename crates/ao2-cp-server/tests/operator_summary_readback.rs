//! K18: Project-start operator summary observer lineage.
//!
//! Codex C19 (`ao2 84621f9 feat(factory): summarize project-start
//! handoffs`) ships `ao2.factory-project-start-operator-summary.v1` —
//! a compact AO2-owned digests/links view of a completed project-start
//! handoff. The summary lets operators and Hermes hit a single AO2
//! artifact instead of chasing seven separate paths (rubric, review,
//! plan, run, bundle, bundle verifier, release-review package).
//!
//! The summary is a links view: each artifact entry carries
//! `path`/`sha256`/`expected_sha256`/`exists` (plus `status` for the
//! bundle verifier). The summary does not embed mutated copies of the
//! artifact bytes; it just pins their digests. C19 fails closed on
//! missing or digest-mismatched artifacts.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The summary declares `ao2.factory-project-start-operator-summary.v1`,
//!    `status=accepted`, `project_status=accepted`,
//!    `bundle_verification_status=accepted`, and preserves the
//!    seven-field observer-safe `trust_boundary` verbatim.
//!
//! 2. The summary lists all seven expected artifact entries
//!    (acceptance_rubric, project_acceptance_review, project_plan,
//!    project_run, project_start_bundle, project_start_bundle_verification,
//!    release_review_package), and each entry carries
//!    `path`/`sha256`/`expected_sha256` plus `exists=true`. The summary
//!    also carries the top-level `project_start` path +
//!    `project_start_sha256` digest.
//!
//! 3. **K18 digest binding**: for every artifact entry,
//!    `sha256 == expected_sha256`. The summary is a digests view, so
//!    "what we found" must equal "what the producer promised". This is
//!    the C19 fail-closed contract surfaced to observers.
//!
//! 4. The summary's `bundle_verification_status` mirrors
//!    `summary.artifacts.project_start_bundle_verification.status`
//!    field-by-field, so observers can read the K16 verdict from
//!    either site without drift.
//!
//! 5. The summary `checks` block lists all four fail-closed checks
//!    (`bundle_digest_matches`, `bundle_verification_accepted`,
//!    `project_start_accepted`, `trust_boundary_verified`) and every
//!    check is `true` for an accepted summary.
//!
//! 6. An accepted summary implies `failure_count=0` and `failures=[]`
//!    — the summary never claims `accepted` with non-empty failures.
//!
//! 7. The summary's artifact set aligns with the K10/K13/K14/K15/K16
//!    canonical surface, and each artifact entry is a links record
//!    (string `path`, hex `sha256`) — NOT a mutated or embedded copy
//!    of the artifact bytes. The Markdown sidecar must mirror the JSON
//!    summary's status and run_id so operators can read either format.

use serde_json::Value;

const SUMMARY_JSON: &str =
    include_str!("fixtures/operator-summary/factory-project-start-operator-summary.json");
const SUMMARY_MD: &str =
    include_str!("fixtures/operator-summary/factory-project-start-operator-summary.md");

fn parse(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("fixture parses as JSON")
}

#[test]
fn operator_summary_declares_schema_status_and_observer_safe_trust_boundary() {
    let s = parse(SUMMARY_JSON);

    assert_eq!(
        s["schema_version"].as_str(),
        Some("ao2.factory-project-start-operator-summary.v1"),
        "summary must declare K18 schema"
    );
    assert_eq!(
        s["status"].as_str(),
        Some("accepted"),
        "summary status must be accepted for a clean project-start"
    );
    assert_eq!(
        s["project_status"].as_str(),
        Some("accepted"),
        "summary project_status must be accepted for a clean project-start"
    );
    assert_eq!(
        s["bundle_verification_status"].as_str(),
        Some("accepted"),
        "summary bundle_verification_status must be accepted for a clean bundle"
    );
    assert!(
        s["run_id"].as_str().is_some(),
        "summary must declare a run_id"
    );

    let tb = &s["trust_boundary"];
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
fn operator_summary_lists_seven_artifacts_with_paths_and_digests() {
    let s = parse(SUMMARY_JSON);
    let artifacts = &s["artifacts"];
    assert!(
        artifacts.is_object(),
        "summary.artifacts must be a labeled object"
    );

    for required_label in [
        "acceptance_rubric",
        "project_acceptance_review",
        "project_plan",
        "project_run",
        "project_start_bundle",
        "project_start_bundle_verification",
        "release_review_package",
    ] {
        let entry = &artifacts[required_label];
        assert!(
            entry.is_object(),
            "summary.artifacts.{} must be a links record object",
            required_label
        );
        assert!(
            entry["path"].as_str().is_some(),
            "summary.artifacts.{}.path must be a string path",
            required_label
        );
        assert!(
            entry["sha256"].as_str().is_some_and(|s| s.len() == 64),
            "summary.artifacts.{}.sha256 must be a 64-hex digest",
            required_label
        );
        assert!(
            entry["expected_sha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64),
            "summary.artifacts.{}.expected_sha256 must be a 64-hex digest",
            required_label
        );
        assert_eq!(
            entry["exists"].as_bool(),
            Some(true),
            "summary.artifacts.{}.exists must be true for accepted summary",
            required_label
        );
    }

    // Top-level project_start links also belong to the summary.
    assert!(
        s["project_start"].as_str().is_some(),
        "summary.project_start must be a path"
    );
    assert!(
        s["project_start_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "summary.project_start_sha256 must be a 64-hex digest"
    );
}

#[test]
fn operator_summary_artifact_sha_equals_expected_sha_for_every_entry() {
    let s = parse(SUMMARY_JSON);
    let artifacts = s["artifacts"]
        .as_object()
        .expect("summary.artifacts is object");

    for (label, entry) in artifacts {
        let actual = entry["sha256"].as_str().expect("artifact sha256 is string");
        let expected = entry["expected_sha256"]
            .as_str()
            .expect("artifact expected_sha256 is string");
        assert_eq!(
            actual, expected,
            "summary.artifacts.{}: sha256 ({}) must equal expected_sha256 ({}) — \
             the summary is a digests view, so what we found must equal what the \
             producer promised. This is C19's fail-closed digest contract surfaced \
             to observers.",
            label, actual, expected
        );
    }
}

#[test]
fn operator_summary_bundle_verification_status_mirrors_artifact_block_status() {
    let s = parse(SUMMARY_JSON);

    let top_status = s["bundle_verification_status"]
        .as_str()
        .expect("summary.bundle_verification_status is string");
    let artifact_status = s["artifacts"]["project_start_bundle_verification"]["status"]
        .as_str()
        .expect("summary.artifacts.project_start_bundle_verification.status is string");

    assert_eq!(
        top_status, artifact_status,
        "summary.bundle_verification_status must equal \
         summary.artifacts.project_start_bundle_verification.status — observers \
         must be able to read the K16 verdict from either site without drift"
    );
    assert_eq!(
        top_status, "accepted",
        "for a clean summary, the bundle_verification_status must be accepted"
    );
}

#[test]
fn operator_summary_lists_four_fail_closed_checks_true_for_accept() {
    let s = parse(SUMMARY_JSON);
    let checks = &s["checks"];

    for required_check in [
        "bundle_digest_matches",
        "bundle_verification_accepted",
        "project_start_accepted",
        "trust_boundary_verified",
    ] {
        assert_eq!(
            checks[required_check].as_bool(),
            Some(true),
            "checks.{} must be present and true for an accepted summary \
             (fail-closed surface visible to control-plane observer)",
            required_check
        );
    }
}

#[test]
fn operator_summary_accepted_status_implies_failure_count_zero_and_failures_empty() {
    let s = parse(SUMMARY_JSON);

    assert_eq!(
        s["failure_count"].as_u64(),
        Some(0),
        "accepted summary must have failure_count=0"
    );
    let failures = s["failures"]
        .as_array()
        .expect("summary.failures must be an array even when empty");
    assert!(
        failures.is_empty(),
        "accepted summary must have failures=[], got {} entries",
        failures.len()
    );
}

#[test]
fn operator_summary_links_view_does_not_embed_artifact_bytes_and_markdown_mirrors_json() {
    let s = parse(SUMMARY_JSON);
    let artifacts = s["artifacts"]
        .as_object()
        .expect("summary.artifacts is object");

    // Links view contract: every artifact entry is a links record with
    // at most these fields (path, sha256, expected_sha256, exists,
    // status). The summary must NOT embed the artifact's bytes, parsed
    // contents, or any mutated copy. Observers can dereference paths
    // themselves but cannot consume mutated copies from the summary.
    let allowed_fields = ["path", "sha256", "expected_sha256", "exists", "status"];
    for (label, entry) in artifacts {
        let obj = entry.as_object().expect("artifact entry is object");
        for key in obj.keys() {
            assert!(
                allowed_fields.contains(&key.as_str()),
                "summary.artifacts.{} has unexpected field '{}' — summary must be a \
                 links view, not an embedded-copy view; allowed fields are \
                 path/sha256/expected_sha256/exists/status",
                label,
                key
            );
        }
    }

    // The Markdown sidecar must mirror the JSON's status and run_id so
    // operators can read either format without seeing different
    // verdicts.
    let status = s["status"].as_str().expect("summary status is string");
    let run_id = s["run_id"].as_str().expect("summary run_id is string");
    assert!(
        SUMMARY_MD.contains(&format!("status: {}", status)),
        "operator summary Markdown sidecar must mirror status={} from JSON",
        status
    );
    assert!(
        SUMMARY_MD.contains(&format!("run_id: {}", run_id)),
        "operator summary Markdown sidecar must mirror run_id={} from JSON",
        run_id
    );

    // The summary's artifact set must align with the K10/K13/K14/K15/K16
    // canonical surface — these are the labeled artifacts an observer
    // would expect to find after a full project-start handoff.
    let canonical_set = [
        ("project_start_bundle", "K10"),
        ("acceptance_rubric", "K13"),
        ("project_acceptance_review", "K14/K15"),
        ("project_start_bundle_verification", "K16/K17"),
    ];
    for (label, k_task) in canonical_set {
        assert!(
            artifacts.contains_key(label),
            "summary.artifacts must include canonical {} surface artifact '{}'",
            k_task,
            label
        );
    }
}
