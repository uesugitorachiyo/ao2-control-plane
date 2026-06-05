//! K14: Signed acceptance review observer lineage.
//!
//! Codex C15 (`850fcef feat(factory): review projects against signed rubrics`)
//! emits `ao2.factory-project-acceptance-review.v1`: an AO2-signed review
//! recommendation that applies the K13-signed acceptance rubric to a
//! project-run and produces an accept/reject recommendation for the
//! factory-v3 evaluator-closer.
//!
//! Control-plane stays read-only and proves seven things from disk:
//!
//! 1. The review carries `schema_version=ao2.factory-project-acceptance-review.v1`,
//!    `status=accepted`, `recommended_decision=accept`, and the seven-field
//!    observer-safe `trust_boundary` verbatim (control plane never accepts
//!    release; factory-v3 evaluator-closer owns acceptance).
//!
//! 2. The signature block carries `ao2.factory-project-acceptance-review-signature.v1`
//!    with `signature_status=signed`, `signature_verified=true`, RSA/SHA-256,
//!    `signed_payload="project_acceptance_review_without_signature_field"`, and
//!    recomputing `sha256(bundled signed-payload bytes) ==
//!    signature.signed_payload_sha256` proves the signed payload bytes match
//!    what the signature pins (tamper detection).
//!
//! 3. **K13 → K14 lineage cross-check**: `sha256(bundled rubric bytes) ==
//!    review.rubric_sha256 == review.rubric.sha256 ==
//!    plan.acceptance_rubric_sha256 (top-level) == every
//!    plan.app_steps[i].acceptance_rubric_sha256`. This is the strongest
//!    binding in the K-series: the review provably applies the same rubric
//!    bytes that K13 tested.
//!
//! 4. **Project-run digest binding**: `sha256(bundled project-run bytes) ==
//!    review.project_run_sha256` and the review's `artifacts.project_run`
//!    path matches `review.project_run` (the review reads the same
//!    project-run bytes the closer would replay).
//!
//! 5. `must_have_artifacts_present=true` with empty `missing_artifacts`, and
//!    the `artifacts` block names `acceptance_rubric`, `project_run`,
//!    `release_review_package`, and `review` (the four artifacts the closer
//!    needs to audit a recommendation).
//!
//! 6. `thresholds.failed_step_count=0`, `release_review_package_ready=true`,
//!    `release_review_ready=true`, `thresholds_satisfied=true`, and
//!    `blockers=[]` (fail-closed gates all green for an `accept`
//!    recommendation).
//!
//! 7. The embedded `rubric` block declares
//!    `schema_version=ao2.factory-acceptance-rubric-validation.v1` referencing
//!    K13's `rubric_schema=ao2.factory-acceptance-rubric.v1`, with
//!    `accepted=true`, `signature_status=signed`, and `signature_verified=true`
//!    — the review propagates the K13 signed-rubric verification verdict
//!    forward into the acceptance recommendation.

use serde_json::Value;
use sha2::{Digest, Sha256};

const REVIEW_JSON: &str =
    include_str!("fixtures/project-acceptance-review/factory-project-acceptance-review.json");
const REVIEW_SIGNED_PAYLOAD_JSON: &str = include_str!(
    "fixtures/project-acceptance-review/factory-project-acceptance-review.signed-payload.json"
);
const RUBRIC_JSON: &str = include_str!(
    "fixtures/project-acceptance-review/missed-call-recovery-project-acceptance-rubric.json"
);
const PROJECT_PLAN_JSON: &str =
    include_str!("fixtures/project-acceptance-review/missed-call-recovery-project-plan.json");
const PROJECT_RUN_JSON: &str =
    include_str!("fixtures/project-acceptance-review/factory-project-run.json");

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
fn review_declares_schema_status_decision_and_observer_safe_trust_boundary() {
    let review = parse(REVIEW_JSON);
    assert_eq!(
        review["schema_version"].as_str(),
        Some("ao2.factory-project-acceptance-review.v1"),
        "K14 schema must be ao2.factory-project-acceptance-review.v1"
    );
    assert_eq!(review["status"].as_str(), Some("accepted"));
    assert_eq!(review["recommended_decision"].as_str(), Some("accept"));
    assert_eq!(review["must_have_artifacts_present"].as_bool(), Some(true));
    assert_eq!(review["thresholds_satisfied"].as_bool(), Some(true));
    assert!(
        review["blockers"].as_array().unwrap().is_empty(),
        "blockers must be empty for an accept recommendation"
    );
    assert!(
        review["missing_artifacts"].as_array().unwrap().is_empty(),
        "missing_artifacts must be empty for must_have_artifacts_present=true"
    );

    let tb = &review["trust_boundary"];
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
    assert!(
        review.get("created_at").is_some(),
        "review must carry created_at"
    );
}

#[test]
fn review_signature_block_is_signed_verified_and_pins_signed_payload_digest() {
    let review = parse(REVIEW_JSON);
    let sig = &review["signature"];
    assert_eq!(
        sig["schema_version"].as_str(),
        Some("ao2.factory-project-acceptance-review-signature.v1"),
        "signature block must declare K14 signature schema"
    );
    assert_eq!(sig["signature_status"].as_str(), Some("signed"));
    assert_eq!(sig["signature_verified"].as_bool(), Some(true));
    assert_eq!(sig["signature_algorithm"].as_str(), Some("RSA/SHA-256"));
    assert_eq!(
        sig["signed_payload"].as_str(),
        Some("project_acceptance_review_without_signature_field"),
        "signed payload pattern must match K13 (signature field stripped before signing)"
    );
    assert!(
        sig.get("signer_id").is_some(),
        "signature must name signer_id"
    );
    assert!(
        sig.get("public_key_sha256").is_some(),
        "signature must pin public_key_sha256 so CP can detect key swap"
    );
    assert!(
        sig.get("signature_sha256").is_some(),
        "signature must pin signature_sha256 for tamper detection on .sig file"
    );

    let pinned_payload_sha = sig["signed_payload_sha256"]
        .as_str()
        .expect("signed_payload_sha256 must be a hex string");
    let recomputed = hex_sha256(REVIEW_SIGNED_PAYLOAD_JSON.as_bytes());
    assert_eq!(
        recomputed, pinned_payload_sha,
        "sha256(bundled signed-payload bytes) must equal signature.signed_payload_sha256 — tamper detection on signed payload"
    );

    // Cross-check: the signed-payload file is the review JSON with the signature
    // field stripped. Every other top-level key must agree byte-equivalently
    // between review.json and signed-payload.json.
    let payload = parse(REVIEW_SIGNED_PAYLOAD_JSON);
    assert!(
        payload.get("signature").is_none(),
        "signed-payload must not carry the signature field (signing input)"
    );
    for key in [
        "schema_version",
        "status",
        "recommended_decision",
        "rubric_sha256",
        "project_run_sha256",
        "must_have_artifacts_present",
        "thresholds_satisfied",
    ] {
        assert_eq!(
            payload[key], review[key],
            "signed-payload key {key} must equal review key (signature is the only delta)"
        );
    }
}

#[test]
fn review_rubric_digest_proves_k13_to_k14_lineage() {
    let review = parse(REVIEW_JSON);
    let plan = parse(PROJECT_PLAN_JSON);

    // Anchor: hash the bundled rubric bytes ourselves.
    let bundled_rubric_sha = hex_sha256(RUBRIC_JSON.as_bytes());
    let pinned_top_level = review["rubric_sha256"].as_str().unwrap();
    let pinned_inner = review["rubric"]["sha256"].as_str().unwrap();

    assert_eq!(
        bundled_rubric_sha, pinned_top_level,
        "sha256(bundled rubric) must equal review.rubric_sha256"
    );
    assert_eq!(
        pinned_inner, pinned_top_level,
        "review.rubric.sha256 must equal review.rubric_sha256 (intra-envelope agreement)"
    );

    // K13 → K14 cross-binding: project-plan top-level rubric digest must match.
    let plan_top = plan["acceptance_rubric_sha256"].as_str().unwrap();
    assert_eq!(
        plan_top, pinned_top_level,
        "K13 lineage: plan.acceptance_rubric_sha256 must equal review.rubric_sha256 — review applies same rubric bytes K13 tested"
    );

    // K13 → K14 cross-binding: every app_step's rubric digest must match.
    let app_steps = plan["app_steps"].as_array().unwrap();
    assert!(
        !app_steps.is_empty(),
        "plan must have at least one app step bound to the rubric"
    );
    for (i, step) in app_steps.iter().enumerate() {
        let step_sha = step["acceptance_rubric_sha256"]
            .as_str()
            .unwrap_or_else(|| panic!("plan.app_steps[{i}].acceptance_rubric_sha256 missing"));
        assert_eq!(
            step_sha, pinned_top_level,
            "plan.app_steps[{i}].acceptance_rubric_sha256 must equal review.rubric_sha256"
        );
    }

    // The review's rubric.path basename must point at an acceptance rubric file
    // (not a swapped artifact), and the rubric.rubric_schema must point back at
    // K13's schema.
    assert_eq!(
        review["rubric"]["rubric_schema"].as_str(),
        Some("ao2.factory-acceptance-rubric.v1"),
        "review.rubric.rubric_schema must reference K13's rubric schema"
    );
    let rubric_path = review["rubric"]["path"].as_str().unwrap();
    assert!(
        rubric_path.contains("acceptance-rubric"),
        "review.rubric.path must reference an acceptance-rubric file (saw {rubric_path})"
    );
}

#[test]
fn review_project_run_digest_pins_run_bytes_and_artifact_path_agreement() {
    let review = parse(REVIEW_JSON);

    let bundled_run_sha = hex_sha256(PROJECT_RUN_JSON.as_bytes());
    let pinned_run_sha = review["project_run_sha256"].as_str().unwrap();
    assert_eq!(
        bundled_run_sha, pinned_run_sha,
        "sha256(bundled project-run bytes) must equal review.project_run_sha256"
    );

    // The review names project_run in two places: the top-level path and the
    // artifacts.project_run path. They must agree so the closer cannot be
    // pointed at a different file than the one whose digest was pinned.
    let top = review["project_run"].as_str().unwrap();
    let in_artifacts = review["artifacts"]["project_run"].as_str().unwrap();
    assert_eq!(
        top, in_artifacts,
        "review.project_run must equal review.artifacts.project_run"
    );
}

#[test]
fn review_lists_must_have_artifacts_for_closer_audit_replay() {
    let review = parse(REVIEW_JSON);
    let artifacts = &review["artifacts"];
    for required in [
        "acceptance_rubric",
        "project_run",
        "release_review_package",
        "review",
    ] {
        let v = artifacts[required]
            .as_str()
            .unwrap_or_else(|| panic!("review.artifacts.{required} must be a path string"));
        assert!(
            !v.is_empty(),
            "review.artifacts.{required} must be non-empty"
        );
    }

    // The self-referential artifacts.review field must end in the review filename
    // so the closer knows where to find the review it just signed.
    let self_ref = review["artifacts"]["review"].as_str().unwrap();
    assert!(
        self_ref.ends_with("factory-project-acceptance-review.json"),
        "review.artifacts.review must self-reference the review JSON"
    );

    // Release-review package must be a packaged artifact (e.g. .tgz) so the
    // closer can replay deterministically.
    let pkg = review["artifacts"]["release_review_package"]
        .as_str()
        .unwrap();
    assert!(
        pkg.ends_with(".tgz") || pkg.ends_with(".tar.gz"),
        "release_review_package must point at a packaged archive (saw {pkg})"
    );
}

#[test]
fn review_thresholds_are_fail_closed_for_accept_recommendation() {
    let review = parse(REVIEW_JSON);
    let t = &review["thresholds"];

    // failed_step_count is the fail-closed step gate — must be 0 for accept.
    assert_eq!(
        t["failed_step_count"].as_i64(),
        Some(0),
        "thresholds.failed_step_count must be 0 for accept recommendation"
    );

    // release_review_ready and release_review_package_ready are the closure
    // gates — both must be true so the closer has a packaged review to sign.
    assert_eq!(
        t["release_review_ready"].as_bool(),
        Some(true),
        "thresholds.release_review_ready must be true"
    );
    assert_eq!(
        t["release_review_package_ready"].as_bool(),
        Some(true),
        "thresholds.release_review_package_ready must be true"
    );

    // Top-level thresholds_satisfied must agree with the threshold contents.
    assert_eq!(review["thresholds_satisfied"].as_bool(), Some(true));

    // Recommended decision and status must be consistent.
    assert_eq!(review["status"].as_str(), Some("accepted"));
    assert_eq!(review["recommended_decision"].as_str(), Some("accept"));
}

#[test]
fn review_embeds_k13_rubric_verification_verdict_and_propagates_signed_status() {
    // The review's embedded `rubric` block is the K13 validation envelope
    // carried forward. K14's job is to propagate that signed verdict — it
    // must declare K13's schema family, signature_status=signed,
    // signature_verified=true, accepted=true, and the same sha256 we
    // independently recomputed.
    let review = parse(REVIEW_JSON);
    let r = &review["rubric"];

    assert_eq!(
        r["schema_version"].as_str(),
        Some("ao2.factory-acceptance-rubric-validation.v1"),
        "embedded rubric block must be the rubric-validation schema"
    );
    assert_eq!(
        r["rubric_schema"].as_str(),
        Some("ao2.factory-acceptance-rubric.v1"),
        "embedded rubric.rubric_schema must reference K13's rubric schema"
    );
    assert_eq!(
        r["accepted"].as_bool(),
        Some(true),
        "rubric must be accepted for review to recommend accept"
    );
    assert_eq!(r["signature_status"].as_str(), Some("signed"));
    assert_eq!(r["signature_verified"].as_bool(), Some(true));
    assert!(
        r["blockers"].as_array().unwrap().is_empty(),
        "rubric.blockers must be empty for accepted=true"
    );
}
