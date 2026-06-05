//! K11 follow-up to BOARD.md Claude lane: prove the control-plane observer
//! can read C12 Hermes-queue handoff envelopes. C12 introduces a new
//! `hermes_queue_handoff` block inside `factory-project-start.json` that
//! declares schema `ao2.hermes-project-start-handoff.v1` and pins the C11
//! project-start-bundle archive by sha256 — so Hermes/queue surface,
//! ao2-control-plane, and factory-v3 evaluator-closer can all reference the
//! same canonical greenfield artifact without scraping a run directory.
//!
//! K11 distinctive cross-binding:
//!   factory-project-start.hermes_queue_handoff.project_start_bundle_sha256
//!     == factory-project-start.artifacts.project_start_bundle_sha256
//!     == factory-project-start-bundle.sha256
//!     == factory-project-start.project_start_bundle.sha256
//!
//! All four sites must agree on the outer-tarball digest. If a malicious AO2
//! swaps any one site, CP detects it. The outer tarball bytes are not
//! embedded (they're binary), but the four redundant text-side claims are
//! enough to catch text-side tamper.
//!
//! K11 also asserts that the role wording inside `hermes_queue_handoff` is
//! observer-safe verbatim: hermes_role="front_end_queue_cron_memory_bookkeeping_only",
//! ao2_role="canonical_project_start_and_evidence_producer",
//! status="ready", plus the standard 5 trust-boundary fields.
//!
//! Fixture origin: ao2 commit `6cbaa5a` factory-project-run-smoke root
//! `20260528T062207Z`.

use sha2::Digest;

const HERMES_PROJECT_START: &str =
    include_str!("fixtures/hermes-project-start-handoff/factory-project-start.json");
const HERMES_BUNDLE_REPORT: &str =
    include_str!("fixtures/hermes-project-start-handoff/factory-project-start-bundle.json");

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn hermes_queue_handoff_block_declares_schema_and_observer_safe_roles() {
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");

    let h = &start["hermes_queue_handoff"];
    assert_eq!(
        h["schema_version"], "ao2.hermes-project-start-handoff.v1",
        "C12 introduces the hermes-project-start-handoff schema inside the project-start envelope"
    );
    assert_eq!(
        h["status"], "ready",
        "C12 marks the Hermes-queue handoff as ready once the bundle is bundled"
    );

    // The role wording must be observer-safe verbatim. A malicious AO2 must
    // not be able to relabel Hermes as a producer or CP as approver.
    assert_eq!(
        h["hermes_role"], "front_end_queue_cron_memory_bookkeeping_only",
        "Hermes role must stay observer-safe — front end, queue, cron, memory only"
    );
    assert_eq!(
        h["ao2_role"], "canonical_project_start_and_evidence_producer",
        "AO2 role must stay canonical producer"
    );

    // Standard trust-boundary fields must hold here too — Hermes-queue
    // handoff cannot drift from the bundle/manifest/handoff trust block.
    assert_eq!(h["control_plane_approves_release"], false);
    assert_eq!(h["mutates_ao_artifacts"], false);
    assert_eq!(
        h["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(h["factory_v3_role"], "parity_oracle_only");
    assert_eq!(h["release_acceptance_owner"], "factory-v3 evaluator-closer");

    // Bundle entry-point references — what Hermes/queue consumers must use
    // to extract bundle contents — must match the K10 bundle layout. If C12
    // diverges from K10, the queue surface and CP would disagree on entry
    // point names.
    assert_eq!(h["handoff_entry"], "handoff.json");
    assert_eq!(h["manifest_entry"], "manifest.json");
    assert_eq!(h["checksum_entry"], "SHA256SUMS");
}

#[test]
fn hermes_queue_handoff_bundle_sha256_agrees_with_bundle_report() {
    // The K11 strongest cross-check: four text-side fields all carry the
    // same outer-tarball digest. CP can detect a malicious swap on any one
    // site by comparing to the other three.
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let report: serde_json::Value = serde_json::from_str(HERMES_BUNDLE_REPORT)
        .expect("factory-project-start-bundle.json must parse");

    let h = &start["hermes_queue_handoff"];
    let from_hermes_block = h["project_start_bundle_sha256"]
        .as_str()
        .expect("hermes_queue_handoff.project_start_bundle_sha256 missing");
    let from_artifacts = start["artifacts"]["project_start_bundle_sha256"]
        .as_str()
        .expect("artifacts.project_start_bundle_sha256 missing");
    let from_inline_bundle = start["project_start_bundle"]["sha256"]
        .as_str()
        .expect("project_start_bundle.sha256 missing");
    let from_report = report["sha256"]
        .as_str()
        .expect("factory-project-start-bundle.sha256 missing");

    assert_eq!(
        from_hermes_block, from_artifacts,
        "hermes_queue_handoff.project_start_bundle_sha256 ({from_hermes_block}) disagrees with artifacts.project_start_bundle_sha256 ({from_artifacts})"
    );
    assert_eq!(
        from_hermes_block, from_inline_bundle,
        "hermes_queue_handoff.project_start_bundle_sha256 disagrees with project_start_bundle.sha256"
    );
    assert_eq!(
        from_hermes_block, from_report,
        "hermes_queue_handoff.project_start_bundle_sha256 disagrees with factory-project-start-bundle.sha256"
    );

    // The bundle path string the four sites carry must also agree.
    let hermes_path = h["project_start_bundle"].as_str().expect("hermes path");
    let artifacts_path = start["artifacts"]["project_start_bundle"]
        .as_str()
        .expect("artifacts path");
    let inline_path = start["project_start_bundle"]["archive"]
        .as_str()
        .expect("inline archive path");
    let report_path = report["archive"].as_str().expect("report archive path");
    assert_eq!(hermes_path, artifacts_path);
    assert_eq!(hermes_path, inline_path);
    assert_eq!(hermes_path, report_path);
}

#[test]
fn hermes_queue_handoff_inline_bundle_index_agrees_with_bundle_report() {
    // Beyond the outer-tarball digest, factory-project-start.json carries a
    // full inline copy of the bundle index under project_start_bundle.
    // K11 asserts artifact_count agrees and every (bundle_path, sha256,
    // size_bytes) tuple matches between the inline copy and the bundle
    // report — so CP can audit the bundle index without re-reading the
    // bundle report file from disk.
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let report: serde_json::Value = serde_json::from_str(HERMES_BUNDLE_REPORT)
        .expect("factory-project-start-bundle.json must parse");

    let inline = &start["project_start_bundle"];
    assert_eq!(
        inline["schema_version"], "ao2.factory-project-start-bundle.v1",
        "inline bundle index declares the K10 bundle schema"
    );
    assert_eq!(inline["artifact_count"], report["artifact_count"]);
    assert_eq!(
        inline["artifact_count"], 8,
        "C12 inline bundle index must report 8 artifacts (same as K10)"
    );

    let inline_artifacts = inline["artifacts"].as_array().expect("inline artifacts");
    let report_artifacts = report["artifacts"].as_array().expect("report artifacts");
    assert_eq!(inline_artifacts.len(), report_artifacts.len());

    for (i, (a, b)) in inline_artifacts.iter().zip(report_artifacts).enumerate() {
        assert_eq!(
            a["bundle_path"], b["bundle_path"],
            "artifact[{i}] bundle_path drift between inline and report"
        );
        assert_eq!(
            a["sha256"], b["sha256"],
            "artifact[{i}] sha256 drift between inline and report"
        );
        assert_eq!(
            a["size_bytes"], b["size_bytes"],
            "artifact[{i}] size_bytes drift between inline and report"
        );
    }
}

#[test]
fn hermes_queue_handoff_envelope_preserves_factory_replacement_boundary() {
    // Bundle report and project-start envelope must both carry the bundle-
    // level trust boundary verbatim. C12 added the hermes_queue_handoff
    // block but must not have softened the K10/K3-K9 boundary.
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let report: serde_json::Value = serde_json::from_str(HERMES_BUNDLE_REPORT)
        .expect("factory-project-start-bundle.json must parse");

    let frb = &start["factory_replacement_boundary"];
    assert_eq!(frb["control_plane_approves_release"], false);
    assert_eq!(frb["mutates_ao_artifacts"], false);
    assert_eq!(frb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(frb["factory_v3_drives_workflow"], false);
    assert_eq!(
        frb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        frb["ao2_execution_owner"], true,
        "factory-project-start.json must affirm AO2 execution ownership"
    );
    assert_eq!(
        frb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );

    let tb = &report["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"], false);
    assert_eq!(tb["mutates_ao_artifacts"], false);
    assert_eq!(
        tb["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(
        tb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(tb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(tb["execution_owner"], "ao2");
    assert_eq!(
        tb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );
}

#[test]
fn hermes_queue_handoff_artifact_sha256_pins_k10_lineage_chain() {
    // C12's factory-project-start envelope carries explicit sha256 fields
    // for every K3-K10 lineage anchor: project_plan, project_plan_validation,
    // factory_project_run, factory_project_run_state, release_review_package,
    // and the two app-run-bundles. K11 asserts each of these digests equals
    // the corresponding bundle-report artifact sha256 — so CP can pin the
    // K3-K10 inner-tarball lineage to the C12 Hermes-queue surface without
    // re-reading the bundle report.
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let report: serde_json::Value = serde_json::from_str(HERMES_BUNDLE_REPORT)
        .expect("factory-project-start-bundle.json must parse");

    let artifacts = &start["artifacts"];
    let report_artifacts = report["artifacts"].as_array().expect("report artifacts");

    let by_bundle_path = |path: &str| {
        report_artifacts
            .iter()
            .find(|a| a["bundle_path"].as_str() == Some(path))
            .unwrap_or_else(|| panic!("bundle report missing {path}"))
    };

    assert_eq!(
        artifacts["project_plan_sha256"],
        by_bundle_path("project-plan/project-plan.json")["sha256"],
        "K11: project_plan_sha256 must pin the K9 plan bytes in the bundle"
    );
    assert_eq!(
        artifacts["project_plan_validation_sha256"],
        by_bundle_path("project-plan/project-plan-validation.json")["sha256"],
        "K11: project_plan_validation_sha256 must pin the K10 validation bytes"
    );
    assert_eq!(
        artifacts["factory_project_run_sha256"],
        by_bundle_path("project-run/factory-project-run.json")["sha256"],
        "K11: factory_project_run_sha256 must pin the K6/K7 run bytes"
    );
    assert_eq!(
        artifacts["factory_project_run_state_sha256"],
        by_bundle_path("project-run/factory-project-run-state.json")["sha256"],
        "K11: factory_project_run_state_sha256 must pin the K8 run-state bytes"
    );
    assert_eq!(
        artifacts["release_review_package_sha256"],
        by_bundle_path("release-review/release-review-package.tgz")["sha256"],
        "K11: release_review_package_sha256 must pin the K4/K6 release-review tarball"
    );

    // Each app-run-bundle sha256 in artifacts.app_run_bundles[] must pin the
    // K3/K5 evidence bundle by index.
    let app_run_bundles = artifacts["app_run_bundles"]
        .as_array()
        .expect("artifacts.app_run_bundles");
    assert_eq!(
        app_run_bundles.len(),
        2,
        "C12 missed-call dogfood emits exactly 2 app-run bundles"
    );
    for (i, arb) in app_run_bundles.iter().enumerate() {
        let claimed = arb["bundle_sha256"]
            .as_str()
            .expect("artifacts.app_run_bundles[].bundle_sha256 missing");
        let expected_path = format!("app-run-bundles/{i}/app-run-evidence-bundle.tgz");
        let expected = by_bundle_path(&expected_path)["sha256"]
            .as_str()
            .expect("bundle report sha256 missing");
        assert_eq!(
            claimed, expected,
            "K11: artifacts.app_run_bundles[{i}].bundle_sha256 must pin the bundled tarball sha256"
        );
        // app-run-bundle index agrees with array position too.
        assert_eq!(
            arb["index"], i,
            "artifacts.app_run_bundles[{i}].index must equal array position"
        );
    }
}

#[test]
fn hermes_queue_handoff_checks_match_k10_handoff_envelope() {
    // C12's factory-project-start.json carries the same `checks` block the
    // C11 handoff.json carries. K11 asserts the four upstream layer
    // statuses match the K10-tested handoff schema: plan/validation/run
    // "accepted" and release_review_package_ready true. If C12 silently
    // drops a check or relaxes a status, this test catches it.
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let checks = &start["checks"];
    assert_eq!(checks["project_plan_status"], "accepted");
    assert_eq!(checks["project_plan_validation_status"], "accepted");
    assert_eq!(checks["project_run_status"], "accepted");
    assert_eq!(checks["release_review_package_ready"], true);

    // The factory-project-start envelope itself must carry a status of
    // accepted with the run failures count at zero — Hermes-queue handoff
    // should never advertise a failed start as "ready".
    assert_eq!(start["failed_step_count"], 0);
    assert_eq!(start["app_run_count"], 2);

    // Cross-check the embedded ao2.hermes-project-start-handoff.v1 status
    // is "ready" only when the upstream layers are all accepted — this is
    // the invariant that lets CP trust the Hermes-queue surface to gate on.
    let hermes_status = start["hermes_queue_handoff"]["status"].as_str();
    let all_accepted = checks["project_plan_status"] == "accepted"
        && checks["project_plan_validation_status"] == "accepted"
        && checks["project_run_status"] == "accepted"
        && checks["release_review_package_ready"] == true;
    assert!(
        all_accepted && hermes_status == Some("ready"),
        "hermes_queue_handoff.status='ready' must coincide with all four upstream checks accepted"
    );
}

#[test]
fn hermes_queue_handoff_bundle_report_artifact_count_matches_inline_artifacts_array() {
    // Bundle report and inline factory-project-start.project_start_bundle
    // must agree on artifact_count, and that count must equal the actual
    // length of the artifacts array on both sides. Catches a malicious AO2
    // that lies about artifact_count while leaving the array intact (or
    // vice versa).
    let start: serde_json::Value =
        serde_json::from_str(HERMES_PROJECT_START).expect("factory-project-start.json must parse");
    let report: serde_json::Value = serde_json::from_str(HERMES_BUNDLE_REPORT)
        .expect("factory-project-start-bundle.json must parse");

    let inline_count = start["project_start_bundle"]["artifact_count"]
        .as_u64()
        .expect("inline artifact_count");
    let report_count = report["artifact_count"]
        .as_u64()
        .expect("report artifact_count");
    let inline_array_len = start["project_start_bundle"]["artifacts"]
        .as_array()
        .expect("inline artifacts array")
        .len() as u64;
    let report_array_len = report["artifacts"]
        .as_array()
        .expect("report artifacts array")
        .len() as u64;

    assert_eq!(inline_count, report_count);
    assert_eq!(inline_count, inline_array_len);
    assert_eq!(report_count, report_array_len);

    // hex_sha256 of the bundle-report bytes must be deterministic — sanity
    // check that the helper is wired up. (We can't recompute the outer
    // tarball sha256 because the tarball is binary and not embedded.)
    let report_self_sha = hex_sha256(HERMES_BUNDLE_REPORT.as_bytes());
    assert_eq!(
        report_self_sha.len(),
        64,
        "sha256 hex string must be 64 chars"
    );
}
