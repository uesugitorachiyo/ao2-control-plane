//! K10 follow-up to BOARD.md Claude lane: prove the control-plane observer
//! can read C11 project-start handoff bundles (`ao2 factory project-start-bundle`).
//! The handoff bundle is the portable artifact that Hermes, factory-v3
//! evaluator-closer, and ao2-control-plane consume instead of scraping a run
//! directory.
//!
//! C11 introduces three new schemas observable through CP:
//!
//! - `ao2.factory-project-start-bundle.v1` on `manifest.json` — top-level
//!   index over the bundled artifacts plus a `source_project_start` pointer
//!   and a top-level `trust_boundary` block.
//! - `ao2.factory-project-start-handoff.v1` on `handoff.json` — the bundle's
//!   own envelope carrying `status`, `run_id`, `artifact_count`, a `checks`
//!   block, and the same `source_project_start` field as the manifest.
//! - `ao2.factory-project-plan-validation.v1` on
//!   `project-plan/project-plan-validation.json` — C8's validation report
//!   pinned to the bundled plan via `project_plan_sha256`.
//!
//! The K10 cross-checks are the bindings that make CP an effective observer:
//! validation→plan, manifest→handoff, manifest→bundled bytes, and the
//! bundle-level trust_boundary. The nested release-review-package.tgz and
//! app-run-bundle tgzs are intentionally not embedded — their integrity is
//! covered by their own sha256 in manifest+SHA256SUMS, and the K6/K7/K8/K9
//! tests already cover the release-review-package's internal lineage.
//!
//! Fixture origin: ao2 commit `c5caa01` factory-project-run-smoke
//! `20260528T060211Z/project-start-handoff.tgz`.

use sha2::Digest;
use std::collections::HashMap;

const BUNDLE_MANIFEST: &str = include_str!("fixtures/project-start-handoff-bundle/manifest.json");
const BUNDLE_SHA256SUMS: &str = include_str!("fixtures/project-start-handoff-bundle/SHA256SUMS");
const BUNDLE_HANDOFF: &str = include_str!("fixtures/project-start-handoff-bundle/handoff.json");
const BUNDLE_PROJECT_START: &str =
    include_str!("fixtures/project-start-handoff-bundle/factory-project-start.json");
const BUNDLE_PROJECT_PLAN: &str =
    include_str!("fixtures/project-start-handoff-bundle/project-plan/project-plan.json");
const BUNDLE_PROJECT_PLAN_VALIDATION: &str =
    include_str!("fixtures/project-start-handoff-bundle/project-plan/project-plan-validation.json");
const BUNDLE_PROJECT_RUN: &str =
    include_str!("fixtures/project-start-handoff-bundle/project-run/factory-project-run.json");
const BUNDLE_PROJECT_RUN_STATE: &str = include_str!(
    "fixtures/project-start-handoff-bundle/project-run/factory-project-run-state.json"
);

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_sha256sums(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let sha = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").trim().to_string();
        if !sha.is_empty() && !path.is_empty() {
            map.insert(path, sha);
        }
    }
    map
}

#[test]
fn handoff_bundle_manifest_schema_and_trust_boundary_are_observer_safe() {
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-project-start-bundle.v1",
        "C11 handoff bundle manifest declares the project-start-bundle schema"
    );
    assert_eq!(
        manifest["artifact_count"], 8,
        "C11 manifest must report 8 artifacts: project-start.json + plan + validation + run + run-state + release-review-package + 2 app-run-bundles"
    );
    assert!(
        manifest["source_project_start"].as_str().is_some(),
        "C11 manifest must declare the source project-start path so CP can attribute the bundle"
    );

    let tb = &manifest["trust_boundary"];
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
fn handoff_envelope_agrees_with_manifest_on_source_and_artifact_count() {
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    let handoff: serde_json::Value =
        serde_json::from_str(BUNDLE_HANDOFF).expect("handoff.json must parse");

    assert_eq!(
        handoff["schema_version"], "ao2.factory-project-start-handoff.v1",
        "C11 handoff envelope declares its own handoff schema, distinct from the manifest"
    );
    assert_eq!(
        handoff["status"], "accepted",
        "C11 handoff envelope publishes the final accept/reject signal"
    );

    // Both the manifest and the handoff envelope must point at the same
    // upstream project-start; otherwise the bundle is internally inconsistent
    // and CP cannot trust either as the source of truth.
    assert_eq!(
        manifest["source_project_start"], handoff["source_project_start"],
        "manifest.source_project_start and handoff.source_project_start must agree"
    );
    assert_eq!(
        manifest["artifact_count"], handoff["artifact_count"],
        "manifest.artifact_count and handoff.artifact_count must agree"
    );

    // The handoff's checks must echo accepted upstream status from each
    // producer layer — plan validation (C8), plan generation (C7), project
    // run (C5/C6), and release-review packaging (C2/C4). If any one is not
    // accepted, CP must see it via handoff.status != "accepted" or via
    // checks[<key>] not being "accepted"/true.
    let checks = &handoff["checks"];
    assert_eq!(checks["project_plan_status"], "accepted");
    assert_eq!(checks["project_plan_validation_status"], "accepted");
    assert_eq!(checks["project_run_status"], "accepted");
    assert_eq!(checks["release_review_package_ready"], true);
}

#[test]
fn handoff_bundle_sha256sums_match_manifest_and_bundled_text_artifacts() {
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    let sums = parse_sha256sums(BUNDLE_SHA256SUMS);

    // SHA256SUMS must self-cover manifest.json plus every manifest.files[]
    // entry. The release-review-package.tgz path and app-run-bundle.tgz paths
    // must be present even though their bytes are not bundled here — the
    // outer K6-K9 chain already validates those tarballs internally.
    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
    for entry in manifest["files"].as_array().expect("manifest.files") {
        let path = entry["path"].as_str().unwrap();
        let claimed = entry["sha256"].as_str().unwrap();
        let sums_sha = sums
            .get(path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing path {path}"));
        assert_eq!(
            sums_sha, claimed,
            "SHA256SUMS disagrees with manifest.files[] for {path}"
        );
    }

    // For the 7 bundled text artifacts whose bytes are embedded as fixtures,
    // recomputed sha256 must equal the manifest's claim. The 2 nested
    // app-run-bundles + the release-review-package tarball aren't embedded;
    // their bytes are validated transitively when consumers re-extract them.
    let mut bundled: HashMap<&str, String> = HashMap::new();
    bundled.insert(
        "factory-project-start.json",
        hex_sha256(BUNDLE_PROJECT_START.as_bytes()),
    );
    bundled.insert(
        "project-plan/project-plan.json",
        hex_sha256(BUNDLE_PROJECT_PLAN.as_bytes()),
    );
    bundled.insert(
        "project-plan/project-plan-validation.json",
        hex_sha256(BUNDLE_PROJECT_PLAN_VALIDATION.as_bytes()),
    );
    bundled.insert(
        "project-run/factory-project-run.json",
        hex_sha256(BUNDLE_PROJECT_RUN.as_bytes()),
    );
    bundled.insert(
        "project-run/factory-project-run-state.json",
        hex_sha256(BUNDLE_PROJECT_RUN_STATE.as_bytes()),
    );
    bundled.insert("handoff.json", hex_sha256(BUNDLE_HANDOFF.as_bytes()));

    let mut matched = 0;
    for entry in manifest["files"].as_array().expect("manifest.files") {
        let path = entry["path"].as_str().unwrap();
        if let Some(computed) = bundled.get(path) {
            let claimed = entry["sha256"].as_str().unwrap();
            assert_eq!(
                claimed, computed,
                "manifest sha256 for {path} drifted from bundled bytes"
            );
            matched += 1;
        }
    }
    assert_eq!(
        matched,
        bundled.len(),
        "expected to match all 6 embedded text fixtures against manifest.files[]"
    );
}

#[test]
fn handoff_bundle_validation_report_binds_to_bundled_plan_via_project_plan_sha256() {
    // The K10 strongest cross-binding: the C8 validation report's
    // project_plan_sha256 field is the cryptographic link between
    // "validation says accepted" and "the bytes that were validated". CP
    // must be able to re-verify that link without trusting the bundle's
    // own manifest — i.e., we recompute the sha256 of the bundled plan
    // bytes locally and compare to validation.project_plan_sha256.
    let validation: serde_json::Value = serde_json::from_str(BUNDLE_PROJECT_PLAN_VALIDATION)
        .expect("project-plan-validation.json must parse");
    assert_eq!(
        validation["schema_version"], "ao2.factory-project-plan-validation.v1",
        "C8 validation report declares its own validation schema"
    );
    assert_eq!(
        validation["status"], "accepted",
        "C11 only bundles validation reports that passed the C8 fail-closed gate"
    );

    let claimed = validation["project_plan_sha256"]
        .as_str()
        .expect("C8 validation must declare project_plan_sha256");
    let computed = hex_sha256(BUNDLE_PROJECT_PLAN.as_bytes());
    assert_eq!(
        claimed, computed,
        "C8 validation.project_plan_sha256 ({claimed}) is not the sha256 of the bundled plan bytes ({computed}); validation→plan binding broken"
    );

    // The manifest's sha256 for the plan path must also equal that value —
    // completing the three-way binding plan bytes <-> validation report <->
    // bundle manifest. A malicious AO2 cannot swap any one side without
    // tripping at least one of these checks.
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    let plan_manifest_entry = manifest["files"]
        .as_array()
        .expect("manifest.files")
        .iter()
        .find(|f| f["path"] == "project-plan/project-plan.json")
        .expect("manifest must list project-plan/project-plan.json");
    assert_eq!(
        plan_manifest_entry["sha256"], claimed,
        "manifest sha256 for the bundled plan must equal C8's project_plan_sha256"
    );

    // Validation also carries its own trust_boundary — observer-only
    // signals must hold there too, otherwise a malicious validator could
    // sign off on a plan and claim CP approved the release.
    let tb = &validation["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"], false);
    assert_eq!(tb["mutates_ao_artifacts"], false);
    assert_eq!(
        tb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
}

#[test]
fn handoff_bundle_run_state_and_envelope_agree_with_release_review_chain() {
    // C11 bundles the C6 project-run-state.json and the C4/C5 project-run.json
    // envelope alongside the plan + validation. K10 cross-checks that the
    // run-state and envelope agree on schema, status, and run_id — proving
    // the handoff bundle didn't pick mismatched artifacts from different runs.
    let run: serde_json::Value =
        serde_json::from_str(BUNDLE_PROJECT_RUN).expect("project-run.json must parse");
    let state: serde_json::Value =
        serde_json::from_str(BUNDLE_PROJECT_RUN_STATE).expect("run-state must parse");

    assert_eq!(
        run["schema_version"], "ao2.factory-project-run.v1",
        "bundled run envelope schema"
    );
    assert_eq!(
        state["schema_version"], "ao2.factory-project-run-state.v1",
        "bundled run-state schema"
    );
    assert_eq!(
        run["run_id"], state["run_id"],
        "bundled run.run_id and state.run_id must agree — otherwise the handoff picked artifacts from different runs"
    );
    assert_eq!(run["status"], "accepted", "C11 only bundles accepted runs");
    assert_eq!(
        state["status"], "accepted",
        "C11 only bundles accepted run-states"
    );

    // The project-start envelope at the bundle root must agree with the
    // handoff envelope on status (both layers must accept), and must carry
    // factory_replacement_boundary affirming ao2 execution ownership.
    let start: serde_json::Value =
        serde_json::from_str(BUNDLE_PROJECT_START).expect("factory-project-start.json must parse");
    let handoff: serde_json::Value =
        serde_json::from_str(BUNDLE_HANDOFF).expect("handoff.json must parse");
    assert_eq!(
        start["schema_version"], "ao2.factory-project-start.v1",
        "bundled project-start envelope schema"
    );
    assert_eq!(
        start["status"], "accepted",
        "bundled project-start must be the accepted one"
    );
    assert_eq!(
        start["status"], handoff["status"],
        "project-start envelope and handoff envelope must agree on status"
    );

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
        "bundled project-start must affirm AO2 execution ownership"
    );
    assert_eq!(
        frb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );
}

#[test]
fn handoff_bundle_release_review_package_digest_is_pinned_in_manifest_and_sums() {
    // K6/K7/K8/K9 validated the release-review-package.tgz's contents
    // exhaustively. K10's job is to prove the C11 handoff bundle includes
    // that exact tarball by reference: manifest.files[] lists the tarball
    // path with a sha256, and SHA256SUMS reports the same value at the same
    // path. CP can pin the K6-K9 chain to a specific bundle by reading these
    // two values alone without re-extracting the inner tarball.
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    let sums = parse_sha256sums(BUNDLE_SHA256SUMS);
    let pkg_path = "release-review/release-review-package.tgz";
    let pkg_entry = manifest["files"]
        .as_array()
        .expect("manifest.files")
        .iter()
        .find(|f| f["path"] == pkg_path)
        .unwrap_or_else(|| panic!("manifest must list {pkg_path}"));
    let pkg_sha_manifest = pkg_entry["sha256"]
        .as_str()
        .expect("release-review-package manifest entry must declare sha256");
    let pkg_sha_sums = sums
        .get(pkg_path)
        .unwrap_or_else(|| panic!("SHA256SUMS missing {pkg_path}"));
    assert_eq!(
        pkg_sha_manifest, pkg_sha_sums,
        "release-review-package sha256 differs between manifest.files[] and SHA256SUMS"
    );

    // Likewise each app-run-bundle by index — proves CP can pin every nested
    // tarball without re-extracting it.
    for i in 0..2 {
        let path = format!("app-run-bundles/{i}/app-run-evidence-bundle.tgz");
        let entry = manifest["files"]
            .as_array()
            .expect("manifest.files")
            .iter()
            .find(|f| f["path"].as_str() == Some(&path))
            .unwrap_or_else(|| panic!("manifest must list {path}"));
        let claimed = entry["sha256"]
            .as_str()
            .expect("app-run-bundle manifest entry must declare sha256");
        let sums_sha = sums
            .get(&path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing {path}"));
        assert_eq!(
            claimed, sums_sha,
            "app-run-bundle sha256 differs between manifest.files[] and SHA256SUMS for {path}"
        );
    }
}
