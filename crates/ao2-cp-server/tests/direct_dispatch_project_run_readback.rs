//! K7 follow-up to BOARD.md Claude lane: prove the control-plane observer can
//! read direct-dispatch project-run packages emitted by AO2 C5. The C5 package
//! adds `project-plan/project-plan.json` (schema
//! `ao2.factory-project-plan.v1`) as a first-class bundled artifact and adds
//! the `ao2_dispatched_project_plan` discipline to the envelope's
//! `project_run_checklist`. Tests prove the dispatch lineage (project plan
//! step -> bundled app-run) cross-validates without any mutation surface.
//!
//! Fixture origin: ao2 commit `324516f` factory-project-run-smoke
//! `20260528T035044Z/project-run/missed-call-recovery-project-release-review-package.tgz`.
//! The 4 fixtures committed here cover the package's `manifest.json`,
//! `SHA256SUMS`, the inner `project-run.json` envelope (which now embeds
//! `project_plan` directly), and the new `project-plan/project-plan.json`
//! direct-dispatch plan. Nested app-run bundle tarballs are not embedded;
//! their integrity is asserted via manifest/SHA256SUMS cross-checks, and their
//! ingest behavior is already covered by `factory_app_run_bundle_readback.rs`.

use sha2::Digest;
use std::collections::HashMap;

const PACKAGE_MANIFEST: &str =
    include_str!("fixtures/direct-dispatch-project-run-package/manifest.json");
const PACKAGE_SHA256SUMS: &str =
    include_str!("fixtures/direct-dispatch-project-run-package/SHA256SUMS");
const PACKAGE_PROJECT_RUN: &str =
    include_str!("fixtures/direct-dispatch-project-run-package/project-run.json");
const PACKAGE_PROJECT_PLAN: &str =
    include_str!("fixtures/direct-dispatch-project-run-package/project-plan/project-plan.json");

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
fn direct_dispatch_manifest_lists_project_plan_as_first_class_artifact() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-project-run.v1",
        "C5 package manifest still declares the project-run schema"
    );
    assert_eq!(
        manifest["run_id"], "missed-call-recovery-project",
        "C5 package preserves the missed-call project run_id"
    );
    assert_eq!(
        manifest["app_run_count"], 2,
        "C5 package references 2 app-runs (intake + messaging)"
    );

    // The new artifact the C5 direct-dispatch package introduces.
    let files = manifest["files"].as_array().expect("manifest.files");
    let project_plan_entry = files
        .iter()
        .find(|f| f["path"] == "project-plan/project-plan.json")
        .expect("C5 manifest must list project-plan/project-plan.json");
    let project_plan_claimed = project_plan_entry["sha256"]
        .as_str()
        .expect("project-plan entry must declare sha256");

    // The bundled bytes for project-plan.json must match the manifest's claim;
    // proves no fixture round-trip altered the dispatch plan.
    let project_plan_computed = hex_sha256(PACKAGE_PROJECT_PLAN.as_bytes());
    assert_eq!(
        project_plan_claimed, project_plan_computed,
        "manifest sha256 for project-plan/project-plan.json drifted from bundled bytes"
    );

    // Same trust-boundary signals K6 enforced — C5 must not silently relax
    // them when adding the direct-dispatch surface.
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
        tb["provider_auth"], "local OAuth CLI only; API-key provider auth forbidden",
        "C5 package must still forbid API-key provider auth"
    );
}

#[test]
fn direct_dispatch_sha256sums_and_manifest_agree_on_every_path() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);

    // SHA256SUMS must cover manifest.json itself plus every manifest.files[]
    // entry. project-plan/project-plan.json must be listed (the K7-new path).
    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
    assert!(
        sums.contains_key("project-plan/project-plan.json"),
        "SHA256SUMS must list project-plan/project-plan.json (the C5-new path)"
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
}

#[test]
fn direct_dispatch_project_plan_steps_match_envelope_app_runs() {
    let plan: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");
    assert_eq!(
        plan["schema_version"], "ao2.factory-project-plan.v1",
        "C5 direct-dispatch plan declares the project-plan schema"
    );
    let steps = plan["app_steps"]
        .as_array()
        .expect("project-plan must carry app_steps");
    assert_eq!(steps.len(), 2, "C5 plan dispatches 2 app steps");
    let step_ids: Vec<&str> = steps
        .iter()
        .map(|s| s["id"].as_str().expect("step id"))
        .collect();
    assert_eq!(
        step_ids,
        vec!["intake", "messaging"],
        "C5 plan dispatches intake then messaging in order"
    );

    // The envelope's app_runs[] must derive run_id from
    // <project-run_id>-<step.id> for each step in order. This is the K7
    // lineage assertion: AO2 dispatched the plan, so the bundled app-run for
    // each plan step must trace back to that step deterministically.
    let envelope: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_RUN).expect("project-run.json must parse");
    let project_run_id = envelope["run_id"].as_str().expect("envelope run_id");
    let app_runs = envelope["app_runs"].as_array().expect("envelope app_runs");
    assert_eq!(
        app_runs.len(),
        steps.len(),
        "envelope app_run count must match plan step count"
    );
    for (i, step) in steps.iter().enumerate() {
        let step_id = step["id"].as_str().unwrap();
        let expected_run_id = format!("{project_run_id}-{step_id}");
        let actual_run_id = app_runs[i]["run_id"].as_str().expect("app_run.run_id");
        assert_eq!(
            actual_run_id, expected_run_id,
            "direct-dispatch lineage broken at index {i}: plan step {step_id} does not match app_run {actual_run_id}"
        );
        let app_run_index = app_runs[i]["index"].as_u64().expect("app_run.index");
        assert_eq!(
            app_run_index, i as u64,
            "app_run[{i}].index must equal its position to preserve dispatch order"
        );
    }

    // Each app_run must also expose bundle_sha256 that SHA256SUMS reports for
    // the corresponding nested bundle path. Proves the dispatched-plan record
    // and the assembled bundle are derived from the same source-of-truth and
    // the control plane cannot silently swap a bundle out from under a step.
    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);
    for (i, app_run) in app_runs.iter().enumerate() {
        let claimed = app_run["bundle_sha256"]
            .as_str()
            .expect("app_run.bundle_sha256");
        let bundle_path = format!("app-run-bundles/{i}/app-run-evidence-bundle.tgz");
        let sums_sha = sums
            .get(&bundle_path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing nested bundle path {bundle_path}"));
        assert_eq!(
            sums_sha, claimed,
            "bundle_sha256 mismatch between envelope app_runs[{i}] and SHA256SUMS for {bundle_path}"
        );
    }
}

#[test]
fn direct_dispatch_envelope_records_ao2_dispatched_project_plan_discipline() {
    let envelope: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_RUN).expect("project-run.json must parse");

    // The C5-new checklist signal: AO2 dispatched the project plan.
    let checklist = &envelope["project_run_checklist"];
    assert_eq!(
        checklist["ao2_dispatched_project_plan"], true,
        "C5 envelope must record that AO2 dispatched the project plan"
    );
    // Pre-existing discipline that K6 already asserted; re-checked here to
    // catch a regression where C5 relaxes them when adding the new key.
    assert_eq!(checklist["ao2_collected_app_run_bundles"], true);
    assert_eq!(checklist["ao2_ingested_project_spec"], true);
    assert_eq!(checklist["control_plane_approves_release"], false);
    assert_eq!(
        checklist["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(checklist["factory_v3_drives_workflow"], false);
    assert_eq!(checklist["factory_v3_role"], "parity_oracle_only");
    assert_eq!(checklist["mutates_ao_artifacts"], false);
    assert_eq!(
        checklist["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(checklist["release_review_package_ready"], true);

    // The envelope now embeds the dispatched project plan directly. The
    // embedded copy must agree with the standalone project-plan/project-plan.json
    // file on schema_version and step ids — proves the package is internally
    // self-consistent about what AO2 dispatched.
    let embedded_plan = &envelope["project_plan"];
    assert_eq!(
        embedded_plan["schema_version"], "ao2.factory-project-plan.v1",
        "envelope's embedded project_plan must declare the project-plan schema"
    );
    let embedded_steps = embedded_plan["app_steps"]
        .as_array()
        .expect("envelope project_plan.app_steps");
    let plan: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");
    let standalone_steps = plan["app_steps"].as_array().expect("plan.app_steps");
    assert_eq!(
        embedded_steps.len(),
        standalone_steps.len(),
        "embedded project_plan must reference the same number of app steps as the standalone plan"
    );
    for (i, embedded_step) in embedded_steps.iter().enumerate() {
        assert_eq!(
            embedded_step["id"], standalone_steps[i]["id"],
            "embedded project_plan step[{i}] id diverges from standalone plan"
        );
    }
}
