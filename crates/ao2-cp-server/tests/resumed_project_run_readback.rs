//! K8 follow-up to BOARD.md Claude lane: prove the control-plane observer can
//! read resumed direct-dispatch project-run packages emitted by AO2 C6.
//!
//! C6 adds resume semantics on top of C5: when a project-run fails partway
//! through, the next dispatch carries forward the previously-accepted app-run
//! evidence verbatim and only re-runs the failed steps. The package now
//! includes `project-state/factory-project-run-state.json` (schema
//! `ao2.factory-project-run-state.v1`), per-step `reused_from_resume` markers,
//! and two new checklist keys: `ao2_reused_resume_state` and
//! `ao2_preserved_partial_evidence`.
//!
//! Fixture origin: ao2 commit `b9aff85` factory-project-run-smoke
//! `20260528T041907Z/project-run/missed-call-recovery-project-release-review-package.tgz`.
//! The 5 fixtures committed here cover the package's `manifest.json`,
//! `SHA256SUMS`, inner `project-run.json` envelope, the dispatched
//! `project-plan/project-plan.json`, and the new
//! `project-state/factory-project-run-state.json`. Nested app-run bundle
//! tarballs are not embedded; their integrity is asserted via manifest +
//! SHA256SUMS cross-checks. The ingest behavior of individual app-run bundles
//! is already covered by `factory_app_run_bundle_readback.rs`.

use sha2::Digest;
use std::collections::HashMap;

const PACKAGE_MANIFEST: &str = include_str!("fixtures/resumed-project-run-package/manifest.json");
const PACKAGE_SHA256SUMS: &str = include_str!("fixtures/resumed-project-run-package/SHA256SUMS");
const PACKAGE_PROJECT_RUN: &str =
    include_str!("fixtures/resumed-project-run-package/project-run.json");
const PACKAGE_PROJECT_PLAN: &str =
    include_str!("fixtures/resumed-project-run-package/project-plan/project-plan.json");
const PACKAGE_PROJECT_STATE: &str = include_str!(
    "fixtures/resumed-project-run-package/project-state/factory-project-run-state.json"
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
fn resumed_manifest_lists_project_state_as_first_class_artifact() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-project-run.v1",
        "C6 package manifest still declares the project-run schema"
    );
    assert_eq!(
        manifest["run_id"], "missed-call-recovery-project",
        "C6 package preserves the missed-call project run_id"
    );
    assert_eq!(
        manifest["app_run_count"], 2,
        "C6 package still references 2 app-runs after resume"
    );

    // The new artifact the C6 resume-state package introduces.
    let files = manifest["files"].as_array().expect("manifest.files");
    let state_entry = files
        .iter()
        .find(|f| f["path"] == "project-state/factory-project-run-state.json")
        .expect("C6 manifest must list project-state/factory-project-run-state.json");
    let state_claimed = state_entry["sha256"]
        .as_str()
        .expect("project-state entry must declare sha256");
    let state_computed = hex_sha256(PACKAGE_PROJECT_STATE.as_bytes());
    assert_eq!(
        state_claimed, state_computed,
        "manifest sha256 for project-state/factory-project-run-state.json drifted from bundled bytes"
    );

    // Confirm C5's direct-dispatch artifact is also still listed (K7 inputs
    // must still be present in the C6 superset).
    assert!(
        files
            .iter()
            .any(|f| f["path"] == "project-plan/project-plan.json"),
        "C6 manifest must still list the C5-introduced project-plan/project-plan.json"
    );

    // Trust-boundary signals must remain observer-only when adding the
    // resume-state surface.
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
        "C6 package must still forbid API-key provider auth"
    );
}

#[test]
fn resumed_sha256sums_and_manifest_agree_on_every_path_including_state() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);

    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
    assert!(
        sums.contains_key("project-state/factory-project-run-state.json"),
        "SHA256SUMS must list project-state/factory-project-run-state.json (the C6-new path)"
    );
    assert!(
        sums.contains_key("project-plan/project-plan.json"),
        "SHA256SUMS must still list project-plan/project-plan.json (the C5 path)"
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
fn resumed_project_state_records_reused_steps_with_observer_safe_lineage() {
    let state: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_STATE).expect("project-state file must parse");

    assert_eq!(
        state["schema_version"], "ao2.factory-project-run-state.v1",
        "C6 state file declares the project-run-state schema"
    );
    assert_eq!(
        state["run_id"], "missed-call-recovery-project",
        "C6 state file preserves the missed-call project run_id"
    );
    assert_eq!(
        state["status"], "accepted",
        "C6 state file records the final accepted status after resume"
    );
    assert_eq!(
        state["step_count"], 2,
        "C6 state file accounts for the full plan step count"
    );
    assert_eq!(
        state["failed_step_count"], 0,
        "C6 resume-then-accept state file must report 0 failed steps at the end"
    );
    assert_eq!(
        state["accepted_step_count"], 2,
        "C6 state file must report both steps accepted after resume"
    );

    // The K8 lineage assertion: at least one step must be marked
    // reused_from_resume=true. Otherwise this fixture is not actually a resume
    // — it's a fresh dispatch — and CP cannot prove it can observe the resume
    // discipline.
    let steps = state["steps"]
        .as_array()
        .expect("state.steps must be an array");
    assert_eq!(steps.len(), 2, "C6 state file lists every plan step");
    let reused_count = steps
        .iter()
        .filter(|s| s["reused_from_resume"].as_bool() == Some(true))
        .count();
    assert!(
        reused_count >= 1,
        "C6 resume fixture must mark at least one step as reused_from_resume=true; got {reused_count}"
    );

    // Every step must carry both app_run_sha256 and bundle_sha256 so CP can
    // pin the carried-forward evidence. Without these hashes a malicious AO2
    // resume could silently substitute different bytes for the "reused" step.
    for step in steps {
        assert!(
            step["app_run_sha256"].as_str().is_some(),
            "every state.step must carry app_run_sha256"
        );
        assert!(
            step["bundle_sha256"].as_str().is_some(),
            "every state.step must carry bundle_sha256"
        );
        assert_eq!(
            step["status"], "accepted",
            "every recorded resume step ends accepted in this fixture"
        );
    }

    // Trust boundary on the state file itself must remain observer-only.
    let tb = &state["trust_boundary"];
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
    assert_eq!(tb["execution_owner"], "ao2");
    assert_eq!(tb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(
        tb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );
}

#[test]
fn resumed_envelope_records_resume_discipline_and_pins_state_to_bundles() {
    let envelope: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_RUN).expect("project-run.json must parse");

    // The C6-new checklist signals: this fixture is the resumed-then-accepted
    // run, so AO2 reused resume state from the prior failed dispatch. The
    // sibling ao2_preserved_partial_evidence flag is the failed-run marker —
    // it's emitted true by the failed run that captured the partial evidence,
    // and emitted false by the subsequent resumed run that consumed it. Both
    // halves of the resume contract are exposed; CP must surface both keys so
    // operators can distinguish a fresh dispatch from a resumed one.
    let checklist = &envelope["project_run_checklist"];
    assert_eq!(
        checklist["ao2_reused_resume_state"], true,
        "C6 resumed-run envelope must record that AO2 reused resume state"
    );
    assert!(
        checklist["ao2_preserved_partial_evidence"].is_boolean(),
        "C6 envelope must expose ao2_preserved_partial_evidence as a boolean (false on the resumed-then-accepted run, true on the failed run that captured the partial evidence)"
    );
    // K7 + K6 signals must still hold.
    assert_eq!(checklist["ao2_dispatched_project_plan"], true);
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

    // The K8 cross-evidence assertion: the envelope must expose
    // project_steps[] that agree byte-for-byte with project-state.steps[] on
    // id, index, app_run_sha256, bundle_sha256, status, and reused_from_resume.
    // This proves CP can detect a malicious AO2 that publishes a state file
    // claiming "reused" but reports an envelope that contradicts the state.
    let state: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_STATE).expect("project-state file must parse");
    let state_steps = state["steps"].as_array().expect("state.steps");
    let envelope_steps = envelope["project_steps"]
        .as_array()
        .expect("envelope.project_steps");
    assert_eq!(
        envelope_steps.len(),
        state_steps.len(),
        "envelope.project_steps count must match project-state.steps count"
    );
    for (i, (env_step, state_step)) in envelope_steps.iter().zip(state_steps.iter()).enumerate() {
        for field in [
            "id",
            "index",
            "app_run_sha256",
            "bundle_sha256",
            "status",
            "reused_from_resume",
        ] {
            assert_eq!(
                env_step[field], state_step[field],
                "envelope.project_steps[{i}].{field} disagrees with project-state.steps[{i}].{field}"
            );
        }
    }

    // The K8 dispatch-lineage assertion (mirroring K7 but with reuse): the
    // dispatched plan's app_steps[i].id must equal envelope.project_steps[i].id
    // and SHA256SUMS for app-run-bundles/{i}/app-run-evidence-bundle.tgz must
    // equal envelope.project_steps[i].bundle_sha256. Even when step i was
    // reused from a prior resume, its current-package bundle must hash to the
    // value SHA256SUMS reports — proving CP cannot be fooled by a state file
    // that claims reuse-from-resume while the bundle bytes silently swap.
    let plan: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");
    let plan_steps = plan["app_steps"].as_array().expect("plan.app_steps");
    assert_eq!(
        plan_steps.len(),
        envelope_steps.len(),
        "plan step count must equal envelope project_steps count"
    );
    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);
    for (i, plan_step) in plan_steps.iter().enumerate() {
        assert_eq!(
            envelope_steps[i]["id"], plan_step["id"],
            "envelope.project_steps[{i}].id diverges from plan.app_steps[{i}].id"
        );
        let claimed = envelope_steps[i]["bundle_sha256"]
            .as_str()
            .expect("envelope.project_steps.bundle_sha256");
        let path = format!("app-run-bundles/{i}/app-run-evidence-bundle.tgz");
        let sums_sha = sums
            .get(&path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing nested bundle path {path}"));
        assert_eq!(
            sums_sha, claimed,
            "envelope.project_steps[{i}].bundle_sha256 disagrees with SHA256SUMS for {path}"
        );
    }
}
