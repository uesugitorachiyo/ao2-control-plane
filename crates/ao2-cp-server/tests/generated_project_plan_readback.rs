//! K9 follow-up to BOARD.md Claude lane: prove the control-plane observer can
//! read AO2-generated `ao2.factory-project-plan.v1` lineage emitted by C7
//! (`ao2 factory project-plan`). C7 replaces hand-authored project plans with
//! AO2-native generation from a human spec; the resulting plan carries new
//! generator-signed metadata that binds it to its source spec and to the
//! downstream package.
//!
//! Distinctive C7 signals vs. K7's hand-authored direct-dispatch plan:
//!
//! - `project_spec_sha256` — sha256 of the source spec bytes, written by AO2 at
//!   plan-generation time. CP can re-compute it against the bundled spec to
//!   prove the generator bound the plan to the spec it claims.
//! - `project_title` — derived from the spec, frozen at generation time.
//! - `status: "accepted"` — the plan was validated (C8 fail-closed gate)
//!   before being bundled.
//! - `factory_replacement_boundary` block at plan level — declares
//!   `factory_v3_role: parity_oracle_only`, `ao2_execution_owner: true`,
//!   `control_plane_role: read_only_observer_after_signed_evidence`,
//!   `release_acceptance_owner: factory-v3 evaluator-closer` directly on the
//!   plan artifact (in addition to the existing trust_boundary block).
//! - Per-step `title`, `provider`, `provider_profile`, `provider_prompt_file`
//!   carried by the generator (C7+C9).
//!
//! Fixture origin: ao2 commit `92f478f` factory-project-run-smoke
//! `20260528T044042Z`. The K9 fixtures are the in-package
//! `project-plan/project-plan.json`, the bundled spec at
//! `project-spec/missed-call-recovery-project.md`, the standalone outer
//! generator output `factory-project-plan.json`, and the package's
//! `manifest.json` + `SHA256SUMS`. Nested app-run bundles and the
//! project-run.json envelope are not re-embedded — K6/K7/K8 already cover
//! those.

use sha2::Digest;
use std::collections::HashMap;

const PACKAGE_MANIFEST: &str =
    include_str!("fixtures/generated-project-plan-package/manifest.json");
const PACKAGE_SHA256SUMS: &str = include_str!("fixtures/generated-project-plan-package/SHA256SUMS");
const IN_PACKAGE_PROJECT_PLAN: &str =
    include_str!("fixtures/generated-project-plan-package/project-plan/project-plan.json");
const BUNDLED_PROJECT_SPEC: &str = include_str!(
    "fixtures/generated-project-plan-package/project-spec/missed-call-recovery-project.md"
);
const STANDALONE_GENERATOR_PLAN: &str =
    include_str!("fixtures/generated-project-plan-package/factory-project-plan.json");

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
fn generated_plan_project_spec_sha256_binds_plan_to_bundled_spec_bytes() {
    let plan: serde_json::Value =
        serde_json::from_str(IN_PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");

    assert_eq!(
        plan["schema_version"], "ao2.factory-project-plan.v1",
        "C7-generated plan declares the project-plan schema"
    );
    assert_eq!(
        plan["status"], "accepted",
        "C7-generated plan in-package copy must be the validation-accepted plan (C8 gate)"
    );
    assert!(
        plan["project_title"].as_str().is_some(),
        "C7-generated plan must carry a project_title derived from the spec"
    );

    let claimed = plan["project_spec_sha256"]
        .as_str()
        .expect("C7-generated plan must declare project_spec_sha256");
    let computed = hex_sha256(BUNDLED_PROJECT_SPEC.as_bytes());
    assert_eq!(
        claimed, computed,
        "C7 generator claims project_spec_sha256 {claimed} but the bundled spec bytes hash to {computed}; the plan is not bound to the spec it claims"
    );

    // Manifest must hash the spec to the same value the generator declared in
    // the plan; this completes the three-way binding plan <-> spec bytes <->
    // manifest. CP can detect a malicious AO2 that quietly swaps either side.
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    let spec_manifest_entry = manifest["files"]
        .as_array()
        .expect("manifest.files")
        .iter()
        .find(|f| f["path"] == "project-spec/missed-call-recovery-project.md")
        .expect("manifest must list project-spec/missed-call-recovery-project.md");
    assert_eq!(
        spec_manifest_entry["sha256"], claimed,
        "manifest sha256 for the bundled spec must equal the generator's project_spec_sha256"
    );
}

#[test]
fn generated_plan_carries_observer_safe_replacement_boundary_at_plan_level() {
    let plan: serde_json::Value =
        serde_json::from_str(IN_PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");

    // Pre-existing trust_boundary block must remain observer-only.
    let tb = &plan["trust_boundary"];
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

    // C7 also writes a factory_replacement_boundary block at the plan level
    // (separate from the bundle's manifest.trust_boundary). It explicitly
    // declares AO2 as execution owner and factory-v3 as parity oracle —
    // catching a regression where AO2 generates a plan but silently transfers
    // execution ownership back to factory-v3.
    let frb = &plan["factory_replacement_boundary"];
    assert_eq!(frb["control_plane_approves_release"], false);
    assert_eq!(frb["mutates_ao_artifacts"], false);
    assert_eq!(
        frb["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(
        frb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(frb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(frb["factory_v3_drives_workflow"], false);
    assert_eq!(
        frb["ao2_execution_owner"], true,
        "C7-generated plan must affirm AO2 is the execution owner"
    );
    assert_eq!(
        frb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );
}

#[test]
fn generated_plan_app_steps_carry_full_c7_c9_generator_metadata() {
    let plan: serde_json::Value =
        serde_json::from_str(IN_PACKAGE_PROJECT_PLAN).expect("project-plan.json must parse");

    let steps = plan["app_steps"].as_array().expect("plan.app_steps");
    assert!(
        steps.len() >= 2,
        "C7-generated plan dispatches at least the intake + messaging steps; got {}",
        steps.len()
    );

    // C7+C9 generator must emit per-step title, provider, provider_prompt_file,
    // plus the K7-era id/spec/target/verifier_command — all as strings.
    // provider_profile is structurally an object carrying provider_auth.
    for (i, step) in steps.iter().enumerate() {
        for field in [
            "id",
            "title",
            "spec",
            "target",
            "verifier_command",
            "provider",
            "provider_prompt_file",
        ] {
            assert!(
                step[field].as_str().is_some(),
                "C7+C9 generator must populate app_steps[{i}].{field} as a string; got {:?}",
                step[field]
            );
        }
        // provider_profile is the C9 secret-safety carrier: an object that
        // declares provider_auth so every dispatched step inherits the local
        // OAuth-CLI-only constraint, blocking API-key drift at the step level.
        let profile = step["provider_profile"].as_object().unwrap_or_else(|| {
            panic!("C9 generator must populate app_steps[{i}].provider_profile as an object")
        });
        assert_eq!(
            profile.get("provider_auth").and_then(|v| v.as_str()),
            Some("local OAuth CLI only; API-key provider auth forbidden"),
            "app_steps[{i}].provider_profile must pin local-OAuth-CLI-only auth"
        );
    }

    // C7 plan must keep deterministic ordering (intake -> messaging) so the
    // package's per-step lineage is reproducible across re-generations.
    assert_eq!(steps[0]["id"], "intake");
    assert_eq!(steps[1]["id"], "messaging");
}

#[test]
fn generated_plan_standalone_generator_output_matches_in_package_plan() {
    // The standalone generator output (the file AO2 wrote to
    // <root>/factory-project-plan.json before bundling) must match the
    // bundled copy on every plan-defining field. Proves the package contains
    // the same plan AO2 generated, not a re-derived or tampered copy.
    let standalone: serde_json::Value =
        serde_json::from_str(STANDALONE_GENERATOR_PLAN).expect("standalone plan must parse");
    let in_package: serde_json::Value =
        serde_json::from_str(IN_PACKAGE_PROJECT_PLAN).expect("in-package plan must parse");

    for field in [
        "schema_version",
        "run_id",
        "project_title",
        "project_spec_sha256",
        "status",
    ] {
        assert_eq!(
            standalone[field], in_package[field],
            "standalone-generator plan vs in-package plan disagree on {field}"
        );
    }

    // app_steps must agree on every observable field per step in order.
    let standalone_steps = standalone["app_steps"]
        .as_array()
        .expect("standalone.app_steps");
    let in_package_steps = in_package["app_steps"]
        .as_array()
        .expect("in_package.app_steps");
    assert_eq!(
        standalone_steps.len(),
        in_package_steps.len(),
        "step count diverges between standalone and in-package plan"
    );
    for (i, (s, p)) in standalone_steps
        .iter()
        .zip(in_package_steps.iter())
        .enumerate()
    {
        for field in [
            "id",
            "title",
            "spec",
            "target",
            "verifier_command",
            "provider",
            "provider_profile",
            "provider_prompt_file",
        ] {
            assert_eq!(
                s[field], p[field],
                "app_steps[{i}].{field} diverges between standalone and in-package plan"
            );
        }
    }

    // Both copies must declare the same plan-level boundary blocks; CP
    // observes them either way and must see the same declaration.
    assert_eq!(
        standalone["trust_boundary"], in_package["trust_boundary"],
        "trust_boundary block diverges between standalone and in-package plan"
    );
    assert_eq!(
        standalone["factory_replacement_boundary"], in_package["factory_replacement_boundary"],
        "factory_replacement_boundary block diverges between standalone and in-package plan"
    );
}

#[test]
fn generated_plan_sha256_in_manifest_matches_in_package_plan_bytes() {
    // SHA256SUMS and manifest.files[] must hash project-plan/project-plan.json
    // to the same value, and that value must equal sha256 of the bundled
    // in-package plan bytes. Otherwise the manifest is not a faithful index
    // of the bytes CP is being shown.
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    let plan_entry = manifest["files"]
        .as_array()
        .expect("manifest.files")
        .iter()
        .find(|f| f["path"] == "project-plan/project-plan.json")
        .expect("manifest must list project-plan/project-plan.json");
    let manifest_claimed = plan_entry["sha256"]
        .as_str()
        .expect("manifest must declare sha256 for project-plan");

    let computed = hex_sha256(IN_PACKAGE_PROJECT_PLAN.as_bytes());
    assert_eq!(
        manifest_claimed, computed,
        "manifest sha256 for project-plan/project-plan.json drifted from bundled plan bytes"
    );

    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);
    let sums_sha = sums
        .get("project-plan/project-plan.json")
        .expect("SHA256SUMS must list project-plan/project-plan.json");
    assert_eq!(
        sums_sha, manifest_claimed,
        "SHA256SUMS disagrees with manifest.files[] for project-plan/project-plan.json"
    );
}
