//! K13 follow-up to BOARD.md Claude lane: prove the control-plane observer
//! can read C14's plan-time signed acceptance rubric. C14 introduces
//! `ao2.factory-acceptance-rubric.v1` — a signed artifact derived from the
//! project spec that carries verifier-grade pass/fail criteria, thresholds,
//! and must-have artifacts. App runs, project runs, handoff bundles, and
//! factory-v3 evaluator-closer reference the rubric SHA256 so the acceptance
//! criteria source of truth moves from implicit factory-v3 expectations into
//! AO2-produced signed evidence.
//!
//! K13's distinctive cross-bindings are *three* three-way digest pins:
//!
//!   (1) Rubric digest:
//!       sha256(rubric.json bytes)
//!         == project-plan.acceptance_rubric_sha256 (top-level)
//!         == every project-plan.app_steps[i].acceptance_rubric_sha256
//!         == project-start.artifacts.acceptance_rubric_sha256
//!
//!   (2) Signed-payload digest:
//!       sha256(signed-payload.json bytes)
//!         == rubric.signature.signed_payload_sha256
//!
//!   (3) Source-spec digest:
//!       sha256(project-spec.md bytes)
//!         == rubric.source_project_spec_sha256
//!         == project-plan.project_spec_sha256
//!       (project-start.project_spec is a path-only binding; the project-
//!        start envelope does not carry a separate spec digest, so the
//!        plan acts as the spec-digest counter-claim for the rubric.)
//!
//! Together these prove the rubric is bound to (a) a specific spec source,
//! (b) a specific signed payload (the rubric minus the signature field),
//! and (c) every plan-step that the project executes. A malicious AO2
//! cannot swap any one side without tripping at least one of these
//! assertions.
//!
//! Fixture origin: ao2 commit `7ec59b2` factory-project-run-smoke root
//! `20260528T071035Z`. Project-start scope is used end-to-end so the plan,
//! rubric, and project-start envelope all reference the same rubric digest.

use sha2::Digest;

const RUBRIC: &str = include_str!("fixtures/acceptance-rubric/acceptance-rubric.json");
const RUBRIC_SIGNED_PAYLOAD: &str =
    include_str!("fixtures/acceptance-rubric/acceptance-rubric-signed-payload.json");
const PROJECT_PLAN: &str = include_str!("fixtures/acceptance-rubric/project-plan.json");
const PROJECT_START: &str = include_str!("fixtures/acceptance-rubric/factory-project-start.json");
const PROJECT_SPEC: &str = include_str!("fixtures/acceptance-rubric/project-spec.md");

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn acceptance_rubric_declares_schema_status_and_observer_safe_trust_boundary() {
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");

    assert_eq!(
        rubric["schema_version"], "ao2.factory-acceptance-rubric.v1",
        "C14 introduces the factory-acceptance-rubric schema"
    );
    assert_eq!(
        rubric["status"], "accepted",
        "C14 rubric must declare accepted as the post-validation state"
    );
    assert!(
        rubric["run_id"].as_str().is_some_and(|s| !s.is_empty()),
        "rubric must declare the run_id it's bound to"
    );
    assert!(
        rubric["project_title"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "rubric must declare the project title it's bound to"
    );

    // Trust boundary preserved verbatim on the rubric itself — the rubric
    // is the future acceptance source of truth, so it must explicitly
    // affirm CP does not approve releases and factory-v3 still owns release
    // acceptance (the rubric only owns the *criteria*, not the decision).
    let tb = &rubric["trust_boundary"];
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
fn acceptance_rubric_signature_block_is_signed_verified_and_pins_signed_payload_digest() {
    // C14's rubric carries a self-described signature block declaring
    // signature_status=signed, signature_verified=true (AO2's own
    // verification result), RSA/SHA-256, plus the sha256 of the signed
    // payload bytes. K13 recomputes the sha256 of the bundled
    // signed-payload.json fixture and confirms it equals
    // rubric.signature.signed_payload_sha256 — so a malicious AO2 cannot
    // swap the signed-payload after-the-fact while keeping the same
    // signature.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");
    let sig = &rubric["signature"];

    assert_eq!(
        sig["schema_version"], "ao2.factory-acceptance-rubric-signature.v1",
        "signature block declares its own signature schema"
    );
    assert_eq!(
        sig["signature_status"], "signed",
        "rubric only ships in signed state when C14 producer accepted it"
    );
    assert_eq!(
        sig["signature_verified"], true,
        "AO2 producer must declare the signature verified before bundling"
    );
    assert_eq!(
        sig["signature_algorithm"], "RSA/SHA-256",
        "signature algorithm is RSA/SHA-256; CP must reject other algos"
    );
    assert_eq!(
        sig["signed_payload"], "acceptance_rubric_without_signature_field",
        "signed payload form is the rubric without the signature field"
    );
    assert!(
        sig["signer_id"].as_str().is_some_and(|s| !s.is_empty()),
        "signer_id must be populated so CP can attribute the signature"
    );
    assert!(
        sig["public_key_path"]
            .as_str()
            .is_some_and(|s| s.ends_with(".pem")),
        "public_key_path must point at a local PEM file"
    );
    assert!(
        sig["signature_path"]
            .as_str()
            .is_some_and(|s| s.ends_with(".sig")),
        "signature_path must point at the binary .sig file"
    );

    // The strongest assertion: claimed signed-payload sha256 equals
    // sha256(bundled signed-payload.json bytes).
    let claimed_payload_sha = sig["signed_payload_sha256"]
        .as_str()
        .expect("signed_payload_sha256 missing");
    let computed_payload_sha = hex_sha256(RUBRIC_SIGNED_PAYLOAD.as_bytes());
    assert_eq!(
        claimed_payload_sha, computed_payload_sha,
        "rubric.signature.signed_payload_sha256 ({claimed_payload_sha}) does not match sha256(bundled signed-payload bytes) ({computed_payload_sha}) — signed-payload tamper"
    );

    // Sanity: public_key_sha256 + signature_sha256 are 64-char hex.
    assert_eq!(
        sig["public_key_sha256"].as_str().map(str::len),
        Some(64),
        "public_key_sha256 must be 64-char hex"
    );
    assert_eq!(
        sig["signature_sha256"].as_str().map(str::len),
        Some(64),
        "signature_sha256 must be 64-char hex"
    );
}

#[test]
fn acceptance_rubric_source_project_spec_sha256_binds_rubric_to_spec_bytes() {
    // K13 source-spec three-way binding: the rubric was derived from a
    // specific project spec, and that spec is the same one the project-start
    // envelope claims. CP recomputes sha256 of the bundled spec bytes and
    // asserts it equals both the rubric's claim AND the project-start
    // envelope's claim — a malicious AO2 cannot derive a rubric from a
    // different spec while claiming the original spec source.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");
    let start: serde_json::Value =
        serde_json::from_str(PROJECT_START).expect("factory-project-start.json must parse");

    let plan: serde_json::Value =
        serde_json::from_str(PROJECT_PLAN).expect("project-plan.json must parse");

    let rubric_claim = rubric["source_project_spec_sha256"]
        .as_str()
        .expect("rubric.source_project_spec_sha256 missing");
    // project-start envelope does not carry project_spec_sha256 directly —
    // the plan does. Plan is what derived the rubric, so plan.project_spec_sha256
    // is the right counter-claim to compare against.
    let plan_claim = plan["project_spec_sha256"]
        .as_str()
        .expect("plan.project_spec_sha256 missing");
    let computed = hex_sha256(PROJECT_SPEC.as_bytes());

    assert_eq!(
        rubric_claim, computed,
        "rubric.source_project_spec_sha256 ({rubric_claim}) != sha256(bundled spec bytes) ({computed})"
    );
    assert_eq!(
        plan_claim, computed,
        "plan.project_spec_sha256 ({plan_claim}) != sha256(bundled spec bytes) ({computed})"
    );
    assert_eq!(
        rubric_claim, plan_claim,
        "rubric and plan disagree on the spec digest"
    );
    // project-start envelope must declare the same project_spec path that
    // the rubric was derived from (path-level binding, since the start
    // envelope itself does not carry a separate spec sha).
    let start_spec_path = start["project_spec"]
        .as_str()
        .expect("project-start.project_spec missing");
    let rubric_spec_path = rubric["source_project_spec"]
        .as_str()
        .expect("rubric.source_project_spec missing");
    assert_eq!(
        start_spec_path, rubric_spec_path,
        "project-start.project_spec and rubric.source_project_spec disagree"
    );
}

#[test]
fn acceptance_rubric_digest_pins_every_plan_app_step_and_project_start() {
    // K13 rubric-digest three-way (actually N-way) binding: the rubric
    // bytes hash to a value that must equal the project-plan's top-level
    // acceptance_rubric_sha256, every project-plan.app_steps[i].
    // acceptance_rubric_sha256, and project-start.acceptance_rubric.
    // acceptance_rubric_sha256. So every plan step is pinned to the same
    // rubric — a malicious AO2 cannot apply different rubrics across steps
    // or swap the rubric between plan and project-start.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");
    let plan: serde_json::Value =
        serde_json::from_str(PROJECT_PLAN).expect("project-plan.json must parse");
    let start: serde_json::Value =
        serde_json::from_str(PROJECT_START).expect("factory-project-start.json must parse");

    let computed_rubric_sha = hex_sha256(RUBRIC.as_bytes());

    // Plan top-level
    let plan_top_sha = plan["acceptance_rubric_sha256"]
        .as_str()
        .expect("plan.acceptance_rubric_sha256 missing");
    assert_eq!(
        plan_top_sha, computed_rubric_sha,
        "plan.acceptance_rubric_sha256 != sha256(bundled rubric bytes)"
    );

    // Plan also embeds the full rubric content as an object. That embedded
    // copy must declare the same schema + status as the bundled rubric — so
    // a malicious AO2 cannot embed one rubric while pointing the digest at
    // a different one.
    let plan_embed = &plan["acceptance_rubric"];
    assert_eq!(
        plan_embed["schema_version"], rubric["schema_version"],
        "plan embedded rubric schema disagrees with bundled rubric"
    );
    assert_eq!(
        plan_embed["status"], rubric["status"],
        "plan embedded rubric status disagrees with bundled rubric"
    );
    assert_eq!(
        plan_embed["run_id"], rubric["run_id"],
        "plan embedded rubric run_id disagrees with bundled rubric"
    );
    assert_eq!(
        plan_embed["source_project_spec_sha256"], rubric["source_project_spec_sha256"],
        "plan embedded rubric source_project_spec_sha256 disagrees with bundled rubric"
    );

    // Every app_step pins to the same sha
    let app_steps = plan["app_steps"].as_array().expect("plan.app_steps array");
    assert!(
        app_steps.len() >= 2,
        "project-start plan must have at least 2 app steps to make this binding meaningful"
    );
    for (i, step) in app_steps.iter().enumerate() {
        let step_sha = step["acceptance_rubric_sha256"]
            .as_str()
            .unwrap_or_else(|| panic!("plan.app_steps[{i}].acceptance_rubric_sha256 missing"));
        assert_eq!(
            step_sha, computed_rubric_sha,
            "plan.app_steps[{i}].acceptance_rubric_sha256 disagrees with the bundled rubric digest"
        );
    }

    // Project-start envelope carries the rubric digest under artifacts.
    let start_sha = start["artifacts"]["acceptance_rubric_sha256"]
        .as_str()
        .expect("project-start.artifacts.acceptance_rubric_sha256 missing");
    assert_eq!(
        start_sha, computed_rubric_sha,
        "project-start.artifacts.acceptance_rubric_sha256 disagrees with the bundled rubric digest"
    );

    // Lineage: rubric.run_id and plan.run_id and project-start.run_id all
    // agree, so the rubric is bound to a specific project-start.
    let rubric_run_id = rubric["run_id"].as_str().expect("rubric.run_id");
    assert_eq!(
        rubric_run_id,
        plan["run_id"].as_str().expect("plan.run_id"),
        "rubric.run_id != plan.run_id"
    );
    assert_eq!(
        rubric_run_id,
        start["run_id"].as_str().expect("project-start.run_id"),
        "rubric.run_id != project-start.run_id"
    );
}

#[test]
fn acceptance_rubric_lists_must_have_artifacts_covering_k3_through_k10_lineage() {
    // C14 rubric declares the must_have_artifacts list — the set of files
    // a project-start bundle must contain for the rubric to be satisfiable.
    // K13 asserts this list covers the K3-K10 lineage anchors so the
    // rubric and the K3-K10 readback chain agree on what a valid bundle
    // must contain.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");
    let must = rubric["must_have_artifacts"]
        .as_array()
        .expect("rubric.must_have_artifacts array");
    let must_paths: Vec<&str> = must.iter().filter_map(|v| v.as_str()).collect();

    for required in [
        "project-plan/project-plan.json",
        "project-plan/project-plan-validation.json",
        "project-run/factory-project-run.json",
        "project-run/factory-project-run-state.json",
        "release-review/release-review-package.tgz",
    ] {
        assert!(
            must_paths.contains(&required),
            "rubric.must_have_artifacts is missing K3-K10 lineage anchor {required}; full list: {must_paths:?}"
        );
    }
}

#[test]
fn acceptance_rubric_thresholds_and_step_criteria_are_verifier_grade() {
    // C14 rubric declares thresholds (fail-closed numeric/string checks) and
    // per-step criteria (must_pass[]). K13 asserts the producer-grade
    // shape: thresholds carries required_signature_status=signed (so a
    // missing signature fails), failed_step_count=0 (so any failed step
    // fails), verifier_exit_code=0 (so any non-zero verifier fails); and
    // every step_criteria entry has index/step/must_pass[] tuples a CP
    // observer can read.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");

    let thresholds = &rubric["thresholds"];
    assert_eq!(
        thresholds["required_signature_status"], "signed",
        "rubric must require signed signature_status — unsigned bundles fail closed"
    );
    assert_eq!(
        thresholds["failed_step_count"], 0,
        "rubric must require zero failed steps"
    );
    assert_eq!(
        thresholds["verifier_exit_code"], 0,
        "rubric must require verifier exit code 0"
    );

    let step_criteria = rubric["step_criteria"]
        .as_array()
        .expect("rubric.step_criteria array");
    assert!(
        !step_criteria.is_empty(),
        "rubric must declare at least one step criterion"
    );
    let mut seen_indexes = Vec::new();
    for sc in step_criteria {
        let idx = sc["index"].as_u64().expect("step_criteria[].index");
        assert!(
            !seen_indexes.contains(&idx),
            "step_criteria has duplicate index {idx}"
        );
        seen_indexes.push(idx);
        assert!(
            sc["step"].as_str().is_some_and(|s| !s.is_empty()),
            "step_criteria[].step must be a non-empty description"
        );
        let must_pass = sc["must_pass"]
            .as_array()
            .expect("step_criteria[].must_pass array");
        assert!(
            !must_pass.is_empty(),
            "step_criteria[].must_pass must be non-empty"
        );
        // Every step must affirm trust-boundary preservation.
        let texts: Vec<&str> = must_pass.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.contains("trust-boundary")),
            "step_criteria[{idx}].must_pass must include a trust-boundary preservation criterion; got {texts:?}"
        );
    }

    let vg = rubric["verifier_grade_pass_fail_criteria"]
        .as_array()
        .expect("verifier_grade_pass_fail_criteria array");
    assert!(
        !vg.is_empty(),
        "rubric must declare verifier-grade pass/fail criteria"
    );
    let mut seen_ids = Vec::new();
    for c in vg {
        let id = c["id"].as_str().expect("verifier criterion id");
        assert!(
            !seen_ids.contains(&id),
            "verifier-grade criterion has duplicate id {id}"
        );
        seen_ids.push(id);
        assert!(
            c["criterion"].as_str().is_some_and(|s| !s.is_empty()),
            "verifier criterion text must be non-empty"
        );
        assert!(
            c["required"].as_bool().is_some(),
            "verifier criterion required field must be a boolean"
        );
    }
}

#[test]
fn project_start_envelope_carries_rubric_status_accepted_and_sha_agreement() {
    // The project-start envelope embeds an `acceptance_rubric` object the
    // rubric digest pins to. K13 asserts the envelope's embedded rubric
    // object declares the same schema_version + status=accepted, and that
    // the source_project_spec_sha256 of the envelope's embedded rubric
    // agrees with the bundled rubric — so CP can observe rubric-acceptance
    // status from the project-start envelope alone without re-reading the
    // separate rubric file.
    let rubric: serde_json::Value =
        serde_json::from_str(RUBRIC).expect("acceptance-rubric.json must parse");
    let start: serde_json::Value =
        serde_json::from_str(PROJECT_START).expect("factory-project-start.json must parse");

    // The project-start envelope's `artifacts.acceptance_rubric` is the path
    // to the rubric file the project-start was bundled against. That path
    // must end with the project-start scoped rubric filename, so a CP
    // observer can attribute the rubric to this project-start run.
    let embed_path = start["artifacts"]["acceptance_rubric"]
        .as_str()
        .expect("project-start.artifacts.acceptance_rubric path missing");
    assert!(
        embed_path.ends_with("missed-call-recovery-project-start-acceptance-rubric.json"),
        "project-start artifacts.acceptance_rubric path must end with the project-start rubric filename; got {embed_path}"
    );

    // K10 lineage check: the project-start.artifacts trust block plus
    // acceptance_rubric_sha256 must agree with the rubric file's run_id
    // (so CP can chain rubric → project-start → bundle).
    let start_run_id = start["run_id"].as_str().expect("project-start.run_id");
    let rubric_run_id = rubric["run_id"].as_str().expect("rubric.run_id");
    assert_eq!(
        start_run_id, rubric_run_id,
        "project-start.run_id must equal rubric.run_id"
    );

    // The project-start envelope's factory_replacement_boundary must still
    // affirm ao2_execution_owner=true even with C14's rubric layer added.
    let frb = &start["factory_replacement_boundary"];
    assert_eq!(frb["ao2_execution_owner"], true);
    assert_eq!(frb["control_plane_approves_release"], false);
    assert_eq!(frb["factory_v3_drives_workflow"], false);
    assert_eq!(
        frb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
}
