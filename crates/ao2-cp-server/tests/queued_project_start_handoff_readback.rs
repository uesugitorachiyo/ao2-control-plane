//! K12 follow-up to BOARD.md Claude lane: prove the control-plane observer
//! can read C13's AO2-native queue path for greenfield project-start handoff
//! jobs. C13 introduces three new schemas on top of the K11 hermes-queue
//! handoff schema:
//!
//!   - ao2.factory-project-start-workbench-queue-submit.v1  (submit envelope)
//!   - ao2.factory-project-start-workbench-queue-entry.v1   (queue entry)
//!   - ao2.factory-project-start-workbench-queue-run-next.v1 (run-next envelope)
//!
//! Hermes submits a bounded queue request; AO2 owns queue execution and
//! emits the same `ao2.hermes-project-start-handoff.v1` block on the queue
//! entry. The K12 distinctive cross-binding: the queue entry that came out
//! of `queue-submit` (status=queued) is the same entry that `queue-run-next`
//! claims and finalizes (status running → accepted), and the final entry
//! pins to the same project_start_bundle_sha256 across three sites
//! (entry.hermes_queue_handoff, entry.project_start_result.hermes_queue_handoff,
//! entry.project_start_result.artifacts).
//!
//! Trust-boundary fields the queue must preserve verbatim across submit,
//! entry, claimed_entry, execution_contract, continuity_contract, and the
//! embedded hermes_queue_handoff block.
//!
//! Fixture origin: ao2 commit `32634f0` factory-project-run-smoke root
//! `20260528T064354Z`.

const QUEUE_SUBMIT: &str =
    include_str!("fixtures/queued-project-start-handoff/factory-queue-project-start-submit.json");
const QUEUE_RUN_NEXT: &str =
    include_str!("fixtures/queued-project-start-handoff/factory-queue-project-start-run-next.json");

#[test]
fn queue_submit_envelope_declares_workbench_queue_schema_and_observer_safe_owner() {
    let submit: serde_json::Value =
        serde_json::from_str(QUEUE_SUBMIT).expect("queue submit envelope must parse");

    assert_eq!(
        submit["schema_version"], "ao2.factory-project-start-workbench-queue-submit.v1",
        "C13 introduces the workbench-queue submit schema"
    );
    assert_eq!(
        submit["status"], "queued",
        "C13 submit must report queued as the initial post-submit state"
    );
    assert_eq!(
        submit["job_kind"], "factory_project_start",
        "C13 submit must carry job_kind=factory_project_start"
    );
    assert_eq!(
        submit["ao2_decision_owner"], "ao2-workbench-queue",
        "AO2 owns the queue decision — not Hermes, not CP, not factory-v3"
    );

    // Observer-safe top-level trust fields on the submit envelope itself
    // (separate from the embedded entry).
    assert_eq!(
        submit["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(submit["factory_v3_role"], "parity_oracle_only");
    assert_eq!(
        submit["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );

    // The queue path must point at a `.ao2/factory-compat/queue.json` —
    // AO2-owned bookkeeping, not Hermes-owned or CP-owned.
    let qp = submit["queue_path"].as_str().expect("queue_path");
    assert!(
        qp.contains(".ao2/factory-compat/queue.json"),
        "queue_path must live under AO2-owned .ao2/factory-compat/queue.json"
    );
}

#[test]
fn queue_entry_schema_carries_execution_contract_with_observer_safe_boundaries() {
    let submit: serde_json::Value =
        serde_json::from_str(QUEUE_SUBMIT).expect("queue submit envelope must parse");
    let entry = &submit["entry"];

    assert_eq!(
        entry["schema_version"], "ao2.factory-project-start-workbench-queue-entry.v1",
        "C13 introduces the workbench-queue entry schema"
    );
    assert_eq!(
        entry["status"], "queued",
        "submit-time entry status must be queued"
    );
    assert_eq!(entry["job_kind"], "factory_project_start");
    assert_eq!(entry["attempts"], 0);

    let ec = &entry["execution_contract"];
    assert_eq!(
        ec["job_kind"], "factory_project_start",
        "execution_contract must agree with entry.job_kind"
    );
    assert_eq!(ec["execution_owner"], "ao2");
    assert_eq!(ec["control_plane_approves_release"], false);
    assert_eq!(ec["mutates_ao_artifacts"], false);
    assert_eq!(
        ec["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(ec["factory_v3_role"], "parity_oracle_only");
    assert_eq!(
        ec["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        ec["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );

    // C13 parity checklist must affirm AO2 ownership of the queue and the
    // queue execution capability — and explicitly deny factory-v3 driving
    // the workflow. This is the surface CP needs to read to know the AO2
    // replacement of factory-v3 covers the queue path.
    let pcp = &entry["parity_checklist_progress"];
    assert_eq!(pcp["ao2_queue_owner"], "ao2-workbench-queue");
    assert_eq!(pcp["ao2_persists_queue_history_cancel_retry_state"], true);
    assert_eq!(pcp["ao2_queue_executes_project_start_handoff_job"], true);
    assert_eq!(pcp["factory_v3_drives_workflow"], false);

    // Project-start request must pin the spec by sha256 so the queue can be
    // audited against a specific spec source — a malicious AO2 cannot swap
    // the spec after submission without contradicting this digest.
    let psr = &entry["project_start_request"];
    let spec_sha = psr["project_spec_sha256"]
        .as_str()
        .expect("project_spec_sha256 missing");
    assert_eq!(
        spec_sha.len(),
        64,
        "project_spec_sha256 must be a hex sha256"
    );
    assert_eq!(psr["provider"], "scripted");
    assert_eq!(psr["verifier_command"], "true");
    assert!(
        psr["signing_key"]
            .as_str()
            .is_some_and(|s| s.ends_with(".pem")),
        "signing_key must point at a local pem file (no API-key/secret bearer)"
    );
}

#[test]
fn queue_run_next_envelope_declares_run_next_schema_and_progresses_to_accepted() {
    let runnext: serde_json::Value =
        serde_json::from_str(QUEUE_RUN_NEXT).expect("queue run-next envelope must parse");

    assert_eq!(
        runnext["schema_version"], "ao2.factory-project-start-workbench-queue-run-next.v1",
        "C13 introduces the workbench-queue run-next schema"
    );
    assert_eq!(
        runnext["status"], "accepted",
        "run-next final status must be accepted after AO2 executes the job"
    );
    assert_eq!(
        runnext["ao2_decision_owner"], "ao2-workbench-queue",
        "AO2 still owns the decision after run-next"
    );

    let claimed = &runnext["claimed_entry"];
    assert_eq!(
        claimed["schema_version"], "ao2.factory-project-start-workbench-queue-entry.v1",
        "claimed_entry uses the queue-entry schema"
    );
    assert_eq!(
        claimed["status"], "running",
        "claimed_entry captures the entry mid-execution (status=running)"
    );

    let entry = &runnext["entry"];
    assert_eq!(
        entry["schema_version"], "ao2.factory-project-start-workbench-queue-entry.v1",
        "final entry also uses the queue-entry schema"
    );
    assert_eq!(
        entry["status"], "accepted",
        "final entry status must be accepted after successful execution"
    );

    // Transition history must show queued → running → accepted on the
    // final entry. The claimed_entry has only queued → running.
    let claimed_hist = claimed["transition_history"]
        .as_array()
        .expect("claimed_entry.transition_history");
    let entry_hist = entry["transition_history"]
        .as_array()
        .expect("entry.transition_history");
    assert_eq!(claimed_hist.len(), 2);
    assert_eq!(claimed_hist[0]["status"], "queued");
    assert_eq!(claimed_hist[1]["status"], "running");
    assert!(
        entry_hist.len() >= 3,
        "final entry transition_history must include at least queued, running, accepted"
    );
    let final_statuses: Vec<&str> = entry_hist
        .iter()
        .filter_map(|t| t["status"].as_str())
        .collect();
    assert!(final_statuses.contains(&"queued"));
    assert!(final_statuses.contains(&"running"));
    assert!(final_statuses.contains(&"accepted"));
}

#[test]
fn queue_continuity_contract_keeps_history_under_ao2_not_hermes_or_factory_v3() {
    let runnext: serde_json::Value =
        serde_json::from_str(QUEUE_RUN_NEXT).expect("queue run-next envelope must parse");
    let cc = &runnext["continuity_contract"];

    assert_eq!(
        cc["cancel_retry_state_owner"], "ao2-workbench-queue",
        "cancel/retry state must be owned by AO2, not Hermes"
    );
    assert_eq!(
        cc["history_owner"], "ao2",
        "queue history must be owned by AO2"
    );
    assert_eq!(
        cc["factory_v3_drives_workflow"], false,
        "factory-v3 must not drive the queue workflow"
    );
    assert_eq!(
        cc["hermes_role"], "front_end_scheduler_queue_and_memory_bookkeeping",
        "Hermes role inside continuity contract must stay front-end/scheduler-only"
    );
    assert_eq!(
        cc["survives_server_restart"], true,
        "queue must persist across restarts so a queued job is not lost"
    );
}

#[test]
fn submit_and_run_next_pin_the_same_run_id_and_request() {
    // Cross-envelope continuity: submit's entry.run_id is the same job
    // run-next claims and finalizes. The project_start_request must
    // survive byte-for-byte from submit to run-next claimed_entry, so a
    // malicious AO2 cannot rewrite the request between submission and
    // execution.
    let submit: serde_json::Value =
        serde_json::from_str(QUEUE_SUBMIT).expect("queue submit envelope must parse");
    let runnext: serde_json::Value =
        serde_json::from_str(QUEUE_RUN_NEXT).expect("queue run-next envelope must parse");

    let submit_run_id = submit["run_id"].as_str().expect("submit run_id");
    assert_eq!(
        submit_run_id,
        runnext["run_id"].as_str().expect("run-next run_id"),
        "top-level run_id must match between submit and run-next"
    );
    assert_eq!(
        submit_run_id,
        submit["entry"]["run_id"]
            .as_str()
            .expect("submit entry run_id")
    );
    assert_eq!(
        submit_run_id,
        runnext["claimed_entry"]["run_id"]
            .as_str()
            .expect("claimed_entry run_id")
    );
    assert_eq!(
        submit_run_id,
        runnext["entry"]["run_id"]
            .as_str()
            .expect("run-next entry run_id")
    );

    // project_start_request preservation: byte-for-byte equal between
    // submit.entry.project_start_request, run-next.claimed_entry.project_start_request,
    // and run-next.entry.project_start_request.
    let submit_req = &submit["entry"]["project_start_request"];
    let claimed_req = &runnext["claimed_entry"]["project_start_request"];
    let entry_req = &runnext["entry"]["project_start_request"];
    assert_eq!(
        submit_req, claimed_req,
        "project_start_request was tampered between submit and claim"
    );
    assert_eq!(
        submit_req, entry_req,
        "project_start_request was tampered between submit and final entry"
    );

    // The queue_path must agree too — only one queue file is touched.
    assert_eq!(
        submit["queue_path"], runnext["queue_path"],
        "queue_path drift between submit and run-next means a different queue was touched"
    );
}

#[test]
fn final_entry_carries_hermes_queue_handoff_pinned_to_k11_schema() {
    // After AO2 executes the job, the final queue entry carries an embedded
    // ao2.hermes-project-start-handoff.v1 block — the same K11 surface that
    // Hermes/queue consumers read. K12 asserts the embedded block matches
    // K11's contract and its project_start_bundle_sha256 matches the
    // result's bundle digest at all three sites.
    let runnext: serde_json::Value =
        serde_json::from_str(QUEUE_RUN_NEXT).expect("queue run-next envelope must parse");
    let entry = &runnext["entry"];
    let psr = &entry["project_start_result"];

    let entry_h = &entry["hermes_queue_handoff"];
    let psr_h = &psr["hermes_queue_handoff"];

    assert_eq!(
        entry_h["schema_version"], "ao2.hermes-project-start-handoff.v1",
        "K12 must embed the K11 hermes-queue handoff schema on the final entry"
    );
    assert_eq!(
        psr_h["schema_version"], "ao2.hermes-project-start-handoff.v1",
        "project_start_result must also carry the K11 hermes-queue handoff schema"
    );
    assert_eq!(entry_h["status"], "ready");
    assert_eq!(psr_h["status"], "ready");

    let entry_sha = entry_h["project_start_bundle_sha256"]
        .as_str()
        .expect("entry.hermes_queue_handoff.project_start_bundle_sha256");
    let psr_sha = psr_h["project_start_bundle_sha256"]
        .as_str()
        .expect("psr.hermes_queue_handoff.project_start_bundle_sha256");
    let psr_artifacts_sha = psr["artifacts"]["project_start_bundle_sha256"]
        .as_str()
        .expect("psr.artifacts.project_start_bundle_sha256");
    let entry_sha_outer = entry["project_start_bundle_sha256"]
        .as_str()
        .expect("entry.project_start_bundle_sha256");

    assert_eq!(entry_sha, psr_sha);
    assert_eq!(entry_sha, psr_artifacts_sha);
    assert_eq!(entry_sha, entry_sha_outer);

    // Role wording must stay observer-safe (verbatim K11).
    assert_eq!(
        entry_h["hermes_role"],
        "front_end_queue_cron_memory_bookkeeping_only"
    );
    assert_eq!(
        entry_h["ao2_role"],
        "canonical_project_start_and_evidence_producer"
    );
    assert_eq!(entry_h["handoff_entry"], "handoff.json");
    assert_eq!(entry_h["manifest_entry"], "manifest.json");
    assert_eq!(entry_h["checksum_entry"], "SHA256SUMS");
}

#[test]
fn final_entry_project_start_result_preserves_k3_through_k11_lineage() {
    // The C13 queue's final entry embeds a full project_start_result that
    // mirrors C11/C12's factory-project-start envelope. K12 asserts the
    // lineage anchors K3-K11 cover (plan, validation, run, run-state,
    // release-review tarball, per-index app-run bundles) are all present
    // with consistent sha256 across artifacts and the inline bundle index,
    // and that the factory_replacement_boundary still affirms AO2
    // execution ownership.
    let runnext: serde_json::Value =
        serde_json::from_str(QUEUE_RUN_NEXT).expect("queue run-next envelope must parse");
    let psr = &runnext["entry"]["project_start_result"];

    assert_eq!(
        psr["schema_version"], "ao2.factory-project-start.v1",
        "project_start_result declares the factory-project-start schema"
    );
    assert_eq!(psr["status"], "accepted");
    assert_eq!(psr["failed_step_count"], 0);
    assert_eq!(psr["app_run_count"], 2);
    assert_eq!(psr["step_count"], 2);

    let frb = &psr["factory_replacement_boundary"];
    assert_eq!(frb["ao2_execution_owner"], true);
    assert_eq!(frb["factory_v3_drives_workflow"], false);
    assert_eq!(frb["control_plane_approves_release"], false);
    assert_eq!(frb["mutates_ao_artifacts"], false);
    assert_eq!(frb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(
        frb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        frb["provider_auth"],
        "local OAuth CLI only; API-key provider auth forbidden"
    );

    // checks block must match K10/K11 envelope (four upstream layers
    // accepted) so the queue cannot claim "accepted" while upstream is
    // not.
    let checks = &psr["checks"];
    assert_eq!(checks["project_plan_status"], "accepted");
    assert_eq!(checks["project_plan_validation_status"], "accepted");
    assert_eq!(checks["project_run_status"], "accepted");
    assert_eq!(checks["release_review_package_ready"], true);

    // K3-K10 lineage anchors must be present with 64-char hex sha256 each.
    let artifacts = &psr["artifacts"];
    for field in [
        "project_plan_sha256",
        "project_plan_validation_sha256",
        "factory_project_run_sha256",
        "factory_project_run_state_sha256",
        "release_review_package_sha256",
        "project_start_bundle_sha256",
    ] {
        let v = artifacts[field]
            .as_str()
            .unwrap_or_else(|| panic!("artifacts.{field} missing"));
        assert_eq!(v.len(), 64, "{field} must be 64-char hex sha256");
    }

    // Per-index app-run bundles still come through with their digests so CP
    // can pin K3/K5 lineage through the queued path.
    let app_run_bundles = artifacts["app_run_bundles"]
        .as_array()
        .expect("artifacts.app_run_bundles");
    assert_eq!(app_run_bundles.len(), 2);
    for (i, arb) in app_run_bundles.iter().enumerate() {
        assert_eq!(arb["index"], i);
        assert_eq!(
            arb["bundle_sha256"].as_str().map(str::len),
            Some(64),
            "app_run_bundles[{i}].bundle_sha256 must be 64-char hex sha256"
        );
        assert!(
            arb["run_id"].as_str().is_some_and(|s| s.contains("queued")),
            "queued path's app-run run_id must include 'queued' marker"
        );
    }
}
