use super::{provider_acceptance_is_live_passed, view::json_str, RELEASE_ASSEMBLY_SCHEMA};

pub(super) fn release_assembly_value(
    readiness: &serde_json::Value,
    handoff: &serde_json::Value,
) -> serde_json::Value {
    let release = handoff.get("release").unwrap_or(&serde_json::Value::Null);
    let artifacts = handoff.get("artifacts").unwrap_or(&serde_json::Value::Null);
    let acceptance = handoff
        .get("acceptance")
        .unwrap_or(&serde_json::Value::Null);
    let candidate_correlation = handoff
        .get("candidate_correlation")
        .unwrap_or(&serde_json::Value::Null);
    let operator_handoff = handoff
        .get("operator_handoff")
        .unwrap_or(&serde_json::Value::Null);
    let release_candidate_version = json_str(release, "version").unwrap_or("unknown");

    let required_artifacts = vec![
        release_assembly_artifact(
            "release_publication",
            "Release publication summary",
            artifact_sha(artifacts, "release_publication"),
            json_str(release, "raw_url").unwrap_or("missing"),
            release_candidate_version,
        ),
        release_assembly_artifact(
            "phase1_checklist",
            "Factory Phase 1 promotion checklist",
            artifact_sha(artifacts, "phase1_checklist"),
            artifact_url(artifacts, "phase1_checklist", "raw_url"),
            release_candidate_version,
        ),
        release_assembly_artifact(
            "phase1_decision",
            "Signed Factory Phase 1 promotion decision",
            artifact_sha(artifacts, "phase1_decision"),
            artifact_url(artifacts, "phase1_decision", "raw_url"),
            release_candidate_version,
        ),
        release_assembly_artifact(
            "three_os_smoke",
            "Mac, Ubuntu, and Windows release smoke proof",
            artifact_sha(artifacts, "three_os_smoke"),
            artifact_url(artifacts, "three_os_smoke", "raw_url"),
            json_str(candidate_correlation, "three_os_version").unwrap_or("unknown"),
        ),
        release_assembly_provider_acceptance("provider_acceptance_codex", "Codex", acceptance),
        release_assembly_provider_acceptance("provider_acceptance_claude", "Claude", acceptance),
    ];

    let readiness_status = json_str(readiness, "status").unwrap_or("attention");
    let handoff_status = json_str(handoff, "status").unwrap_or("attention");
    let correlation_status = json_str(candidate_correlation, "status").unwrap_or("mismatched");
    let assembly_blockers =
        release_assembly_blockers(readiness_status, handoff_status, candidate_correlation);
    let artifact_sha256s = serde_json::json!({
        "release_publication": artifact_sha(artifacts, "release_publication"),
        "phase1_checklist": artifact_sha(artifacts, "phase1_checklist"),
        "phase1_decision": artifact_sha(artifacts, "phase1_decision"),
        "three_os_smoke": artifact_sha(artifacts, "three_os_smoke"),
    });

    serde_json::json!({
        "schema_version": RELEASE_ASSEMBLY_SCHEMA,
        "status": if readiness_status == "ready"
            && handoff_status == "ready"
            && correlation_status == "matched"
        {
            "assembled"
        } else {
            "attention"
        },
        "release_candidate_version": release_candidate_version,
        "release_tag": json_str(release, "release_tag").unwrap_or("unknown"),
        "candidate_correlation": correlation_status,
        "candidate_correlation_detail": candidate_correlation,
        "artifact_sha256s": artifact_sha256s,
        "required_artifacts": required_artifacts,
        "assembly_blockers": assembly_blockers,
        "release_acceptance_owner": json_str(operator_handoff, "release_acceptance_owner")
            .unwrap_or("factory-v3 evaluator-closer"),
        "control_plane_role": "read_only_observer",
        "control_plane_approves_release": false,
        "mutates_ao_artifacts": false,
        "next_action": if readiness_status == "ready"
            && handoff_status == "ready"
            && correlation_status == "matched"
        {
            "factory-v3 evaluator-closer reviews this assembled same-candidate bundle before release-line acceptance"
        } else if correlation_status != "matched" {
            same_candidate_republish_action()
        } else {
            "resolve readiness or handoff gaps before assembling a release-line handoff"
        },
    })
}

fn release_assembly_blockers(
    readiness_status: &str,
    handoff_status: &str,
    candidate_correlation: &serde_json::Value,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if readiness_status != "ready" {
        blockers.push(format!(
            "release_readiness: expected ready, observed {readiness_status}"
        ));
    }
    if handoff_status != "ready" {
        blockers.push(format!(
            "release_candidate_handoff: expected ready, observed {handoff_status}"
        ));
    }
    if json_str(candidate_correlation, "status") != Some("matched") {
        if let Some(correlation_blockers) = candidate_correlation
            .get("blockers")
            .and_then(serde_json::Value::as_array)
        {
            for blocker in correlation_blockers {
                if let Some(blocker) = blocker.as_str() {
                    blockers.push(format!("candidate_correlation: {blocker}"));
                }
            }
        }
        if !blockers
            .iter()
            .any(|blocker| blocker.starts_with("candidate_correlation:"))
        {
            blockers.push(format!(
                "candidate_correlation: expected matched, observed {}",
                json_str(candidate_correlation, "status").unwrap_or("missing")
            ));
        }
    }
    blockers
}

fn release_assembly_artifact(
    id: &str,
    label: &str,
    sha256: &str,
    raw_url: &str,
    release_candidate_version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "label": label,
        "sha256": sha256,
        "raw_url": raw_url,
        "release_candidate_version": release_candidate_version,
        "status": if sha256 == "missing" { "missing" } else { "observed" },
    })
}

fn release_assembly_provider_acceptance(
    id: &str,
    label: &str,
    acceptance: &serde_json::Value,
) -> serde_json::Value {
    let provider_key = if id.ends_with("codex") {
        "codex"
    } else {
        "claude"
    };
    let provider = acceptance
        .get(provider_key)
        .unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "id": id,
        "label": format!("{label} live provider acceptance"),
        "sha256": json_str(provider, "sha256").unwrap_or("missing"),
        "raw_url": json_str(provider, "raw_url").unwrap_or("missing"),
        "release_candidate_version": json_str(provider, "release_candidate_version").unwrap_or("unknown"),
        "source_class": json_str(provider, "source_class").unwrap_or("missing"),
        "status": if provider_acceptance_is_live_passed(provider) { "observed" } else { "attention" },
    })
}

fn artifact_sha<'a>(artifacts: &'a serde_json::Value, id: &str) -> &'a str {
    artifacts
        .get(id)
        .and_then(|artifact| json_str(artifact, "sha256"))
        .unwrap_or("missing")
}

fn artifact_url<'a>(artifacts: &'a serde_json::Value, id: &str, key: &str) -> &'a str {
    artifacts
        .get(id)
        .and_then(|artifact| json_str(artifact, key))
        .unwrap_or("missing")
}

pub(super) fn install_verification_trust_value(
    artifact: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(artifact) = artifact else {
        return serde_json::json!({
            "schema_version": "missing",
            "status": "missing",
            "offline_verification_status": "missing",
            "path": "missing",
            "sha256": "missing",
            "provider_api_keys_required": false,
            "control_plane_approves_release": false,
            "mutates_ao_artifacts": false,
        });
    };

    serde_json::json!({
        "schema_version": json_str(artifact, "schema_version").unwrap_or("missing"),
        "status": json_str(artifact, "status").unwrap_or("missing"),
        "offline_verification_status": artifact
            .get("offline_verification")
            .and_then(|offline| json_str(offline, "status"))
            .unwrap_or("missing"),
        "path": json_str(artifact, "path").unwrap_or("missing"),
        "sha256": json_str(artifact, "sha256").unwrap_or("missing"),
        "provider_api_keys_required": artifact
            .get("provider_api_keys_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "control_plane_approves_release": artifact
            .get("control_plane_approves_release")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "mutates_ao_artifacts": artifact
            .get("mutates_ao_artifacts")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
    })
}

pub(super) fn hosted_release_smoke_value(
    install_verification: &serde_json::Value,
) -> serde_json::Value {
    let install_schema = json_str(install_verification, "schema_version").unwrap_or("missing");
    let install_status = json_str(install_verification, "status").unwrap_or("missing");
    let offline_status =
        json_str(install_verification, "offline_verification_status").unwrap_or("missing");
    let provider_api_keys_required = install_verification
        .get("provider_api_keys_required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let control_plane_approves_release = install_verification
        .get("control_plane_approves_release")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let mutates_ao_artifacts = install_verification
        .get("mutates_ao_artifacts")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let passed = install_schema == "ao2.install-verification-evidence.v1"
        && install_status == "verified"
        && offline_status == "verified"
        && !provider_api_keys_required
        && !control_plane_approves_release
        && !mutates_ao_artifacts;

    serde_json::json!({
        "schema_version": "ao2.release-archive-hosted-smoke.v1",
        "status": if passed { "passed" } else { "failed" },
        "target": "release-archive-hosted-smoke",
        "install_verification_schema": install_schema,
        "install_verification_evidence": json_str(install_verification, "path").unwrap_or("missing"),
        "provider_api_keys_required": provider_api_keys_required,
        "control_plane_approves_release": control_plane_approves_release,
        "mutates_ao_artifacts": mutates_ao_artifacts,
        "release_acceptance_owner": "factory-v3 evaluator-closer",
    })
}

pub(super) fn install_verification_readiness_observed(install: &serde_json::Value) -> String {
    if json_str(install, "schema_version") == Some("ao2.install-verification-evidence.v1")
        && json_str(install, "status") == Some("verified")
        && json_str(install, "offline_verification_status") == Some("verified")
        && install
            .get("provider_api_keys_required")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && install
            .get("control_plane_approves_release")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && install
            .get("mutates_ao_artifacts")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && json_str(install, "path") != Some("missing")
        && json_str(install, "sha256") != Some("missing")
    {
        "verified/offline_verified/read_only".to_string()
    } else {
        json_str(install, "status").unwrap_or("missing").to_string()
    }
}

pub(super) fn release_readiness_gate(
    id: &str,
    label: &str,
    observed: &str,
    expected: &str,
) -> serde_json::Value {
    release_readiness_gate_with_detail(id, label, observed, expected, None)
}

pub(super) fn release_readiness_gate_with_detail(
    id: &str,
    label: &str,
    observed: &str,
    expected: &str,
    detail: Option<&serde_json::Value>,
) -> serde_json::Value {
    let status = if observed == expected {
        "passed"
    } else {
        "blocked"
    };
    let mut value = serde_json::json!({
        "id": id,
        "label": label,
        "observed": observed,
        "expected": expected,
        "status": status,
    });
    if status != "passed" {
        if let Some(detail) = detail {
            value["detail"] = detail.clone();
        }
        if id == "candidate_correlation" {
            value["next_action"] = serde_json::json!(same_candidate_republish_action());
        }
    }
    value
}

pub(super) fn same_candidate_republish_action() -> &'static str {
    "republish same-candidate release, evaluator, provider acceptance, and three-OS evidence before factory-v3 evaluator-closer review"
}

pub(super) fn provider_acceptance_readiness(entry: &serde_json::Value) -> &'static str {
    if provider_acceptance_is_live_passed(entry) {
        "passed/live"
    } else {
        "attention"
    }
}
