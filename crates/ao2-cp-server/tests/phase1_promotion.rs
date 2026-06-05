use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use std::sync::Arc;
use tempfile::tempdir;

const CODEX_FIXTURE: &str = include_str!("../../../tests/fixtures/codex-acceptance-v0.4.66.json");
const CLAUDE_FIXTURE: &str = include_str!("../../../tests/fixtures/claude-acceptance-v0.4.66.json");
const TEST_API_TOKEN: &str = "redacted-value";

fn test_auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

async fn spawn_server() -> (String, tempfile::TempDir) {
    spawn_server_with_trusted_keys(Vec::new()).await
}

async fn spawn_server_with_trusted_keys(
    signed_artifact_trusted_key_sha256s: Vec<String>,
) -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s,
        metrics: std::sync::Arc::new(Metrics::new()),
        audit_log: std::sync::Arc::new(ao2_cp_server::audit_log::AuditLog::default()),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), dir)
}

#[tokio::test]
async fn phase1_operator_support_bundle_empty_index_uses_explicit_epoch_fallback_source() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let download = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/download"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    let download_sha = download
        .headers()
        .get("x-ao2-cp-support-bundle-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let download_bytes = download.bytes().await.unwrap();
    let downloaded_body: serde_json::Value = serde_json::from_slice(&download_bytes).unwrap();
    assert_eq!(downloaded_body["generated_at"], "1970-01-01T00:00:00Z");
    assert_eq!(
        downloaded_body["generated_at_source"],
        "no_observed_phase1_index_entry_epoch_fallback"
    );

    let checksums = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(checksums.status(), 200);
    let checksums_text = checksums.text().await.unwrap();
    let checksum_line = checksums_text
        .lines()
        .find(|line| line.ends_with("  ao2-phase1-operator-support-bundle.json"))
        .expect("checksums include operator support bundle filename");
    let (checksum_sha, _) = checksum_line
        .split_once("  ")
        .expect("checksums line uses sha256sum-compatible spacing");
    assert_eq!(checksum_sha, download_sha);

    let manifest = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(manifest.status(), 200);
    let manifest_body: serde_json::Value = manifest.json().await.unwrap();
    assert_eq!(manifest_body["artifacts"][0]["sha256"], download_sha);
    assert_eq!(
        manifest_body["artifacts"][0]["size_bytes"],
        serde_json::json!(download_bytes.len())
    );
}

fn provider_phase1_readiness_fixture() -> String {
    serde_json::json!({
        "schema": "factory-v3/hermes-provider-phase1-readiness/v1",
        "status": "passed",
        "live_provider_policy": "not_run_by_default",
        "required_live_provider_pilots": [],
        "contracts": {
            "codex": {"status": "verified"},
            "claude": {"status": "verified"},
            "antigravity": {"status": "verified"}
        },
        "scripted_gate": {"verdict": "ready"},
        "codex_gate": {"verdict": "not_ready"},
        "codex_pilot": {"status": "blocked"}
    })
    .to_string()
}

fn live_acceptance_fixture(raw: &str, provider: &str) -> String {
    raw.replace(
        r#""root": "<root>""#,
        &format!(r#""root": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/{provider}""#),
    )
    .replace(
        r#""target": "<target>""#,
        &format!(
            r#""target": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/{provider}/discount-service""#
        ),
    )
    .replace(
        r#""evidence_pack": "<evidence>""#,
        &format!(
            r#""evidence_pack": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/{provider}/discount-service/.ao2/runs/live-{provider}-provider-pilot/evidence-pack/evidence-pack.json""#
        ),
    )
}

fn phase1_promotion_checklist_fixture() -> String {
    serde_json::json!({
        "schema": "factory-v3/ao2-phase1-promotion-checklist/v1",
        "status": "passed",
        "phase1_state": "phase1_candidate_ready",
        "next_action": "operator release-line decision",
        "checklist": {
            "provider_readiness": {
                "status": "superseded_by_live_acceptance",
                "phase1_state": "blocked",
                "superseded_by": "live_provider_acceptance"
            },
            "live_provider_acceptance": {
                "status": "passed",
                "state": "live_acceptance_complete",
                "codex": "passed",
                "claude": "passed",
                "source_class": "live"
            },
            "release_gate": {
                "status": "passed",
                "state": "dry_run_passed"
            },
            "three_os_smoke": {
                "status": "passed",
                "local_smoke": "passed",
                "linux_x86_64_remote_smoke": "passed",
                "windows_native_smoke": "passed",
                "native_windows_required": true
            }
        }
    })
    .to_string()
}

fn phase1_promotion_inputs_verification_fixture() -> String {
    serde_json::json!({
        "schema_version": "ao2.phase1-replacement-promotion-inputs-verification.v1",
        "status": "accepted",
        "mode": "decision_gate",
        "manifest_path": "/work/ao2/target/phase1-replacement-promotion/promotion-inputs.json",
        "missing_required_inputs": [],
        "failure_count": 0,
        "failures": [],
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "control_plane_approves_release": false
        }
    })
    .to_string()
}

fn three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "report": "/work/ao2-control-plane/target/three-os-release-smoke/report.md",
        "root": "/work/ao2-control-plane/target/three-os-release-smoke",
        "remote_command_files": {
            "ubuntu": "/work/ao2-control-plane/target/three-os-release-smoke/ubuntu-command.sh",
            "windows": "/work/ao2-control-plane/target/three-os-release-smoke/windows-command.ps1"
        },
        "rerun_commands": {
            "all_required": "AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh",
            "macos_only": "AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh"
        },
        "targets": {
            "macos": {
                "status": "passed",
                "log": "/work/ao2-control-plane/target/three-os-release-smoke/macos.log"
            },
            "ubuntu": {
                "status": "passed",
                "log": "/work/ao2-control-plane/target/three-os-release-smoke/ubuntu.log"
            },
            "windows": {
                "status": "passed",
                "log": "/work/ao2-control-plane/target/three-os-release-smoke/windows.log"
            }
        }
    })
    .to_string()
}

fn phase1_promotion_decision_fixture(checklist_sha: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "factory-v3/ao2-phase1-promotion-decision/v1",
        "status": "passed",
        "decision": "promote_phase1_candidate",
        "phase1_state": "phase1_candidate_ready",
        "checklist_sha256": checklist_sha,
        "operator": "release-lead",
        "rationale": "All required Phase 1 checklist evidence is present and observed.",
        "artifacts": {
            "phase1_promotion_checklist": "/factory/docs/status/hermes-nightly-ao2/phase1-promotion-checklist.json"
        }
    })
}

/// Generate a fresh RSA-2048 signing key for phase-1 promotion decision
/// fixtures, returning the signer, its public-key PEM, and the SHA-256 of
/// that PEM — the value an operator would pin in the trusted-key allowlist.
fn phase1_promotion_decision_signer() -> (rsa::pkcs1v15::SigningKey<Sha256>, String, String) {
    let mut rng = rsa::rand_core::OsRng;
    let signing_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_pem = signing_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let public_key_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(public_key_pem.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    (
        rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key),
        public_key_pem,
        public_key_sha256,
    )
}

/// Build a signed phase-1 promotion decision upload using a caller-supplied
/// signer, so a test can pin the signing key's SHA-256 in the trusted-key
/// allowlist before the decision is produced.
fn signed_phase1_promotion_decision_fixture_with_signer(
    decision: serde_json::Value,
    tamper_signature: bool,
    signer: &rsa::pkcs1v15::SigningKey<Sha256>,
    public_key_pem: &str,
) -> serde_json::Value {
    let decision_raw = serde_json::to_string_pretty(&decision).unwrap();
    let mut signature = signer.sign(decision_raw.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let signature_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&signature);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let public_key_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(public_key_pem.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::json!({
        "schema_version": "ao2.cp-phase1-promotion-decision-signed-upload.v1",
        "decision": decision,
        "signature": {
            "schema_version": "ao2.cp-phase1-promotion-decision-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "release-lead",
            "signature_sha256": signature_sha256,
            "signature_hex": signature_hex,
            "public_key_sha256": public_key_sha256,
            "public_key_pem": public_key_pem
        }
    })
}

fn signed_phase1_promotion_decision_fixture_over_exact_bytes_with_signer(
    signed_bytes: &str,
    tamper_signature: bool,
    signer: &rsa::pkcs1v15::SigningKey<Sha256>,
    public_key_pem: &str,
) -> serde_json::Value {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    let decision: serde_json::Value = serde_json::from_str(signed_bytes).unwrap();
    let mut signature = signer.sign(signed_bytes.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let signature_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&signature);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let public_key_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(public_key_pem.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::json!({
        "schema_version": "ao2.cp-phase1-promotion-decision-signed-upload.v1",
        "decision": decision,
        "decision_b64": BASE64_STANDARD.encode(signed_bytes.as_bytes()),
        "signature": {
            "schema_version": "ao2.cp-phase1-promotion-decision-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "release-lead",
            "signature_sha256": signature_sha256,
            "signature_hex": signature_hex,
            "public_key_sha256": public_key_sha256,
            "public_key_pem": public_key_pem
        }
    })
}

fn signed_phase1_promotion_decision_fixture(
    decision: serde_json::Value,
    tamper_signature: bool,
) -> serde_json::Value {
    let (signer, public_key_pem, _) = phase1_promotion_decision_signer();
    signed_phase1_promotion_decision_fixture_with_signer(
        decision,
        tamper_signature,
        &signer,
        &public_key_pem,
    )
}

#[tokio::test]
async fn signed_phase1_promotion_decision_verifies_over_exact_decision_b64_bytes() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();
    let decision = phase1_promotion_decision_fixture(checklist_sha);
    let signed_bytes = serde_json::to_string(&decision).unwrap();
    let (signer, public_key_pem, _) = phase1_promotion_decision_signer();
    let upload = signed_phase1_promotion_decision_fixture_over_exact_bytes_with_signer(
        &signed_bytes,
        false,
        &signer,
        &public_key_pem,
    );

    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&upload)
        .send()
        .await
        .unwrap();

    assert_eq!(
        post.status(),
        200,
        "signed phase1 decision must verify over decision_b64 exact bytes"
    );
}

#[tokio::test]
async fn signed_phase1_promotion_decision_stores_exact_decision_b64_bytes() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();
    let decision = phase1_promotion_decision_fixture(checklist_sha);
    let signed_bytes = serde_json::to_string(&decision).unwrap();
    let (signer, public_key_pem, _) = phase1_promotion_decision_signer();
    let mut upload = signed_phase1_promotion_decision_fixture_over_exact_bytes_with_signer(
        &signed_bytes,
        false,
        &signer,
        &public_key_pem,
    );
    upload["decision"]["rationale"] =
        serde_json::Value::String("attacker-controlled-not-signed".to_string());

    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        200,
        "decision_b64 must be the trusted content when parallel decision diverges"
    );
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let stored = client
        .get(format!("{base}/api/v1/phase1/promotion/decision/{sha}"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(stored.status(), 200);
    let stored_body = stored.text().await.unwrap();
    assert_eq!(stored_body, signed_bytes);
    assert!(!stored_body.contains("attacker-controlled-not-signed"));
}

#[tokio::test]
async fn phase1_promotion_dashboard_correlates_readiness_acceptance_and_external_gates() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let readiness = client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", test_auth_header())
        .body(provider_phase1_readiness_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);

    for fixture in [
        live_acceptance_fixture(CODEX_FIXTURE, "codex"),
        live_acceptance_fixture(CLAUDE_FIXTURE, "claude"),
        live_acceptance_fixture(
            &CLAUDE_FIXTURE
                .replace(
                    "ao2.claude-provider-pilot-acceptance.v1",
                    "ao2.antigravity-provider-pilot-acceptance.v1",
                )
                .replace("\"provider\": \"claude\"", "\"provider\": \"antigravity\"")
                .replace("claude", "antigravity"),
            "antigravity",
        ),
    ] {
        let response = client
            .post(format!("{base}/api/v1/acceptance"))
            .header("authorization", test_auth_header())
            .body(fixture)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    let dashboard_json = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();

    assert_eq!(
        body["schema_version"],
        "ao2.cp-phase1-promotion-dashboard.v1"
    );
    assert_eq!(body["state"], "release_gate_ready");
    assert_eq!(
        body["checklist"]["provider_readiness"]["status"],
        "superseded_by_live_acceptance"
    );
    assert_eq!(
        body["checklist"]["provider_readiness"]["phase1_state"],
        "blocked"
    );
    assert_eq!(
        body["checklist"]["provider_readiness"]["superseded_by"],
        "live_provider_acceptance"
    );
    assert_eq!(
        body["checklist"]["live_provider_acceptance"]["status"],
        "passed"
    );
    assert_eq!(
        body["checklist"]["live_provider_acceptance"]["state"],
        "live_acceptance_complete"
    );
    assert_eq!(
        body["checklist"]["release_gate"]["status"],
        "external_required"
    );
    assert_eq!(
        body["checklist"]["three_os_smoke"]["status"],
        "external_required"
    );
    assert_eq!(
        body["next_action"],
        "run the guarded release gate with the latest factory-v3 three-OS evidence before Phase 1 promotion"
    );
    assert_eq!(
        body["gap_report"]["schema_version"],
        "ao2.cp-phase1-gap-report.v1"
    );
    assert_eq!(body["gap_report"]["total_open_gaps"], 2);
    assert_eq!(body["gap_report"]["blocking_gaps"][0]["id"], "release_gate");
    assert_eq!(
        body["gap_report"]["blocking_gaps"][1]["id"],
        "three_os_smoke"
    );
    assert_eq!(
        body["gap_report"]["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        body["gap_report"]["trust_boundary"]["mutates_ao_artifacts"],
        false
    );
    assert_eq!(
        body["links"]["acceptance_dashboard"],
        "/api/v1/acceptance/dashboard"
    );
    assert_eq!(
        body["links"]["gap_report_json"],
        "/api/v1/phase1/promotion/gap-report.json"
    );
    assert_eq!(
        body["links"]["gap_report_download"],
        "/api/v1/phase1/promotion/gap-report/download"
    );
    assert_eq!(
        body["links"]["gap_report_checksums"],
        "/api/v1/phase1/promotion/gap-report/SHA256SUMS"
    );

    assert!(body["candidate_correlation"].is_object());
    let phase1_correlation_status = body["candidate_correlation"]["status"]
        .as_str()
        .expect("phase1 dashboard candidate_correlation.status must be a string");
    assert!(
        ["matched", "mismatched"].contains(&phase1_correlation_status),
        "unexpected phase1 dashboard candidate_correlation status: {phase1_correlation_status}"
    );
    assert!(body["candidate_correlation"]["blockers"].is_array());

    let gap_report = client
        .get(format!("{base}/api/v1/phase1/promotion/gap-report.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(gap_report.status(), 200);
    let gap_body: serde_json::Value = gap_report.json().await.unwrap();
    assert_eq!(gap_body["schema_version"], "ao2.cp-phase1-gap-report.v1");
    assert_eq!(gap_body["state"], "release_gate_ready");
    assert_eq!(gap_body["total_open_gaps"], 2);
    assert_eq!(gap_body["blocking_gaps"][0]["id"], "release_gate");
    assert_eq!(gap_body["summary"]["blocking"], 2);
    assert_eq!(gap_body["summary"]["read_only_observer"], true);
    assert_eq!(gap_body["operator_action_queue"][0]["id"], "release_gate");
    assert_eq!(
        gap_body["operator_action_queue"][0]["owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        gap_body["operator_action_queue"][0]["control_plane_action"],
        "observe_only"
    );
    assert_eq!(gap_body["operator_action_queue"][0]["action_order"], 1);
    assert_eq!(
        gap_body["operator_action_queue"][0]["depends_on"],
        serde_json::json!([
            "provider_readiness",
            "live_provider_acceptance",
            "three_os_smoke"
        ])
    );
    assert_eq!(
        gap_body["operator_action_queue"][0]["ready_to_start"],
        false
    );
    assert_eq!(gap_body["operator_action_queue"][1]["id"], "three_os_smoke");
    assert_eq!(gap_body["operator_action_queue"][1]["action_order"], 2);
    assert_eq!(
        gap_body["operator_action_queue"][1]["depends_on"],
        serde_json::json!(["provider_readiness", "live_provider_acceptance"])
    );
    assert_eq!(gap_body["operator_action_queue"][1]["ready_to_start"], true);
    assert_eq!(gap_body["critical_path"][0]["id"], "three_os_smoke");
    assert_eq!(gap_body["critical_path"][1]["id"], "release_gate");
    assert_eq!(
        gap_body["critical_path"][1]["blocked_by_open_gaps"],
        serde_json::json!(["three_os_smoke"])
    );
    assert_eq!(gap_body["summary"]["ready_to_start_actions"], 1);
    assert_eq!(
        gap_body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );

    let gap_download = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/gap-report/download"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(gap_download.status(), 200);
    assert_eq!(
        gap_download
            .headers()
            .get("x-ao2-cp-control-plane-role")
            .and_then(|value| value.to_str().ok()),
        Some("read-only-observer")
    );
    let gap_disposition = gap_download
        .headers()
        .get("content-disposition")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(gap_disposition.contains("attachment"));
    assert!(gap_disposition.contains("ao2-phase1-gap-report.json"));
    let gap_sha = gap_download
        .headers()
        .get("x-ao2-cp-gap-report-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(gap_sha.len(), 64);
    let gap_download_bytes = gap_download.bytes().await.unwrap();
    let actual_gap_download_sha = Sha256::digest(&gap_download_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(gap_sha, actual_gap_download_sha);
    let gap_download_body: serde_json::Value = serde_json::from_slice(&gap_download_bytes).unwrap();
    assert_eq!(
        gap_download_body["schema_version"],
        "ao2.cp-phase1-gap-report.v1"
    );
    assert_eq!(gap_download_body["total_open_gaps"], 2);
    assert!(!serde_json::to_string(&gap_download_body)
        .unwrap()
        .contains("Bearer"));

    let gap_checksums = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/gap-report/SHA256SUMS"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(gap_checksums.status(), 200);
    assert_eq!(
        gap_checksums
            .headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"SHA256SUMS\"")
    );
    let gap_checksums_text = gap_checksums.text().await.unwrap();
    assert!(gap_checksums_text.contains("# schema: ao2.cp-phase1-gap-report-checksums.v1"));
    assert!(gap_checksums_text.contains("# control-plane-role: read-only-observer"));
    assert!(gap_checksums_text.contains("# release-acceptance-owner: factory-v3 evaluator-closer"));
    assert!(gap_checksums_text.contains("ao2-phase1-gap-report.json"));
    let gap_checksum_line = gap_checksums_text
        .lines()
        .find(|line| line.ends_with("  ao2-phase1-gap-report.json"))
        .expect("checksums include phase1 gap report filename");
    let (gap_checksum_sha, _) = gap_checksum_line
        .split_once("  ")
        .expect("gap checksums line uses sha256sum-compatible spacing");
    assert_eq!(gap_checksum_sha, gap_sha);
    assert!(!gap_checksums_text.contains("secret"));
    assert!(!gap_checksums_text.contains("Bearer"));

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("AO2 Phase 1 Promotion Checklist"));
    assert!(html.contains("release_gate_ready"));
    assert!(html.contains("live_acceptance_complete"));
    assert!(html.contains("external_required"));
    assert!(html.contains("Phase readiness gap report"));
    assert!(html.contains("/api/v1/phase1/promotion/gap-report.json"));
    assert!(html.contains("Open blocking gaps"));
    assert!(html.contains("release_gate"));
    assert!(html.contains("three_os_smoke"));
    assert!(html.contains("Remote smoke rerun metadata"));
    assert!(html.contains("No remote command files have been observed yet."));
    assert!(html.contains("Candidate Correlation"));
    assert!(html.contains("Release version"));
    assert!(html.contains("Three-OS smoke version"));
    assert!(html.contains("/api/v1/release/publication/dashboard"));
    assert!(!html.contains("Bearer"));
    assert!(!html.contains("secret"));

    let panel_json = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-panel.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(panel_json.status(), 200);
    let panel_body: serde_json::Value = panel_json.json().await.unwrap();
    assert_eq!(panel_body["status"], "attention");
    assert_eq!(panel_body["operator_action_queue"][0]["id"], "release_gate");
    assert_eq!(
        panel_body["operator_action_queue"][0]["owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        panel_body["operator_action_queue"][0]["control_plane_action"],
        "observe_only"
    );

    let operator_panel = client
        .get(format!("{base}/api/v1/phase1/promotion/operator-panel"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(operator_panel.status(), 200);
    let operator_html = operator_panel.text().await.unwrap();
    assert!(operator_html.contains("Operator Action Queue"));
    assert!(operator_html.contains("factory-v3 evaluator-closer"));
    assert!(operator_html.contains("observe-only"));
    assert!(operator_html.contains("release_gate"));
    assert!(operator_html.contains("three_os_smoke"));

    let support_bundle = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(support_bundle.status(), 200);
    let support_body: serde_json::Value = support_bundle.json().await.unwrap();
    assert_eq!(
        support_body["schema_version"],
        "ao2.cp-phase1-operator-support-bundle.v1"
    );
    assert_eq!(support_body["portable"], true);
    assert_eq!(support_body["mutates_ao_artifacts"], false);
    assert_eq!(
        support_body["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        support_body["snapshots"]["operator_panel"]["operator_action_queue"][0]["id"],
        "release_gate"
    );
    assert_eq!(
        support_body["snapshots"]["gap_report"]["operator_action_queue"][1]["id"],
        "three_os_smoke"
    );
    assert_eq!(
        support_body["snapshots"]["dashboard"]["links"]["operator_support_bundle_json"],
        "/api/v1/phase1/promotion/operator-support-bundle.json"
    );
    assert_eq!(
        support_body["bundle_manifest"]["entries"],
        serde_json::json!([
            "dashboard",
            "gap_report",
            "operator_panel",
            "operator_action_queue",
            "promotion_history",
            "promotion_timeline",
            "timeline_integrity",
            "trust_boundary"
        ])
    );
    let serialized = serde_json::to_string(&support_body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));

    let download = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/download"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download
            .headers()
            .get("x-ao2-cp-control-plane-role")
            .and_then(|value| value.to_str().ok()),
        Some("read-only-observer")
    );
    let disposition = download
        .headers()
        .get("content-disposition")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(disposition.contains("attachment"));
    assert!(disposition.contains("ao2-phase1-operator-support-bundle.json"));
    let download_sha = download
        .headers()
        .get("x-ao2-cp-support-bundle-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(download_sha.len(), 64);
    let download_bytes = download.bytes().await.unwrap();
    let actual_download_sha = Sha256::digest(&download_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(download_sha, actual_download_sha);
    let downloaded_body: serde_json::Value = serde_json::from_slice(&download_bytes).unwrap();
    assert_eq!(
        downloaded_body["schema_version"],
        "ao2.cp-phase1-operator-support-bundle.v1"
    );
    assert_eq!(
        downloaded_body["generated_at_source"],
        "latest_observed_phase1_index_entry"
    );
    assert_eq!(downloaded_body["mutates_ao_artifacts"], false);
    assert!(!serde_json::to_string(&downloaded_body)
        .unwrap()
        .contains("Bearer"));

    let checksums = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(checksums.status(), 200);
    assert_eq!(
        checksums
            .headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"SHA256SUMS\"")
    );
    let checksums_text = checksums.text().await.unwrap();
    assert!(checksums_text.contains("# schema: ao2.cp-phase1-operator-support-bundle-checksums.v1"));
    assert!(checksums_text.contains("# control-plane-role: read-only-observer"));
    assert!(checksums_text.contains("# release-acceptance-owner: factory-v3 evaluator-closer"));
    assert!(checksums_text.contains("ao2-phase1-operator-support-bundle.json"));
    let checksum_line = checksums_text
        .lines()
        .find(|line| line.ends_with("  ao2-phase1-operator-support-bundle.json"))
        .expect("checksums include operator support bundle filename");
    let (checksum_sha, _) = checksum_line
        .split_once("  ")
        .expect("checksums line uses sha256sum-compatible spacing");
    assert_eq!(checksum_sha, download_sha);
    assert!(!checksums_text.contains("secret"));
    assert!(!checksums_text.contains("Bearer"));

    let manifest = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(manifest.status(), 200);
    let manifest_body: serde_json::Value = manifest.json().await.unwrap();
    assert_eq!(
        manifest_body["schema_version"],
        "ao2.cp-phase1-portable-manifest.v1"
    );
    assert_eq!(manifest_body["portable"], true);
    assert_eq!(manifest_body["contains_credentials"], false);
    assert_eq!(manifest_body["mutates_ao_artifacts"], false);
    assert_eq!(manifest_body["artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(
        manifest_body["artifacts"][0]["name"],
        "phase1_operator_support_bundle"
    );
    assert_eq!(
        manifest_body["artifacts"][0]["digest_scope"],
        "manifest_snapshot_pretty_json_bytes"
    );
    assert_eq!(
        manifest_body["artifacts"][0]["download_recomputes_generated_at"],
        false
    );
    assert_eq!(manifest_body["artifacts"][0]["sha256"], download_sha);
    assert_eq!(
        manifest_body["artifacts"][0]["size_bytes"],
        serde_json::json!(download_bytes.len())
    );
    assert_eq!(manifest_body["artifacts"][1]["name"], "phase1_gap_report");
    assert_eq!(
        manifest_body["artifacts"][1]["filename"],
        "ao2-phase1-gap-report.json"
    );
    assert_eq!(
        manifest_body["artifacts"][1]["digest_scope"],
        "manifest_snapshot_pretty_json_bytes"
    );
    assert_eq!(
        manifest_body["artifacts"][1]["download_recomputes_generated_at"],
        false
    );
    assert_eq!(manifest_body["artifacts"][1]["sha256"], gap_sha);
    assert_eq!(
        manifest_body["artifacts"][1]["size_bytes"],
        serde_json::json!(gap_download_bytes.len())
    );
    assert_eq!(
        manifest_body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        manifest_body["links"]["portable_manifest"],
        "/api/v1/phase1/promotion/portable-manifest"
    );
    assert_eq!(
        manifest_body["links"]["portable_manifest_download"],
        "/api/v1/phase1/promotion/portable-manifest/download"
    );
    assert_eq!(
        manifest_body["links"]["portable_manifest_checksums"],
        "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS"
    );
    assert_eq!(
        manifest_body["links"]["portable_manifest_verify_json"],
        "/api/v1/phase1/promotion/portable-manifest/verify.json"
    );

    // Detached operators triaging the portable manifest offline (without
    // fetching the live phase1 dashboard) MUST see candidate_correlation
    // at the top level so they can read the release/three_os/evaluator/
    // codex/claude verdict directly from the manifest JSON. The object
    // MUST be the same shape published on every release-publication
    // shaped surface (object + status in matched|mismatched + blockers).
    assert!(manifest_body["candidate_correlation"].is_object());
    let manifest_correlation_status = manifest_body["candidate_correlation"]["status"]
        .as_str()
        .expect("portable manifest candidate_correlation.status must be a string");
    assert!(
        ["matched", "mismatched", "missing"].contains(&manifest_correlation_status),
        "unexpected portable manifest candidate_correlation status: {manifest_correlation_status}"
    );
    assert!(manifest_body["candidate_correlation"]["blockers"].is_array());
    assert!(!serde_json::to_string(&manifest_body)
        .unwrap()
        .contains("Bearer"));

    let manifest_verification = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest/verify.json"
        ))
        .header("authorization", test_auth_header())
        .json(&serde_json::json!({
            "schema_version": "ao2.cp-phase1-portable-manifest-verification-upload.v1",
            "manifest": manifest_body,
            "artifacts": {
                "phase1_operator_support_bundle": support_body,
                "phase1_gap_report": gap_download_body
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(manifest_verification.status(), 200);
    let manifest_verification_body: serde_json::Value = manifest_verification.json().await.unwrap();
    assert_eq!(
        manifest_verification_body["schema_version"],
        "ao2.cp-phase1-portable-manifest-verification.v1"
    );
    assert_eq!(manifest_verification_body["status"], "verified");
    assert_eq!(
        manifest_verification_body["counts"]["verified_artifacts"],
        2
    );
    assert_eq!(
        manifest_verification_body["counts"]["mismatched_artifacts"],
        0
    );
    assert_eq!(
        manifest_verification_body["counts"]["unexpected_artifacts"],
        0
    );
    assert_eq!(
        manifest_verification_body["results"][0]["artifact_name"],
        "phase1_operator_support_bundle"
    );
    assert_eq!(manifest_verification_body["results"][0]["verified"], true);
    assert_eq!(
        manifest_verification_body["trust_boundary"]["mutates_ao_artifacts"],
        false
    );
    assert!(!serde_json::to_string(&manifest_verification_body)
        .unwrap()
        .contains("Bearer"));

    let mut tampered_manifest_upload = serde_json::json!({
        "schema_version": "ao2.cp-phase1-portable-manifest-verification-upload.v1",
        "manifest": manifest_body,
        "artifacts": {
            "phase1_operator_support_bundle": support_body,
            "phase1_gap_report": gap_download_body
        }
    });
    tampered_manifest_upload["artifacts"]["phase1_gap_report"]["state"] =
        serde_json::json!("tampered-offline-state");
    let tampered_manifest_verification = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest/verify.json"
        ))
        .header("authorization", test_auth_header())
        .json(&tampered_manifest_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(tampered_manifest_verification.status(), 200);
    let tampered_manifest_body: serde_json::Value =
        tampered_manifest_verification.json().await.unwrap();
    assert_eq!(tampered_manifest_body["status"], "tampered");
    assert_eq!(tampered_manifest_body["counts"]["verified_artifacts"], 1);
    assert_eq!(tampered_manifest_body["counts"]["mismatched_artifacts"], 1);
    assert_eq!(tampered_manifest_body["results"][1]["verified"], false);

    let unexpected_manifest_verification = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest/verify.json"
        ))
        .header("authorization", test_auth_header())
        .json(&serde_json::json!({
            "schema_version": "ao2.cp-phase1-portable-manifest-verification-upload.v1",
            "manifest": manifest_body,
            "artifacts": {
                "phase1_operator_support_bundle": support_body,
                "phase1_gap_report": gap_download_body,
                "operator_local_note": {
                    "schema_version": "operator.local-note.v1",
                    "contains_credentials": false,
                    "note": "must not be accepted as manifest-covered evidence"
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unexpected_manifest_verification.status(), 200);
    let unexpected_manifest_body: serde_json::Value =
        unexpected_manifest_verification.json().await.unwrap();
    assert_eq!(unexpected_manifest_body["status"], "tampered");
    assert_eq!(unexpected_manifest_body["counts"]["verified_artifacts"], 2);
    assert_eq!(
        unexpected_manifest_body["counts"]["unexpected_artifacts"],
        1
    );
    assert_eq!(
        unexpected_manifest_body["unexpected_artifacts"],
        serde_json::json!(["operator_local_note"])
    );

    let manifest_download = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest/download"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(manifest_download.status(), 200);
    assert_eq!(
        manifest_download
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap(),
        "application/json; charset=utf-8"
    );
    let manifest_disposition = manifest_download
        .headers()
        .get("content-disposition")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert!(manifest_disposition.contains("attachment"));
    assert!(manifest_disposition.contains("ao2-phase1-portable-manifest.json"));
    let manifest_sha = manifest_download
        .headers()
        .get("x-ao2-cp-portable-manifest-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(manifest_sha.len(), 64);
    let manifest_download_bytes = manifest_download.bytes().await.unwrap();
    let actual_manifest_download_sha = Sha256::digest(&manifest_download_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(manifest_sha, actual_manifest_download_sha);
    let manifest_download_body: serde_json::Value =
        serde_json::from_slice(&manifest_download_bytes).unwrap();
    assert_eq!(
        manifest_download_body["schema_version"],
        "ao2.cp-phase1-portable-manifest.v1"
    );
    assert_eq!(manifest_download_body["contains_credentials"], false);
    assert!(!serde_json::to_string(&manifest_download_body)
        .unwrap()
        .contains("Bearer"));

    let manifest_checksums = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/portable-manifest/SHA256SUMS"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(manifest_checksums.status(), 200);
    let manifest_checksums_text = manifest_checksums.text().await.unwrap();
    assert!(
        manifest_checksums_text.contains("# schema: ao2.cp-phase1-portable-manifest-checksums.v1")
    );
    assert!(manifest_checksums_text.contains("# control-plane-role: read-only-observer"));
    assert!(
        manifest_checksums_text.contains("# release-acceptance-owner: factory-v3 evaluator-closer")
    );
    assert!(manifest_checksums_text.contains("ao2-phase1-portable-manifest.json"));
    let manifest_checksum_line = manifest_checksums_text
        .lines()
        .find(|line| line.ends_with("  ao2-phase1-portable-manifest.json"))
        .expect("checksums include portable manifest filename");
    let (manifest_checksum_sha, _) = manifest_checksum_line
        .split_once("  ")
        .expect("manifest checksums line uses sha256sum-compatible spacing");
    assert_eq!(manifest_checksum_sha, manifest_sha);
    assert!(!manifest_checksums_text.contains("secret"));
    assert!(!manifest_checksums_text.contains("Bearer"));

    let manifest_html = client
        .get(format!("{base}/api/v1/phase1/promotion/portable-manifest"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(manifest_html.status(), 200);
    let manifest_html_body = manifest_html.text().await.unwrap();
    assert!(manifest_html_body.contains("AO2 Phase 1 Portable Manifest"));
    assert!(manifest_html_body.contains("ao2-phase1-operator-support-bundle.json"));
    assert!(manifest_html_body.contains("ao2-phase1-gap-report.json"));
    assert!(manifest_html_body.contains("read_only_observer"));
    assert!(!manifest_html_body.contains("Bearer"));
}

#[tokio::test]
async fn phase1_three_os_smoke_is_ingested_and_clears_release_gate_gap() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let readiness = client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", test_auth_header())
        .body(provider_phase1_readiness_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);

    for fixture in [
        live_acceptance_fixture(CODEX_FIXTURE, "codex"),
        live_acceptance_fixture(CLAUDE_FIXTURE, "claude"),
        live_acceptance_fixture(
            &CLAUDE_FIXTURE
                .replace(
                    "ao2.claude-provider-pilot-acceptance.v1",
                    "ao2.antigravity-provider-pilot-acceptance.v1",
                )
                .replace("\"provider\": \"claude\"", "\"provider\": \"antigravity\"")
                .replace("claude", "antigravity"),
            "antigravity",
        ),
    ] {
        let response = client
            .post(format!("{base}/api/v1/acceptance"))
            .header("authorization", test_auth_header())
            .body(fixture)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    let smoke = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(three_os_release_smoke_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(smoke.status(), 200);
    let receipt: serde_json::Value = smoke.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "ao2-control-plane.three-os-release-smoke.v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/three-os-smoke/latest"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(latest_body["status"], "passed");
    assert_eq!(latest_body["source_dirty"], false);
    assert_eq!(
        latest_body["remote_command_files"]["ubuntu"],
        "/work/ao2-control-plane/target/three-os-release-smoke/ubuntu-command.sh"
    );
    assert_eq!(
        latest_body["remote_command_files"]["windows"],
        "/work/ao2-control-plane/target/three-os-release-smoke/windows-command.ps1"
    );
    assert_eq!(
        latest_body["rerun_commands"]["all_required"],
        "AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh"
    );
    assert!(!serde_json::to_string(&latest_body)
        .unwrap()
        .contains("redacted-value"));

    let raw = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/three-os-smoke/{sha}"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);

    let dashboard_json = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();

    assert_eq!(body["state"], "release_gate_ready");
    assert_eq!(body["checklist"]["three_os_smoke"]["status"], "passed");
    assert_eq!(body["checklist"]["three_os_smoke"]["source_dirty"], false);
    assert_eq!(body["checklist"]["three_os_smoke"]["sha256"], sha);
    assert_eq!(
        body["checklist"]["three_os_smoke"]["remote_command_files"]["windows"],
        "/work/ao2-control-plane/target/three-os-release-smoke/windows-command.ps1"
    );
    assert_eq!(
        body["checklist"]["three_os_smoke"]["rerun_commands"]["macos_only"],
        "AO2_CP_REQUIRE_UBUNTU=0 AO2_CP_REQUIRE_WINDOWS=0 AO2_CP_API_TOKEN=<local-token> scripts/smoke-three-os-release.sh"
    );
    assert_eq!(
        body["checklist"]["three_os_smoke"]["targets"]["windows"]["status"],
        "passed"
    );
    assert_eq!(body["gap_report"]["total_open_gaps"], 1);
    assert_eq!(body["gap_report"]["blocking_gaps"][0]["id"], "release_gate");
    assert_eq!(
        body["links"]["latest_three_os_smoke"],
        "/api/v1/phase1/promotion/three-os-smoke/latest"
    );

    let html = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Three-OS smoke"));
    assert!(html.contains("passed"));
    assert!(html.contains("/api/v1/phase1/promotion/three-os-smoke/latest"));
    assert!(html.contains("Remote smoke rerun metadata"));
    assert!(html.contains("ubuntu-command.sh"));
    assert!(html.contains("windows-command.ps1"));
    assert!(html.contains("scripts/smoke-three-os-release.sh"));
    assert!(html.contains("AO2_CP_API_TOKEN=&lt;redacted&gt;"));
    assert!(!html.contains("AO2_CP_API_TOKEN=&lt;local-token&gt;"));
    assert!(!html.contains("Bearer"));
    assert!(!html.contains("secret"));
}

#[tokio::test]
async fn phase1_promotion_checklist_is_ingested_and_shown_on_dashboard() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/ao2-phase1-promotion-checklist/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!("{base}/api/v1/phase1/promotion/checklist/latest"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(latest_body["phase1_state"], "phase1_candidate_ready");

    let raw = client
        .get(format!("{base}/api/v1/phase1/promotion/checklist/{sha}"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);
    let raw_body: serde_json::Value = raw.json().await.unwrap();
    assert_eq!(raw_body["checklist"]["three_os_smoke"]["status"], "passed");

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(body["state"], "release_candidate_observed");
    assert_eq!(body["checklist_artifact"]["status"], "passed");
    assert_eq!(body["checklist_artifact"]["sha256"], sha);
    assert_eq!(body["gap_report"]["total_open_gaps"], 1);
    assert_eq!(
        body["gap_report"]["blocking_gaps"][0]["id"],
        "signed_promotion_decision"
    );
    assert_eq!(
        body["checklist_artifact"]["raw_url"],
        format!("/api/v1/phase1/promotion/checklist/{sha}")
    );
}

#[tokio::test]
async fn signed_phase1_promotion_decision_signature_sidecar_is_write_once_per_content_sha() {
    // The signature sidecar records *who signed* a given promotion-decision
    // content sha. A second signed upload of the *same decision bytes* but a
    // *different* signature (different key / provenance) must NOT silently
    // overwrite the first signer's sidecar — otherwise any holder of a valid
    // signing key could rewrite the recorded provenance of an already-observed
    // governance decision. First write wins; a conflicting re-sign is rejected.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    // Same decision content, two independently generated signing keys.
    let decision = phase1_promotion_decision_fixture(checklist_sha);
    let first = signed_phase1_promotion_decision_fixture(decision.clone(), false);
    let second = signed_phase1_promotion_decision_fixture(decision, false);
    assert_eq!(
        first["decision"], second["decision"],
        "fixtures must share identical decision content"
    );
    assert_ne!(
        first["signature"]["signature_hex"], second["signature"]["signature_hex"],
        "fixtures must use distinct keys to represent conflicting provenance"
    );
    let first_sig_hex = first["signature"]["signature_hex"]
        .as_str()
        .unwrap()
        .to_string();

    let post1 = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(post1.status(), 200, "first signed upload is accepted");
    let receipt: serde_json::Value = post1.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();

    // Conflicting re-sign of an existing content sha: rejected, not stored.
    let post2 = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post2.status(),
        422,
        "a conflicting re-sign of an existing content sha must be rejected"
    );

    // The stored sidecar still reflects the FIRST signer's signature.
    let sidecar = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/decision/{sha}/signature"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(sidecar.status(), 200);
    let sidecar_body: serde_json::Value = sidecar.json().await.unwrap();
    assert_eq!(
        sidecar_body["signature"]["signature_hex"], first_sig_hex,
        "first writer's provenance must be preserved, not overwritten"
    );
}

#[tokio::test]
async fn signed_phase1_promotion_decision_reupload_of_identical_artifact_stays_idempotent() {
    // The write-once guard must not break idempotent retries: re-POSTing the
    // *exact same* signed artifact (identical signature bytes) yields the same
    // sidecar_raw, so it is accepted as a no-op rather than rejected as a
    // conflict. Guards the `existing == sidecar_raw` branch of the guard.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let artifact = signed_phase1_promotion_decision_fixture(
        phase1_promotion_decision_fixture(checklist_sha),
        false,
    );
    for attempt in 1..=2 {
        let post = client
            .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
            .header("authorization", test_auth_header())
            .json(&artifact)
            .send()
            .await
            .unwrap();
        assert_eq!(
            post.status(),
            200,
            "identical signed artifact must be accepted idempotently (attempt {attempt})"
        );
    }
}

#[tokio::test]
async fn signed_phase1_promotion_decision_is_observed_with_signature_sidecar() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed = signed_phase1_promotion_decision_fixture(
        phase1_promotion_decision_fixture(checklist_sha),
        false,
    );
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/ao2-phase1-promotion-decision/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!("{base}/api/v1/phase1/promotion/decision/latest"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(latest_body["decision"], "promote_phase1_candidate");

    let signature = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/decision/{sha}/signature"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-phase1-promotion-decision-signature.v1"
    );
    assert_eq!(signature_body["phase1_promotion_decision_sha256"], sha);
    assert_eq!(signature_body["signature"]["signature_verified"], true);
    assert_eq!(signature_body["signature"]["signer_id"], "release-lead");

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(body["state"], "promotion_decision_observed");
    assert_eq!(
        body["decision_artifact"]["decision"],
        "promote_phase1_candidate"
    );
    assert_eq!(
        body["decision_artifact"]["signature"]["signature_verified"],
        true
    );
    assert_eq!(body["gap_report"]["total_open_gaps"], 0);
    assert_eq!(
        body["gap_report"]["blocking_gaps"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        body["decision_artifact"]["signature_url"],
        format!("/api/v1/phase1/promotion/decision/{sha}/signature")
    );
}

#[tokio::test]
async fn phase1_operator_panel_summarizes_ready_candidate_without_mutating_trust_path() {
    // A candidate is only release-ready when the promotion decision is signed
    // by a configured trust anchor. Generate the signer up front so its
    // public-key SHA-256 can be pinned in the allowlist before the server
    // starts; otherwise the verified-but-unpinned signature is observer-only
    // and the panel withholds "ready".
    let (signer, public_key_pem, pinned_key_sha256) = phase1_promotion_decision_signer();
    let (base, _dir) = spawn_server_with_trusted_keys(vec![pinned_key_sha256.clone()]).await;
    let client = reqwest::Client::new();

    let smoke = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(three_os_release_smoke_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(smoke.status(), 200);

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed = signed_phase1_promotion_decision_fixture_with_signer(
        phase1_promotion_decision_fixture(checklist_sha),
        false,
        &signer,
        &public_key_pem,
    );
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let panel = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-panel.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(panel.status(), 200);
    let body: serde_json::Value = panel.json().await.unwrap();

    assert_eq!(body["schema_version"], "ao2.cp-phase1-operator-panel.v1");
    assert_eq!(body["status"], "ready");
    assert_eq!(
        body["operator_status"]["state"],
        "promotion_decision_observed"
    );
    assert_eq!(
        body["operator_status"]["phase1_state"],
        "phase1_candidate_ready"
    );
    assert_eq!(body["badges"]["checklist"], "passed");
    assert_eq!(body["badges"]["signed_decision"], "passed");
    assert_eq!(body["badges"]["signature"], "verified");
    assert_eq!(body["badges"]["three_os"], "passed");
    // The pinned signer makes this decision release-authoritative, which is
    // what unlocks the "ready" status above (a verified-but-unpinned key
    // would be observer-only and the panel would withhold "ready").
    assert_eq!(body["operator_status"]["release_authoritative"], true);
    assert_eq!(body["operator_status"]["signature_verified"], true);
    assert_eq!(body["gap_report"]["total_open_gaps"], 0);
    assert_eq!(body["operator_action_queue"].as_array().unwrap().len(), 0);
    assert_eq!(
        body["links"]["operator_panel"],
        "/api/v1/phase1/promotion/operator-panel"
    );

    // The dashboard records the pinned-key trust classification verbatim:
    // cryptographically verified AND matched against the configured anchor.
    let dashboard: serde_json::Value = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = &dashboard["decision_artifact"]["signature"];
    assert_eq!(sig["signature_verified"], true);
    assert_eq!(sig["verification_scope"], "cryptographic-and-pinned-key");
    assert_eq!(
        sig["trust_anchor"],
        "configured-signed-artifact-public-key-sha256"
    );
    assert_eq!(sig["trust_policy"]["trusted_key_match"], true);
    assert_eq!(sig["trust_policy"]["release_authoritative"], true);
    assert_eq!(
        sig["trust_policy"]["matched_public_key_sha256"],
        pinned_key_sha256
    );
    assert_eq!(
        body["links"]["operator_panel_json"],
        "/api/v1/phase1/promotion/operator-panel.json"
    );
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );

    // Phase 1 operator panel now mirrors the cockpit candidate_correlation
    // surface so operators landing on phase1 see the same release/three_os/
    // evaluator/codex/claude triage verdict without having to jump to the
    // cockpit. Additive: existing badges and shape are unchanged otherwise.
    let panel_correlation = &body["candidate_correlation"];
    assert!(
        panel_correlation.is_object(),
        "phase1 operator panel should expose candidate_correlation for operator triage"
    );
    let panel_correlation_status = panel_correlation["status"].as_str().unwrap_or("");
    assert!(
        panel_correlation_status == "matched" || panel_correlation_status == "mismatched",
        "candidate_correlation.status was {panel_correlation_status:?}"
    );
    assert!(panel_correlation["release_version"].is_string());
    assert!(panel_correlation["release_tag"].is_string());
    assert!(panel_correlation["three_os_version"].is_string());
    assert!(panel_correlation["release_evaluator_version"].is_string());
    assert!(panel_correlation["codex_acceptance_version"].is_string());
    assert!(panel_correlation["claude_acceptance_version"].is_string());
    assert!(panel_correlation["blockers"].is_array());
    assert_eq!(
        body["badges"]["candidate_correlation"],
        panel_correlation_status
    );

    let html = client
        .get(format!("{base}/api/v1/phase1/promotion/operator-panel"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let rendered = html.text().await.unwrap();
    assert!(rendered.contains("AO2 Phase 1 Operator Panel"));
    assert!(rendered.contains("ready"));
    assert!(rendered.contains("Three-OS"));
    assert!(rendered.contains("/api/v1/phase1/promotion/operator-panel.json"));
    assert!(rendered.contains("Operator Action Queue"));
    assert!(rendered.contains("No open operator actions observed"));
    // Phase 1 operator panel HTML now mirrors the cockpit "Candidate
    // Correlation" section.
    assert!(rendered.contains("Candidate Correlation"));
    assert!(rendered.contains("Three-OS smoke version"));
    assert!(rendered.contains("Evaluator version"));
    assert!(rendered.contains("Codex acceptance version"));
    assert!(rendered.contains("Claude acceptance version"));
    assert!(rendered.contains("Blockers"));
    assert!(rendered.contains("Candidate correlation"));
    assert!(!rendered.contains("secret"));
    assert!(!serde_json::to_string(&body).unwrap().contains("Bearer"));
}

#[tokio::test]
async fn phase1_operator_panel_withholds_ready_for_unpinned_self_signed_decision() {
    // sec-1 guard. A token holder can mint a cryptographically valid
    // signature with an arbitrary self-generated key. With no trust anchor
    // configured, the control plane MUST NOT present that decision as a
    // release-authoritative "ready" candidate. The signature is still
    // recorded as cryptographically verified (we do not lie about the
    // crypto check), but it is classified observer-only
    // (release_authoritative: false), and the operator panel withholds
    // "ready". This preserves the observer-only invariant: the control
    // plane never manufactures release authority from an unpinned key.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let smoke = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(three_os_release_smoke_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(smoke.status(), 200);

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed = signed_phase1_promotion_decision_fixture(
        phase1_promotion_decision_fixture(checklist_sha),
        false,
    );
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    // Operator panel: every other gate is green (gaps cleared, three-OS
    // passed, signature cryptographically verified) — but the signer is
    // not a configured trust anchor, so "ready" must be withheld.
    let panel: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-panel.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        panel["status"], "ready",
        "an unpinned self-signed decision must not be presented as release-ready"
    );
    assert_eq!(panel["status"], "review");
    assert_eq!(panel["operator_status"]["signature_verified"], true);
    assert_eq!(panel["operator_status"]["release_authoritative"], false);
    assert_eq!(panel["badges"]["signature"], "verified");
    assert_eq!(panel["gap_report"]["total_open_gaps"], 0);

    // Dashboard: the recorded signature carries the honest trust
    // classification — verified, but observer-only.
    let dashboard: serde_json::Value = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = &dashboard["decision_artifact"]["signature"];
    assert_eq!(sig["signature_verified"], true);
    assert_eq!(sig["verification_scope"], "cryptographic-only");
    assert_eq!(sig["trust_anchor"], "upload-public-key-not-authority");
    assert_eq!(sig["trust_policy"]["trusted_key_match"], false);
    assert_eq!(sig["trust_policy"]["release_authoritative"], false);
}

#[tokio::test]
async fn phase1_promotion_history_lists_recent_observer_artifacts() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let smoke = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(three_os_release_smoke_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(smoke.status(), 200);
    let smoke_receipt: serde_json::Value = smoke.json().await.unwrap();
    let smoke_sha = smoke_receipt["sha256"].as_str().unwrap();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed = signed_phase1_promotion_decision_fixture(
        phase1_promotion_decision_fixture(checklist_sha),
        false,
    );
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);
    let decision_receipt: serde_json::Value = decision.json().await.unwrap();
    let decision_sha = decision_receipt["sha256"].as_str().unwrap();

    let inputs = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/inputs-verification"
        ))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_inputs_verification_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(inputs.status(), 200);
    let inputs_receipt: serde_json::Value = inputs.json().await.unwrap();
    let inputs_sha = inputs_receipt["sha256"].as_str().unwrap();

    let history = client
        .get(format!("{base}/api/v1/phase1/promotion/history.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(history.status(), 200);
    let body: serde_json::Value = history.json().await.unwrap();

    assert_eq!(body["schema_version"], "ao2.cp-phase1-promotion-history.v1");
    assert_eq!(body["counts"]["checklists"], 1);
    assert_eq!(body["counts"]["signed_decisions"], 1);
    assert_eq!(body["counts"]["three_os_smokes"], 1);
    assert_eq!(body["counts"]["promotion_input_verifications"], 1);
    assert_eq!(body["latest"]["checklist_sha256"], checklist_sha);
    assert_eq!(body["latest"]["decision_sha256"], decision_sha);
    assert_eq!(body["latest"]["three_os_smoke_sha256"], smoke_sha);
    assert_eq!(
        body["latest"]["promotion_inputs_verification_sha256"],
        inputs_sha
    );
    assert_eq!(
        body["history"]["promotion_input_verifications"][0]["raw_url"],
        format!("/api/v1/phase1/promotion/inputs-verification/{inputs_sha}")
    );
    assert_eq!(
        body["history"]["promotion_input_verifications"][0]["status"],
        "accepted"
    );
    assert_eq!(
        body["history"]["promotion_input_verifications"][0]["control_plane_role"],
        "read_only_observer"
    );
    assert_eq!(
        body["history"]["checklists"][0]["raw_url"],
        format!("/api/v1/phase1/promotion/checklist/{checklist_sha}")
    );
    assert_eq!(
        body["history"]["signed_decisions"][0]["signature"]["signature_verified"],
        true
    );
    assert_eq!(
        body["history"]["three_os_smokes"][0]["targets"]["ubuntu"]["status"],
        "passed"
    );
    assert_eq!(body["timeline"].as_array().unwrap().len(), 4);
    assert_eq!(
        body["timeline"][0]["artifact_kind"],
        "phase1_promotion_inputs_verification"
    );
    assert_eq!(body["timeline"][0]["sha256"], inputs_sha);
    assert_eq!(
        body["timeline"][0]["raw_url"],
        format!("/api/v1/phase1/promotion/inputs-verification/{inputs_sha}")
    );
    assert_eq!(
        body["timeline"][1]["artifact_kind"],
        "signed_phase1_promotion_decision"
    );
    assert_eq!(body["timeline"][1]["sha256"], decision_sha);
    assert_eq!(body["timeline"][1]["signature_verified"], true);
    assert_eq!(
        body["timeline"][1]["raw_url"],
        format!("/api/v1/phase1/promotion/decision/{decision_sha}")
    );
    assert_eq!(
        body["timeline"][1]["signature_url"],
        format!("/api/v1/phase1/promotion/decision/{decision_sha}/signature")
    );
    assert_eq!(
        body["timeline"][2]["artifact_kind"],
        "phase1_promotion_checklist"
    );
    assert_eq!(body["timeline"][2]["sha256"], checklist_sha);
    assert_eq!(
        body["timeline"][3]["artifact_kind"],
        "three_os_release_smoke"
    );
    assert_eq!(body["timeline"][3]["sha256"], smoke_sha);
    assert_eq!(
        body["links"]["portable_manifest_json"],
        "/api/v1/phase1/promotion/portable-manifest.json"
    );
    assert_eq!(
        body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);

    let support_bundle = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(support_bundle.status(), 200);
    let support_body: serde_json::Value = support_bundle.json().await.unwrap();
    assert_eq!(
        support_body["bundle_manifest"]["entries"],
        serde_json::json!([
            "dashboard",
            "gap_report",
            "operator_panel",
            "operator_action_queue",
            "promotion_history",
            "promotion_timeline",
            "timeline_integrity",
            "trust_boundary"
        ])
    );
    assert_eq!(
        support_body["snapshots"]["promotion_timeline"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        support_body["snapshots"]["promotion_history"]["latest"]["decision_sha256"],
        decision_sha
    );
    let timeline_integrity = support_body["timeline_integrity"].as_array().unwrap();
    assert_eq!(timeline_integrity.len(), 4);
    assert_eq!(
        timeline_integrity[0]["artifact_kind"],
        "phase1_promotion_inputs_verification"
    );
    assert_eq!(timeline_integrity[0]["sha256"], inputs_sha);
    assert_eq!(
        timeline_integrity[0]["control_plane_role"],
        "read-only-observer"
    );
    assert_eq!(
        timeline_integrity[1]["artifact_kind"],
        "signed_phase1_promotion_decision"
    );
    assert_eq!(timeline_integrity[1]["sha256"], decision_sha);
    assert_eq!(
        timeline_integrity[1]["digest_scope"],
        "timeline_entry_canonical_json"
    );
    assert_eq!(
        timeline_integrity[1]["canonical_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        timeline_integrity[1]["control_plane_role"],
        "read-only-observer"
    );
    assert_eq!(timeline_integrity[1]["mutates_ao_artifacts"], false);
    assert_eq!(
        support_body["links"]["history_json"],
        "/api/v1/phase1/promotion/history.json"
    );

    let verification = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/verify.json"
        ))
        .header("authorization", test_auth_header())
        .json(&support_body)
        .send()
        .await
        .unwrap();
    assert_eq!(verification.status(), 200);
    let verification_body: serde_json::Value = verification.json().await.unwrap();
    assert_eq!(
        verification_body["schema_version"],
        "ao2.cp-phase1-operator-support-bundle-verification.v1"
    );
    assert_eq!(verification_body["status"], "verified");
    assert_eq!(verification_body["counts"]["verified_entries"], 4);
    assert_eq!(verification_body["counts"]["mismatched_entries"], 0);
    assert_eq!(
        verification_body["trust_boundary"]["mutates_ao_artifacts"],
        false
    );
    assert_eq!(
        verification_body["results"][0]["expected_canonical_sha256"],
        timeline_integrity[0]["canonical_sha256"]
    );
    assert_eq!(verification_body["results"][0]["verified"], true);

    let verification_html = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/verify"
        ))
        .header("authorization", test_auth_header())
        .json(&support_body)
        .send()
        .await
        .unwrap();
    assert_eq!(verification_html.status(), 200);
    let verification_html_body = verification_html.text().await.unwrap();
    assert!(verification_html_body.contains("Phase 1 Operator Support Bundle Verification"));
    assert!(verification_html_body.contains("verified"));
    assert!(verification_html_body.contains("read-only-observer"));

    let mut tampered_bundle = support_body.clone();
    tampered_bundle["snapshots"]["promotion_timeline"][0]["raw_url"] =
        serde_json::json!("/tampered/offline/path");
    let tampered_verification = client
        .post(format!(
            "{base}/api/v1/phase1/promotion/operator-support-bundle/verify.json"
        ))
        .header("authorization", test_auth_header())
        .json(&tampered_bundle)
        .send()
        .await
        .unwrap();
    assert_eq!(tampered_verification.status(), 200);
    let tampered_body: serde_json::Value = tampered_verification.json().await.unwrap();
    assert_eq!(tampered_body["status"], "tampered");
    assert_eq!(tampered_body["counts"]["verified_entries"], 3);
    assert_eq!(tampered_body["counts"]["mismatched_entries"], 1);
    assert_eq!(tampered_body["results"][0]["verified"], false);
    assert_eq!(
        tampered_body["results"][0]["artifact_kind"],
        "phase1_promotion_inputs_verification"
    );

    assert!(!serde_json::to_string(&support_body)
        .unwrap()
        .contains("Bearer"));

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(dashboard.contains("/api/v1/phase1/promotion/history.json"));
}

// Lane W: server-side recomputation of candidate_correlation_parity
// from per-target evidence. The aggregator
// (scripts/smoke-three-os-release.sh) computes parity from per-OS
// smoke logs and writes it to the top-level
// candidate_correlation_parity field. A tampered ingestion could set
// candidate_correlation_parity=matched while per-target
// candidate_correlation_status values disagree
// (matched/mismatched/matched). validate_three_os_release_smoke MUST
// reject any ingestion where the posted top-level field disagrees
// with the server-side recomputation. Closes the
// server-trusted-input vs. recomputable-from-evidence gap.
#[tokio::test]
async fn three_os_release_smoke_ingestion_rejects_tampered_top_level_parity() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // A tampered smoke: per-target candidate_correlation_status values
    // are matched/mismatched/matched (which the aggregator would
    // resolve to "drift"), but a malicious ingestor has stamped the
    // top-level candidate_correlation_parity to "matched" to hide the
    // drift from downstream readiness gates.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "matched",
        "targets": {
            "macos": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "candidate_correlation_status": "mismatched"
            },
            "windows": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            }
        }
    });

    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(
        post.status(),
        422,
        "tampered top-level parity must be rejected at ingestion time \
         with SchemaInvalid → 422 Unprocessable Entity"
    );
    let error_text = post.text().await.unwrap();
    assert!(
        error_text.contains("candidate_correlation_parity"),
        "rejection must name the failing field: got {error_text:?}"
    );
    assert!(
        error_text.contains("posted=matched") && error_text.contains("recomputed=drift"),
        "rejection must surface both the posted and recomputed verdicts: got {error_text:?}"
    );

    // A correctly-stamped drift smoke (top-level parity matches
    // per-target evidence) MUST still be ingested — the server is
    // recomputing, not blanket-blocking drift.
    let honest_drift = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "drift",
        "targets": {
            "macos": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "candidate_correlation_status": "mismatched"
            },
            "windows": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            }
        }
    });

    let honest_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_drift.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        honest_post.status(),
        200,
        "an honest drift smoke whose top-level parity matches the \
         recomputation must be accepted; Lane W is about catching \
         tampering, not blocking drift"
    );

    // A correctly-stamped matched smoke must also still be accepted.
    let honest_matched = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "matched",
        "targets": {
            "macos": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "windows": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            }
        }
    });

    let matched_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_matched.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(matched_post.status(), 200);

    // An ingestion that OMITS candidate_correlation_parity entirely
    // (older schema clients before Lane P) must still be accepted —
    // the recomputation check only fires when the field is present.
    // This protects backwards compatibility with the existing fixture
    // shape that does not stamp the top-level field.
    let no_parity_field = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });

    let no_parity_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(no_parity_field.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_parity_post.status(),
        200,
        "smokes without a top-level candidate_correlation_parity field \
         must still be accepted for backwards compatibility"
    );
}

// Lane DD: server-side recomputation of top-level smoke.status from
// per-target evidence. The aggregator
// (scripts/smoke-three-os-release.sh, line ~164) computes
// status="passed" iff every per-target status is "passed", else
// "failed". A tampered ingestion could stamp top-level status="passed"
// while one or more per-target statuses are "failed" or "skipped" —
// hiding a real cross-OS failure from any downstream consumer that
// trusts the top-level field. validate_three_os_release_smoke MUST
// reject any ingestion where the posted top-level status disagrees
// with the server-side recomputation. Closes the
// server-trusted-input vs. recomputable-from-evidence gap (parallel to
// Lane W's defense for candidate_correlation_parity).
#[tokio::test]
async fn three_os_release_smoke_ingestion_rejects_tampered_top_level_status() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // A tampered smoke: windows is reported as "failed" but the
    // top-level status is stamped "passed" to hide the windows
    // failure from downstream consumers.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "failed"}
        }
    });

    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(
        post.status(),
        422,
        "tampered top-level status must be rejected at ingestion time \
         with SchemaInvalid → 422 Unprocessable Entity"
    );
    let error_text = post.text().await.unwrap();
    assert!(
        error_text.contains("top-level status"),
        "rejection must name the failing field: got {error_text:?}"
    );
    assert!(
        error_text.contains("posted=passed") && error_text.contains("recomputed=failed"),
        "rejection must surface both the posted and recomputed verdicts: got {error_text:?}"
    );

    // A skipped target is also "not passed" — the aggregator counts it
    // as "failed" at the top level. Lane DD must reject status="passed"
    // when ANY target is not passed, including skipped targets.
    let tampered_skipped = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "skipped"}
        }
    });

    let skipped_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_skipped.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        skipped_post.status(),
        422,
        "tampered top-level status with a skipped target must also be \
         rejected — the aggregator counts skipped as not-passed"
    );

    // A tampered smoke in the OPPOSITE direction (status="failed" but
    // every target passed) must ALSO be rejected — Lane DD enforces
    // strict equality with the recomputation, not just one direction.
    let tampered_failed = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "failed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });

    let failed_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_failed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        failed_post.status(),
        422,
        "tampered top-level status=failed with every target passed must \
         also be rejected: the field MUST match the recomputation"
    );

    // An honest failed smoke (status="failed" with at least one
    // non-passing target) MUST still be ingested — Lane DD is about
    // catching tampering, not blocking failed smokes.
    let honest_failed = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "failed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "failed"}
        }
    });

    let honest_failed_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_failed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        honest_failed_post.status(),
        200,
        "an honest failed smoke (top-level matches per-target evidence) \
         must be accepted; Lane DD is about catching tampering, not \
         blocking failed runs"
    );

    // An honest passed smoke (all targets passed, top-level passed)
    // must also still be accepted — proves the recomputation isn't
    // blocking the common case.
    let honest_passed = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });

    let honest_passed_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_passed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(honest_passed_post.status(), 200);
}

// Lane KK: ingestion-time format constraint on source_commit and
// tightened Lane DD recomputation that includes source_dirty.
//
// The aggregator (scripts/smoke-three-os-release.sh, line ~73) ALWAYS
// emits a 40-char lowercase hex SHA via `git rev-parse HEAD`. A
// tampered ingestion could swap that for a placeholder ("unknown",
// "tampered", "fake") and pass the legacy non-empty check. Lane KK
// rejects any source_commit that is not a valid git sha1.
//
// Additionally, downstream `three_os_smoke_clean_status` in
// release_publication.rs derives "passed" only when status=passed AND
// !source_dirty AND all targets passed. Without Lane KK's tightening,
// a tampered ingestion with source_dirty=true + all targets passed +
// status="passed" would pass Lane DD's gate but render as "failed"
// downstream — leaving operators with inconsistent verdicts.
#[tokio::test]
async fn three_os_release_smoke_ingestion_rejects_lane_kk_tampering() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Case 1: source_commit is a placeholder string ("unknown")
    let tampered_placeholder = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "unknown",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let placeholder_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_placeholder.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        placeholder_post.status(),
        422,
        "placeholder source_commit must be rejected: must be a 40-char hex git sha1"
    );
    let placeholder_text = placeholder_post.text().await.unwrap();
    assert!(
        placeholder_text.contains("source_commit") && placeholder_text.contains("hex git sha1"),
        "rejection must name source_commit + sha1 expectation: {placeholder_text:?}"
    );

    // Case 2: source_commit is too short (39 chars)
    let tampered_short = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e587",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let short_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_short.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        short_post.status(),
        422,
        "39-char source_commit must be rejected: must be 40 chars"
    );

    // Case 3: source_commit contains uppercase hex (not the
    // aggregator's lowercase output)
    let tampered_upper = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52BBFF188626315CA832C328570BC638260E5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let upper_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_upper.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        upper_post.status(),
        422,
        "uppercase source_commit must be rejected: aggregator emits lowercase hex"
    );

    // Case 4: source_dirty=true + status=passed + all targets passed.
    // Legacy Lane DD accepts this; Lane KK tightens to also require
    // !source_dirty for "passed".
    let dirty_passed = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let dirty_passed_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(dirty_passed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        dirty_passed_post.status(),
        422,
        "Lane KK tightening: status=passed with source_dirty=true must be \
         rejected; downstream three_os_smoke_clean_status downgrades this \
         to failed"
    );
    let dirty_text = dirty_passed_post.text().await.unwrap();
    assert!(
        dirty_text.contains("source_dirty=true"),
        "rejection must surface source_dirty in the diagnostic: {dirty_text:?}"
    );

    // Case 5: source_dirty=true + status=failed + all targets passed.
    // This is the honest representation — Lane KK requires status to
    // match the recomputation, and source_dirty=true → recomputed=failed.
    let honest_dirty = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "failed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let honest_dirty_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_dirty.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        honest_dirty_post.status(),
        200,
        "an honest source_dirty=true smoke (status=failed) must still be ingested"
    );
}

// Lane PP-server: server-side enforcement that the per-target
// source_commit_at_target values match the top-level source_commit.
// The orchestrator builds source.tgz from `git rev-parse HEAD`, embeds
// `.source-commit` into the tarball, ships it to each target, and each
// target's smoke emits source_commit_at_target. A tampered or drifted
// ingestion (orchestrator HEAD advanced between packaging and one of
// the per-target runs, OR a forged per-target run from a stale
// source.tgz) would produce a disagreement. This gate closes the
// resulting class of cross-OS evidence drift.
//
// Five cases:
// 1. Posted drift=false but actual drift exists → 422 (recomputation
//    mismatch).
// 2. Posted drift=true (orchestrator surfaced the drift correctly) →
//    422 (drift signal is itself a rejection).
// 3. Top-level source_commit disagrees with a per-target value while
//    the drift bool is absent → 422 (recomputation alone catches it).
// 4. Bundle without `source_commit_per_target` → 200 (legacy
//    acceptance hatch for pre-Lane-OO clients).
// 5. Bundle with consistent values across top-level and every per-
//    target → 200 (honest case).
#[tokio::test]
async fn three_os_release_smoke_ingestion_rejects_source_commit_per_target_drift_lane_pp_server() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let top_level_sha = "52bbff188626315ca832c328570bc638260e5874";
    let drifted_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    // Case 1: posted drift=false but ubuntu disagrees with top-level.
    let mismatch_lied = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": top_level_sha,
        "source_dirty": false,
        "targets": {
            "macos":   {"status": "passed", "source_commit_at_target": top_level_sha},
            "ubuntu":  {"status": "passed", "source_commit_at_target": drifted_sha},
            "windows": {"status": "passed", "source_commit_at_target": top_level_sha}
        },
        "source_commit_per_target": {
            "macos": top_level_sha,
            "ubuntu": drifted_sha,
            "windows": top_level_sha
        },
        "source_commit_per_target_drift": false
    });
    let mismatch_lied_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(mismatch_lied.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        mismatch_lied_post.status(),
        422,
        "posted source_commit_per_target_drift=false with real drift must be rejected"
    );
    let mismatch_lied_text = mismatch_lied_post.text().await.unwrap();
    assert!(
        mismatch_lied_text.contains("source_commit_per_target_drift")
            && mismatch_lied_text.contains("disagrees with server-side recomputation"),
        "diagnostic must name source_commit_per_target_drift + recomputation: \
         {mismatch_lied_text:?}"
    );

    // Case 2: drift=true (orchestrator honestly surfaced the drift).
    // Even an honest report of drift must be rejected on ingestion —
    // an operator must rerun the smoke after fixing the orchestrator
    // before the bundle is acceptable for promotion. Top-level status
    // remains "passed" because Lane DD recomputes from the per-target
    // status field, which IS "passed" on every target (the drift is
    // in source_commit_at_target, not status); Lane DD's check passes
    // and the new Lane PP-server check fires.
    let honest_drift = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": top_level_sha,
        "source_dirty": false,
        "targets": {
            "macos":   {"status": "passed", "source_commit_at_target": top_level_sha},
            "ubuntu":  {"status": "passed", "source_commit_at_target": drifted_sha},
            "windows": {"status": "passed", "source_commit_at_target": top_level_sha}
        },
        "source_commit_per_target": {
            "macos": top_level_sha,
            "ubuntu": drifted_sha,
            "windows": top_level_sha
        },
        "source_commit_per_target_drift": true
    });
    let honest_drift_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest_drift.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        honest_drift_post.status(),
        422,
        "honest source_commit_per_target_drift=true must still be rejected"
    );
    let honest_drift_text = honest_drift_post.text().await.unwrap();
    assert!(
        honest_drift_text.contains("source_commit_per_target drift")
            && honest_drift_text.contains("ubuntu="),
        "diagnostic must name the dissenting target: {honest_drift_text:?}"
    );

    // Case 3: bundle includes source_commit_per_target with drift but
    // OMITS the boolean (some hypothetical legacy producer that
    // populated the per-target block but not the bool). Recomputation
    // alone MUST surface the drift. Top-level status stays "passed"
    // because Lane DD recomputes from per-target status only.
    let drift_no_bool = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": top_level_sha,
        "source_dirty": false,
        "targets": {
            "macos":   {"status": "passed"},
            "ubuntu":  {"status": "passed"},
            "windows": {"status": "passed"}
        },
        "source_commit_per_target": {
            "macos": top_level_sha,
            "ubuntu": drifted_sha,
            "windows": top_level_sha
        }
    });
    let drift_no_bool_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(drift_no_bool.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        drift_no_bool_post.status(),
        422,
        "drift in per-target block alone must be rejected even without the drift bool"
    );

    // Case 4: legacy bundle with NO source_commit_per_target. Lane PP-
    // server is gated on field presence so pre-Lane-OO clients still
    // get accepted via the legacy validation path. The fixture below
    // mirrors three_os_release_smoke_fixture() exactly so it satisfies
    // all upstream Lane KK/DD/W gates.
    let legacy = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": top_level_sha,
        "source_dirty": false,
        "targets": {
            "macos":   {"status": "passed"},
            "ubuntu":  {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let legacy_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(legacy.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        legacy_post.status(),
        200,
        "legacy pre-Lane-OO bundle without source_commit_per_target must still be accepted"
    );

    // Case 5: every per-target value matches top-level, drift=false.
    // Honest happy path — must be ingested.
    let consistent = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": top_level_sha,
        "source_dirty": false,
        "targets": {
            "macos":   {"status": "passed", "source_commit_at_target": top_level_sha},
            "ubuntu":  {"status": "passed", "source_commit_at_target": top_level_sha},
            "windows": {"status": "passed", "source_commit_at_target": top_level_sha}
        },
        "source_commit_per_target": {
            "macos": top_level_sha,
            "ubuntu": top_level_sha,
            "windows": top_level_sha
        },
        "source_commit_per_target_drift": false,
        "source_commit_per_target_drift_status": "false"
    });
    let consistent_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(consistent.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        consistent_post.status(),
        200,
        "consistent source_commit across top-level + every per-target must be accepted"
    );
}

// Lane LL: append-only audit log for rejected three-OS smoke
// ingestions. Every 422 from validate_three_os_release_smoke must
// produce one JSON-line record in
// <storage-root>/rejected-three-os-smoke.jsonl containing:
// (a) the rejection reason, (b) a sha256 of the rejected body, and
// (c) a redacted allowlist summary of the posted payload. Honest
// ingestions (200 OK) MUST NOT touch the audit log.
//
// The redaction allowlist is strict: only schema/status/version/
// release_candidate_version/source_commit_short (12 chars)/
// source_dirty/candidate_correlation_parity/surface_content_hash_parity/
// target_statuses are captured. An accidental bearer/credential
// anywhere in the payload cannot leak via the audit log because
// nothing outside this allowlist is written.
#[tokio::test]
async fn three_os_release_smoke_rejection_appends_audit_log_entry() {
    let (base, dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // The audit log must not exist yet — pre-rejection state.
    assert!(
        !audit_path.exists(),
        "audit log must not exist before any rejection"
    );

    // Tamper class: source_dirty=true with status=passed and all
    // targets passed. Lane KK's tightened recomputation flips this
    // to recomputed=failed → 422.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let raw_body = tampered.to_string();
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(raw_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);

    // The audit log file must now exist with exactly one JSON line.
    assert!(
        audit_path.exists(),
        "audit log must be created on first rejection"
    );
    let raw_log = std::fs::read_to_string(&audit_path).expect("audit log readable");
    let lines: Vec<&str> = raw_log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one audit record after one rejection"
    );
    let record: serde_json::Value =
        serde_json::from_str(lines[0]).expect("audit record is valid JSON");

    assert_eq!(record["schema"], "ao2.cp-rejected-three-os-smoke.v1");
    assert!(record["timestamp_utc"].is_string());
    let reason = record["rejection_reason"].as_str().unwrap();
    assert!(
        reason.contains("source_dirty=true"),
        "rejection reason must surface source_dirty in the audit log: {reason:?}"
    );
    assert_eq!(record["body_size_bytes"], raw_body.len());
    let body_sha = record["body_sha256"].as_str().unwrap();
    assert_eq!(body_sha.len(), 64, "body_sha256 must be a full hex sha256");
    let summary = &record["posted_summary"];
    assert_eq!(
        summary["schema"],
        "ao2-control-plane.three-os-release-smoke.v1"
    );
    assert_eq!(summary["status"], "passed");
    assert_eq!(summary["source_dirty"], true);
    // source_commit is captured truncated to first 12 chars only — never
    // the full SHA. The 12-char prefix is enough to identify the
    // candidate without leaking the full commit into the audit log.
    assert_eq!(summary["source_commit_short"], "52bbff188626");
    assert_eq!(summary["target_statuses"]["macos"], "passed");
    assert_eq!(summary["target_statuses"]["ubuntu"], "passed");
    assert_eq!(summary["target_statuses"]["windows"], "passed");

    // The audit log MUST NOT contain the rejected body verbatim — the
    // body is only fingerprinted via body_sha256 and described via
    // the redacted summary. Confirm by checking the log does NOT
    // contain the rejected-body's full string.
    assert!(
        !raw_log.contains(&raw_body),
        "audit log must not contain the raw rejected body"
    );

    // A second rejection must APPEND, not overwrite.
    let tampered_again = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "failed"}
        }
    });
    let second_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered_again.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(second_post.status(), 422);
    let raw_log_after = std::fs::read_to_string(&audit_path).expect("audit log readable");
    let lines_after: Vec<&str> = raw_log_after
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines_after.len(),
        2,
        "two rejections must produce two audit records (append-only)"
    );

    // An honest 200 ingestion MUST NOT touch the audit log.
    let honest = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let honest_post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(honest.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(honest_post.status(), 200);
    let raw_log_final = std::fs::read_to_string(&audit_path).expect("audit log readable");
    let final_lines: Vec<&str> = raw_log_final
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        final_lines.len(),
        2,
        "honest 200 ingestion must not touch the audit log"
    );
}

// Lane UU: the append-only Lane LL audit log must NOT grow unbounded.
// When a post-append size would exceed the 1 MiB cap, the file is
// rewritten keeping the newest records that fit. Without the cap a
// long-running control plane seeing regular tampering attempts would
// accumulate the file indefinitely. With the cap, operators retain
// the most-recent forensic record set; older records age out FIFO.
#[tokio::test]
async fn rejected_smoke_audit_log_rotates_at_one_mib_cap_lane_uu() {
    let (base, dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // Pre-populate the audit log with a synthetic record set that
    // sits at ~1.0 MiB so the next legitimate append crosses the cap
    // and triggers rotation. Each synthetic line is a valid
    // ao2.cp-rejected-three-os-smoke.v1 record so the per-line schema
    // contract (Lane RR) still holds after rotation.
    let synthetic_record = |idx: usize| {
        format!(
            "{{\"schema\":\"ao2.cp-rejected-three-os-smoke.v1\",\"timestamp_utc\":\"2026-05-24T00:00:00+00:00\",\"rejection_reason\":\"synthetic-fill-{idx}\",\"body_sha256\":\"{}\",\"body_size_bytes\":42,\"posted_summary\":{{\"schema\":\"ao2-control-plane.three-os-release-smoke.v1\",\"status\":\"passed\",\"version\":\"0.1.0\",\"release_candidate_version\":\"0.4.79\",\"source_commit_short\":\"abcdef012345\",\"source_dirty\":false,\"candidate_correlation_parity\":null,\"surface_content_hash_parity\":null,\"target_statuses\":{{\"macos\":\"passed\",\"ubuntu\":\"passed\",\"windows\":\"passed\"}}}}}}",
            "0".repeat(64),
        )
    };
    let mut pre_fill = String::new();
    let mut next_idx: usize = 0;
    // Fill UP TO 1 MiB exactly (within bytes-of-padding) so the next
    // legitimate production append unambiguously crosses the cap and
    // forces rotation. Without this density we'd land far enough
    // below 1 MiB that the production append would still fit and
    // rotation would not trigger.
    loop {
        let next = synthetic_record(next_idx);
        let projected = pre_fill.len() + next.len() + 1;
        if projected > 1024 * 1024 {
            break;
        }
        pre_fill.push_str(&next);
        pre_fill.push('\n');
        next_idx += 1;
    }
    let prefill_line_count = pre_fill.lines().count();
    std::fs::write(&audit_path, &pre_fill).expect("write pre-fill audit log");
    assert!(
        prefill_line_count > 100,
        "pre-fill must contain enough records to demonstrate FIFO eviction; got {prefill_line_count}"
    );

    // Trigger a legitimate rejection so the production code path
    // appends and (because the projected size exceeds the cap)
    // rotates.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "fedcba9876543210fedcba9876543210fedcba98",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);

    // Post-rotation invariants:
    //
    // (1) The file size is <= 1 MiB. Without the Lane UU cap the
    // size would have grown past 1 MiB by exactly one record.
    let rotated = std::fs::read_to_string(&audit_path).expect("audit log readable");
    assert!(
        rotated.len() <= 1024 * 1024,
        "rotated audit log must be <= 1 MiB; got {} bytes",
        rotated.len()
    );

    // (2) The newest record (the one this test triggered) is the
    // LAST line in the file — operators expect chronological order
    // even after rotation.
    let lines: Vec<&str> = rotated.lines().filter(|l| !l.trim().is_empty()).collect();
    let last = lines.last().expect("at least one record after rotation");
    // Lane LL redacts source_commit to a 12-char prefix; the full
    // SHA never appears in the audit record. Match on the redacted
    // prefix that uniquely identifies this test's rejection.
    assert!(
        last.contains("\"source_commit_short\":\"fedcba987654\""),
        "newest record (the just-triggered Lane UU rotation) must be last; got: {last}"
    );
    // The just-triggered record's rejection_reason names the
    // source_dirty cause; ensure that propagates.
    assert!(
        last.contains("source_dirty=true"),
        "newest record must contain the Lane KK source_dirty diagnostic"
    );
    // Synthetic pre-fill records carry "synthetic-fill-" in their
    // rejection_reason; the just-triggered record must NOT carry
    // that marker (proves the last line is the production-path
    // append, not a leftover synthetic).
    assert!(
        !last.contains("synthetic-fill-"),
        "newest record must be the production append, not a leftover synthetic; got: {last}"
    );

    // (3) FIFO eviction: the file MUST have fewer records than the
    // pre-fill + the new append (proving the rotation actually
    // dropped older records).
    assert!(
        lines.len() < prefill_line_count + 1,
        "rotation must drop older records; pre-fill={prefill_line_count}, post-rotation={}",
        lines.len()
    );

    // (4) Every kept record must still be valid JSON with the
    // documented schema — rotation must not corrupt records or
    // produce partial lines.
    for (idx, line) in lines.iter().enumerate() {
        let record: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("rotated record {idx} must be valid JSON: {e}"));
        assert_eq!(
            record["schema"], "ao2.cp-rejected-three-os-smoke.v1",
            "rotated record {idx} must still carry the schema constant"
        );
    }

    // (5) An immediately-following second append must also respect
    // the cap and must not regrow past it (rotation is repeatable).
    let post_again = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", test_auth_header())
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(post_again.status(), 422);
    let after_two = std::fs::read_to_string(&audit_path).expect("audit log readable");
    assert!(
        after_two.len() <= 1024 * 1024,
        "audit log must stay <= 1 MiB across repeated rotations; got {} bytes",
        after_two.len()
    );
}

// Lane RR: the Lane LL audit log's allowlist is the trust boundary
// that keeps auth tokens / provider keys / cookies / credentials out
// of the forensic record. The existing Lane LL test asserts the
// allowlisted fields ARE present; Lane RR asserts no EXTRA fields
// slipped in — a future code change that accidentally widens the
// allowlist (e.g., dumping the full request body into the record)
// would fail this contract loudly. Strict key-set equality at the
// top level and under posted_summary.
#[tokio::test]
async fn rejected_smoke_audit_log_records_exact_allowlist_schema_lane_rr() {
    let (base, dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // Three distinct rejection classes — each must produce a record
    // with the exact same top-level + posted_summary shape. If a
    // future code path branches and emits a different shape for one
    // rejection class, this test catches the divergence.
    let rejections = [
        // (1) Lane KK: source_commit format failure.
        serde_json::json!({
            "schema": "ao2-control-plane.three-os-release-smoke.v1",
            "version": "0.1.0",
            "release_candidate_version": "0.4.79",
            "status": "passed",
            "source_commit": "unknown",
            "source_dirty": false,
            "targets": {
                "macos": {"status": "passed"},
                "ubuntu": {"status": "passed"},
                "windows": {"status": "passed"}
            }
        }),
        // (2) Lane KK: source_dirty=true with status=passed.
        serde_json::json!({
            "schema": "ao2-control-plane.three-os-release-smoke.v1",
            "version": "0.1.0",
            "release_candidate_version": "0.4.79",
            "status": "passed",
            "source_commit": "52bbff188626315ca832c328570bc638260e5874",
            "source_dirty": true,
            "targets": {
                "macos": {"status": "passed"},
                "ubuntu": {"status": "passed"},
                "windows": {"status": "passed"}
            }
        }),
        // (3) Lane DD: status=passed but a target is failed.
        serde_json::json!({
            "schema": "ao2-control-plane.three-os-release-smoke.v1",
            "version": "0.1.0",
            "release_candidate_version": "0.4.79",
            "status": "passed",
            "source_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "source_dirty": false,
            "targets": {
                "macos": {"status": "passed"},
                "ubuntu": {"status": "passed"},
                "windows": {"status": "failed"}
            }
        }),
    ];
    for body in &rejections {
        let post = client
            .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
            .header("authorization", test_auth_header())
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 422);
    }

    let raw_log = std::fs::read_to_string(&audit_path).expect("audit log readable");
    let lines: Vec<&str> = raw_log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        rejections.len(),
        "one audit record per rejection (no merging, no skipping)"
    );

    // Top-level allowlist: exactly these keys, no extras.
    let expected_top_level: std::collections::BTreeSet<&str> = [
        "schema",
        "timestamp_utc",
        "rejection_reason",
        "body_sha256",
        "body_size_bytes",
        "posted_summary",
    ]
    .into_iter()
    .collect();

    // posted_summary allowlist: exactly these keys, no extras.
    let expected_summary: std::collections::BTreeSet<&str> = [
        "schema",
        "status",
        "version",
        "release_candidate_version",
        "source_commit_short",
        "source_dirty",
        "candidate_correlation_parity",
        "surface_content_hash_parity",
        "target_statuses",
    ]
    .into_iter()
    .collect();

    for (idx, line) in lines.iter().enumerate() {
        let record: serde_json::Value =
            serde_json::from_str(line).expect("audit record is valid JSON");
        let record_obj = record
            .as_object()
            .unwrap_or_else(|| panic!("audit record {idx} is not a JSON object"));
        let top_keys: std::collections::BTreeSet<&str> =
            record_obj.keys().map(String::as_str).collect();
        assert_eq!(
            top_keys, expected_top_level,
            "audit record {idx} top-level keys must EXACTLY match the allowlist; any extra key is a potential leak surface and any missing key is a forensic-record regression"
        );

        // schema must be the documented constant — not free-form.
        assert_eq!(
            record["schema"], "ao2.cp-rejected-three-os-smoke.v1",
            "audit record {idx} must use the documented schema constant"
        );
        // body_sha256 must be a full 64-char lowercase hex.
        let sha = record["body_sha256"].as_str().unwrap();
        assert_eq!(sha.len(), 64, "body_sha256 must be a full hex sha256");
        assert!(
            sha.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "body_sha256 must be lowercase hex only"
        );

        let summary_obj = record["posted_summary"]
            .as_object()
            .unwrap_or_else(|| panic!("audit record {idx} posted_summary is not an object"));
        let summary_keys: std::collections::BTreeSet<&str> =
            summary_obj.keys().map(String::as_str).collect();
        assert_eq!(
            summary_keys, expected_summary,
            "audit record {idx} posted_summary keys must EXACTLY match the allowlist; a leaked source_commit (full SHA, not just short) or a leaked auth/cookie field would surface as an extra key"
        );

        // source_commit_short must be at most 12 chars (or null). The
        // redactor takes the first 12 chars of source_commit and
        // filters to ascii alphanumerics; a real `git rev-parse`
        // output yields a 12-char prefix, while a malformed/placeholder
        // value (e.g., "unknown") yields whatever fits under 12 chars.
        // Any value > 12 chars would mean the redactor's truncation
        // failed and the audit log started leaking more of the SHA
        // than necessary.
        if let Some(short) = summary_obj["source_commit_short"].as_str() {
            assert!(
                short.len() <= 12,
                "source_commit_short must be <= 12 chars (redactor truncation cap); got {} chars: {short:?}",
                short.len()
            );
        }

        // target_statuses keys must be a subset of {macos, ubuntu,
        // windows}. A future OS expansion would need to land here AND
        // in the allowlist intentionally.
        let target_keys: std::collections::BTreeSet<&str> = summary_obj["target_statuses"]
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let allowed_targets: std::collections::BTreeSet<&str> =
            ["macos", "ubuntu", "windows"].into_iter().collect();
        assert!(
            target_keys.is_subset(&allowed_targets),
            "target_statuses keys must be a subset of {{macos, ubuntu, windows}}; got {target_keys:?}"
        );
    }
}

fn phase1_promotion_decision_fixture_governed_run_primary(
    checklist_sha: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "factory-v3/ao2-phase1-promotion-decision/v1",
        "status": "passed",
        "decision": "promote_phase1_candidate",
        "phase1_state": "phase1_candidate_ready",
        "checklist_sha256": checklist_sha,
        "operator": "release-lead",
        "rationale": "AO2 owns the replacement run path and all Phase 1 gates are verified.",
        "artifacts": {
            "phase1_promotion_checklist": "/factory/docs/status/hermes-nightly-ao2/phase1-promotion-checklist.json",
            "governed_run_evidence": [
                "/factory/target/three-os-real-runspec-evidence/macos/governed-run.json",
                "/factory/target/three-os-real-runspec-evidence/ubuntu/governed-run.json",
                "/factory/target/three-os-real-runspec-evidence/windows/governed-run.json"
            ],
            "replacement_smoke_gate": null
        }
    })
}

#[tokio::test]
async fn governed_run_primary_decision_surfaces_decision_mode_on_dashboard_and_operator_panel() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed = signed_phase1_promotion_decision_fixture(
        phase1_promotion_decision_fixture_governed_run_primary(checklist_sha),
        false,
    );
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let dashboard_body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(
        dashboard_body["decision_artifact"]["decision_mode"],
        "governed_run_primary"
    );
    assert_eq!(
        dashboard_body["decision_artifact"]["governed_run_evidence_count"],
        3
    );
    assert_eq!(
        dashboard_body["decision_artifact"]["replacement_smoke_gate_present"],
        false
    );

    let dashboard_html = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_html.status(), 200);
    let html_body = dashboard_html.text().await.unwrap();
    assert!(
        html_body.contains("Decision mode"),
        "dashboard HTML must surface a 'Decision mode' row"
    );
    assert!(
        html_body.contains("governed_run_primary"),
        "dashboard HTML must surface the governed_run_primary mode value"
    );

    let panel = client
        .get(format!(
            "{base}/api/v1/phase1/promotion/operator-panel.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(panel.status(), 200);
    let panel_body: serde_json::Value = panel.json().await.unwrap();
    assert_eq!(
        panel_body["badges"]["decision_mode"],
        "governed_run_primary"
    );

    let panel_html = client
        .get(format!("{base}/api/v1/phase1/promotion/operator-panel"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(panel_html.status(), 200);
    let panel_html_body = panel_html.text().await.unwrap();
    assert!(
        panel_html_body.contains("Decision mode"),
        "operator panel HTML must surface a 'Decision mode' badge row"
    );
    assert!(
        panel_html_body.contains("governed_run_primary"),
        "operator panel HTML must surface the governed_run_primary value"
    );
}

#[tokio::test]
async fn replacement_smoke_decision_surfaces_replacement_smoke_decision_mode() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", test_auth_header())
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let mut decision = phase1_promotion_decision_fixture(checklist_sha);
    decision["artifacts"]["governed_run_evidence"] = serde_json::Value::Array(vec![]);
    decision["artifacts"]["replacement_smoke_gate"] =
        serde_json::Value::String("/factory/target/replacement-smoke/gate.json".into());

    let signed = signed_phase1_promotion_decision_fixture(decision, false);
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", test_auth_header())
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);

    let dashboard = client
        .get(format!("{base}/api/v1/phase1/promotion/dashboard.json"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(
        body["decision_artifact"]["decision_mode"],
        "replacement_smoke"
    );
    assert_eq!(body["decision_artifact"]["governed_run_evidence_count"], 0);
    assert_eq!(
        body["decision_artifact"]["replacement_smoke_gate_present"],
        true
    );
}
