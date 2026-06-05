use ao2_cp_schema::canonical::canonical_json;
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use std::sync::Arc;
use tempfile::tempdir;

fn provider_registry_fixture() -> String {
    serde_json::json!({
        "schema": "ao2.provider-plugin-registry.v1",
        "phase": "phase_2_registry_groundwork",
        "trust_boundary": {
            "execution_owner": "ao2-local-cli",
            "control_plane_role": "read_only_observer_only"
        },
        "providers": [
            {
                "provider": "scripted",
                "metadata_source": "ao2-adapters",
                "crate": "ao2-adapters",
                "adapter_kind": "built_in_deterministic",
                "doctor": {
                    "metadata_source": "ao2-adapters",
                    "doctor_args": []
                },
                "guards": {
                    "explicit_live_env": null
                },
                "extension_slots": ["factory_hermes_bridge", "control_plane_observer"]
            },
            {
                "provider": "codex",
                "metadata_source": "ao2-adapter-codex",
                "crate": "ao2-adapter-codex",
                "adapter_kind": "local_oauth_cli",
                "doctor": {
                    "metadata_source": "ao2-adapter-codex",
                    "doctor_args": ["--version"]
                },
                "guards": {
                    "explicit_live_env": "AO2_LIVE_CODEX_PILOT"
                },
                "extension_slots": ["factory_hermes_bridge", "control_plane_observer"]
            }
        ]
    })
    .to_string()
}

fn signed_provider_registry_fixture(tamper_signature: bool) -> serde_json::Value {
    let registry: serde_json::Value = serde_json::from_str(&provider_registry_fixture()).unwrap();
    let registry_raw = serde_json::to_string_pretty(&registry).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut signature = signing_key.sign(registry_raw.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    serde_json::json!({
        "schema_version": "ao2.cp-provider-registry-signed-upload.v1",
        "registry": registry,
        "signature": {
            "schema_version": "ao2.cp-provider-registry-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "registry-lead"
        }
    })
}

fn signed_provider_registry_fixture_over_exact_bytes(
    signed_bytes: &str,
    tamper_signature: bool,
) -> serde_json::Value {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    let registry: serde_json::Value = serde_json::from_str(signed_bytes).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut signature = signing_key.sign(signed_bytes.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    serde_json::json!({
        "schema_version": "ao2.cp-provider-registry-signed-upload.v1",
        "registry": registry,
        "registry_b64": BASE64_STANDARD.encode(signed_bytes.as_bytes()),
        "signature": {
            "schema_version": "ao2.cp-provider-registry-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "registry-lead"
        }
    })
}

async fn spawn_server() -> (String, tempfile::TempDir) {
    spawn_server_with_provider_readiness_trusted_keys(Vec::new()).await
}

async fn spawn_server_with_provider_readiness_trusted_keys(
    provider_readiness_trusted_key_sha256s: Vec<String>,
) -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: "secret".to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s,
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
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
async fn post_signed_provider_registry_verifies_over_exact_registry_b64_bytes() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let signed_bytes = provider_registry_fixture();
    let upload = signed_provider_registry_fixture_over_exact_bytes(&signed_bytes, false);

    let post = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();

    assert_eq!(
        post.status(),
        200,
        "signed provider registry must verify over registry_b64 exact bytes"
    );
}

#[tokio::test]
async fn post_signed_provider_registry_stores_exact_registry_b64_bytes() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let signed_bytes = provider_registry_fixture();
    let mut upload = signed_provider_registry_fixture_over_exact_bytes(&signed_bytes, false);
    upload["registry"] = serde_json::json!({
        "schema": "ao2.provider-plugin-registry.v1",
        "phase": "attacker-controlled-not-signed",
        "trust_boundary": {"control_plane_role": "producer"},
        "providers": []
    });

    let post = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        200,
        "registry_b64 must be the trusted content when parallel registry diverges"
    );
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let stored = client
        .get(format!("{base}/api/v1/provider/registry/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(stored.status(), 200);
    let stored_body = stored.text().await.unwrap();
    assert_eq!(stored_body, signed_bytes);
    assert!(!stored_body.contains("attacker-controlled-not-signed"));
}

#[tokio::test]
async fn post_provider_registry_returns_receipt_and_latest() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let fixture = provider_registry_fixture();

    let post = client
        .post(format!("{base}/api/v1/provider/registry"))
        .header("authorization", "Bearer secret")
        .body(fixture)
        .send()
        .await
        .unwrap();

    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "ao2.provider-plugin-registry.v1"
    );

    let latest = client
        .get(format!("{base}/api/v1/provider/registry/latest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(body["schema"], "ao2.provider-plugin-registry.v1");
    assert_eq!(body["trust_boundary"]["execution_owner"], "ao2-local-cli");
}

#[tokio::test]
async fn post_signed_provider_registry_returns_receipt_signature_and_detail() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_registry_fixture(false))
        .send()
        .await
        .unwrap();

    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "ao2.provider-plugin-registry.v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let signature = client
        .get(format!("{base}/api/v1/provider/registry/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-provider-registry-signature.v1"
    );
    assert_eq!(signature_body["provider_registry_sha256"], sha);
    assert_eq!(signature_body["signature"]["signature_verified"], true);
    assert_eq!(signature_body["signature"]["signer_id"], "registry-lead");

    let detail = client
        .get(format!("{base}/api/v1/provider/registry/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let html = detail.text().await.unwrap();
    assert!(html.contains("AO2 Provider Registry Detail"));
    assert!(html.contains("registry-lead"));
    assert!(html.contains("Signature verified"));
    assert!(html.contains("codex"));
    assert!(html.contains("AO2_LIVE_CODEX_PILOT"));
    assert!(html.contains("/api/v1/evidence-pack/dashboard"));
    assert!(html.contains("/api/v1/memory/export/dashboard"));

    let detail_json = client
        .get(format!("{base}/api/v1/provider/registry/{sha}/detail.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail_json.status(), 200);
    let detail_body: serde_json::Value = detail_json.json().await.unwrap();
    assert_eq!(
        detail_body["schema_version"],
        "ao2.cp-provider-registry-detail.v1"
    );
    assert_eq!(detail_body["sha256"], sha);
    assert_eq!(detail_body["signature"]["signature_verified"], true);
    assert_eq!(detail_body["signature"]["signer_id"], "registry-lead");
    assert_eq!(detail_body["provider_count"], 2);
    assert_eq!(detail_body["providers"][1]["provider"], "codex");
    assert_eq!(
        detail_body["providers"][1]["metadata_source"],
        "ao2-adapter-codex"
    );
    assert_eq!(
        detail_body["providers"][1]["doctor_metadata_source"],
        "ao2-adapter-codex"
    );
    assert_eq!(
        detail_body["providers"][1]["live_guard"],
        "AO2_LIVE_CODEX_PILOT"
    );
    assert_eq!(
        detail_body["providers"][1]["evidence_dashboard_json_url"],
        "/api/v1/evidence-pack/dashboard.json"
    );
    assert_eq!(
        detail_body["links"]["signature"],
        format!("/api/v1/provider/registry/{sha}/signature")
    );
}

#[tokio::test]
async fn signed_provider_registry_signature_sidecar_is_write_once_per_content_sha() {
    // The signature sidecar records *who signed* a given registry content sha.
    // A second signed upload of the *same registry bytes* but a *different*
    // signature (different key / provenance) must NOT silently overwrite the
    // first signer's sidecar — otherwise any holder of a valid signing key could
    // rewrite the recorded provenance of already-ingested evidence. First write
    // wins; a conflicting re-sign is rejected. This mirrors the existing
    // write-once guard on the provider-readiness signature sidecar.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let first = signed_provider_registry_fixture(false);
    let second = signed_provider_registry_fixture(false);
    // Precondition: same registry content (same sha) but independently generated
    // keys, so the signatures genuinely differ — this is what makes it a
    // provenance conflict rather than an idempotent re-upload.
    assert_eq!(
        first["registry"], second["registry"],
        "fixtures must share identical registry content"
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
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(post1.status(), 200, "first signed upload is accepted");
    let receipt: serde_json::Value = post1.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();

    // Conflicting re-sign of an existing content sha: rejected, not stored.
    let post2 = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
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
        .get(format!("{base}/api/v1/provider/registry/{sha}/signature"))
        .header("authorization", "Bearer secret")
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
async fn signed_provider_registry_reupload_of_identical_artifact_stays_idempotent() {
    // The write-once guard must not break idempotent retries: re-POSTing the
    // *exact same* signed artifact (identical signature bytes) yields the same
    // sidecar_raw, so it is accepted as a no-op rather than rejected as a
    // conflict. Guards the `existing == sidecar_raw` branch of the guard.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let artifact = signed_provider_registry_fixture(false);

    for attempt in 1..=2 {
        let post = client
            .post(format!("{base}/api/v1/provider/registry/signed"))
            .header("authorization", "Bearer secret")
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
async fn list_and_dashboard_render_provider_registry_as_observer_only() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/api/v1/provider/registry"))
        .header("authorization", "Bearer secret")
        .body(provider_registry_fixture())
        .send()
        .await
        .unwrap();

    let list = client
        .get(format!("{base}/api/v1/provider/registry"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let list_body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(
        list_body["schema_version"],
        "ao2.cp-provider-registry-list.v1"
    );
    assert_eq!(list_body["total_count"], 1);

    let dashboard = client
        .get(format!("{base}/api/v1/provider/registry/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("AO2 Provider Registry"));
    assert!(html.contains("read-only observer"));
    assert!(html.contains("phase_2_registry_groundwork"));
    assert!(html.contains("/api/v1/provider/registry/latest"));
    assert!(html.contains("/api/v1/provider/registry/"));
    assert!(html.contains("/detail"));
}

#[tokio::test]
async fn provider_registry_dashboard_json_summarizes_latest_signed_registry() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_registry_fixture(false))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let dashboard = client
        .get(format!("{base}/api/v1/provider/registry/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let body: serde_json::Value = dashboard.json().await.unwrap();

    assert_eq!(
        body["schema_version"],
        "ao2.cp-provider-registry-dashboard.v1"
    );
    assert_eq!(body["status"], "observed");
    assert_eq!(body["latest"]["sha256"], sha);
    assert_eq!(body["latest"]["phase"], "phase_2_registry_groundwork");
    assert_eq!(body["latest"]["provider_count"], 2);
    assert_eq!(body["latest"]["signature"]["signature_verified"], true);
    assert_eq!(body["latest"]["signature"]["signer_id"], "registry-lead");
    assert_eq!(body["providers"][1]["provider"], "codex");
    assert_eq!(body["providers"][1]["metadata_source"], "ao2-adapter-codex");
    assert_eq!(
        body["providers"][1]["doctor_metadata_source"],
        "ao2-adapter-codex"
    );
    assert_eq!(body["providers"][1]["live_guard"], "AO2_LIVE_CODEX_PILOT");
    assert_eq!(
        body["links"]["acceptance_dashboard"],
        "/api/v1/acceptance/dashboard"
    );
    assert_eq!(
        body["links"]["phase1_operator_panel_json"],
        "/api/v1/phase1/promotion/operator-panel.json"
    );
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert!(!serde_json::to_string(&body).unwrap().contains("Bearer"));

    let html = client
        .get(format!("{base}/api/v1/provider/registry/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("/api/v1/provider/registry/dashboard.json"));
}

fn provider_phase1_readiness_fixture() -> String {
    provider_phase1_readiness_fixture_with("passed", "not_ready", "blocked", Vec::new())
}

fn provider_phase1_readiness_fixture_with(
    status: &str,
    codex_gate: &str,
    codex_pilot: &str,
    required_live_provider_pilots: Vec<&str>,
) -> String {
    serde_json::json!({
        "schema": "factory-v3/hermes-provider-phase1-readiness/v1",
        "status": status,
        "live_provider_policy": "not_run_by_default",
        "required_live_provider_pilots": required_live_provider_pilots,
        "contracts": {
            "codex": {"status": "verified"},
            "claude": {"status": "verified"},
            "antigravity": {"status": "verified"}
        },
        "scripted_gate": {"verdict": "ready"},
        "codex_gate": {"verdict": codex_gate},
        "codex_pilot": {"status": codex_pilot}
    })
    .to_string()
}

fn signed_provider_phase1_readiness_fixture(tamper_signature: bool) -> serde_json::Value {
    signed_provider_phase1_readiness_fixture_with(tamper_signature, false)
}

fn signed_provider_phase1_readiness_fixture_with(
    tamper_signature: bool,
    include_unsupported_signature_field: bool,
) -> serde_json::Value {
    let readiness: serde_json::Value = serde_json::from_str(
        &provider_phase1_readiness_fixture_with("passed", "ready", "ready", vec!["codex"]),
    )
    .unwrap();
    let readiness_raw = canonical_json(&readiness).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut signature = signing_key.sign(readiness_raw.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let mut upload = serde_json::json!({
        "schema_version": "ao2.cp-provider-readiness-signed-upload.v1",
        "readiness": readiness,
        "signature": {
            "schema_version": "ao2.cp-provider-readiness-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "provider-readiness-evaluator"
        }
    });
    if include_unsupported_signature_field {
        upload["signature"]["bearer_token"] = serde_json::json!("should-not-persist");
    }
    upload
}

fn provider_readiness_public_key_sha256(upload: &serde_json::Value) -> String {
    let public_key_pem = upload["signature"]["public_key_pem"].as_str().unwrap();
    let mut hasher = Sha256::new();
    hasher.update(public_key_pem.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn signed_provider_phase1_readiness_marks_configured_trusted_key_as_release_authoritative() {
    let upload = signed_provider_phase1_readiness_fixture(false);
    let trusted_key = provider_readiness_public_key_sha256(&upload);
    let (base, _dir) =
        spawn_server_with_provider_readiness_trusted_keys(vec![trusted_key.clone()]).await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let signature = client
        .get(format!("{base}/api/v1/provider/readiness/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["signature"]["verification_scope"],
        "cryptographic-and-pinned-key"
    );
    assert_eq!(
        signature_body["signature"]["trust_anchor"],
        "configured-provider-readiness-public-key-sha256"
    );
    assert_eq!(
        signature_body["signature"]["trust_policy"]["policy"],
        "pinned-public-key-sha256"
    );
    assert_eq!(
        signature_body["signature"]["trust_policy"]["trusted_key_match"],
        true
    );
    assert_eq!(
        signature_body["signature"]["trust_policy"]["release_authoritative"],
        true
    );
    assert_eq!(
        signature_body["signature"]["trust_policy"]["matched_public_key_sha256"],
        trusted_key
    );
    assert!(signature_body["signature"]["public_key_pem"].is_null());
}

#[tokio::test]
async fn provider_phase1_readiness_is_observed_without_execution() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", "Bearer secret")
        .body(provider_phase1_readiness_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/hermes-provider-phase1-readiness/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!("{base}/api/v1/provider/readiness/latest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(
        latest_body["schema"],
        "factory-v3/hermes-provider-phase1-readiness/v1"
    );
    assert_eq!(latest_body["codex_gate"]["verdict"], "not_ready");

    let raw = client
        .get(format!("{base}/api/v1/provider/readiness/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);
    let raw_body: serde_json::Value = raw.json().await.unwrap();
    assert_eq!(raw_body["codex_pilot"]["status"], "blocked");

    let list = client
        .get(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let list_body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(
        list_body["schema_version"],
        "ao2.cp-provider-readiness-list.v1"
    );
    assert_eq!(
        list_body["entries"][0]["detail_url"],
        format!("/api/v1/provider/readiness/{sha}/detail")
    );
    assert_eq!(
        list_body["entries"][0]["detail_json_url"],
        format!("/api/v1/provider/readiness/{sha}/detail.json")
    );

    let dashboard = client
        .get(format!("{base}/api/v1/provider/readiness/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("AO2 Provider Phase 1 Readiness"));
    assert!(html.contains("read-only observer"));
    assert!(html.contains("not_run_by_default"));
    assert!(html.contains("codex"));
    assert!(html.contains("not_ready"));
    assert!(html.contains("blocked"));
    assert!(html.contains(&format!("/api/v1/provider/readiness/{sha}/detail")));

    let detail = client
        .get(format!("{base}/api/v1/provider/readiness/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail_html = detail.text().await.unwrap();
    assert!(detail_html.contains("Provider Readiness Detail"));
    assert!(detail_html.contains("Evidence Dashboard"));
    assert!(detail_html.contains("Memory Dashboard"));
    assert!(detail_html.contains("Latest Readiness JSON"));

    let detail_json = client
        .get(format!(
            "{base}/api/v1/provider/readiness/{sha}/detail.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail_json.status(), 200);
    let detail_body: serde_json::Value = detail_json.json().await.unwrap();
    assert_eq!(
        detail_body["schema_version"],
        "ao2.cp-provider-readiness-detail.v1"
    );
    assert_eq!(detail_body["sha256"], sha);
    assert_eq!(detail_body["provider_gates"]["codex"]["gate"], "not_ready");
    assert_eq!(detail_body["provider_gates"]["codex"]["pilot"], "blocked");
    assert_eq!(
        detail_body["links"]["evidence_dashboard"],
        "/api/v1/evidence-pack/dashboard"
    );
    assert_eq!(
        detail_body["links"]["acceptance_dashboard"],
        "/api/v1/acceptance/dashboard"
    );

    let dashboard_json = client
        .get(format!("{base}/api/v1/provider/readiness/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let dashboard_body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(
        dashboard_body["schema_version"],
        "ao2.cp-provider-readiness-dashboard.v1"
    );
    assert_eq!(dashboard_body["entries"][0]["sha256"], sha);
    assert_eq!(
        dashboard_body["entries"][0]["detail_json_url"],
        format!("/api/v1/provider/readiness/{sha}/detail.json")
    );
    assert_eq!(
        dashboard_body["links"]["support_bundle_json"],
        "/api/v1/provider/readiness/support-bundle.json"
    );
}

#[tokio::test]
async fn provider_readiness_support_bundle_is_portable_and_digest_indexed() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", "Bearer secret")
        .body(provider_phase1_readiness_fixture_with(
            "passed",
            "ready",
            "ready",
            vec!["codex"],
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let bundle = client
        .get(format!(
            "{base}/api/v1/provider/readiness/support-bundle.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(bundle.status(), 200);
    let bundle_body: serde_json::Value = bundle.json().await.unwrap();
    assert_eq!(
        bundle_body["schema_version"],
        "ao2.cp-provider-readiness-support-bundle.v1"
    );
    assert_eq!(bundle_body["control_plane_role"], "read_only_observer");
    assert_eq!(bundle_body["mutates_ao_artifacts"], false);
    assert_eq!(bundle_body["contains_bearer_token"], false);
    assert_eq!(bundle_body["latest_provider_readiness_sha256"], sha);
    assert_eq!(bundle_body["latest_provider_readiness"]["status"], "passed");
    assert_eq!(bundle_body["dashboard"]["total_count"], 1);
    assert_eq!(
        bundle_body["links"]["support_bundle_download"],
        "/api/v1/provider/readiness/support-bundle/download"
    );
    let serialized = serde_json::to_string(&bundle_body).unwrap();
    assert!(!serialized.contains("Bearer"));
    assert!(!serialized.contains("secret"));

    let download = client
        .get(format!(
            "{base}/api/v1/provider/readiness/support-bundle/download"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download.headers()["x-ao2-cp-control-plane-role"],
        "read-only-observer"
    );
    assert!(download.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .contains("ao2-provider-readiness-support-bundle-"));

    let checksums = client
        .get(format!(
            "{base}/api/v1/provider/readiness/support-bundle/SHA256SUMS"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(checksums.status(), 200);
    let checksums_text = checksums.text().await.unwrap();
    assert!(checksums_text.contains("ao2.cp-provider-readiness-support-bundle-checksums.v1"));
    assert!(checksums_text.contains("read-only-observer"));
    assert!(checksums_text.contains("surfaces/provider-readiness-dashboard.json"));
    assert!(checksums_text.contains("surfaces/latest-provider-readiness.json"));
}

#[tokio::test]
async fn signed_provider_phase1_readiness_returns_signature_and_dashboard_state() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_phase1_readiness_fixture(false))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/hermes-provider-phase1-readiness/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let signature = client
        .get(format!("{base}/api/v1/provider/readiness/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-provider-readiness-signature.v1"
    );
    assert_eq!(signature_body["provider_readiness_sha256"], sha);
    assert_eq!(signature_body["signature"]["signature_verified"], true);
    assert_eq!(
        signature_body["signature"]["signer_id"],
        "provider-readiness-evaluator"
    );
    assert_eq!(
        signature_body["signature"]["verification_scope"],
        "cryptographic-only"
    );
    assert_eq!(
        signature_body["signature"]["trust_anchor"],
        "upload-public-key-not-authority"
    );
    assert!(signature_body["signature"]["public_key_pem"].is_null());
    assert!(!serde_json::to_string(&signature_body)
        .unwrap()
        .contains("bearer_token"));

    let detail_json = client
        .get(format!(
            "{base}/api/v1/provider/readiness/{sha}/detail.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail_json.status(), 200);
    let detail_body: serde_json::Value = detail_json.json().await.unwrap();
    assert_eq!(detail_body["signature"]["signature_verified"], true);
    assert_eq!(
        detail_body["links"]["signature"],
        format!("/api/v1/provider/readiness/{sha}/signature")
    );

    let detail_html = client
        .get(format!("{base}/api/v1/provider/readiness/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(detail_html.contains("Signature verified"));
    assert!(detail_html.contains("provider-readiness-evaluator"));
    assert!(detail_html.contains("/api/v1/provider/readiness/"));
    assert!(detail_html.contains("/signature"));

    let dashboard_json = client
        .get(format!("{base}/api/v1/provider/readiness/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let dashboard_body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(
        dashboard_body["entries"][0]["signature"]["signature_verified"],
        true
    );
    assert_eq!(
        dashboard_body["entries"][0]["signature_url"],
        format!("/api/v1/provider/readiness/{sha}/signature")
    );
    assert!(!serde_json::to_string(&dashboard_body)
        .unwrap()
        .contains("Bearer"));
}

#[tokio::test]
async fn signed_provider_phase1_readiness_rejects_bad_signature() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_phase1_readiness_fixture(true))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);
}

#[tokio::test]
async fn signed_provider_phase1_readiness_rejects_unsupported_signature_metadata() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_phase1_readiness_fixture_with(true, true))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);
}

#[tokio::test]
async fn signed_provider_phase1_readiness_rejects_conflicting_sidecar_for_same_sha() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_phase1_readiness_fixture(false))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let conflicting = client
        .post(format!("{base}/api/v1/provider/readiness/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_phase1_readiness_fixture(false))
        .send()
        .await
        .unwrap();
    assert_eq!(conflicting.status(), 422);
}

#[tokio::test]
async fn provider_readiness_dashboard_json_reports_trend_summary() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", "Bearer secret")
        .body(provider_phase1_readiness_fixture_with(
            "passed",
            "not_ready",
            "blocked",
            Vec::new(),
        ))
        .send()
        .await
        .unwrap();

    let ready = client
        .post(format!("{base}/api/v1/provider/readiness"))
        .header("authorization", "Bearer secret")
        .body(provider_phase1_readiness_fixture_with(
            "passed",
            "ready",
            "ready",
            vec!["codex"],
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
    let ready_receipt: serde_json::Value = ready.json().await.unwrap();
    let ready_sha = ready_receipt["sha256"].as_str().unwrap();

    let dashboard_json = client
        .get(format!("{base}/api/v1/provider/readiness/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(body["trend"]["total_count"], 2);
    assert_eq!(body["trend"]["latest_sha256"], ready_sha);
    assert_eq!(body["trend"]["latest_status"], "passed");
    assert_eq!(body["trend"]["latest_codex_gate"], "ready");
    assert_eq!(body["trend"]["latest_codex_pilot"], "ready");
    assert_eq!(body["trend"]["codex_ready_count"], 1);
    assert_eq!(body["trend"]["codex_blocked_count"], 1);
    assert_eq!(body["trend"]["required_live_provider_pilot_count"], 1);
    assert_eq!(body["phase1_status"]["state"], "pilot_complete");
    assert_eq!(body["phase1_status"]["provider"], "codex");
    assert_eq!(body["phase1_status"]["gate"], "ready");
    assert_eq!(body["phase1_status"]["pilot"], "ready");
    assert_eq!(
        body["phase1_status"]["next_action"],
        "review signed provider-pilot acceptance evidence for Phase 1 promotion"
    );
    assert_eq!(
        body["phase1_next_actions"][0],
        "review signed provider-pilot acceptance evidence for Phase 1 promotion"
    );
    assert_eq!(
        body["links"]["acceptance_dashboard"],
        "/api/v1/acceptance/dashboard"
    );
    assert_eq!(
        body["phase1_blockers"][0],
        "blocked readiness artifacts remain in provider readiness history"
    );
    assert_eq!(
        body["entries"][0]["phase1_status"]["state"],
        "pilot_complete"
    );
    assert_eq!(
        body["entries"][1]["phase1_blockers"][0],
        "Codex readiness gate is not ready"
    );
    assert_eq!(body["entries"][1]["phase1_status"]["state"], "blocked");

    let dashboard = client
        .get(format!("{base}/api/v1/provider/readiness/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("Readiness Trend"));
    assert!(html.contains("Phase 1 State"));
    assert!(html.contains("Phase 1 Blockers"));
    assert!(html.contains("Safe Next Actions"));
    assert!(html.contains("blocked readiness artifacts remain in provider readiness history"));
    assert!(html.contains("/api/v1/acceptance/dashboard"));
    assert!(html.contains("pilot_complete"));
    assert!(html.contains("Latest Codex Gate"));
    assert!(html.contains("ready"));
}

#[tokio::test]
async fn post_provider_registry_rejects_wrong_schema_or_owner() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let wrong_schema = client
        .post(format!("{base}/api/v1/provider/registry"))
        .header("authorization", "Bearer secret")
        .body(r#"{"schema":"ao2.memory-export.v1","providers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_schema.status(), 422);

    let wrong_owner = client
        .post(format!("{base}/api/v1/provider/registry"))
        .header("authorization", "Bearer secret")
        .body(
            r#"{"schema":"ao2.provider-plugin-registry.v1","trust_boundary":{"execution_owner":"control-plane"},"providers":[{"provider":"codex"}]}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_owner.status(), 422);

    let bad_signature = client
        .post(format!("{base}/api/v1/provider/registry/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed_provider_registry_fixture(true))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_signature.status(), 422);
}
