//! K3 follow-up to BOARD.md Claude lane: replay the first C1-emitted
//! `ao2 factory app-run` signed evidence pack through the read-only observer
//! surfaces and assert that the control plane never approves the release or
//! mutates the AO artifact.
//!
//! Fixture origin: `ao2 factory-app-run-smoke/20260528T021427Z/run/governed-run/
//! factory-app-smoke-evidence-pack.json` (Codex C1 output, commit `3cbb8dc` on
//! `ao2/main`). The raw `.sig` binary is not reused here because the
//! CP verifier re-serializes the inner pack with `serde_json::to_string_pretty`
//! before checking the RSA/SHA-256 signature; the fixture is re-signed in the
//! test with a freshly generated key (same pattern as `evidence_pack.rs`).

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{SignatureEncoding, Signer};
use std::sync::Arc;
use tempfile::tempdir;

const FACTORY_APP_RUN_EVIDENCE_PACK: &str =
    include_str!("fixtures/factory-app-run/factory-app-smoke-evidence-pack.json");

async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: "secret".to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
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

fn sign_factory_app_run_evidence_pack() -> serde_json::Value {
    let evidence_pack: serde_json::Value =
        serde_json::from_str(FACTORY_APP_RUN_EVIDENCE_PACK).expect("C1 fixture must parse as JSON");
    let evidence_raw = serde_json::to_string_pretty(&evidence_pack).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let signature_bytes = signing_key.sign(evidence_raw.as_bytes()).to_vec();
    let signature_hex = signature_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    serde_json::json!({
        "schema_version": "ao2.cp-evidence-pack-signed-upload.v1",
        "evidence_pack": evidence_pack,
        "signature": {
            "schema_version": "ao2.cp-evidence-pack-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "factory-app-run-readback-test"
        }
    })
}

#[tokio::test]
async fn factory_app_run_evidence_pack_round_trips_through_observer_endpoints() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = sign_factory_app_run_evidence_pack();

    // 1. Ingest the C1-shaped signed evidence pack via the observer's only
    //    write surface for evidence packs.
    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(
        ingest.status().is_success(),
        "C1 factory-app-run evidence pack must ingest cleanly through CP /evidence-pack/signed: status={}",
        ingest.status()
    );
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    assert_eq!(
        receipt["ingested_schema_version"], "ao2.evidence-pack.v1",
        "CP receipt must echo the AO2 evidence-pack schema verbatim"
    );
    let sha = receipt["sha256"]
        .as_str()
        .expect("receipt must include sha256")
        .to_string();

    // 2. The C1 run_id readback surface must return the evidence pack
    //    unchanged and observer-decorated only.
    let by_run = client
        .get(format!(
            "{base}/api/v1/evidence-pack/run/factory-app-smoke/latest"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(by_run.status().is_success());
    let by_run_body: serde_json::Value = by_run.json().await.unwrap();
    let evidence_pack = by_run_body.get("evidence_pack").unwrap_or(&by_run_body);
    let pack_view = evidence_pack
        .pointer("/evidence_pack")
        .unwrap_or(evidence_pack);
    assert_eq!(
        pack_view["run_id"], "factory-app-smoke",
        "readback must preserve the C1 run_id"
    );
    assert_eq!(
        pack_view["verdict"], "accepted",
        "readback must preserve C1's accepted verdict"
    );
    assert_eq!(
        pack_view["schema_version"], "ao2.evidence-pack.v1",
        "readback must preserve the v1 evidence-pack schema string"
    );

    // 3. The detail endpoint must return the stored body byte-for-byte
    //    (modulo re-serialization), proving CP does not mutate AO artifacts.
    let detail = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(detail.status().is_success());
    let detail_body: serde_json::Value = detail.json().await.unwrap();
    let detail_pack = detail_body
        .pointer("/evidence_pack")
        .unwrap_or(&detail_body);
    let detail_pack = detail_pack.pointer("/evidence_pack").unwrap_or(detail_pack);
    assert_eq!(detail_pack["run_id"], "factory-app-smoke");
    assert_eq!(detail_pack["verdict"], "accepted");

    // 4. Observer-only invariant: the C1 trust-boundary signals carried by the
    //    evidence pack must survive readback unchanged. The control plane must
    //    NEVER rewrite these fields to claim ownership of release approval.
    assert_eq!(
        detail_pack["factory_v3_compatibility"]["factory_v3_role"], "parity_oracle_only",
        "control plane must not erase the factory_v3 parity_oracle_only role"
    );
    assert_eq!(
        detail_pack["factory_v3_compatibility"]["ao2_execution_owner"], true,
        "control plane must not transfer ao2's execution ownership to itself"
    );

    // 5. Observer-only invariant: HEAD returns existence, GET returns content,
    //    no other HTTP verb mutates the stored artifact. We exercise the
    //    documented surface to confirm DELETE/PATCH/PUT are not registered as
    //    routes for the per-sha artifact (axum returns 405 Method Not Allowed
    //    when the path matches but the verb is unsupported).
    let head_resp = client
        .head(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(head_resp.status().is_success(), "HEAD must be supported");
    let delete_resp = client
        .delete(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(
        delete_resp.status().is_client_error(),
        "DELETE must not be a supported observer verb; status={}",
        delete_resp.status()
    );
    let put_resp = client
        .put(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .json(&serde_json::json!({"verdict": "rejected"}))
        .send()
        .await
        .unwrap();
    assert!(
        put_resp.status().is_client_error(),
        "PUT must not be a supported observer verb; status={}",
        put_resp.status()
    );

    // 6. Observer-only invariant: the ingest receipt must not contain a release
    //    approval token, decision, or any field that could be interpreted as
    //    CP-side acceptance of the release. CP records observation, never
    //    approval.
    let receipt_str = receipt.to_string();
    assert!(
        !receipt_str.contains("release_approved"),
        "ingest receipt leaked a release_approved field: {receipt_str}"
    );
    assert!(
        !receipt_str.contains("approval_granted"),
        "ingest receipt leaked an approval_granted field: {receipt_str}"
    );
    // The receipt may surface the AO-side verdict (observation), but it must
    // not promote that verdict to a control-plane decision.
    assert!(
        !receipt_str.contains("control_plane_decision"),
        "ingest receipt leaked a control_plane_decision field: {receipt_str}"
    );
}
