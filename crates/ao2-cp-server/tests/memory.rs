use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use std::sync::Arc;
use tempfile::tempdir;

const MEMORY_FIXTURE: &str = include_str!("../../../tests/fixtures/memory-export-sample.json");

#[test]
fn signed_memory_export_verification_does_not_shell_out_to_openssl() {
    let source = include_str!("../src/handlers/memory.rs");
    assert!(
        !source.contains("std::process::Command"),
        "signed memory verification must not depend on spawning external commands"
    );
    assert!(
        !source.contains("\"openssl\""),
        "signed memory verification must be native Rust, not a runtime openssl executable"
    );
}

#[test]
fn signed_memory_export_tests_do_not_skip_without_openssl() {
    let source = include_str!("memory.rs");
    let skip_marker = ["skipping ", "OpenSSL-backed signature test"].concat();
    let command_marker = ["Command::new(", "\"openssl\"", ")"].concat();
    assert!(
        !source.contains(&skip_marker),
        "signed memory tests must exercise native verification on every supported OS"
    );
    assert!(
        !source.contains(&command_marker),
        "signed memory tests must not depend on a local openssl executable"
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn signed_memory_payload(tamper_signature: bool) -> serde_json::Value {
    let export: serde_json::Value = serde_json::from_str(MEMORY_FIXTURE).unwrap();
    let export_raw = serde_json::to_string_pretty(&export).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut signature = signing_key.sign(export_raw.as_bytes()).to_vec();
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    serde_json::json!({
        "schema_version": "ao2.cp-memory-export-signed-upload.v1",
        "export": export,
        "signature": {
            "present": true,
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "local-operator",
            "signature_path": "memory-export.json.sig",
            "signature_sha256": sha256_bytes(&signature),
            "signature_hex": hex_encode(&signature),
            "public_key_path": "memory-export-signing-public.pem",
            "public_key_sha256": sha256_bytes(public_key_pem.as_bytes()),
            "public_key_pem": public_key_pem
        }
    })
}

/// A schema-valid memory export whose on-the-wire bytes deliberately differ from the
/// server's `to_string_pretty(&export)`: compact separators plus a float carrying more
/// significant digits than an `f64` round-trips to. Re-serializing the parsed value
/// both reflows the whitespace and shortens the float, so a server that verifies over
/// the reconstruction (instead of the producer's exact signed bytes) fail-closes this
/// untampered upload.
const DIVERGENT_MEMORY_EXPORT_BYTES: &str = r#"{"schema_version":"ao2.memory-export.v1","record_count":1,"link_count":0,"records":[{"id":"rec-float","score":0.12345678901234567890123456789}],"links":[]}"#;

/// Build a signed memory upload whose signature covers EXACTLY `signed_bytes`, carried
/// verbatim in `export_b64`. The parsed `export` is included too (as a real producer
/// ships it), but it re-serializes to different bytes — so verifying over `export`
/// rather than `export_b64` would reject this untampered upload.
fn signed_memory_upload_over_exact_bytes(
    signed_bytes: &str,
    tamper_signature: bool,
) -> serde_json::Value {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    let export: serde_json::Value = serde_json::from_str(signed_bytes).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut signature = signing_key.sign(signed_bytes.as_bytes()).to_vec();
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    serde_json::json!({
        "schema_version": "ao2.cp-memory-export-signed-upload.v1",
        "export": export,
        "export_b64": BASE64_STANDARD.encode(signed_bytes.as_bytes()),
        "signature": {
            "present": true,
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "local-operator",
            "signature_path": "memory-export.json.sig",
            "signature_sha256": sha256_bytes(&signature),
            "signature_hex": hex_encode(&signature),
            "public_key_path": "memory-export-signing-public.pem",
            "public_key_sha256": sha256_bytes(public_key_pem.as_bytes()),
            "public_key_pem": public_key_pem
        }
    })
}

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

#[tokio::test]
async fn post_memory_export_returns_receipt() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .body(MEMORY_FIXTURE)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(body["ingested_schema_version"], "ao2.memory-export.v1");
}

#[tokio::test]
async fn list_after_post_returns_one_memory_export() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .body(MEMORY_FIXTURE)
        .send()
        .await
        .unwrap();

    let list = client
        .get(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-memory-export-list.v1");
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["entries"][0]["schema_version"], "ao2.memory-export.v1");
}

#[tokio::test]
async fn get_memory_export_by_sha_returns_original() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .body(MEMORY_FIXTURE)
        .send()
        .await
        .unwrap();
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let get = client
        .get(format!("{base}/api/v1/memory/export/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(&body[..], MEMORY_FIXTURE.as_bytes());
}

#[tokio::test]
async fn post_wrong_schema_returns_422() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .body(r#"{"schema_version":"ao2.control-plane-fleet-bundle.v1"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn post_signed_memory_export_stores_signature_sidecar() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_memory_payload(false);
    if payload.is_null() {
        return;
    }

    let post = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let list = client
        .get(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["entries"][0]["status"], "signed");

    let signature = client
        .get(format!("{base}/api/v1/memory/export/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-memory-export-signature.v1"
    );
    assert_eq!(signature_body["export_sha256"], sha);
    assert_eq!(signature_body["signature"]["signer_id"], "local-operator");
    assert_eq!(signature_body["signature"]["signature_verified"], true);
}

#[tokio::test]
async fn post_signed_memory_export_rejects_invalid_signature() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_memory_payload(true);
    if payload.is_null() {
        return;
    }

    let post = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(post.status(), 422);
    let body: serde_json::Value = post.json().await.unwrap();
    assert_eq!(body["code"], "schema_invalid");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("signature verification failed"));
}

#[tokio::test]
async fn post_signed_memory_export_verifies_over_exact_bytes_not_reserialization() {
    // Regression for the latent fail-closed bug: the server must verify the signature
    // over the producer's exact signed bytes (supplied verbatim in `export_b64`), not
    // over a `to_string_pretty(&upload.export)` reconstruction that can reflow
    // whitespace and shorten floats. Here the signed bytes are compact and carry a
    // many-significant-digit float, so the reconstruction differs from what was
    // signed; an untampered upload must still be accepted.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_memory_upload_over_exact_bytes(DIVERGENT_MEMORY_EXPORT_BYTES, false);

    let post = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(
        post.status(),
        200,
        "untampered signed upload must verify over its exact signed bytes (export_b64)"
    );
}

#[tokio::test]
async fn post_signed_memory_export_stores_exact_signed_bytes_ignoring_export_field() {
    // The `export_b64` bytes are the *only* trusted content: the signature is verified
    // over them, and they (not the parallel `export` JSON field) are what gets parsed,
    // hashed, and stored. Here we ship a VALID signature over the divergent bytes but
    // replace the `export` field with attacker-controlled content. The upload must be
    // accepted (proving verification used `export_b64`, not the now-mismatched `export`)
    // and GET-by-sha must return the exact signed bytes verbatim (proving the inert
    // `export` field was never parsed or stored). Guards against a regression to
    // trusting/storing the lossy `export` reconstruction.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let mut payload = signed_memory_upload_over_exact_bytes(DIVERGENT_MEMORY_EXPORT_BYTES, false);
    // Diverge the `export` field from the signed bytes. If any code path trusted it,
    // verification would fail (422) or the stored bytes would carry this sentinel.
    payload["export"] = serde_json::json!({
        "schema_version": "ao2.memory-export.v1",
        "record_count": 1,
        "link_count": 0,
        "records": [{"id": "ATTACKER-CONTROLLED-NOT-SIGNED"}],
        "links": []
    });

    let post = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        200,
        "signature must verify over export_b64, not the mismatched export field"
    );
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();

    let get = client
        .get(format!("{base}/api/v1/memory/export/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(
        &body[..],
        DIVERGENT_MEMORY_EXPORT_BYTES.as_bytes(),
        "server must store the exact signed bytes, never the inert export field"
    );
}

#[tokio::test]
async fn signed_memory_export_signature_sidecar_is_write_once_per_content_sha() {
    // The signature sidecar records *who signed* a given memory-export content
    // sha. A second signed upload of the *same export bytes* but a *different*
    // signature (different key / provenance) must NOT silently overwrite the
    // first signer's sidecar — otherwise any holder of a valid signing key could
    // rewrite the recorded provenance of already-ingested evidence. First write
    // wins; a conflicting re-sign is rejected. Mirrors the write-once guard on
    // the provider-readiness / provider-registry signature sidecars.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let first = signed_memory_payload(false);
    let second = signed_memory_payload(false);
    if first.is_null() || second.is_null() {
        return;
    }
    // Precondition: same export content (same sha) but independently generated
    // keys, so the signatures genuinely differ — a provenance conflict, not an
    // idempotent re-upload.
    assert_eq!(
        first["export"], second["export"],
        "fixtures must share identical export content"
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
        .post(format!("{base}/api/v1/memory/export/signed"))
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
        .post(format!("{base}/api/v1/memory/export/signed"))
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
        .get(format!("{base}/api/v1/memory/export/{sha}/signature"))
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
async fn signed_memory_export_reupload_of_identical_artifact_stays_idempotent() {
    // The write-once guard must not break idempotent retries: re-POSTing the
    // *exact same* signed artifact (identical signature bytes) yields the same
    // sidecar_raw, so it is accepted as a no-op rather than rejected as a
    // conflict. Guards the `existing == sidecar_raw` branch of the guard.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let artifact = signed_memory_payload(false);
    if artifact.is_null() {
        return;
    }

    for attempt in 1..=2 {
        let post = client
            .post(format!("{base}/api/v1/memory/export/signed"))
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
async fn dashboard_renders_memory_exports() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/api/v1/memory/export"))
        .header("authorization", "Bearer secret")
        .body(MEMORY_FIXTURE)
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/api/v1/memory/export/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("AO2 Memory Exports"));
    assert!(html.contains("ao2.memory-export.v1"));
    assert!(html.contains("accepted"));
}
