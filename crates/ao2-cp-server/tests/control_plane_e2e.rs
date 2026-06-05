//! End-to-end integration test for the control plane's signed-artifact
//! lifecycle, exercised through the real HTTP surface.
//!
//! Every other integration test in this crate isolates one subsystem: the
//! memory handler, the storage layer, the audit-log ring buffer, the SSE
//! stream. This test wires them into the single operator workflow the control
//! plane exists to serve, and asserts the trust-boundary invariants survive the
//! whole exchange:
//!
//! 1. **Liveness** — `/healthz` and `/readyz` answer before any traffic.
//! 2. **Signed ingest** — a valid RSA/SHA-256-signed memory export is accepted,
//!    the signature is verified server-side (`crate::signing`), and content +
//!    signature sidecar are persisted content-addressed.
//! 3. **Readback** — an observer reads the stored artifact back and gets the
//!    original export, plus a sidecar that reports `signature_verified: true`.
//! 4. **Tamper rejection is a persistence gate** — a payload with a corrupted
//!    signature is rejected `422 schema_invalid` **and never lands in the
//!    index**. The list count stays at one. Verification is not advisory; it
//!    decides whether the artifact exists at all.
//! 5. **Observability** — the audit-log SSE stream, replayed from
//!    `last_event_id=0`, contains the signed-ingest POST and the readback GET,
//!    and the bearer token never appears anywhere on the stream.
//!
//! Doing the requests first and replaying the buffered audit entries afterward
//! keeps the SSE assertion deterministic — no dependence on subscribe-before-
//! append timing — while still driving the live streaming endpoint.

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
use std::time::Duration;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "secret-e2e-token";
const MEMORY_FIXTURE: &str = include_str!("../../../tests/fixtures/memory-export-sample.json");

async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
        metrics: Arc::new(Metrics::new()),
        audit_log: Arc::new(ao2_cp_server::audit_log::AuditLog::default()),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), dir)
}

fn auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// Build a signed memory-export upload payload. The signature is computed over
/// the pretty-printed export exactly as the handler re-serializes it before
/// verifying, so a non-tampered payload verifies cleanly. `tamper_signature`
/// flips a byte of the signature to drive the rejection path.
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
            "signature_sha256": sha256_hex(&signature),
            "signature_hex": hex_encode(&signature),
            "public_key_path": "memory-export-signing-public.pem",
            "public_key_sha256": sha256_hex(public_key_pem.as_bytes()),
            "public_key_pem": public_key_pem
        }
    })
}

/// Read bytes from an SSE response until `predicate` is satisfied or `timeout`
/// elapses. Mirrors the helper in `audit_log_stream.rs` — keeps the read
/// bounded so a failed assertion never leaves a background task streaming.
async fn read_until(
    response: &mut reqwest::Response,
    timeout: Duration,
    mut predicate: impl FnMut(&str) -> bool,
) -> String {
    let mut acc = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                acc.push_str(&String::from_utf8_lossy(&chunk));
                if predicate(&acc) {
                    break;
                }
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    acc
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_artifact_lifecycle_is_observable_end_to_end() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // 1. Liveness — the server answers before any artifact traffic. /healthz is
    //    unauthenticated; /readyz reports storage + config readiness.
    let health = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(health.status(), 200, "healthz must be live");
    let ready = client.get(format!("{base}/readyz")).send().await.unwrap();
    assert_eq!(ready.status(), 200, "readyz must report readiness");

    // 2. Signed ingest — valid signature, verified server-side, persisted.
    let post = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", auth_header())
        .json(&signed_memory_payload(false))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200, "valid signed export must be accepted");
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();
    assert_eq!(sha.len(), 64, "receipt must carry a content-address sha256");
    // The receipt is a public surface — no bearer token may leak into it.
    assert!(
        !serde_json::to_string(&receipt)
            .unwrap()
            .contains(TEST_API_TOKEN),
        "ingest receipt must never echo the bearer token"
    );

    // 3. Readback — the observer reads the stored content and gets the original
    //    export back (parsed equality; the handler stores the pretty form).
    let original_export: serde_json::Value = serde_json::from_str(MEMORY_FIXTURE).unwrap();
    let get = client
        .get(format!("{base}/api/v1/memory/export/{sha}"))
        .header("authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200, "stored artifact must be readable back");
    let read_back: serde_json::Value = get.json().await.unwrap();
    assert_eq!(
        read_back, original_export,
        "round-tripped export must equal the ingested export"
    );

    // The signature sidecar proves the server verified the signature itself.
    let sidecar = client
        .get(format!("{base}/api/v1/memory/export/{sha}/signature"))
        .header("authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(sidecar.status(), 200);
    let sidecar_body: serde_json::Value = sidecar.json().await.unwrap();
    assert_eq!(sidecar_body["export_sha256"], sha);
    assert_eq!(
        sidecar_body["signature"]["signature_verified"], true,
        "sidecar must record that the server verified the signature"
    );
    assert_eq!(sidecar_body["signature"]["signer_id"], "local-operator");

    // 4. Tamper rejection is a persistence gate, not an advisory flag.
    let tampered = client
        .post(format!("{base}/api/v1/memory/export/signed"))
        .header("authorization", auth_header())
        .json(&signed_memory_payload(true))
        .send()
        .await
        .unwrap();
    assert_eq!(
        tampered.status(),
        422,
        "a tampered signature must be rejected"
    );
    let tampered_body: serde_json::Value = tampered.json().await.unwrap();
    assert_eq!(tampered_body["code"], "schema_invalid");
    assert!(tampered_body["message"]
        .as_str()
        .unwrap()
        .contains("signature verification failed"));

    // The rejected artifact must NOT exist: the index still holds exactly the
    // one good export. This is the invariant that makes verification matter.
    let list = client
        .get(format!("{base}/api/v1/memory/export"))
        .header("authorization", auth_header())
        .send()
        .await
        .unwrap();
    let list_body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(
        list_body["total_count"], 1,
        "a rejected signature must leave nothing persisted"
    );
    assert_eq!(list_body["entries"][0]["status"], "signed");

    // 5. Observability — replay the buffered audit entries over the live SSE
    //    endpoint and confirm the exchange was recorded, token-free.
    let mut stream = client
        .get(format!("{base}/api/v1/audit-log/stream?last_event_id=0"))
        .header("authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    assert!(stream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .starts_with("text/event-stream"));

    let signed_path = "/api/v1/memory/export/signed";
    let readback_path = format!("/api/v1/memory/export/{sha}");
    let body = read_until(&mut stream, Duration::from_secs(5), |acc| {
        acc.contains(signed_path) && acc.contains(&readback_path)
    })
    .await;

    assert!(
        body.contains(signed_path),
        "audit stream must record the signed-ingest POST; body:\n{body}"
    );
    assert!(
        body.contains(&readback_path),
        "audit stream must record the artifact readback GET; body:\n{body}"
    );
    assert!(
        body.contains("\"method\":\"POST\"") && body.contains("\"method\":\"GET\""),
        "audit stream must distinguish POST ingest from GET readback"
    );
    assert!(
        !body.contains(TEST_API_TOKEN),
        "bearer token must never appear on the audit stream"
    );
}
