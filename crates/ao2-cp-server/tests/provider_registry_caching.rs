//! Integration test for provider-registry ETag + HEAD caching.
//!
//! Verifies:
//! 1. GET /api/v1/provider/registry/latest returns an ETag header whose
//!    value is the double-quoted sha256 of the AO2 canonical JSON v1 payload.
//! 2. A second GET with `If-None-Match` matching that ETag returns 304
//!    with NO body and the ETag still set.
//! 3. HEAD on the same URL returns the ETag + Cache-Control headers
//!    without a body.
//! 4. The Cache-Control header announces `public, max-age=60, must-revalidate`.

use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "registry-caching-token";

async fn spawn_server() -> (String, tempfile::TempDir, String) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    // Seed one registry entry so /latest has something to return.
    let registry = json!({
        "schema_version": "ao2.provider-plugin-registry.v1",
        "phase": "phase1",
        "providers": []
    });
    let canonical_bytes = ao2_cp_schema::canonical::canonical_json(&registry)
        .unwrap()
        .into_bytes();
    let sha = sha256_of_canonical(&registry).unwrap();
    storage
        .bundles
        .write(
            ao2_cp_storage::bundle::BundleKind::ProviderRegistry,
            &sha,
            &canonical_bytes,
        )
        .await
        .unwrap();
    storage
        .index
        .append(ao2_cp_storage::index::IndexEntry {
            ingested_at: chrono::Utc::now(),
            schema: "ao2.provider-plugin-registry.v1".to_string(),
            provider: None,
            sha256: sha.clone(),
            status: Some("accepted".to_string()),
            size_bytes: canonical_bytes.len() as u64,
        })
        .await
        .unwrap();

    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 1024 * 1024,
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
    (format!("http://{addr}"), dir, sha)
}

fn auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

#[tokio::test]
async fn provider_registry_latest_emits_etag_and_cache_control() {
    let (base, _dir, sha) = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/v1/provider/registry/latest"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let etag = resp
        .headers()
        .get("etag")
        .expect("ETag header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        etag,
        format!("\"{sha}\""),
        "ETag must be quoted sha256 of the canonical payload"
    );

    let cache_control = resp
        .headers()
        .get("cache-control")
        .expect("Cache-Control header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(cache_control, "public, max-age=60, must-revalidate");
}

#[tokio::test]
async fn provider_registry_get_with_matching_if_none_match_returns_304() {
    let (base, _dir, sha) = spawn_server().await;
    let client = reqwest::Client::new();

    let etag = format!("\"{sha}\"");
    let resp = client
        .get(format!("{base}/api/v1/provider/registry/latest"))
        .header("Authorization", auth_header())
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304, "matching ETag must yield 304");
    assert_eq!(
        resp.headers().get("etag").unwrap().to_str().unwrap(),
        etag,
        "304 response must still echo the ETag"
    );
    let body = resp.bytes().await.unwrap();
    assert!(
        body.is_empty(),
        "304 must have empty body, got {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn provider_registry_head_returns_etag_without_body() {
    let (base, _dir, sha) = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .head(format!("{base}/api/v1/provider/registry/latest"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag = resp
        .headers()
        .get("etag")
        .expect("HEAD must emit ETag")
        .to_str()
        .unwrap();
    assert_eq!(etag, format!("\"{sha}\""));
    assert!(
        resp.headers().get("cache-control").is_some(),
        "HEAD must emit Cache-Control"
    );
    let body = resp.bytes().await.unwrap();
    assert!(
        body.is_empty(),
        "HEAD response must have no body, got {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn provider_registry_head_with_matching_etag_returns_304() {
    let (base, _dir, sha) = spawn_server().await;
    let client = reqwest::Client::new();

    let etag = format!("\"{sha}\"");
    let resp = client
        .head(format!("{base}/api/v1/provider/registry/latest"))
        .header("Authorization", auth_header())
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304);
}

#[tokio::test]
async fn provider_registry_get_with_wildcard_etag_returns_304() {
    let (base, _dir, _sha) = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/v1/provider/registry/latest"))
        .header("Authorization", auth_header())
        .header("If-None-Match", "*")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        304,
        "wildcard If-None-Match must yield 304 when resource exists"
    );
}
