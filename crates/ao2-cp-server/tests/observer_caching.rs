//! Integration tests for HEAD + ETag + 304 caching across all
//! content-addressed observer GET endpoints.
//!
//! Each endpoint pattern is verified for four properties:
//! 1. `GET /...sha` emits `ETag: "<sha>"` + `Cache-Control: public,
//!    max-age=60, must-revalidate`.
//! 2. `GET` with matching `If-None-Match` returns `304` with empty body.
//! 3. `HEAD /...sha` returns 200, ETag, Cache-Control, empty body.
//! 4. `HEAD` with matching `If-None-Match` returns `304`.
//!
//! Provider-registry caching is already covered by
//! `provider_registry_caching.rs`; this file rolls out the same
//! contract to acceptance, control-plane bundle, evidence-pack,
//! memory-export, phase1 (checklist/decision/three-os-smoke),
//! provider-readiness, release-publication and release-evaluator-
//! decision endpoints.

use ao2_cp_schema::canonical::{canonical_json, sha256_of_canonical};
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, Storage};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "observer-caching-token";
const EXPECTED_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

struct Server {
    base: String,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

async fn spawn_server() -> Server {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
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
    let app = ao2_cp_server::server::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        base: format!("http://{addr}"),
        state,
        _dir: dir,
    }
}

async fn seed(server: &Server, kind: BundleKind, schema: &str, payload: Value) -> String {
    let canonical = canonical_json(&payload).unwrap().into_bytes();
    let sha = sha256_of_canonical(&payload).unwrap();
    server
        .state
        .storage
        .bundles
        .write(kind, &sha, &canonical)
        .await
        .unwrap();
    server
        .state
        .storage
        .index
        .append(IndexEntry {
            ingested_at: Utc::now(),
            schema: schema.to_string(),
            provider: None,
            sha256: sha.clone(),
            status: Some("accepted".to_string()),
            size_bytes: canonical.len() as u64,
        })
        .await
        .unwrap();
    sha
}

fn auth() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

async fn assert_caching_contract(base: &str, path_template: &str, sha: &str) {
    let client = reqwest::Client::new();
    let url = path_template.replace(":sha", sha);
    let full = format!("{base}{url}");
    let etag = format!("\"{sha}\"");

    // 1. GET emits ETag + Cache-Control.
    let resp = client
        .get(&full)
        .header("Authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET {full} must be 200");
    let got_etag = resp
        .headers()
        .get("etag")
        .unwrap_or_else(|| panic!("GET {full} missing ETag"))
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(got_etag, etag, "GET {full} ETag mismatch");
    let got_cc = resp
        .headers()
        .get("cache-control")
        .unwrap_or_else(|| panic!("GET {full} missing Cache-Control"))
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(got_cc, EXPECTED_CACHE_CONTROL, "GET {full} Cache-Control");

    // 2. GET with matching If-None-Match → 304, empty body.
    let resp = client
        .get(&full)
        .header("Authorization", auth())
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        304,
        "GET {full} with matching If-None-Match must be 304"
    );
    let body = resp.bytes().await.unwrap();
    assert!(body.is_empty(), "304 body must be empty");

    // 3. HEAD → 200, ETag, Cache-Control, empty body.
    let resp = client
        .head(&full)
        .header("Authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "HEAD {full} must be 200");
    let got_etag = resp
        .headers()
        .get("etag")
        .unwrap_or_else(|| panic!("HEAD {full} missing ETag"))
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(got_etag, etag, "HEAD {full} ETag mismatch");
    assert!(
        resp.headers().get("cache-control").is_some(),
        "HEAD {full} missing Cache-Control"
    );
    let body = resp.bytes().await.unwrap();
    assert!(body.is_empty(), "HEAD body must be empty");

    // 4. HEAD with matching If-None-Match → 304.
    let resp = client
        .head(&full)
        .header("Authorization", auth())
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        304,
        "HEAD {full} with matching If-None-Match must be 304"
    );
}

#[tokio::test]
async fn acceptance_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::AcceptanceCodex,
        "factory-v3/codex-acceptance/v1",
        json!({"schema_version": "factory-v3/codex-acceptance/v1", "result": "passed"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/acceptance/:sha", &sha).await;
}

#[tokio::test]
async fn control_plane_bundle_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::ControlPlaneBundle,
        "ao2.control-plane-bundle.v1",
        json!({"schema_version": "ao2.control-plane-bundle.v1", "kind": "test"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/control-plane/bundle/:sha", &sha).await;
}

#[tokio::test]
async fn evidence_pack_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::EvidencePack,
        "ao2.evidence-pack.v1",
        json!({"schema_version": "ao2.evidence-pack.v1", "phase": "phase1"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/evidence-pack/:sha", &sha).await;
}

#[tokio::test]
async fn memory_export_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::MemoryExport,
        "ao2.memory-export.v1",
        json!({"schema_version": "ao2.memory-export.v1", "entries": []}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/memory/export/:sha", &sha).await;
}

#[tokio::test]
async fn phase1_checklist_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::Phase1PromotionChecklist,
        "factory-v3/phase1-promotion-checklist/v1",
        json!({"schema_version": "factory-v3/phase1-promotion-checklist/v1", "status": "ready"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/phase1/promotion/checklist/:sha", &sha).await;
}

#[tokio::test]
async fn phase1_decision_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::Phase1PromotionDecision,
        "factory-v3/phase1-promotion-decision/v1",
        json!({"schema_version": "factory-v3/phase1-promotion-decision/v1", "decision": "approve"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/phase1/promotion/decision/:sha", &sha).await;
}

#[tokio::test]
async fn phase1_three_os_smoke_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::ThreeOsReleaseSmoke,
        "ao2.cp-three-os-release-smoke.v1",
        json!({"schema_version": "ao2.cp-three-os-release-smoke.v1", "status": "ok"}),
    )
    .await;
    assert_caching_contract(
        &s.base,
        "/api/v1/phase1/promotion/three-os-smoke/:sha",
        &sha,
    )
    .await;
}

#[tokio::test]
async fn provider_readiness_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(&s,
        BundleKind::ProviderReadiness,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        json!({"schema_version": "factory-v3/hermes-provider-phase1-readiness/v1", "live_provider_policy": "opt_in"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/provider/readiness/:sha", &sha).await;
}

#[tokio::test]
async fn release_publication_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::ReleasePublication,
        "ao2.release-publication-summary.v1",
        json!({"schema_version": "ao2.release-publication-summary.v1", "release": "v0.1.0"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/release/publication/:sha", &sha).await;
}

#[tokio::test]
async fn release_evaluator_decision_sha_emits_caching_contract() {
    let s = spawn_server().await;
    let sha = seed(
        &s,
        BundleKind::ReleaseEvaluatorDecision,
        "ao2.release-evaluator-decision.v1",
        json!({"schema_version": "ao2.release-evaluator-decision.v1", "decision": "ship"}),
    )
    .await;
    assert_caching_contract(&s.base, "/api/v1/release/evaluator-decision/:sha", &sha).await;
}
