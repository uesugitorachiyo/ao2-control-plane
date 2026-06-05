//! Integration test for the `/api/v1/status` structured status endpoint.
//!
//! `/healthz` and `/readyz` are binary liveness/readiness probes with no
//! auth. `/api/v1/status` is the human-and-dashboard read of the same
//! state, token-gated, returning `ao2.cp-status.v1` JSON with build info,
//! storage stats, retention pressure, request totals, and uptime.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "status-token-secret";

async fn spawn_server() -> (String, tempfile::TempDir) {
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

#[tokio::test]
async fn status_endpoint_requires_bearer_token() {
    let (base, _dir) = spawn_server().await;
    let resp = reqwest::get(format!("{base}/api/v1/status")).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn status_endpoint_returns_ao2_cp_status_v1_envelope() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/v1/status"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["schema_version"], "ao2.cp-status.v1");

    let build = &body["build"];
    assert!(build["version"].is_string(), "build.version must be string");
    assert!(
        !build["version"].as_str().unwrap().is_empty(),
        "build.version must be non-empty"
    );
    assert!(
        build["rustc_target"].is_string(),
        "build.rustc_target must be string"
    );
    assert!(build["profile"].is_string(), "build.profile must be string");

    assert!(
        body["uptime_seconds"].is_number(),
        "uptime_seconds must be a number"
    );
    assert!(
        body["uptime_seconds"].as_f64().unwrap() >= 0.0,
        "uptime_seconds must be non-negative"
    );

    let storage = &body["storage"];
    assert!(
        storage["data_dir"].is_string(),
        "storage.data_dir must be string"
    );
    assert_eq!(
        storage["index_entries"], 0,
        "fresh storage must have zero index entries"
    );
    assert!(
        storage["data_dir_bytes"].is_number(),
        "storage.data_dir_bytes must be a number"
    );

    let retention = &body["retention"];
    assert!(
        retention["soft_cap_index_entries"].is_number(),
        "retention.soft_cap_index_entries must be a number"
    );
    assert!(
        retention["pressure_pct"].is_number(),
        "retention.pressure_pct must be a number"
    );

    let requests = &body["requests"];
    assert!(
        requests["total"].is_number(),
        "requests.total must be a number"
    );
    assert!(
        requests["in_flight"].is_number(),
        "requests.in_flight must be a number"
    );

    let config = &body["config"];
    assert_eq!(
        config["max_body_bytes"],
        1024 * 1024,
        "config.max_body_bytes must echo configured ceiling"
    );

    let audit = &body["audit_log"];
    assert!(
        audit["capacity"].is_number(),
        "audit_log.capacity must be a number"
    );
    assert!(
        audit["buffered"].is_number(),
        "audit_log.buffered must be a number"
    );
    assert!(
        audit["total_appended_since_boot"].is_number(),
        "audit_log.total_appended_since_boot must be a number"
    );
    let persistence = &audit["persistence"];
    assert!(
        persistence["enabled"].is_boolean(),
        "audit_log.persistence.enabled must be a boolean"
    );
    assert_eq!(
        persistence["enabled"], false,
        "persistence is disabled by default in the test harness"
    );
    assert!(
        persistence["path"].is_null(),
        "persistence.path must be null when persistence is disabled (was {})",
        persistence["path"]
    );
    assert!(
        persistence["last_error"].is_null(),
        "persistence.last_error must be null on a fresh server (was {})",
        persistence["last_error"]
    );
    let rotation = &persistence["rotation"];
    assert!(
        rotation["max_bytes"].is_null(),
        "rotation.max_bytes must be null when AO2_CP_AUDIT_LOG_MAX_BYTES is unset (was {})",
        rotation["max_bytes"]
    );
    assert_eq!(
        rotation["count"], 0,
        "rotation.count must be zero on a fresh server"
    );
    assert!(
        rotation["last_rotated_unix_micros"].is_null(),
        "rotation.last_rotated_unix_micros must be null on a fresh server (was {})",
        rotation["last_rotated_unix_micros"]
    );
}

#[tokio::test]
async fn status_endpoint_audit_log_block_reflects_observed_traffic() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Drive traffic — every authenticated request hits the audit log.
    for _ in 0..5 {
        let resp = client
            .get(format!("{base}/healthz"))
            .header("Authorization", auth_header())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    let resp = client
        .get(format!("{base}/api/v1/status"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let audit = &body["audit_log"];
    let total_appended = audit["total_appended_since_boot"].as_u64().unwrap();
    assert!(
        total_appended >= 5,
        "after 5 driven requests the boot-cumulative counter must be >= 5 (got {total_appended})"
    );
    let buffered = audit["buffered"].as_u64().unwrap();
    assert!(
        buffered >= 5,
        "after 5 driven requests the live buffer must hold at least 5 entries (got {buffered})"
    );

    // The bearer token must never be echoed into the status JSON.
    let body_text = serde_json::to_string(&body).unwrap();
    assert!(
        !body_text.contains(TEST_API_TOKEN),
        "status JSON must never leak the bearer token (entire payload: {body_text})"
    );
}

#[tokio::test]
async fn status_endpoint_reflects_observed_traffic() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Drive some traffic so request counters move off zero.
    for _ in 0..3 {
        let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }
    let unauth = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    let resp = client
        .get(format!("{base}/api/v1/status"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    let total = body["requests"]["total"].as_u64().unwrap();
    assert!(
        total >= 4,
        "after 3 healthz + 1 unauth GET (plus possibly this status request itself), total must be >= 4 (got {total})"
    );
    let errors = body["requests"]["errors_4xx_5xx"].as_u64().unwrap();
    assert!(
        errors >= 1,
        "the unauth GET we just issued must show up in errors_4xx_5xx (got {errors})"
    );
}
