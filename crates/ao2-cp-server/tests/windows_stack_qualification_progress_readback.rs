use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TOKEN: &str = "progress-readback-secret";

const RUNNING_PROGRESS: &str = r#"{
  "schema_version": "ao2.windows-stack-qualification-progress.v1",
  "request_id": "windows-stack-qualification-20260718T230000Z",
  "profile_digest": "sha256:72b9e8b5e4e5e745b3a9b95d61a0a77ef6fb01c530c5f66a04ce27d9a4a4fd31",
  "source_heads": {
    "ao2": "0a4509fb904c90827c11dfcfe1c9e9c552c9f590",
    "ao2-control-plane": "fixture-control-plane-head"
  },
  "state": "running",
  "started_at": "2026-07-19T01:50:00Z",
  "updated_at": "2026-07-19T01:54:30Z",
  "elapsed_seconds": 270,
  "completed_shards": 3,
  "total_shards": 8,
  "current_shards": [
    {
      "shard_id": "windows-qualification-shard-04",
      "checkpoint_id": "checkpoint-04",
      "state": "running",
      "started_at": "2026-07-19T01:53:10Z",
      "completed_rows": 11,
      "total_rows": 30,
      "current_repository": "ao2"
    }
  ],
  "last_completed_shard": "windows-qualification-shard-03",
  "cache_hits": 19,
  "cache_misses": 4,
  "bounded_eta_seconds_or_unknown": 540,
  "global_deadline_at": "2026-07-19T02:20:00Z",
  "control_plane_readback": {
    "role": "read_only_observer",
    "requires_credentials": false,
    "can_mutate_ao2_artifacts": false,
    "can_mutate_release_metadata": false,
    "can_claim_release_readiness": false
  }
}"#;

async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TOKEN.to_string(),
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

fn auth() -> &'static str {
    "Bearer progress-readback-secret"
}

#[tokio::test(flavor = "current_thread")]
async fn windows_stack_qualification_progress_ingest_and_latest_readback_are_observer_only() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .post(format!("{base}/api/v1/windows/qualification/progress"))
        .body(RUNNING_PROGRESS)
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let receipt_response = client
        .post(format!("{base}/api/v1/windows/qualification/progress"))
        .header("authorization", auth())
        .body(RUNNING_PROGRESS)
        .send()
        .await
        .unwrap();
    assert_eq!(receipt_response.status(), 200);
    let receipt: serde_json::Value = receipt_response.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "ao2.windows-stack-qualification-progress.v1"
    );

    let latest_response = client
        .get(format!(
            "{base}/api/v1/windows/qualification/progress/latest"
        ))
        .header("authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(latest_response.status(), 200);
    let latest: serde_json::Value = latest_response.json().await.unwrap();

    assert_eq!(
        latest["schema_version"],
        "ao2.cp-windows-stack-qualification-progress-readback.v1"
    );
    assert_eq!(
        latest["artifact_schema_version"],
        "ao2.windows-stack-qualification-progress.v1"
    );
    assert_eq!(
        latest["request_id"],
        "windows-stack-qualification-20260718T230000Z"
    );
    assert_eq!(latest["state"], "running");
    assert_eq!(latest["completed_shards"], 3);
    assert_eq!(latest["total_shards"], 8);
    assert_eq!(latest["current_shards"].as_array().unwrap().len(), 1);
    assert_eq!(
        latest["current_shards"][0]["shard_id"],
        "windows-qualification-shard-04"
    );
    assert_eq!(latest["cache_hits"], 19);
    assert_eq!(latest["cache_misses"], 4);
    assert_eq!(latest["bounded_eta_seconds_or_unknown"], 540);
    assert_eq!(latest["global_deadline_at"], "2026-07-19T02:20:00Z");
    assert_eq!(
        latest["links"]["raw_progress"],
        format!(
            "/api/v1/windows/qualification/progress/{}",
            receipt["sha256"].as_str().unwrap()
        )
    );

    let boundary = &latest["control_plane_readback"];
    assert_eq!(boundary["role"], "read_only_observer");
    assert_eq!(boundary["requires_credentials"], false);
    assert_eq!(boundary["can_mutate_ao2_artifacts"], false);
    assert_eq!(boundary["can_mutate_release_metadata"], false);
    assert_eq!(boundary["can_claim_release_readiness"], false);

    let payload = serde_json::to_string(&latest).unwrap();
    assert!(!payload.contains(TOKEN));
    assert!(
        !latest["release_readiness"].as_bool().unwrap_or(false),
        "progress readback must not claim release readiness from partial shard state"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn windows_stack_qualification_progress_dashboard_summarizes_running_state_without_results() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let receipt_response = client
        .post(format!("{base}/api/v1/windows/qualification/progress"))
        .header("authorization", auth())
        .body(RUNNING_PROGRESS)
        .send()
        .await
        .unwrap();
    assert_eq!(receipt_response.status(), 200);

    let dashboard_response = client
        .get(format!(
            "{base}/api/v1/windows/qualification/progress/dashboard.json"
        ))
        .header("authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_response.status(), 200);
    let dashboard: serde_json::Value = dashboard_response.json().await.unwrap();

    assert_eq!(
        dashboard["schema_version"],
        "ao2.cp-windows-stack-qualification-progress-dashboard.v1"
    );
    assert_eq!(dashboard["summary"]["total_progress_records"], 1);
    assert_eq!(dashboard["summary"]["running_requests"], 1);
    assert_eq!(dashboard["summary"]["completed_requests"], 0);
    assert_eq!(dashboard["summary"]["read_only_observer"], true);
    assert_eq!(
        dashboard["summary"]["control_plane_approves_release"],
        false
    );
    assert_eq!(
        dashboard["entries"][0]["request_id"],
        "windows-stack-qualification-20260718T230000Z"
    );
    assert_eq!(dashboard["entries"][0]["state"], "running");
    assert_eq!(dashboard["entries"][0]["completed_shards"], 3);
    assert_eq!(dashboard["entries"][0]["total_shards"], 8);
}

#[tokio::test(flavor = "current_thread")]
async fn windows_stack_qualification_progress_rejects_mutating_or_release_readiness_claims() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let invalid = serde_json::json!({
        "schema_version": "ao2.windows-stack-qualification-progress.v1",
        "request_id": "bad-progress",
        "profile_digest": "sha256:72b9e8b5e4e5e745b3a9b95d61a0a77ef6fb01c530c5f66a04ce27d9a4a4fd31",
        "source_heads": {"ao2": "0a4509fb904c90827c11dfcfe1c9e9c552c9f590"},
        "state": "running",
        "started_at": "2026-07-19T01:50:00Z",
        "updated_at": "2026-07-19T01:54:30Z",
        "elapsed_seconds": 270,
        "completed_shards": 3,
        "total_shards": 8,
        "current_shards": [],
        "last_completed_shard": "windows-qualification-shard-03",
        "cache_hits": 19,
        "cache_misses": 4,
        "bounded_eta_seconds_or_unknown": 540,
        "global_deadline_at": "2026-07-19T02:20:00Z",
        "release_readiness": true,
        "control_plane_readback": {
            "role": "read_only_observer",
            "requires_credentials": true,
            "can_mutate_ao2_artifacts": true,
            "can_mutate_release_metadata": false,
            "can_claim_release_readiness": true
        }
    });

    let response = client
        .post(format!("{base}/api/v1/windows/qualification/progress"))
        .header("authorization", auth())
        .json(&invalid)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let body = response.text().await.unwrap();
    assert!(body.contains("requires_credentials"));
    assert!(body.contains("can_mutate_ao2_artifacts"));
    assert!(body.contains("release_readiness"));
}

#[test]
fn route_catalog_advertises_windows_stack_qualification_progress_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path, portable, mutates_observer_storage) in [
        (
            "POST",
            "/api/v1/windows/qualification/progress",
            false,
            true,
        ),
        (
            "GET",
            "/api/v1/windows/qualification/progress/latest",
            true,
            false,
        ),
        (
            "GET",
            "/api/v1/windows/qualification/progress/dashboard.json",
            true,
            false,
        ),
        (
            "GET",
            "/api/v1/windows/qualification/progress/:sha",
            true,
            false,
        ),
    ] {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing route catalog entry for {method} {path}"));
        assert_eq!(route.category, "windows-qualification-progress-observer");
        assert_eq!(route.owner, "ao2-control-plane observer");
        assert!(!route.download);
        assert_eq!(route.portable, portable);
        assert_eq!(route.mutates_observer_storage, mutates_observer_storage);
    }
}
