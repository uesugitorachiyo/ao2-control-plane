use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TASK_BOARD: &str = r#"{
  "schema_version": "ao2.ai-task-board.v1",
  "status": "ready",
  "release_objective": "Expose Pulse work as an operator-readable task board.",
  "source_recommendation": "Advance production readiness with task-board readback.",
  "release_train": {
    "version": "v0.4.81",
    "theme": "AI task board control surface"
  },
  "tasks": [
    {
      "task_id": "ao2-ai-task-board-control-plane-readback",
      "title": "AI task board control-plane readback",
      "kind": "control-plane-readback",
      "status": "proposed",
      "objective": "Prove the control plane can consume the board as a read-only observer.",
      "confidence": "high",
      "rationale": "Operators need a single current-task surface.",
      "required_evidence": ["ao2.ai-task-board.v1", "ao2.control-plane-fixture-consumer-smoke.v1"],
      "stop_conditions": ["Stop if readback requires credentials or release mutation authority."],
      "source_recommendation": "Expose Pulse work as a task board.",
      "release_train": "v0.4.81"
    }
  ],
  "control_plane_readback": {
    "role": "read_only_observer",
    "requires_credentials": false,
    "can_mutate_ao2_artifacts": false,
    "can_mutate_release_metadata": false
  },
  "trust_boundary": {
    "local_only": true,
    "stores_credentials": false,
    "mutates_releases": false
  }
}"#;

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

#[tokio::test(flavor = "current_thread")]
async fn ai_task_board_ingest_latest_and_dashboard_are_read_only() {
    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .post(format!("{base}/api/v1/ai/task-board"))
        .body(TASK_BOARD)
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let receipt_response = client
        .post(format!("{base}/api/v1/ai/task-board"))
        .header("authorization", "Bearer secret")
        .body(TASK_BOARD)
        .send()
        .await
        .unwrap();
    assert_eq!(receipt_response.status(), 200);
    let receipt: serde_json::Value = receipt_response.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(receipt["ingested_schema_version"], "ao2.ai-task-board.v1");

    let latest_response = client
        .get(format!("{base}/api/v1/ai/task-board/latest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest_response.status(), 200);
    let latest: serde_json::Value = latest_response.json().await.unwrap();
    assert_eq!(latest["schema_version"], "ao2.cp-ai-task-board-readback.v1");
    assert_eq!(latest["artifact_schema_version"], "ao2.ai-task-board.v1");
    assert_eq!(latest["status"], "ready");
    assert_eq!(latest["release_train"]["version"], "v0.4.81");
    assert_eq!(latest["task_count"], 1);
    assert_eq!(
        latest["tasks"][0]["task_id"],
        "ao2-ai-task-board-control-plane-readback"
    );
    assert_eq!(
        latest["tasks"][0]["required_evidence"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        latest["tasks"][0]["stop_conditions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        latest["control_plane_readback"]["role"],
        "read_only_observer"
    );
    assert_eq!(
        latest["control_plane_readback"]["requires_credentials"],
        false
    );
    assert_eq!(
        latest["control_plane_readback"]["can_mutate_ao2_artifacts"],
        false
    );
    assert_eq!(
        latest["control_plane_readback"]["can_mutate_release_metadata"],
        false
    );
    assert_eq!(latest["trust_boundary"]["read_only"], true);
    assert_eq!(latest["trust_boundary"]["stores_credentials"], false);
    assert_eq!(latest["trust_boundary"]["mutates_releases"], false);
    assert_eq!(
        latest["links"]["raw_task_board"],
        format!(
            "/api/v1/ai/task-board/{}",
            receipt["sha256"].as_str().unwrap()
        )
    );

    let dashboard_response = client
        .get(format!("{base}/api/v1/ai/task-board/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_response.status(), 200);
    let dashboard: serde_json::Value = dashboard_response.json().await.unwrap();
    assert_eq!(
        dashboard["schema_version"],
        "ao2.cp-ai-task-board-dashboard.v1"
    );
    assert_eq!(dashboard["summary"]["total_boards"], 1);
    assert_eq!(dashboard["summary"]["total_tasks"], 1);
    assert_eq!(dashboard["summary"]["read_only_observer"], true);
    assert_eq!(dashboard["entries"][0]["task_count"], 1);
    assert_eq!(
        dashboard["entries"][0]["release_train"]["version"],
        "v0.4.81"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ai_task_board_rejects_missing_evidence_or_mutating_readback() {
    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let invalid = serde_json::json!({
        "schema_version": "ao2.ai-task-board.v1",
        "status": "ready",
        "release_objective": "Expose Pulse work as an operator-readable task board.",
        "tasks": [{
            "task_id": "bad-task",
            "title": "Bad task",
            "required_evidence": [],
            "stop_conditions": []
        }],
        "control_plane_readback": {
            "role": "read_only_observer",
            "requires_credentials": true,
            "can_mutate_release_metadata": true
        },
        "trust_boundary": {
            "local_only": true,
            "stores_credentials": false,
            "mutates_releases": true
        }
    });

    let response = client
        .post(format!("{base}/api/v1/ai/task-board"))
        .header("authorization", "Bearer secret")
        .json(&invalid)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let body = response.text().await.unwrap();
    assert!(body.contains("requires_credentials"));
    assert!(body.contains("task_missing_required_evidence:bad-task"));
}

#[test]
fn route_catalog_advertises_ai_task_board_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path, portable, mutates_observer_storage) in [
        ("POST", "/api/v1/ai/task-board", false, true),
        ("GET", "/api/v1/ai/task-board/latest", true, false),
        ("GET", "/api/v1/ai/task-board/dashboard.json", true, false),
        ("GET", "/api/v1/ai/task-board/:sha", true, false),
    ] {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing route catalog entry for {method} {path}"));
        assert_eq!(route.category, "ai-task-board-observer");
        assert_eq!(route.owner, "ao2-control-plane observer");
        assert!(!route.download);
        assert_eq!(route.portable, portable);
        assert_eq!(route.mutates_observer_storage, mutates_observer_storage);
    }
}
