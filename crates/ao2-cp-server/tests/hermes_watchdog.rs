use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

fn sample_panel(run_id: &str, generated_at_ms: u64) -> String {
    serde_json::json!({
        "schema": "factory-v3/hermes-ao2-watchdog-panel/v1",
        "generated_at_ms": generated_at_ms,
        "watchdog_status": "would_start",
        "watchdog_action": "dry_run",
        "next_check_seconds": 600,
        "backend_route": "repair_resume_latest",
        "reason": "latest non-accepted AO2 evidence pack exists",
        "selected_evidence": {
            "run_id": run_id,
            "verdict": "rejected",
            "path": format!("/tmp/ao2-example/ao2/.ao2/runs/{run_id}/evidence-pack/evidence-pack.json")
        },
        "backend_command": ["python3", "scripts/hermes_ao_bridge.py", "repair-resume-latest", "--json"],
        "backend_command_text": "python3 scripts/hermes_ao_bridge.py repair-resume-latest --json",
        "prompt_snapshot": "/tmp/ao2-example/factory-v3/docs/status/hermes-ao2-watchdog/ao2-watchdog-prompt.md",
        "trust_boundary": {
            "frontend": "Hermes",
            "trusted_execution": "ao2 repair resume",
            "governed_backend": "AO2 governed evaluator-closer",
            "control_plane": "ao2-control-plane read-only observer"
        },
        "operator_links": {
            "selected_evidence": format!("/tmp/ao2-example/ao2/.ao2/runs/{run_id}/evidence-pack/evidence-pack.json"),
            "prompt_snapshot": "/tmp/ao2-example/factory-v3/docs/status/hermes-ao2-watchdog/ao2-watchdog-prompt.md",
            "watchdog_status": "/tmp/ao2-example/factory-v3/docs/status/hermes-ao2-watchdog/watchdog-status.json"
        }
    })
    .to_string()
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
async fn hermes_watchdog_panel_ingest_latest_and_history_are_observer_only() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/api/v1/hermes/watchdog/panel"))
        .header("authorization", "Bearer secret")
        .body(sample_panel("older-rejected", 100))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_receipt: serde_json::Value = first.json().await.unwrap();
    assert_eq!(
        first_receipt["ingested_schema_version"],
        "factory-v3/hermes-ao2-watchdog-panel/v1"
    );

    let second = client
        .post(format!("{base}/api/v1/hermes/watchdog/panel"))
        .header("authorization", "Bearer secret")
        .body(sample_panel("latest-rejected", 200))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);

    let latest = client
        .get(format!("{base}/api/v1/hermes/watchdog/panel/latest.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(
        latest_body["schema_version"],
        "ao2.cp-hermes-watchdog-panel-latest.v1"
    );
    assert_eq!(latest_body["control_plane_role"], "read-only-observer");
    assert_eq!(latest_body["mutates_ao_artifacts"], false);
    assert_eq!(latest_body["control_plane_approves_release"], false);
    assert_eq!(
        latest_body["panel"]["backend_route"],
        "repair_resume_latest"
    );
    assert_eq!(
        latest_body["panel"]["selected_evidence"]["run_id"],
        "latest-rejected"
    );
    assert_eq!(
        latest_body["links"]["history_json"],
        "/api/v1/hermes/watchdog/history.json"
    );

    let history = client
        .get(format!("{base}/api/v1/hermes/watchdog/history.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(history.status(), 200);
    let history_body: serde_json::Value = history.json().await.unwrap();
    assert_eq!(
        history_body["schema_version"],
        "ao2.cp-hermes-watchdog-history.v1"
    );
    assert_eq!(history_body["total_count"], 2);
    assert_eq!(history_body["entries"][0]["panel"]["generated_at_ms"], 200);
    assert_eq!(history_body["entries"][1]["panel"]["generated_at_ms"], 100);

    let serialized = serde_json::to_string(&history_body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));
}

#[tokio::test]
async fn hermes_watchdog_panel_html_renders_route_evidence_and_trust_boundary() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/api/v1/hermes/watchdog/panel"))
        .header("authorization", "Bearer secret")
        .body(sample_panel("latest-rejected", 200))
        .send()
        .await
        .unwrap();

    let page = client
        .get(format!("{base}/api/v1/hermes/watchdog/panel"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let content_type = page
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(content_type, "text/html; charset=utf-8");
    let html = page.text().await.unwrap();
    assert!(html.contains("Hermes AO2 Watchdog Panel"));
    assert!(html.contains("repair_resume_latest"));
    assert!(html.contains("latest-rejected"));
    assert!(html.contains("Open selected evidence"));
    assert!(html.contains("ao2-control-plane read-only observer"));
    assert!(html.contains("/api/v1/hermes/watchdog/history.json"));
    assert!(!html.contains("secret"));
    assert!(!html.contains("Bearer"));
}

#[tokio::test]
async fn hermes_watchdog_routes_are_advertised_without_secret_bearing_urls() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let routes = body["routes"].as_array().unwrap();
    for (method, path, mutates_storage) in [
        ("POST", "/api/v1/hermes/watchdog/panel", true),
        ("GET", "/api/v1/hermes/watchdog/panel", false),
        ("GET", "/api/v1/hermes/watchdog/panel/latest.json", false),
        ("GET", "/api/v1/hermes/watchdog/history.json", false),
    ] {
        let route = routes
            .iter()
            .find(|route| route["method"] == method && route["path"] == path)
            .unwrap_or_else(|| panic!("missing route {method} {path}"));
        assert_eq!(route["category"], "hermes-watchdog-observer");
        assert_eq!(route["mutates_ao_artifacts"], false);
        assert_eq!(route["control_plane_approves_release"], false);
        assert_eq!(route["mutates_observer_storage"], mutates_storage);
        assert!(!route["path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("token"));
    }
}
