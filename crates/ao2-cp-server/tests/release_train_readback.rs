use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

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

fn write_release_train_summary(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("public-release-train-summary.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema_version": "ao2.public-release-train-drill.v1",
            "status": "passed",
            "artifact_root": "/private/ao2/target/public-release-train-drill/latest",
            "release_readiness_artifact_consumer_contract": {
                "status": "passed",
                "required_check": "ci_release_readiness_artifact_consumer_job",
                "release_readiness_status": "passed",
                "check_detail": "downloads ao2-release-readiness and validates schema/status/core cross-OS checks"
            },
            "checks": [
                {"name": "release_evidence_closure", "status": "passed", "exit_code": 0},
                {"name": "release_readiness_static", "status": "passed", "exit_code": 0},
                {"name": "release_readiness_regression_gate", "status": "passed", "exit_code": 0},
                {"name": "retention_preflight", "status": "passed", "exit_code": 0},
                {"name": "artifact_consumer", "status": "passed", "exit_code": 0},
                {"name": "post_merge_canary", "status": "passed", "exit_code": 0}
            ],
            "publish_guards": {
                "refuses_publish_side_effects_by_default": true,
                "tag_push_publish_deploy": "not executed by this drill"
            },
            "component_summaries": {
                "release_readiness_static": "target/public-release-train-drill/latest/release-readiness-static/summary.json"
            },
            "trust_boundary": {
                "local_only": true,
                "stores_credentials": false
            }
        })
        .to_string(),
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "current_thread")]
async fn release_train_readback_json_and_dashboard_are_read_only_observer_surfaces() {
    let _guard = ENV_LOCK.lock().await;
    let fixture_dir = tempdir().unwrap();
    let summary_path = write_release_train_summary(&fixture_dir);
    std::env::set_var("AO2_CP_RELEASE_TRAIN_SUMMARY", &summary_path);

    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{base}/api/v1/release/train.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let response = client
        .get(format!("{base}/api/v1/release/train.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-release-train-readback.v1");
    assert_eq!(body["status"], "observed");
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(body["mutates_observer_storage"], false);
    assert_eq!(body["control_plane_approves_release"], false);
    assert_eq!(body["auth"]["credential_material_included"], false);
    assert_eq!(
        body["source"]["configured_env"],
        "AO2_CP_RELEASE_TRAIN_SUMMARY"
    );
    assert_eq!(
        body["release_train"]["schema_version"],
        "ao2.public-release-train-drill.v1"
    );
    assert_eq!(body["release_train"]["status"], "passed");
    assert_eq!(
        body["release_train"]["release_readiness_artifact_consumer_contract"]["status"],
        "passed"
    );
    assert_eq!(
        body["release_train"]["publish_guards"]["refuses_publish_side_effects_by_default"],
        true
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
    assert!(!serde_json::to_string(&body)
        .unwrap()
        .contains("/private/ao2"));

    let html_response = client
        .get(format!("{base}/api/v1/release/train"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html_response.status(), 200);
    let html = html_response.text().await.unwrap();
    assert!(html.contains("AO2 Release Train Readback"));
    assert!(html.contains("ao2.public-release-train-drill.v1"));
    assert!(html.contains("ci_release_readiness_artifact_consumer_job"));
    assert!(html.contains("release_readiness_static"));
    assert!(html.contains("read-only-observer"));
    assert!(html.contains("not executed by this drill"));
    assert!(!html.contains("Bearer secret"));
    assert!(!html.contains("/private/ao2"));

    std::env::remove_var("AO2_CP_RELEASE_TRAIN_SUMMARY");
}

#[tokio::test(flavor = "current_thread")]
async fn release_train_readback_returns_not_found_when_not_configured() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("AO2_CP_RELEASE_TRAIN_SUMMARY");

    let (base, _data_dir) = spawn_server().await;
    let response = reqwest::Client::new()
        .get(format!("{base}/api/v1/release/train.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[test]
fn route_catalog_advertises_release_train_readback_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path) in [
        ("GET", "/api/v1/release/train"),
        ("GET", "/api/v1/release/train.json"),
    ] {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing route catalog entry for {method} {path}"));
        assert_eq!(route.category, "release-readiness");
        assert_eq!(route.owner, "ao2-control-plane observer");
        assert!(route.portable);
        assert!(!route.download);
        assert!(!route.mutates_observer_storage);
    }
}
