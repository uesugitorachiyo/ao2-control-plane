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

fn write_operator_release_evidence_bundle(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir
        .path()
        .join("operator-release-evidence-bundle-summary.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema_version": "ao2.operator-release-evidence-bundle.v1",
            "status": "passed",
            "operator_release_evidence_ready": true,
            "artifact_root": "/private/ao2/target/operator-release-evidence-bundle/latest/downloaded-artifacts",
            "download_status": "passed",
            "required_artifacts": [
                {"component": "ao2", "platform": "ci", "artifact": "ao2-dual-repo-release-publication-closure-index", "kind": "dual-repo-index"},
                {"component": "ao2", "platform": "linux", "artifact": "post-stable-release-smoke-Linux", "kind": "ao2-post-stable"},
                {"component": "ao2", "platform": "macos", "artifact": "post-stable-release-smoke-macOS", "kind": "ao2-post-stable"},
                {"component": "ao2", "platform": "windows", "artifact": "post-stable-release-smoke-Windows", "kind": "ao2-post-stable"},
                {"component": "ao2-control-plane", "platform": "ubuntu", "artifact": "ao2-control-plane-post-release-verification-ubuntu", "kind": "control-plane-post-release"},
                {"component": "ao2-control-plane", "platform": "macos", "artifact": "ao2-control-plane-post-release-verification-macos", "kind": "control-plane-post-release"},
                {"component": "ao2-control-plane", "platform": "windows", "artifact": "ao2-control-plane-post-release-verification-windows", "kind": "control-plane-post-release"}
            ],
            "checks": [
                {"component": "ao2", "platform": "ci", "artifact": "ao2-dual-repo-release-publication-closure-index", "kind": "dual-repo-index", "status": "passed", "schema_version": "ao2.dual-repo-release-publication-closure-index.v1", "path": "/Users/local/ao2/closure"},
                {"component": "ao2", "platform": "linux", "artifact": "post-stable-release-smoke-Linux", "kind": "ao2-post-stable", "status": "passed", "signature_verified": true, "install_status": "installed"},
                {"component": "ao2", "platform": "macos", "artifact": "post-stable-release-smoke-macOS", "kind": "ao2-post-stable", "status": "passed", "signature_verified": true, "install_status": "installed"},
                {"component": "ao2", "platform": "windows", "artifact": "post-stable-release-smoke-Windows", "kind": "ao2-post-stable", "status": "passed", "signature_verified": true, "install_status": "installed"},
                {"component": "ao2-control-plane", "platform": "ubuntu", "artifact": "ao2-control-plane-post-release-verification-ubuntu", "kind": "control-plane-post-release", "status": "passed", "schema_version": "ao2.cp-release-publication-closure.v1", "checksum_verified": true, "credential_material_included": false, "mutates_github_releases": false},
                {"component": "ao2-control-plane", "platform": "macos", "artifact": "ao2-control-plane-post-release-verification-macos", "kind": "control-plane-post-release", "status": "passed", "schema_version": "ao2.cp-release-publication-closure.v1", "checksum_verified": true, "credential_material_included": false, "mutates_github_releases": false},
                {"component": "ao2-control-plane", "platform": "windows", "artifact": "ao2-control-plane-post-release-verification-windows", "kind": "control-plane-post-release", "status": "passed", "schema_version": "ao2.cp-release-publication-closure.v1", "checksum_verified": true, "credential_material_included": false, "mutates_github_releases": false}
            ],
            "trust_boundary": {
                "queries_github_actions": true,
                "downloads_github_actions_artifacts": true,
                "mutates_releases": false,
                "stores_credentials": false
            },
            "download_log": "/private/ao2/target/operator-release-evidence-bundle/latest/download.log"
        })
        .to_string(),
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "current_thread")]
async fn operator_release_evidence_json_and_dashboard_are_read_only_observer_surfaces() {
    let _guard = ENV_LOCK.lock().await;
    let fixture_dir = tempdir().unwrap();
    let summary_path = write_operator_release_evidence_bundle(&fixture_dir);
    std::env::set_var("AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY", &summary_path);

    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{base}/api/v1/release/operator-evidence.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let response = client
        .get(format!("{base}/api/v1/release/operator-evidence.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["schema_version"],
        "ao2.cp-operator-release-evidence-readback.v1"
    );
    assert_eq!(body["status"], "observed");
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(body["mutates_observer_storage"], false);
    assert_eq!(body["control_plane_approves_release"], false);
    assert_eq!(body["auth"]["credential_material_included"], false);
    assert_eq!(
        body["source"]["configured_env"],
        "AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY"
    );
    assert_eq!(
        body["operator_release_evidence"]["schema_version"],
        "ao2.operator-release-evidence-bundle.v1"
    );
    assert_eq!(body["operator_release_evidence"]["status"], "passed");
    assert_eq!(
        body["operator_release_evidence"]["operator_release_evidence_ready"],
        true
    );
    assert_eq!(
        body["operator_release_evidence"]["checks"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
    assert!(!serde_json::to_string(&body)
        .unwrap()
        .contains("/private/ao2"));
    assert!(!serde_json::to_string(&body)
        .unwrap()
        .contains("/Users/local"));

    let html_response = client
        .get(format!("{base}/api/v1/release/operator-evidence"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html_response.status(), 200);
    let html = html_response.text().await.unwrap();
    assert!(html.contains("AO2 Operator Release Evidence"));
    assert!(html.contains("ao2.operator-release-evidence-bundle.v1"));
    assert!(html.contains("ao2.cp-operator-release-evidence-readback.v1"));
    assert!(html.contains("post-stable-release-smoke-Linux"));
    assert!(html.contains("ao2-control-plane-post-release-verification-windows"));
    assert!(html.contains("read-only-observer"));
    assert!(!html.contains("Bearer secret"));
    assert!(!html.contains("/private/ao2"));
    assert!(!html.contains("/Users/local"));

    let routes_response = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(routes_response.status(), 200);
    let routes: serde_json::Value = routes_response.json().await.unwrap();
    let portable = routes["portable_artifacts"].as_array().unwrap();
    assert!(portable.iter().any(|item| {
        item["id"] == "operator_release_evidence"
            && item["schema_version"] == "ao2.cp-operator-release-evidence-readback.v1"
            && item["links"]["html"] == "/api/v1/release/operator-evidence"
            && item["links"]["json"] == "/api/v1/release/operator-evidence.json"
    }));

    std::env::remove_var("AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY");
}

#[tokio::test(flavor = "current_thread")]
async fn operator_release_evidence_readback_returns_not_found_when_not_configured() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY");

    let (base, _data_dir) = spawn_server().await;
    let response = reqwest::Client::new()
        .get(format!("{base}/api/v1/release/operator-evidence.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[test]
fn route_catalog_advertises_operator_release_evidence_readback_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path) in [
        ("GET", "/api/v1/release/operator-evidence"),
        ("GET", "/api/v1/release/operator-evidence.json"),
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
