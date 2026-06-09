use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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

fn write_manifest(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("artifact-manifest.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema_version": "ao2.risky-pr-golden-artifact-manifest.v1",
            "status": "indexed",
            "run_id": "risky-pr-golden-path",
            "artifact_root": ".",
            "artifact_count": 2,
            "artifacts": [
                {
                    "relative_path": "summary.json",
                    "path": "summary.json",
                    "size_bytes": 2045,
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "schema_version": "ao2.risky-pr-golden-path.v1"
                },
                {
                    "relative_path": "release-support-bundle/release-support-bundle.json",
                    "path": "release-support-bundle/release-support-bundle.json",
                    "size_bytes": 8237,
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "schema_version": "ao2.cp-release-support-bundle.v1"
                }
            ]
        })
        .to_string(),
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "current_thread")]
async fn risky_pr_golden_manifest_json_and_dashboard_are_read_only_observer_surfaces() {
    let _guard = ENV_LOCK.lock().unwrap();
    let manifest_dir = tempdir().unwrap();
    let manifest_path = write_manifest(&manifest_dir);
    std::env::set_var("AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST", &manifest_path);

    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!(
            "{base}/api/v1/risky-pr/golden/artifact-manifest.json"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let json_response = client
        .get(format!(
            "{base}/api/v1/risky-pr/golden/artifact-manifest.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(json_response.status(), 200);
    let body: serde_json::Value = json_response.json().await.unwrap();
    assert_eq!(
        body["schema_version"],
        "ao2.cp-risky-pr-golden-artifact-manifest-observer.v1"
    );
    assert_eq!(
        body["manifest"]["schema_version"],
        "ao2.risky-pr-golden-artifact-manifest.v1"
    );
    assert_eq!(body["manifest"]["artifact_count"], 2);
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(body["control_plane_approves_release"], false);
    assert_eq!(body["auth"]["credential_material_included"], false);
    assert_eq!(
        body["source"]["configured_env"],
        "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST"
    );

    let html_response = client
        .get(format!("{base}/api/v1/risky-pr/golden/artifact-manifest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html_response.status(), 200);
    let html = html_response.text().await.unwrap();
    assert!(html.contains("Risky PR Golden Artifact Manifest"));
    assert!(html.contains("ao2.risky-pr-golden-artifact-manifest.v1"));
    assert!(html.contains("summary.json"));
    assert!(html.contains("release-support-bundle/release-support-bundle.json"));
    assert!(html.contains("read-only-observer"));
    assert!(!html.contains("Bearer secret"));

    std::env::remove_var("AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST");
}

#[tokio::test(flavor = "current_thread")]
async fn risky_pr_golden_manifest_returns_not_found_when_not_configured() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST");

    let (base, _data_dir) = spawn_server().await;
    let response = reqwest::Client::new()
        .get(format!(
            "{base}/api/v1/risky-pr/golden/artifact-manifest.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[test]
fn route_catalog_advertises_risky_pr_golden_manifest_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path) in [
        ("GET", "/api/v1/risky-pr/golden/artifact-manifest"),
        ("GET", "/api/v1/risky-pr/golden/artifact-manifest.json"),
    ] {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing route catalog entry for {method} {path}"));
        assert_eq!(route.category, "release-support-bundle");
        assert_eq!(route.owner, "ao2 signed evidence boundary");
        assert!(route.portable);
        assert!(!route.download);
        assert!(!route.mutates_observer_storage);
    }
}
