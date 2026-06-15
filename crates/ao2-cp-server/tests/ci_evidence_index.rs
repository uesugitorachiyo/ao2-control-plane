use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

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
async fn ci_evidence_index_json_and_dashboard_are_read_only_operator_surfaces() {
    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{base}/api/v1/ci/evidence-index.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let json_response = client
        .get(format!("{base}/api/v1/ci/evidence-index.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(json_response.status(), 200);
    let body: serde_json::Value = json_response.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-ci-evidence-index.v1");
    assert_eq!(body["status"], "indexed");
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["control_plane_approves_release"], false);
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(body["mutates_observer_storage"], false);
    assert_eq!(body["auth"]["credential_material_included"], false);
    assert_eq!(body["auth"]["credential_material_in_urls"], false);

    let evidence = body["evidence_families"].as_array().unwrap();
    assert_eq!(evidence.len(), 6);
    let ids = evidence
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            "risky-pr-golden-bridge-smoke",
            "release-train-bridge-smoke",
            "ingest-smoke",
            "release-archive-smoke",
            "backup-restore-drill",
            "stable-promotion-evidence-readback",
        ]
    );
    assert!(evidence.iter().all(|item| {
        item["artifact_name_pattern"]
            .as_str()
            .unwrap()
            .contains("ao2")
            && !item["schema_versions"].as_array().unwrap().is_empty()
            && item["operator_action"].as_str().unwrap() == "download-ci-artifact"
            && item["trust_boundary"]["read_only"].as_bool().unwrap()
            && !item["trust_boundary"]["approves_release"]
                .as_bool()
                .unwrap()
            && !item["trust_boundary"]["mutates_ao_artifacts"]
                .as_bool()
                .unwrap()
    }));
    for item in evidence {
        let provenance = &item["ci_artifact_provenance"];
        assert_eq!(provenance["provider"], "github-actions");
        assert_eq!(provenance["workflow_file"], ".github/workflows/ci.yml");
        assert_eq!(provenance["workflow_name"], "CI");
        assert_eq!(provenance["run_id_source"], "github_actions_run_id");
        assert_eq!(provenance["token_free"], true);
        assert!(!provenance["job_names"].as_array().unwrap().is_empty());
        assert!(!provenance["artifact_names"].as_array().unwrap().is_empty());
        assert!(provenance["artifact_names"]
            .as_array()
            .unwrap()
            .iter()
            .all(|name| name.as_str().unwrap().contains("ao2-control-plane")));
        assert!(provenance["run_url_template"]
            .as_str()
            .unwrap()
            .contains("/actions/runs/<run_id>"));
        assert!(provenance["artifact_download_url_template"]
            .as_str()
            .unwrap()
            .contains("/actions/runs/<run_id>/artifacts"));
        assert!(provenance["digest_reference"]
            .as_str()
            .unwrap()
            .contains("summary"));
    }

    let html_response = client
        .get(format!("{base}/api/v1/ci/evidence-index"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html_response.status(), 200);
    let html = html_response.text().await.unwrap();
    assert!(html.contains("AO2 CI Evidence Index"));
    assert!(html.contains("ao2.cp-ci-evidence-index.v1"));
    assert!(html.contains("Risky PR golden bridge smoke"));
    assert!(html.contains("Release train bridge smoke"));
    assert!(html.contains("Release archive smoke"));
    assert!(html.contains("Backup/restore drill"));
    assert!(html.contains("Stable promotion evidence readback"));
    assert!(!html.contains("Bearer secret"));
}

#[test]
fn route_catalog_advertises_ci_evidence_index_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path) in [
        ("GET", "/api/v1/ci/evidence-index"),
        ("GET", "/api/v1/ci/evidence-index.json"),
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
