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

fn write_stable_promotion_evidence_index(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir
        .path()
        .join("stable-promotion-evidence-index-summary.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema_version": "ao2.stable-promotion-evidence-index.v1",
            "status": "passed",
            "stable_promotion_evidence_index_ready": true,
            "artifact_root": "/private/ao2/target/stable-promotion-evidence-index/latest",
            "blockers": [],
            "evidence": {
                "artifact_size_budget_audit": {
                    "schema_version": "ao2.release-artifact-size-budget-audit.v1",
                    "status": "passed",
                    "ready": true,
                    "violations": [],
                    "summary_path": "/Users/local/ao2/artifact-size/summary.json"
                },
                "post_release_verification_gate": {
                    "schema_version": "ao2.stable-promotion-evidence-gate.v1",
                    "status": "passed",
                    "ready": true,
                    "post_release_evidence_ready": true
                },
                "public_pair_digest_audit": {
                    "schema_version": "ao2.public-release-pair-digest-audit.v1",
                    "status": "passed",
                    "ready": true,
                    "archive_parity_status": "passed"
                },
                "stable_release_evidence_packet": {
                    "schema_version": "ao2.stable-release-evidence-packet.v1",
                    "status": "passed",
                    "ready": true,
                    "stable_release_evidence_ready": true
                }
            },
            "trust_boundary": {
                "local_only": true,
                "control_plane_approves_release": false,
                "mutates_releases": false,
                "stores_credentials": false
            }
        })
        .to_string(),
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "current_thread")]
async fn stable_promotion_evidence_json_and_dashboard_are_read_only_observer_surfaces() {
    let _guard = ENV_LOCK.lock().await;
    let fixture_dir = tempdir().unwrap();
    let summary_path = write_stable_promotion_evidence_index(&fixture_dir);
    std::env::set_var(
        "AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY",
        &summary_path,
    );

    let (base, _data_dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!(
            "{base}/api/v1/release/stable-promotion-evidence.json"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);

    let response = client
        .get(format!(
            "{base}/api/v1/release/stable-promotion-evidence.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["schema_version"],
        "ao2.cp-stable-promotion-evidence-readback.v1"
    );
    assert_eq!(body["status"], "observed");
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(body["mutates_observer_storage"], false);
    assert_eq!(body["control_plane_approves_release"], false);
    assert_eq!(body["auth"]["credential_material_included"], false);
    assert_eq!(
        body["source"]["configured_env"],
        "AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY"
    );
    assert_eq!(
        body["stable_promotion_evidence"]["schema_version"],
        "ao2.stable-promotion-evidence-index.v1"
    );
    assert_eq!(body["stable_promotion_evidence"]["status"], "passed");
    assert_eq!(
        body["stable_promotion_evidence"]["stable_promotion_evidence_index_ready"],
        true
    );
    assert_eq!(
        body["stable_promotion_evidence"]["blockers"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    for required in [
        "artifact_size_budget_audit",
        "post_release_verification_gate",
        "public_pair_digest_audit",
        "stable_release_evidence_packet",
    ] {
        assert_eq!(
            body["stable_promotion_evidence"]["evidence"][required]["status"],
            "passed"
        );
        assert_eq!(
            body["stable_promotion_evidence"]["evidence"][required]["ready"],
            true
        );
    }
    assert_eq!(
        body["stable_promotion_evidence"]["evidence"]["public_pair_digest_audit"]
            ["archive_parity_status"],
        "passed"
    );
    assert_eq!(
        body["stable_promotion_evidence"]["trust_boundary"]["mutates_releases"],
        false
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
    assert!(!serde_json::to_string(&body)
        .unwrap()
        .contains("/private/ao2"));
    assert!(!serde_json::to_string(&body)
        .unwrap()
        .contains("/Users/local"));

    let html_response = client
        .get(format!("{base}/api/v1/release/stable-promotion-evidence"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html_response.status(), 200);
    let html = html_response.text().await.unwrap();
    assert!(html.contains("AO2 Stable Promotion Evidence"));
    assert!(html.contains("ao2.cp-stable-promotion-evidence-readback.v1"));
    assert!(html.contains("ao2.stable-promotion-evidence-index.v1"));
    assert!(html.contains("artifact_size_budget_audit"));
    assert!(html.contains("post_release_verification_gate"));
    assert!(html.contains("public_pair_digest_audit"));
    assert!(html.contains("archive_parity_status=passed"));
    assert!(html.contains("stable_release_evidence_packet"));
    assert!(html.contains("control_plane_approves_release=false"));
    assert!(html.contains("mutates_releases=false"));
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
        item["id"] == "stable_promotion_evidence"
            && item["schema_version"] == "ao2.cp-stable-promotion-evidence-readback.v1"
            && item["links"]["html"] == "/api/v1/release/stable-promotion-evidence"
            && item["links"]["json"] == "/api/v1/release/stable-promotion-evidence.json"
    }));

    std::env::remove_var("AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY");
}

#[tokio::test(flavor = "current_thread")]
async fn stable_promotion_evidence_readback_returns_not_found_when_not_configured() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY");

    let (base, _data_dir) = spawn_server().await;
    let response = reqwest::Client::new()
        .get(format!(
            "{base}/api/v1/release/stable-promotion-evidence.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[test]
fn route_catalog_advertises_stable_promotion_evidence_surfaces() {
    let routes = ao2_cp_server::route_catalog::ROUTES;

    for (method, path) in [
        ("GET", "/api/v1/release/stable-promotion-evidence"),
        ("GET", "/api/v1/release/stable-promotion-evidence.json"),
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
