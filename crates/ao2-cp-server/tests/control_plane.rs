use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const BUNDLE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/control-plane-bundle-sample.json");

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
async fn post_bundle_returns_receipt() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .header("authorization", "Bearer secret")
        .body(BUNDLE_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        body["ingested_schema_version"],
        "ao2.control-plane-fleet-bundle.v1"
    );
}

#[tokio::test]
async fn list_after_post_returns_one() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .header("authorization", "Bearer secret")
        .body(BUNDLE_FIXTURE)
        .send()
        .await
        .unwrap();
    let list = client
        .get(format!("{base}/api/v1/control-plane/bundle"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["schema_version"], "ao2.cp-bundle-list.v1");
}

#[tokio::test]
async fn get_by_sha_returns_original() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .header("authorization", "Bearer secret")
        .body(BUNDLE_FIXTURE)
        .send()
        .await
        .unwrap();
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();
    let get = client
        .get(format!("{base}/api/v1/control-plane/bundle/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(&body[..], BUNDLE_FIXTURE.as_bytes());
}

#[tokio::test]
async fn post_wrong_schema_returns_422() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .header("authorization", "Bearer secret")
        .body(r#"{"schema_version":"ao2.codex-provider-pilot-acceptance.v1"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn route_index_surfaces_frontend_safe_observer_contracts() {
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
    assert_eq!(body["schema_version"], "ao2.cp-route-index.v1");
    assert_eq!(body["control_plane_role"], "read-only-observer");
    assert_eq!(body["mutates_ao_artifacts"], false);
    assert_eq!(
        body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(body["auth"]["required"], true);
    assert_eq!(body["auth"]["credential_material_included"], false);

    let routes = body["routes"].as_array().unwrap();
    assert!(routes.iter().any(|route| {
        route["method"] == "GET"
            && route["path"] == "/api/v1/release/support-bundle/manifest"
            && route["portable"] == true
            && route["mutates_ao_artifacts"] == false
    }));
    assert!(routes.iter().any(|route| {
        route["method"] == "GET"
            && route["path"] == "/api/v1/phase1/promotion/gap-report/download"
            && route["download"] == true
            && route["owner"] == "ao2-control-plane observer"
    }));
    assert!(routes.iter().any(|route| {
        route["method"] == "POST"
            && route["path"] == "/api/v1/release/evaluator-decision/signed"
            && route["owner"] == "factory-v3 evaluator-closer"
            && route["control_plane_approves_release"] == false
    }));

    let portable_artifacts = body["portable_artifacts"].as_array().unwrap();
    let release_support_bundle = portable_artifacts
        .iter()
        .find(|artifact| artifact["id"] == "release_support_bundle")
        .expect("release support bundle portable artifact is advertised");
    assert_eq!(
        release_support_bundle["owner"],
        "ao2-control-plane observer"
    );
    assert_eq!(
        release_support_bundle["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(release_support_bundle["mutates_ao_artifacts"], false);
    assert_eq!(release_support_bundle["credential_material_in_urls"], false);
    assert_eq!(
        release_support_bundle["links"]["json"],
        "/api/v1/release/support-bundle.json"
    );
    assert_eq!(
        release_support_bundle["links"]["download"],
        "/api/v1/release/support-bundle/download"
    );
    assert_eq!(
        release_support_bundle["links"]["checksums"],
        "/api/v1/release/support-bundle/SHA256SUMS"
    );
    assert_eq!(
        release_support_bundle["links"]["verify_json"],
        "/api/v1/release/support-bundle/verify.json"
    );
    assert_eq!(
        release_support_bundle["links"]["verifier_handoff_json"],
        "/api/v1/release/support-bundle/handoff.json"
    );
    assert_eq!(
        release_support_bundle["links"]["verifier_handoff"],
        "/api/v1/release/support-bundle/handoff"
    );

    let phase1_gap_report = portable_artifacts
        .iter()
        .find(|artifact| artifact["id"] == "phase1_gap_report")
        .expect("Phase 1 gap report portable artifact is advertised");
    assert_eq!(
        phase1_gap_report["links"]["json"],
        "/api/v1/phase1/promotion/gap-report.json"
    );
    assert_eq!(
        phase1_gap_report["links"]["download"],
        "/api/v1/phase1/promotion/gap-report/download"
    );
    assert_eq!(
        phase1_gap_report["links"]["checksums"],
        "/api/v1/phase1/promotion/gap-report/SHA256SUMS"
    );

    let phase1_operator_support_bundle = portable_artifacts
        .iter()
        .find(|artifact| artifact["id"] == "phase1_operator_support_bundle")
        .expect("Phase 1 operator support bundle portable artifact is advertised");
    assert_eq!(
        phase1_operator_support_bundle["links"]["portable_manifest_download"],
        "/api/v1/phase1/promotion/portable-manifest/download"
    );
    assert_eq!(
        phase1_operator_support_bundle["links"]["portable_manifest_checksums"],
        "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS"
    );

    let storage_support_bundle = portable_artifacts
        .iter()
        .find(|artifact| artifact["id"] == "storage_support_bundle")
        .expect("storage support bundle portable artifact is advertised");
    assert_eq!(
        storage_support_bundle["links"]["contract_json"],
        "/api/v1/storage/support-bundle/contract.json"
    );

    let ci_evidence_index = portable_artifacts
        .iter()
        .find(|artifact| artifact["id"] == "ci_evidence_index")
        .expect("CI evidence index portable artifact is advertised");
    assert_eq!(ci_evidence_index["owner"], "ao2-control-plane observer");
    assert_eq!(
        ci_evidence_index["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(ci_evidence_index["mutates_ao_artifacts"], false);
    assert_eq!(ci_evidence_index["control_plane_approves_release"], false);
    assert_eq!(ci_evidence_index["credential_material_in_urls"], false);
    assert_eq!(
        ci_evidence_index["links"]["html"],
        "/api/v1/ci/evidence-index"
    );
    assert_eq!(
        ci_evidence_index["links"]["json"],
        "/api/v1/ci/evidence-index.json"
    );

    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));
}

#[tokio::test]
async fn route_index_uses_shared_route_catalog_without_secret_bearing_urls() {
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
    let expected_routes = ao2_cp_server::route_catalog::route_index_entries();
    assert_eq!(routes, expected_routes.as_slice());

    let response_tuples: std::collections::BTreeSet<(String, String)> = routes
        .iter()
        .map(|route| {
            (
                route["method"].as_str().unwrap().to_string(),
                route["path"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let catalog_tuples: std::collections::BTreeSet<(String, String)> =
        ao2_cp_server::route_catalog::ROUTES
            .iter()
            .map(|route| (route.method.to_string(), route.path.to_string()))
            .collect();

    assert_eq!(response_tuples, catalog_tuples);
    assert!(routes.iter().all(|route| route["auth_required"] == true));
    assert!(routes
        .iter()
        .all(|route| route["control_plane_role"] == "read-only-observer"));
    assert!(routes
        .iter()
        .all(|route| route["mutates_ao_artifacts"] == false));
    assert!(routes
        .iter()
        .all(|route| route["control_plane_approves_release"] == false));

    let route_tuples: std::collections::BTreeSet<(String, String)> = routes
        .iter()
        .map(|route| {
            (
                route["method"].as_str().unwrap().to_string(),
                route["path"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for artifact in body["portable_artifacts"].as_array().unwrap() {
        assert_eq!(artifact["mutates_ao_artifacts"], false);
        assert_eq!(artifact["control_plane_approves_release"], false);
        assert_eq!(artifact["credential_material_in_urls"], false);
        let links = artifact["links"].as_object().unwrap();
        for (label, path) in links {
            let path = path.as_str().unwrap();
            assert!(
                route_tuples.contains(&("GET".to_string(), path.to_string())),
                "portable artifact {} link {label} points at a route missing from the shared catalog: {path}",
                artifact["id"].as_str().unwrap()
            );
        }
    }

    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));
    assert!(!serialized.to_ascii_lowercase().contains("token="));
}

#[tokio::test]
async fn route_index_covers_frontend_static_surfaces_without_secret_bearing_urls() {
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

    let route_tuples: std::collections::BTreeSet<(String, String)> = routes
        .iter()
        .map(|route| {
            (
                route["method"].as_str().unwrap().to_string(),
                route["path"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    let expected_frontend_surfaces = [
        ("GET", "/api/v1/acceptance"),
        ("POST", "/api/v1/acceptance"),
        ("GET", "/api/v1/acceptance/dashboard.json"),
        ("GET", "/api/v1/acceptance/:sha"),
        ("GET", "/api/v1/control-plane/bundle"),
        ("POST", "/api/v1/control-plane/bundle"),
        ("GET", "/api/v1/control-plane/bundle/:sha"),
        ("GET", "/api/v1/evidence-pack"),
        ("GET", "/api/v1/evidence-pack/dashboard.json"),
        ("POST", "/api/v1/evidence-pack/signed"),
        ("GET", "/api/v1/evidence-pack/:sha/detail.json"),
        ("GET", "/api/v1/evidence-pack/:sha/signature"),
        ("GET", "/api/v1/evidence-pack/run/:run_id/latest"),
        ("GET", "/api/v1/operator-packet"),
        ("POST", "/api/v1/operator-packet/signed"),
        ("GET", "/api/v1/operator-packet/dashboard.json"),
        ("GET", "/api/v1/operator-packet/:sha/detail.json"),
        ("GET", "/api/v1/operator-packet/:sha/signature"),
        ("GET", "/api/v1/operator-packet/run/:run_id/latest"),
        ("GET", "/api/v1/memory/export"),
        ("POST", "/api/v1/memory/export"),
        ("GET", "/api/v1/memory/export/dashboard"),
        ("POST", "/api/v1/memory/export/signed"),
        ("GET", "/api/v1/memory/export/:sha/signature"),
        ("GET", "/api/v1/phase1/promotion/operator-panel.json"),
        ("GET", "/api/v1/phase1/promotion/portable-manifest.json"),
        ("GET", "/api/v1/phase1/promotion/portable-manifest/download"),
        (
            "GET",
            "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS",
        ),
        ("POST", "/api/v1/phase1/promotion/three-os-smoke"),
        ("GET", "/api/v1/phase1/promotion/three-os-smoke/latest"),
        ("GET", "/api/v1/phase1/promotion/checklist/latest"),
        ("GET", "/api/v1/phase1/promotion/decision/:sha/signature"),
        ("GET", "/api/v1/provider/registry"),
        ("POST", "/api/v1/provider/registry"),
        ("GET", "/api/v1/provider/registry/dashboard.json"),
        ("POST", "/api/v1/provider/registry/signed"),
        ("GET", "/api/v1/provider/registry/latest"),
        ("GET", "/api/v1/provider/registry/:sha/detail.json"),
        ("GET", "/api/v1/provider/registry/:sha/signature"),
        ("GET", "/api/v1/provider/readiness"),
        ("POST", "/api/v1/provider/readiness"),
        ("POST", "/api/v1/provider/readiness/signed"),
        ("GET", "/api/v1/provider/readiness/latest"),
        ("GET", "/api/v1/provider/readiness/support-bundle.json"),
        ("GET", "/api/v1/provider/readiness/support-bundle/download"),
        (
            "GET",
            "/api/v1/provider/readiness/support-bundle/SHA256SUMS",
        ),
        ("GET", "/api/v1/provider/readiness/:sha/detail.json"),
        ("GET", "/api/v1/provider/readiness/:sha/signature"),
        ("POST", "/api/v1/release/publication"),
        ("GET", "/api/v1/release/cockpit.json"),
        ("GET", "/api/v1/release/support-bundle/manifest.json"),
        ("POST", "/api/v1/release/evaluator-decision"),
        ("GET", "/api/v1/release/evaluator-decision/latest"),
        ("GET", "/api/v1/release/evaluator-decision/:sha/signature"),
        ("GET", "/api/v1/release/publication/latest"),
        ("GET", "/api/v1/storage/report"),
        ("GET", "/api/v1/storage/support-bundle.json"),
        ("GET", "/api/v1/storage/support-bundle/contract.json"),
        ("GET", "/api/v1/storage/support-bundle/SHA256SUMS"),
    ];

    for (method, path) in expected_frontend_surfaces {
        assert!(
            route_tuples.contains(&(method.to_string(), path.to_string())),
            "route index missing {method} {path}"
        );
    }

    for route in routes {
        assert_eq!(route["auth_required"], true);
        assert_eq!(route["control_plane_role"], "read-only-observer");
        assert_eq!(route["mutates_ao_artifacts"], false);
        assert_eq!(route["control_plane_approves_release"], false);
        assert!(
            !route["path"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("token"),
            "route index must not advertise token-bearing URLs: {route:?}"
        );
    }
}
