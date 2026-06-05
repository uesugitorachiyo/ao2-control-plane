use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, Storage};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "redacted-value";

fn test_auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
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

async fn seed_memory_export(dir: &tempfile::TempDir, sha: &str, age_seconds: i64) {
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    storage
        .bundles
        .write(BundleKind::MemoryExport, sha, b"{}")
        .await
        .unwrap();
    storage
        .bundles
        .write(BundleKind::MemoryExportSignature, sha, b"{}")
        .await
        .unwrap();
    storage
        .index
        .append(IndexEntry {
            ingested_at: Utc::now() - Duration::seconds(age_seconds),
            schema: "ao2.memory-export.v1".to_string(),
            provider: None,
            sha256: sha.to_string(),
            status: Some("signed".to_string()),
            size_bytes: 2,
        })
        .await
        .unwrap();
}

async fn seed_index_entry(
    dir: &tempfile::TempDir,
    schema: &str,
    provider: Option<&str>,
    sha: &str,
    status: Option<&str>,
    age_seconds: i64,
) {
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    storage
        .index
        .append(IndexEntry {
            ingested_at: Utc::now() - Duration::seconds(age_seconds),
            schema: schema.to_string(),
            provider: provider.map(str::to_string),
            sha256: sha.to_string(),
            status: status.map(str::to_string),
            size_bytes: 2,
        })
        .await
        .unwrap();
}

async fn seed_verified_signature_sidecar(dir: &tempfile::TempDir, kind: BundleKind, sha: &str) {
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    storage
        .bundles
        .write(kind, sha, br#"{"signature":{"signature_verified":true}}"#)
        .await
        .unwrap();
}

#[tokio::test]
async fn storage_report_is_authenticated_and_dry_run_only() {
    let (base, dir) = spawn_server().await;
    let old_sha = "1".repeat(64);
    let new_sha = "2".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!("{base}/api/v1/storage/report?keep_latest=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let report = client
        .get(format!("{base}/api/v1/storage/report?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), 200);
    let body: serde_json::Value = report.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-storage-retention-report.v1");
    assert_eq!(body["total_prune_candidates"], 1);
    assert_eq!(body["prune_candidates_limit"], 100);
    assert_eq!(body["prune_candidates_truncated"], false);
    assert_eq!(body["prune_candidates"][0]["sha256"], old_sha);
    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{old_sha}.json"))
        .exists());
}

#[tokio::test]
async fn storage_support_bundle_manifest_is_authenticated_read_only_and_token_free() {
    let (base, dir) = spawn_server().await;
    let old_sha = "3".repeat(64);
    let new_sha = "4".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle.json?keep_latest=1"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let bundle = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(bundle.status(), 200);
    let body: serde_json::Value = bundle.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-support-bundle.v1");
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(
        body["operator_handoff"]["control_plane_role"],
        "read_only_observer"
    );
    assert_eq!(body["operator_handoff"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["storage_dashboard"],
        "/api/v1/storage/dashboard?keep_latest=1"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["support_bundle_json"],
        "/api/v1/storage/support-bundle.json?keep_latest=1"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["support_bundle_download"],
        "/api/v1/storage/support-bundle/download?keep_latest=1"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["support_bundle_checksums"],
        "/api/v1/storage/support-bundle/SHA256SUMS?keep_latest=1"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_promotion_history_json"],
        "/api/v1/phase1/promotion/history.json"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_operator_panel_json"],
        "/api/v1/phase1/promotion/operator-panel.json"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_operator_support_bundle_json"],
        "/api/v1/phase1/promotion/operator-support-bundle.json"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_operator_support_bundle_download"],
        "/api/v1/phase1/promotion/operator-support-bundle/download"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_operator_support_bundle_checksums"],
        "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["phase1_promotion_gap_report_json"],
        "/api/v1/phase1/promotion/gap-report.json"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["provider_registry_dashboard_json"],
        "/api/v1/provider/registry/dashboard.json"
    );
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["release_cockpit_json"],
        "/api/v1/release/cockpit.json"
    );
    assert_eq!(
        body["operator_handoff"]["recommended_follow_up"][0],
        "Review signed evidence and phase readiness dashboards before release-line decisions."
    );
    assert!(body["operator_handoff"]["cross_os_smoke_commands"]
        .as_object()
        .unwrap()
        .contains_key("windows_powershell"));
    assert_eq!(
        body["phase1_release_readiness"]["schema_version"],
        "ao2.cp-support-bundle-phase1-readiness.v1"
    );
    assert_eq!(
        body["phase1_release_readiness"]["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        body["phase1_release_readiness"]["observed_artifacts"]["provider_readiness"],
        serde_json::Value::Null
    );
    assert!(body["phase1_release_readiness"]["blocking_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["id"] == "signed_phase1_promotion_decision"));
    assert_eq!(
        body["phase1_release_readiness"]["gap_summary"]["schema_version"],
        "ao2.cp-support-bundle-phase1-gap-summary.v1"
    );
    assert_eq!(
        body["phase1_release_readiness"]["gap_summary"]["total_blocking"],
        body["phase1_release_readiness"]["total_open_gaps"]
    );
    assert_eq!(
        body["phase1_release_readiness"]["gap_summary"]["missing_artifact_count"],
        body["phase1_release_readiness"]["total_open_gaps"]
    );
    assert_eq!(
        body["phase1_release_readiness"]["gap_summary"]["stale_artifact_count"],
        0
    );
    assert_eq!(
        body["phase1_release_readiness"]["gap_summary"]["failed_status_count"],
        0
    );
    assert_eq!(
        body["phase1_release_readiness"]["critical_path"][0]["id"],
        "provider_readiness"
    );
    assert_eq!(
        body["phase1_release_readiness"]["critical_path"][0]["operator_step"],
        1
    );
    assert_eq!(body["retention_report"]["total_prune_candidates"], 1);
    assert_eq!(
        body["retention_report"]["prune_candidates"][0]["sha256"],
        old_sha
    );
    assert_eq!(body["latest_index_entries"].as_array().unwrap().len(), 2);
    assert_eq!(body["latest_index_entries"][0]["sha256"], new_sha);

    let contract = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle/contract.json"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(contract.status(), 200);
    let contract_body: serde_json::Value = contract.json().await.unwrap();
    assert_eq!(
        contract_body["schema_version"],
        "ao2.cp-storage-support-bundle-contract.v1"
    );
    assert_eq!(
        contract_body["describes_schema_version"],
        body["schema_version"]
    );
    assert_eq!(contract_body["mutates_ao_artifacts"], false);
    assert_eq!(contract_body["control_plane_approves_release"], false);
    assert_eq!(
        contract_body["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    for field in [
        "gap_summary",
        "critical_path",
        "blocking_gaps",
        "next_recommended_action",
    ] {
        assert!(contract_body["required_phase1_release_readiness_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == field));
    }
    for field in ["gap_kind", "evidence_needed", "next_action"] {
        assert!(contract_body["required_blocking_gap_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == field));
    }
    assert!(contract_body["gap_kind_values"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "stale_artifact"));
    assert_eq!(
        contract_body["portable_endpoints"]["checksums"],
        "/api/v1/storage/support-bundle/SHA256SUMS"
    );

    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{old_sha}.json"))
        .exists());
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));
}

#[tokio::test]
async fn storage_support_bundle_download_and_checksums_are_portable_read_only_and_token_free() {
    let (base, dir) = spawn_server().await;
    let old_sha = "5".repeat(64);
    let new_sha = "6".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle/download?keep_latest=1"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let download = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle/download?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(
        download.headers()["content-disposition"],
        "attachment; filename=\"ao2-storage-support-bundle.json\""
    );
    assert_eq!(
        download.headers()["x-ao2-cp-control-plane-role"],
        "read-only-observer"
    );
    let declared_sha = download.headers()["x-ao2-cp-support-bundle-sha256"]
        .to_str()
        .unwrap()
        .to_string();
    let bytes = download.bytes().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-support-bundle.v1");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(body["latest_index_entries"][0]["sha256"], new_sha);

    let checksum = client
        .get(format!(
            "{base}/api/v1/storage/support-bundle/SHA256SUMS?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(checksum.status(), 200);
    assert_eq!(
        checksum.headers()["content-disposition"],
        "attachment; filename=\"SHA256SUMS\""
    );
    assert_eq!(
        checksum.headers()["x-ao2-cp-control-plane-role"],
        "read-only-observer"
    );
    let checksum_text = checksum.text().await.unwrap();
    assert!(checksum_text.contains("# schema: ao2.cp-storage-support-bundle-checksums.v1"));
    assert!(checksum_text.contains("# mutates-ao-artifacts: false"));
    assert!(checksum_text.contains("  ao2-storage-support-bundle.json"));
    let checksum_line = checksum_text
        .lines()
        .find(|line| line.ends_with("  ao2-storage-support-bundle.json"))
        .expect("checksums include storage support bundle filename");
    let (checksum_sha, _) = checksum_line
        .split_once("  ")
        .expect("checksums line uses sha256sum-compatible spacing");
    assert_eq!(checksum_sha.len(), 64);
    assert!(checksum_sha.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(declared_sha.len(), 64);
    assert!(declared_sha.chars().all(|ch| ch.is_ascii_hexdigit()));
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains(TEST_API_TOKEN));
    assert!(!checksum_text.contains(TEST_API_TOKEN));
    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{old_sha}.json"))
        .exists());
}

#[tokio::test]
async fn storage_support_bundle_phase1_readiness_tracks_latest_artifacts() {
    let (base, dir) = spawn_server().await;
    seed_index_entry(
        &dir,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &"1".repeat(64),
        Some("observed"),
        50,
    )
    .await;
    seed_index_entry(
        &dir,
        "ao2.codex-provider-pilot-acceptance.v1",
        Some("codex"),
        &"2".repeat(64),
        Some("accepted"),
        40,
    )
    .await;
    seed_index_entry(
        &dir,
        "ao2.claude-provider-pilot-acceptance.v1",
        Some("claude"),
        &"3".repeat(64),
        Some("accepted"),
        30,
    )
    .await;
    seed_index_entry(
        &dir,
        "factory-v3/ao2-phase1-promotion-checklist/v1",
        None,
        &"4".repeat(64),
        Some("passed"),
        20,
    )
    .await;
    seed_index_entry(
        &dir,
        "factory-v3/ao2-phase1-promotion-decision/v1",
        None,
        &"5".repeat(64),
        Some("signed"),
        10,
    )
    .await;
    seed_index_entry(
        &dir,
        "ao2-control-plane.three-os-release-smoke.v1",
        None,
        &"6".repeat(64),
        Some("passed"),
        10,
    )
    .await;
    seed_index_entry(
        &dir,
        "ao2.release-publication-summary.v1",
        None,
        &"7".repeat(64),
        Some("published_verified"),
        5,
    )
    .await;
    seed_index_entry(
        &dir,
        "factory-v3/ao2-release-evaluator-decision/v1",
        None,
        &"8".repeat(64),
        Some("accepted"),
        1,
    )
    .await;
    seed_verified_signature_sidecar(
        &dir,
        BundleKind::Phase1PromotionDecisionSignature,
        &"5".repeat(64),
    )
    .await;
    seed_verified_signature_sidecar(
        &dir,
        BundleKind::ReleaseEvaluatorDecisionSignature,
        &"8".repeat(64),
    )
    .await;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{base}/api/v1/storage/support-bundle.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let readiness = &body["phase1_release_readiness"];
    assert_eq!(readiness["readiness_status"], "ready");
    assert_eq!(readiness["release_decision_allowed"], true);
    assert_eq!(readiness["total_open_gaps"], 0);
    assert!(readiness["blocking_gaps"].as_array().unwrap().is_empty());
    assert_eq!(
        readiness["observed_artifacts"]["signed_phase1_promotion_decision"]["raw_url"],
        "/api/v1/phase1/promotion/decision/latest"
    );
    assert_eq!(
        readiness["observed_artifacts"]["three_os_release_smoke"]["raw_url"],
        "/api/v1/phase1/promotion/three-os-smoke/latest"
    );
    assert_eq!(
        readiness["operator_links"]["phase1_promotion_history_json"],
        "/api/v1/phase1/promotion/history.json"
    );
    assert_eq!(
        readiness["operator_links"]["phase1_operator_panel_json"],
        "/api/v1/phase1/promotion/operator-panel.json"
    );
    assert_eq!(
        readiness["operator_links"]["phase1_operator_support_bundle_json"],
        "/api/v1/phase1/promotion/operator-support-bundle.json"
    );
    assert_eq!(
        readiness["operator_links"]["phase1_operator_support_bundle_download"],
        "/api/v1/phase1/promotion/operator-support-bundle/download"
    );
    assert_eq!(
        readiness["operator_links"]["phase1_operator_support_bundle_checksums"],
        "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS"
    );
    assert_eq!(
        readiness["operator_links"]["provider_registry_dashboard_json"],
        "/api/v1/provider/registry/dashboard.json"
    );
    assert_eq!(
        readiness["operator_links"]["release_cockpit_json"],
        "/api/v1/release/cockpit.json"
    );
    assert_eq!(
        readiness["operator_links"]["factory_phase1_promotion_panel"],
        "factory-v3:scripts/hermes_ao_bridge.py phase1-promotion-panel"
    );
    assert_eq!(
        readiness["observed_artifacts"]["release_publication"]["raw_url"],
        "/api/v1/release/publication/latest"
    );
    assert_eq!(
        readiness["observed_artifacts"]["codex_live_acceptance"]["raw_url"],
        format!("/api/v1/acceptance/{}", "2".repeat(64))
    );
    assert_eq!(
        readiness["observed_artifacts"]["provider_readiness"]["stale_after_seconds"],
        24 * 60 * 60
    );
    assert_eq!(
        readiness["observed_artifacts"]["provider_readiness"]["is_stale"],
        false
    );
    assert!(
        readiness["observed_artifacts"]["provider_readiness"]["age_seconds"]
            .as_i64()
            .unwrap()
            >= 50
    );
    assert_eq!(readiness["trust_boundary"]["mutates_ao_artifacts"], false);
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));
}

#[tokio::test]
async fn storage_dashboard_exposes_support_links_and_retention_pressure_without_mutation() {
    let (base, dir) = spawn_server().await;
    let old_sha = "5".repeat(64);
    let new_sha = "6".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!("{base}/api/v1/storage/dashboard?keep_latest=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let dashboard_json = client
        .get(format!(
            "{base}/api/v1/storage/dashboard.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-storage-dashboard.v1");
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["operator_handoff"]["relative_endpoints"]["support_bundle_json"],
        "/api/v1/storage/support-bundle.json?keep_latest=1"
    );
    assert_eq!(body["retention_report"]["reclaimable_bytes"], 4);
    assert_eq!(
        body["links"]["support_bundle_json"],
        "/api/v1/storage/support-bundle.json?keep_latest=1"
    );
    assert!(body["links"].get("prune_execute").is_none());
    assert_eq!(body["latest_index_entries"][0]["sha256"], new_sha);
    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{old_sha}.json"))
        .exists());
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("Bearer"));

    let dashboard_html = client
        .get(format!("{base}/api/v1/storage/dashboard?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_html.status(), 200);
    let content_type = dashboard_html
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/html"));
    let html = dashboard_html.text().await.unwrap();
    assert!(html.contains("AO2 Control Plane Storage"));
    assert!(html.contains("Support Bundle JSON"));
    assert!(html.contains("read_only_observer"));
    assert!(html.contains(&old_sha[..12]));
    assert!(html.contains(&new_sha[..12]));
    assert!(html.contains("Gap Summary"));
    assert!(html.contains("Critical Path"));
    assert!(html.contains("missing_artifact"));
}

#[tokio::test]
async fn storage_dashboard_calls_out_missing_release_evaluator_decision() {
    let (base, dir) = spawn_server().await;
    for (schema, provider, sha, status, age_seconds) in [
        (
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1",
            Some("observed"),
            50,
        ),
        (
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2",
            Some("accepted"),
            40,
        ),
        (
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3",
            Some("accepted"),
            30,
        ),
        (
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4",
            Some("passed"),
            20,
        ),
        (
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5",
            Some("signed"),
            10,
        ),
        (
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6",
            Some("passed"),
            10,
        ),
        (
            "ao2.release-publication-summary.v1",
            None,
            "7",
            Some("published_verified"),
            5,
        ),
    ] {
        seed_index_entry(&dir, schema, provider, &sha.repeat(64), status, age_seconds).await;
    }
    seed_verified_signature_sidecar(
        &dir,
        BundleKind::Phase1PromotionDecisionSignature,
        &"5".repeat(64),
    )
    .await;

    let client = reqwest::Client::new();
    let dashboard_json = client
        .get(format!(
            "{base}/api/v1/storage/dashboard.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    let gaps = body["phase1_release_readiness"]["blocking_gaps"]
        .as_array()
        .unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["id"], "release_evaluator_decision");

    let dashboard_html = client
        .get(format!("{base}/api/v1/storage/dashboard?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_html.status(), 200);
    let html = dashboard_html.text().await.unwrap();
    assert!(html.contains("Release evaluator decision required"));
    assert!(html.contains("Factory v3 evaluator-closer"));
    assert!(html.contains("release_evaluator_decision"));
    assert!(html.contains("/api/v1/release/evaluator-decision/dashboard"));
    assert!(html.contains("/api/v1/storage/support-bundle.json?keep_latest=1"));
    assert!(!html.contains("secret"));
    assert!(!html.contains("Bearer"));
}

#[tokio::test]
async fn storage_dashboard_renders_stale_phase1_release_readiness() {
    let (base, dir) = spawn_server().await;
    seed_index_entry(
        &dir,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &"c".repeat(64),
        Some("observed"),
        25 * 60 * 60,
    )
    .await;
    seed_index_entry(
        &dir,
        "factory-v3/ao2-phase1-promotion-decision/v1",
        None,
        &"d".repeat(64),
        Some("signed"),
        10,
    )
    .await;
    let client = reqwest::Client::new();

    let dashboard_json = client
        .get(format!(
            "{base}/api/v1/storage/dashboard.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    let readiness = &body["phase1_release_readiness"];
    assert_eq!(
        readiness["schema_version"],
        "ao2.cp-support-bundle-phase1-readiness.v1"
    );
    assert_eq!(
        readiness["observed_artifacts"]["provider_readiness"]["is_stale"],
        true
    );
    assert!(readiness["blocking_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["id"] == "provider_readiness"));

    let dashboard_html = client
        .get(format!("{base}/api/v1/storage/dashboard?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_html.status(), 200);
    let html = dashboard_html.text().await.unwrap();
    assert!(html.contains("Phase 1 Release Readiness"));
    assert!(html.contains("Readiness status"));
    assert!(html.contains("blocked"));
    assert!(html.contains("Release decision allowed"));
    assert!(html.contains("false"));
    assert!(html.contains("provider_readiness"));
    assert!(html.contains("stale"));
    assert!(html.contains("/api/v1/provider/readiness/latest"));
    assert!(html.contains("refresh stale evidence"));
    assert!(!html.contains("secret"));
    assert!(!html.contains("Bearer"));
}

#[tokio::test]
async fn storage_dashboard_warns_when_prune_candidate_preview_is_truncated() {
    let (base, dir) = spawn_server().await;
    for index in 0..110 {
        let sha = format!("{index:064x}");
        seed_memory_export(&dir, &sha, 1_000 + i64::from(index)).await;
    }
    let newest_sha = "f".repeat(64);
    seed_memory_export(&dir, &newest_sha, 1).await;
    let client = reqwest::Client::new();

    let dashboard_json = client
        .get(format!(
            "{base}/api/v1/storage/dashboard.json?keep_latest=1"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(body["retention_report"]["total_prune_candidates"], 110);
    assert_eq!(body["retention_report"]["prune_candidates_limit"], 100);
    assert_eq!(body["retention_report"]["prune_candidates_truncated"], true);
    assert_eq!(
        body["retention_report"]["prune_candidates"]
            .as_array()
            .unwrap()
            .len(),
        100
    );

    let dashboard_html = client
        .get(format!("{base}/api/v1/storage/dashboard?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_html.status(), 200);
    let html = dashboard_html.text().await.unwrap();
    assert!(html.contains("Prune candidate preview truncated"));
    assert!(html.contains("showing 100 of 110 candidates"));
    assert!(html.contains("Retention Report JSON"));
    assert!(!html.contains("secret"));
    assert!(!html.contains("Bearer"));
    assert!(dir.path().join("memory-export").exists());
}

#[tokio::test]
async fn storage_prune_execute_is_gated_off_by_default() {
    // The dry-run prune (no `execute`) is always available, but a *destructive*
    // `execute=true` from a remote caller is gated off by default (sec-4): unless
    // the operator sets AO2_CP_ALLOW_DESTRUCTIVE_PRUNE on the server, the request
    // is refused with 403 and nothing is deleted. This test runs with the env
    // unset (the production default); the enabled path is covered in its own
    // isolated test binary (storage_prune_destructive_gate.rs) so this process
    // never mutates global env.
    let (base, dir) = spawn_server().await;
    let old_sha = "a".repeat(64);
    let new_sha = "b".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    // Dry-run is unaffected by the gate: it reports candidates, deletes nothing.
    let dry_run = client
        .post(format!("{base}/api/v1/storage/prune?keep_latest=1"))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(dry_run.status(), 200);
    let dry_body: serde_json::Value = dry_run.json().await.unwrap();
    assert_eq!(dry_body["schema_version"], "ao2.cp-storage-prune.v1");
    assert_eq!(dry_body["dry_run"], true);
    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{old_sha}.json"))
        .exists());

    // execute=true with the gate off: refused with 403, and BOTH bundles remain.
    let blocked = client
        .post(format!(
            "{base}/api/v1/storage/prune?keep_latest=1&execute=true"
        ))
        .header("authorization", test_auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(
        blocked.status(),
        403,
        "destructive execute must be gated off by default"
    );
    let blocked_body: serde_json::Value = blocked.json().await.unwrap();
    assert_eq!(blocked_body["code"], "forbidden");
    assert!(
        blocked_body["message"]
            .as_str()
            .unwrap()
            .contains("AO2_CP_ALLOW_DESTRUCTIVE_PRUNE"),
        "the 403 message must tell the operator how to enable it: {}",
        blocked_body["message"]
    );
    // Nothing was deleted — the gate blocked before prune_retention ran.
    assert!(
        dir.path()
            .join("memory-export")
            .join(format!("{old_sha}.json"))
            .exists(),
        "a blocked execute must not delete the old bundle"
    );
    assert!(dir
        .path()
        .join("memory-export")
        .join(format!("{new_sha}.json"))
        .exists());
}
