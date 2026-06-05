use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const CODEX_FIXTURE: &str = include_str!("../../../tests/fixtures/codex-acceptance-v0.4.66.json");
const CLAUDE_FIXTURE: &str = include_str!("../../../tests/fixtures/claude-acceptance-v0.4.66.json");
const BAD_SCHEMA: &str = include_str!("../../../tests/fixtures/bad-schema-version.json");
const TAMPERED: &str = include_str!("../../../tests/fixtures/tampered-acceptance.json");

fn live_antigravity_fixture() -> String {
    let mut value: serde_json::Value = serde_json::from_str(CLAUDE_FIXTURE).unwrap();
    value["schema_version"] = serde_json::json!("ao2.antigravity-provider-pilot-acceptance.v1");
    value["provider"] = serde_json::json!("antigravity");
    value["run_id"] = serde_json::json!("live-antigravity-provider-pilot");
    value["source_class"] = serde_json::json!("live");
    value["root"] =
        serde_json::json!("/work/ao2/target/antigravity-provider-pilot/v0.4.80/antigravity");
    value["target"] = serde_json::json!(
        "/work/ao2/target/antigravity-provider-pilot/v0.4.80/antigravity/discount-service"
    );
    value["evidence_pack"] = serde_json::json!(
        "/work/ao2/target/antigravity-provider-pilot/v0.4.80/antigravity/discount-service/.ao2/runs/live-antigravity-provider-pilot/evidence-pack/evidence-pack.json"
    );
    if let Some(providers) = value
        .get_mut("smoke")
        .and_then(|smoke| smoke.get_mut("providers"))
        .and_then(serde_json::Value::as_array_mut)
    {
        for provider in providers {
            if provider.get("provider").and_then(serde_json::Value::as_str) == Some("claude") {
                provider["provider"] = serde_json::json!("antigravity");
            }
        }
    }
    serde_json::to_string(&value).unwrap()
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
async fn root_landing_page_is_public_token_safe_and_links_operator_surfaces() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("{base}/")).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("<title>AO2 Control Plane</title>"));
    assert!(html.contains("/healthz"));
    assert!(html.contains("/readyz"));
    assert!(html.contains("/api/v1/phase1/promotion/dashboard"));
    assert!(html.contains("/api/v1/storage/dashboard"));
    assert!(html.contains("/api/v1/audit-log/dashboard"));
    assert!(html.contains("Authorization: Bearer"));
    assert!(html.contains("Do not put bearer tokens in browser URLs"));
    assert!(html.contains("scripts/cp_dashboard_snapshot.py"));
    assert!(!html.contains("Bearer secret"));
    assert!(!html.contains("AO2_CP_API_TOKEN=secret"));
}

#[tokio::test]
async fn post_codex_acceptance_returns_receipt() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .header("content-type", "application/json")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        body["ingested_schema_version"],
        "ao2.codex-provider-pilot-acceptance.v1"
    );
    assert!(body["sha256"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn post_without_auth_returns_401() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("content-type", "application/json")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn post_bad_schema_returns_422() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .header("content-type", "application/json")
        .body(BAD_SCHEMA)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn post_provider_mismatch_returns_422() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .header("content-type", "application/json")
        .body(TAMPERED)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn post_idempotent_same_sha() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let r1 = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    let b1: serde_json::Value = r1.json().await.unwrap();
    let b2: serde_json::Value = r2.json().await.unwrap();
    assert_eq!(b1["sha256"], b2["sha256"]);

    let list_resp = client
        .get(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let list_body: serde_json::Value = list_resp.json().await.unwrap();
    assert_eq!(list_body["total_count"], 1);
}

#[tokio::test]
async fn get_acceptance_by_sha_returns_original_bytes() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let get = client
        .get(format!("{base}/api/v1/acceptance/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(&body[..], CODEX_FIXTURE.as_bytes());
}

#[tokio::test]
async fn list_after_codex_and_claude_returns_two() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CODEX_FIXTURE)
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CLAUDE_FIXTURE)
        .send()
        .await
        .unwrap();

    let list = client
        .get(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["total_count"], 2);
    let entries = body["entries"].as_array().unwrap();
    let providers: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["provider"].as_str().unwrap().to_string())
        .collect();
    assert!(providers.contains("codex"));
    assert!(providers.contains("claude"));
}

#[tokio::test]
async fn acceptance_dashboard_json_and_html_summarize_provider_pilots() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let live_codex_fixture = CODEX_FIXTURE
        .replace(
            r#""root": "<root>""#,
            r#""root": "C:\\work\\ao2\\target\\provider-pilot-acceptance\\v0.4.78\\codex""#,
        )
        .replace(
            r#""target": "<target>""#,
            r#""target": "C:\\work\\ao2\\target\\provider-pilot-acceptance\\v0.4.78\\codex\\discount-service""#,
        )
        .replace(
            r#""evidence_pack": "<evidence>""#,
            r#""evidence_pack": "C:\\work\\ao2\\target\\provider-pilot-acceptance\\v0.4.78\\codex\\discount-service\\.ao2\\runs\\live-codex-provider-pilot\\evidence-pack\\evidence-pack.json""#,
        );
    let codex = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(live_codex_fixture)
        .send()
        .await
        .unwrap();
    let codex_receipt: serde_json::Value = codex.json().await.unwrap();
    let codex_sha = codex_receipt["sha256"].as_str().unwrap();
    client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(CLAUDE_FIXTURE)
        .send()
        .await
        .unwrap();
    let antigravity = client
        .post(format!("{base}/api/v1/acceptance"))
        .header("authorization", "Bearer secret")
        .body(live_antigravity_fixture())
        .send()
        .await
        .unwrap();
    let antigravity_receipt: serde_json::Value = antigravity.json().await.unwrap();
    let antigravity_sha = antigravity_receipt["sha256"].as_str().unwrap();

    let dashboard_json = client
        .get(format!("{base}/api/v1/acceptance/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-acceptance-dashboard.v1");
    assert_eq!(body["total_count"], 3);
    assert_eq!(body["provider_counts"]["codex"], 1);
    assert_eq!(body["provider_counts"]["claude"], 1);
    assert_eq!(body["provider_counts"]["antigravity"], 1);
    assert_eq!(body["source_class_counts"]["live"], 2);
    assert_eq!(body["source_class_counts"]["fixture"], 1);
    assert_eq!(body["source_class_counts"]["unknown"], 0);
    assert_eq!(body["passed_count"], 3);
    assert_eq!(body["latest_by_provider"]["codex"]["sha256"], codex_sha);
    assert_eq!(body["latest_by_provider"]["codex"]["source_class"], "live");
    assert_eq!(
        body["latest_by_provider"]["antigravity"]["sha256"],
        antigravity_sha
    );
    assert_eq!(
        body["latest_by_provider"]["antigravity"]["source_class"],
        "live"
    );
    assert_eq!(body["phase1_acceptance"]["antigravity"], "passed");
    assert_eq!(
        body["latest_by_provider"]["codex"]["raw_url"],
        format!("/api/v1/acceptance/{codex_sha}")
    );
    let claude_entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["provider"] == "claude")
        .unwrap();
    assert_eq!(
        claude_entry["schema_version"],
        "ao2.claude-provider-pilot-acceptance.v1"
    );
    assert_eq!(claude_entry["source_class"], "fixture");
    assert!(claude_entry["score"].as_u64().unwrap() >= 90);
    assert_eq!(
        body["links"]["provider_readiness_dashboard"],
        "/api/v1/provider/readiness/dashboard"
    );
    assert_eq!(
        body["links"]["evidence_dashboard"],
        "/api/v1/evidence-pack/dashboard"
    );

    let codex_only = client
        .get(format!(
            "{base}/api/v1/acceptance/dashboard.json?provider=codex"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(codex_only.status(), 200);
    let codex_body: serde_json::Value = codex_only.json().await.unwrap();
    assert_eq!(codex_body["total_count"], 1);
    assert_eq!(codex_body["entries"][0]["provider"], "codex");

    let dashboard = client
        .get(format!("{base}/api/v1/acceptance/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("AO2 Provider Pilot Acceptance"));
    assert!(html.contains("Acceptance Trend"));
    assert!(html.contains("<th>Source</th>"));
    assert!(html.contains("<dt>Live</dt><dd>2</dd>"));
    assert!(html.contains("<dt>Fixture</dt><dd>1</dd>"));
    assert!(html.contains("Latest Codex"));
    assert!(html.contains("Latest Claude"));
    assert!(html.contains("Latest Antigravity"));
    assert!(html.contains("/api/v1/provider/readiness/dashboard"));
    assert!(html.contains(&format!("/api/v1/acceptance/{codex_sha}")));
}

#[tokio::test]
async fn acceptance_dashboard_marks_phase1_live_acceptance_complete() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let live_codex_fixture = CODEX_FIXTURE
        .replace(
            r#""root": "<root>""#,
            r#""root": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/codex""#,
        )
        .replace(
            r#""target": "<target>""#,
            r#""target": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/codex/discount-service""#,
        )
        .replace(
            r#""evidence_pack": "<evidence>""#,
            r#""evidence_pack": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/codex/discount-service/.ao2/runs/live-codex-provider-pilot/evidence-pack/evidence-pack.json""#,
        );
    let live_claude_fixture = CLAUDE_FIXTURE
        .replace(
            r#""root": "<root>""#,
            r#""root": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/claude""#,
        )
        .replace(
            r#""target": "<target>""#,
            r#""target": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/claude/discount-service""#,
        )
        .replace(
            r#""evidence_pack": "<evidence>""#,
            r#""evidence_pack": "/work/ao2/target/provider-pilot-acceptance/v0.4.78/claude/discount-service/.ao2/runs/live-claude-provider-pilot/evidence-pack/evidence-pack.json""#,
        );

    for fixture in [live_codex_fixture, live_claude_fixture] {
        let response = client
            .post(format!("{base}/api/v1/acceptance"))
            .header("authorization", "Bearer secret")
            .body(fixture)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    let dashboard_json = client
        .get(format!("{base}/api/v1/acceptance/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard_json.status(), 200);
    let body: serde_json::Value = dashboard_json.json().await.unwrap();

    assert_eq!(
        body["phase1_acceptance"]["state"],
        "live_acceptance_complete"
    );
    assert_eq!(body["phase1_acceptance"]["codex"], "passed");
    assert_eq!(body["phase1_acceptance"]["claude"], "passed");
    assert_eq!(body["phase1_acceptance"]["source_class"], "live");
    assert_eq!(
        body["phase1_acceptance"]["next_action"],
        "review signed evidence and run the guarded release gate before Phase 1 promotion"
    );

    let dashboard = client
        .get(format!("{base}/api/v1/acceptance/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("Phase 1 Acceptance"));
    assert!(html.contains("live_acceptance_complete"));
}
