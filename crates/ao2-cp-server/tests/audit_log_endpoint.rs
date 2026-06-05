//! Integration test for the `GET /api/v1/audit-log` operator endpoint.
//!
//! Verifies that:
//! 1. The endpoint requires the bearer token (401 without).
//! 2. Requests are appended to the in-memory ring buffer and surfaced
//!    in newest-first order with the documented JSON shape.
//! 3. The bearer-token value NEVER appears in the response body, even
//!    after authenticated requests that supplied it.
//! 4. Query filters (`method`, `status`, `status_class`, `path_prefix`,
//!    `authenticated`, `since_unix_micros`, `limit`) all work and
//!    compose.
//! 5. The buffer is bounded: when capacity is exceeded, the oldest
//!    entries are evicted.

use ao2_cp_server::audit_log::AuditLog;
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "audit-log-token-feedface-baadf00d";

struct Server {
    base: String,
    _dir: tempfile::TempDir,
}

async fn spawn_server_with_capacity(capacity: usize) -> Server {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
        metrics: Arc::new(Metrics::new()),
        audit_log: Arc::new(AuditLog::new(capacity)),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        base: format!("http://{addr}"),
        _dir: dir,
    }
}

fn bearer() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_requires_bearer_token() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/audit-log", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_records_each_request_and_returns_newest_first() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    // Generate a known sequence of requests.
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();
    client
        .get(format!("{}/api/v1/control-plane/routes.json", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    client
        .get(format!("{}/api/v1/acceptance", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();

    // Read the audit log itself (this also gets recorded but should be
    // the newest entry on top).
    let resp = client
        .get(format!("{}/api/v1/audit-log", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["schema_version"], "ao2.cp-audit-log.v1");
    assert_eq!(body["buffer"]["capacity"], 64);
    // The middleware records each request AFTER the handler returns, so
    // the audit-log GET that produced this response is not yet present
    // in its own snapshot. Three prior requests must be visible:
    // healthz, routes.json, acceptance.
    let total = body["buffer"]["total_buffered"].as_u64().unwrap();
    assert!(total >= 3, "expected >=3 buffered entries, got {total}");

    let entries = body["entries"].as_array().expect("entries array");
    assert!(!entries.is_empty(), "no entries returned");
    // Newest first: the most recent prior request (the /api/v1/acceptance
    // hit) should be at entries[0].
    assert_eq!(entries[0]["path"], "/api/v1/acceptance");
    assert_eq!(entries[0]["method"], "GET");
    assert_eq!(entries[0]["authenticated"], true);
    assert_eq!(entries[0]["auth_attempted"], true);

    // The earlier requests are present.
    let paths: Vec<&str> = entries
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/healthz"));
    assert!(paths.contains(&"/api/v1/control-plane/routes.json"));
    assert!(paths.contains(&"/api/v1/acceptance"));

    // healthz is unauthenticated.
    let hz = entries
        .iter()
        .find(|e| e["path"] == "/healthz")
        .expect("healthz entry");
    assert_eq!(hz["authenticated"], false);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_never_leaks_bearer_token_in_response() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    // Hit a few authenticated endpoints so the token is sent on the wire.
    for _ in 0..3 {
        client
            .get(format!("{}/api/v1/control-plane/routes.json", s.base))
            .header("Authorization", bearer())
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .get(format!("{}/api/v1/audit-log?limit=1024", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();

    // CRITICAL: the response body must never contain the literal token.
    assert!(
        !body.contains(TEST_API_TOKEN),
        "audit-log response leaked bearer token! body was: {body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_filters_compose_status_class_method_path() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    // 200s: healthz x2, routes x1
    for _ in 0..2 {
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
    }
    client
        .get(format!("{}/api/v1/control-plane/routes.json", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    // 401: missing bearer on /api/v1/*.
    client
        .get(format!("{}/api/v1/acceptance", s.base))
        .send()
        .await
        .unwrap();
    // 401: bad bearer.
    client
        .get(format!("{}/api/v1/acceptance", s.base))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();

    // Filter to status_class=4xx.
    let resp = client
        .get(format!("{}/api/v1/audit-log?status_class=4xx", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    for e in entries {
        let status = e["status"].as_u64().unwrap();
        assert!(
            (400..=499).contains(&status),
            "non-4xx leaked through status_class=4xx filter: {e}"
        );
    }

    // path_prefix excludes /healthz.
    let resp = client
        .get(format!("{}/api/v1/audit-log?path_prefix=/api/v1", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    for e in entries {
        let path = e["path"].as_str().unwrap();
        assert!(
            path.starts_with("/api/v1"),
            "path_prefix filter let {path} through"
        );
    }

    // method=GET + authenticated=false should match the 401s on /api/v1/*.
    let resp = client
        .get(format!(
            "{}/api/v1/audit-log?method=GET&authenticated=false",
            s.base
        ))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    for e in entries {
        assert_eq!(e["method"], "GET");
        assert_eq!(e["authenticated"], false);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_buffer_is_bounded_and_evicts_oldest() {
    let s = spawn_server_with_capacity(5).await;
    let client = reqwest::Client::new();

    // 10 requests into a 5-slot buffer.
    for _ in 0..10 {
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .get(format!("{}/api/v1/audit-log?limit=1024", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let total = body["buffer"]["total_buffered"].as_u64().unwrap();
    assert_eq!(total, 5, "buffer exceeded its declared capacity");
    assert_eq!(body["buffer"]["capacity"], 5);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_limit_clamps_to_max_and_to_one() {
    let s = spawn_server_with_capacity(32).await;
    let client = reqwest::Client::new();

    for _ in 0..10 {
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
    }

    // limit=0 must return at least one entry (clamped up to 1).
    let resp = client
        .get(format!("{}/api/v1/audit-log?limit=0", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let limit = body["limit"].as_u64().unwrap();
    assert_eq!(limit, 1);
    assert_eq!(body["returned"].as_u64().unwrap(), 1);

    // Huge limit is clamped to MAX_RESPONSE_ENTRIES (1024).
    let resp = client
        .get(format!("{}/api/v1/audit-log?limit=999999", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["limit"].as_u64().unwrap(), 1024);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_since_unix_micros_filters_old_entries() {
    let s = spawn_server_with_capacity(32).await;
    let client = reqwest::Client::new();

    // Earlier request.
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();

    // Capture a "now-ish" boundary; sleep so subsequent timestamps are
    // strictly larger.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let boundary = ao2_cp_server::audit_log::now_unix_micros();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Later requests.
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!(
            "{}/api/v1/audit-log?since_unix_micros={boundary}",
            s.base,
        ))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    for e in entries {
        let ts = e["timestamp_unix_micros"].as_u64().unwrap();
        assert!(
            ts >= boundary,
            "entry with ts={ts} leaked through since_unix_micros={boundary} filter"
        );
    }
    // The earlier healthz hit (before boundary) must be excluded.
    let returned = body["returned"].as_u64().unwrap();
    let filtered_total = body["filtered_total"].as_u64().unwrap();
    let buffered = body["buffer"]["total_buffered"].as_u64().unwrap();
    // The middleware appends each request AFTER the handler returns, so
    // the audit-log GET itself is not in its own snapshot. The 2 later
    // healthz hits ARE visible; the 1 earlier healthz must NOT appear.
    assert!(
        returned >= 2,
        "expected >=2 post-boundary entries, got {returned}"
    );
    assert!(
        filtered_total < buffered,
        "filter did not drop pre-boundary entries: filtered_total={filtered_total} buffered={buffered}"
    );
}

async fn spawn_server_with_persistence(
    capacity: usize,
    persistence_path: &std::path::Path,
) -> Server {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let audit_log = AuditLog::with_persistence(capacity, persistence_path)
        .expect("open persistence file in test");
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
        metrics: Arc::new(Metrics::new()),
        audit_log: Arc::new(audit_log),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        base: format!("http://{addr}"),
        _dir: dir,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_persistence_writes_one_ndjson_line_per_request() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");
    let s = spawn_server_with_persistence(64, &path).await;
    let client = reqwest::Client::new();

    // Authenticated + unauthenticated mix.
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();
    client
        .get(format!("{}/api/v1/acceptance", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    client
        .get(format!("{}/api/v1/audit-log", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();

    // Give the middleware time to flush the file writer for each request.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(&path).expect("read persistence file back");
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "expected one ndjson line per appended request, got {} (file: {raw:?})",
        lines.len()
    );

    let mut methods = Vec::new();
    let mut paths = Vec::new();
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("each persisted line parses as JSON");
        methods.push(v["method"].as_str().unwrap().to_string());
        paths.push(v["path"].as_str().unwrap().to_string());
        // The audit entry must never contain the bearer token bytes.
        assert!(
            !line.contains(TEST_API_TOKEN),
            "persisted ndjson line leaked bearer token: {line}"
        );
    }
    assert_eq!(methods, vec!["GET", "GET", "GET"]);
    assert_eq!(
        paths,
        vec!["/healthz", "/api/v1/acceptance", "/api/v1/audit-log"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_persistence_survives_two_server_lifetimes() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");

    // First server lifetime — 2 requests.
    {
        let s = spawn_server_with_persistence(8, &path).await;
        let client = reqwest::Client::new();
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Second server lifetime — 1 more request. Existing file must NOT be
    // truncated; the new entry must be appended.
    {
        let s = spawn_server_with_persistence(8, &path).await;
        let client = reqwest::Client::new();
        client
            .get(format!("{}/healthz", s.base))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let raw = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "audit log persistence must survive process restart, got {} lines",
        lines.len()
    );
}

async fn spawn_server_with_rotated_persistence(
    capacity: usize,
    persistence_path: &std::path::Path,
    max_bytes: u64,
) -> Server {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let audit_log = AuditLog::with_persistence_rotated(capacity, persistence_path, max_bytes)
        .expect("open rotated persistence file in test");
    let state = Arc::new(AppState {
        storage,
        api_token: TEST_API_TOKEN.to_string(),
        max_body_bytes: 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
        metrics: Arc::new(Metrics::new()),
        audit_log: Arc::new(audit_log),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        base: format!("http://{addr}"),
        _dir: dir,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_dashboard_requires_bearer_token() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/audit-log/dashboard", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = client
        .get(format!("{}/api/v1/audit-log/dashboard.json", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_dashboard_html_renders_buffer_telemetry_and_redacts_token() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    // Drive a known mix of traffic so the dashboard has rows.
    for _ in 0..3 {
        client
            .get(format!("{}/healthz", s.base))
            .header("Authorization", bearer())
            .send()
            .await
            .unwrap();
    }
    client
        .get(format!("{}/api/v1/control-plane/routes.json", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    // 401 case (no bearer) so the table contains a `rejected` row.
    client
        .get(format!("{}/api/v1/acceptance", s.base))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/api/v1/audit-log/dashboard", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        ctype.starts_with("text/html"),
        "audit-log dashboard must return HTML, got Content-Type={ctype}"
    );
    let html = resp.text().await.unwrap();

    // Token-redaction invariant: the bearer must never appear in the
    // HTML. This is the v0.1.4 → v0.1.7 invariant extended to the
    // human-facing surface.
    assert!(
        !html.contains(TEST_API_TOKEN),
        "audit-log dashboard HTML leaked bearer token! payload was: {html}"
    );

    // Top-level chrome must be present so the dashboard is recognisable
    // even if a future refactor changes column wording.
    assert!(
        html.contains("AO2 Control Plane Audit Log"),
        "dashboard HTML missing title heading"
    );
    assert!(
        html.contains("Ring Buffer"),
        "dashboard HTML missing 'Ring Buffer' card"
    );
    assert!(
        html.contains("Persistence"),
        "dashboard HTML missing 'Persistence' card"
    );
    assert!(
        html.contains("Rotation"),
        "dashboard HTML missing 'Rotation' card"
    );
    assert!(
        html.contains("Trust Boundary"),
        "dashboard HTML missing 'Trust Boundary' section"
    );
    // The table must surface the requests we just drove.
    assert!(
        html.contains("/healthz"),
        "dashboard HTML missing /healthz row"
    );
    assert!(
        html.contains("/api/v1/control-plane/routes.json"),
        "dashboard HTML missing routes.json row"
    );
    // The 401 case must surface as a `rejected` cell.
    assert!(
        html.contains("rejected"),
        "dashboard HTML missing rejected auth label"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_dashboard_json_exposes_schema_links_and_redacts_token() {
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        client
            .get(format!("{}/healthz", s.base))
            .header("Authorization", bearer())
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .get(format!("{}/api/v1/audit-log/dashboard.json", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body_text = resp.text().await.unwrap();
    // Token redaction also applies to the JSON surface.
    assert!(
        !body_text.contains(TEST_API_TOKEN),
        "dashboard JSON leaked bearer token: {body_text}"
    );

    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-audit-log-dashboard.v1");
    let links = &body["links"];
    assert_eq!(links["dashboard"], "/api/v1/audit-log/dashboard");
    assert_eq!(links["dashboard_json"], "/api/v1/audit-log/dashboard.json");
    assert_eq!(links["audit_log_json"], "/api/v1/audit-log");
    assert_eq!(links["status_json"], "/api/v1/status");
    let trust = &body["trust_boundary"];
    assert_eq!(trust["role"], "read_only_observer");
    assert_eq!(trust["mutates_ao_artifacts"], false);
    // The dashboard JSON re-uses the same `buffer` shape as the
    // ring-buffer endpoint; assert one telemetry field to lock in
    // the contract.
    let buffer = &body["buffer"];
    assert!(buffer["total_appended_since_boot"].is_number());
    assert!(buffer["persistence"]["rotation"]["count"].is_number());
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_dashboard_html_does_not_render_injectable_script_tag() {
    // The audit log records the raw URL path. The dashboard renders
    // each `path` value through `escape_html`. We exercise both layers
    // by driving (a) a percent-encoded path (preserved by axum
    // verbatim, no decoding) and (b) a path with literal angle
    // brackets in the route URL. In neither case should a live
    // <script> tag survive into the dashboard HTML.
    let s = spawn_server_with_capacity(64).await;
    let client = reqwest::Client::new();

    // Case A: percent-encoded payload — the literal "<" never enters
    // the audit log, but the escape path should still hold.
    client
        .get(format!(
            "{}/{}",
            s.base, "abc%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
        ))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();

    // Case B: a query string with raw angle brackets. axum decodes
    // query strings into the audit-log `path` value's tail; if any
    // pipeline component along the way did decode, the dashboard's
    // escape pass is the last line of defense.
    client
        .get(format!("{}/healthz?x=<script>", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/api/v1/audit-log/dashboard", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    let html = resp.text().await.unwrap();
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "dashboard HTML rendered an unescaped <script> tag from a percent-encoded path: {html}"
    );
    // Look for any raw "<script>" substring anywhere in the body that
    // is NOT one we'd legitimately emit (we emit none). The presence
    // of any "<script>" in the response body is a regression.
    assert!(
        !html.contains("<script>"),
        "dashboard HTML contained a raw <script> tag — escape pass failed: {html}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_log_persistence_rotates_when_threshold_exceeded() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");
    // 1_000-byte threshold trips every ~5-6 requests.
    let s = spawn_server_with_rotated_persistence(64, &path, 1_000).await;
    let client = reqwest::Client::new();

    // Drive enough requests to force at least one rotation. Each
    // request makes one ~150-200-byte entry, so 20 requests is well
    // past the threshold.
    for _ in 0..20 {
        let resp = client
            .get(format!("{}/api/v1/audit-log", s.base))
            .header("Authorization", bearer())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // The most recent /audit-log response carries the rotation
    // telemetry. Query again to read it after the writes above.
    let resp = client
        .get(format!("{}/api/v1/audit-log", s.base))
        .header("Authorization", bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let buffer = &body["buffer"];
    let persistence = &buffer["persistence"];
    let rotation = &persistence["rotation"];
    assert_eq!(
        rotation["max_bytes"].as_u64(),
        Some(1_000),
        "max_bytes must be echoed back to the dashboard"
    );
    let count = rotation["count"].as_u64().unwrap();
    assert!(
        count >= 1,
        "at least one rotation must have occurred after 20 oversize requests (got {count})"
    );
    assert!(
        rotation["last_rotated_unix_micros"].is_number(),
        "last_rotated_unix_micros must be a number after rotation has fired (was {})",
        rotation["last_rotated_unix_micros"]
    );

    // The .1 sidecar must exist and parse line-by-line as JSON.
    let sidecar = {
        let mut s = path.clone().into_os_string();
        s.push(".1");
        std::path::PathBuf::from(s)
    };
    assert!(
        sidecar.exists(),
        "rotated sidecar must exist at {}",
        sidecar.display()
    );
    let sidecar_raw = std::fs::read_to_string(&sidecar).unwrap();
    for line in sidecar_raw.lines() {
        let _: serde_json::Value =
            serde_json::from_str(line).expect("each sidecar line parses as JSON");
        // Bearer-token invariant survives rotation.
        assert!(
            !line.contains(TEST_API_TOKEN),
            "rotated sidecar leaked bearer token: {line}"
        );
    }
}
