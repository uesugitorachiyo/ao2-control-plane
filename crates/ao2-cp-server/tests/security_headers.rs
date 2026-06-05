//! Verifies the defensive security headers are attached to every response
//! (both public health routes and the authenticated API), and that splitting
//! the SSE stream onto its own timeout/concurrency-exempt branch did not break
//! its routing or auth gating.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "secret-headers-token";

async fn spawn_server() -> (String, tempfile::TempDir) {
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

fn assert_security_headers(resp: &reqwest::Response) {
    let h = resp.headers();
    assert_eq!(
        h.get("x-content-type-options").map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        h.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        h.get("referrer-policy").map(|v| v.to_str().unwrap()),
        Some("no-referrer")
    );
    let csp = h
        .get("content-security-policy")
        .map(|v| v.to_str().unwrap())
        .expect("CSP header must be present");
    assert!(csp.contains("default-src 'none'"), "CSP: {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "CSP: {csp}");
    // The dashboards rely on inline styles and one inline EventSource script.
    assert!(
        csp.contains("style-src 'self' 'unsafe-inline'"),
        "CSP: {csp}"
    );
    assert!(
        csp.contains("script-src 'self' 'unsafe-inline'"),
        "CSP: {csp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_headers_present_on_public_health_route() {
    let (base, _dir) = spawn_server().await;
    let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_security_headers(&resp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_headers_present_on_authenticated_api_route() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/v1/audit-log"))
        .header("Authorization", format!("Bearer {TEST_API_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_security_headers(&resp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_headers_present_even_on_401() {
    let (base, _dir) = spawn_server().await;
    // No bearer token -> 401, but the headers must still be attached.
    let resp = reqwest::get(format!("{base}/api/v1/audit-log"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_security_headers(&resp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_stream_still_routes_and_requires_auth_after_split() {
    let (base, _dir) = spawn_server().await;
    // Unauthenticated stream request is still rejected (route exists, gated).
    let unauth = reqwest::get(format!("{base}/api/v1/audit-log/stream"))
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    // Authenticated stream request opens with the SSE content type — proving
    // the stream branch is reachable and was not eaten by the timeout layer.
    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{base}/api/v1/audit-log/stream"))
        .header("Authorization", format!("Bearer {TEST_API_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let content_type = ok
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE content type, got {content_type}"
    );
}
