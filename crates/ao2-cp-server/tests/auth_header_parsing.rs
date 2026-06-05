//! Edge-case coverage for the `require_token` bearer-auth middleware.
//!
//! The happy paths are already pinned elsewhere: no token → 401
//! (`health.rs`), a correct header → 200 (`health.rs`), a wrong token still
//! generates a 4xx (`audit_log_endpoint.rs`), and the `?token=` query fallback
//! is accepted on `/stream` but rejected on JSON routes
//! (`audit_log_stream.rs`). What was *not* pinned is how the middleware parses
//! the `Authorization` header itself — and that parsing is the security
//! boundary: `strip_prefix("Bearer ")` is exact and case-sensitive, and the
//! `?token=` fallback is consulted *only* when no header is present.
//!
//! These tests drive the real router so the middleware, the `/api/v1` nest, and
//! the `route_layer` ordering are all exercised together.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::TempDir;

const TOKEN: &str = "correct-horse-battery-staple";

/// Spin up the real server on an ephemeral port. The returned `TempDir` must be
/// held for the lifetime of the test — dropping it deletes the data dir out
/// from under the running server.
async fn spawn() -> (String, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: TOKEN.to_string(),
        max_body_bytes: 4096,
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

/// A simple authenticated JSON route used as the probe target.
fn protected(base: &str) -> String {
    format!("{base}/api/v1/healthz/extended")
}

#[tokio::test]
async fn correct_bearer_header_is_accepted() {
    // Positive control: proves the route works with the right token, so the
    // 401s below are attributable to header parsing, not a broken route.
    let (base, _dir) = spawn().await;
    let resp = reqwest::Client::new()
        .get(protected(&base))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn malformed_authorization_headers_are_rejected() {
    let (base, _dir) = spawn().await;
    let client = reqwest::Client::new();

    // Each of these carries the right secret but in a shape the middleware must
    // not accept. The scheme match is exact and case-sensitive, and the value
    // is compared byte-for-byte (no trimming).
    let bad_headers = [
        ("lowercase scheme", format!("bearer {TOKEN}")),
        ("uppercase scheme", format!("BEARER {TOKEN}")),
        ("wrong scheme", format!("Basic {TOKEN}")),
        ("token scheme", format!("Token {TOKEN}")),
        ("no scheme, bare token", TOKEN.to_string()),
        ("scheme only, no token", "Bearer".to_string()),
        (
            "scheme with trailing space, empty token",
            "Bearer ".to_string(),
        ),
        ("double space before token", format!("Bearer  {TOKEN}")),
        ("wrong token", "Bearer nope".to_string()),
    ];

    for (label, value) in bad_headers {
        let resp = client
            .get(protected(&base))
            .header("Authorization", &value)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "`{label}` (Authorization: {value:?}) must be rejected"
        );
    }
}

#[tokio::test]
async fn trailing_header_whitespace_is_trimmed_by_transport_and_still_authenticates() {
    // Worth pinning so it isn't mistaken for a middleware bug: a trailing space
    // on the header value authenticates. HTTP header values may be surrounded by
    // optional whitespace (OWS, RFC 7230 §3.2); the hyper/reqwest stack strips
    // trailing OWS before the value reaches `require_token`, so
    // `strip_prefix("Bearer ")` sees the exact token. The lesson: the boundary
    // does NOT rely on rejecting trailing whitespace — the transport normalizes
    // it away. (Interior whitespace, e.g. a double space after the scheme, is
    // preserved and IS rejected — see the malformed-header test.)
    let (base, _dir) = spawn().await;
    let resp = reqwest::Client::new()
        .get(protected(&base))
        .header("Authorization", format!("Bearer {TOKEN} "))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn query_token_does_not_rescue_a_present_but_wrong_header_on_stream() {
    // The `?token=` fallback is consulted ONLY when no Authorization header is
    // present (`header_token.or(query_token)`). On the SSE stream route, a
    // wrong header must therefore 401 even though a correct query token is also
    // supplied — a present header always wins, so the query path can never be
    // used to override or smuggle past a header.
    let (base, _dir) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v1/audit-log/stream?token={TOKEN}"))
        .header("Authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn correct_header_authenticates_the_stream_route_without_a_query_token() {
    // The header path works on `/stream` too; the query fallback is an
    // addition for browsers, not the only way in.
    let (base, _dir) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v1/audit-log/stream"))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
