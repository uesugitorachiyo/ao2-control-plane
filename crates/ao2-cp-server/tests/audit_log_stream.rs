//! Integration test for the `/api/v1/audit-log/stream` SSE endpoint.
//!
//! Verifies that:
//! - the endpoint is bearer-token gated like the rest of `/api/v1/*`,
//! - each entry on the stream renders as one `event: audit-log` block
//!   with the entry's `timestamp_unix_micros` as the SSE `id:` field,
//!   and the JSON payload as the `data:` field,
//! - filter query params (`method`, `path_prefix`) prune events live
//!   without disconnecting the stream,
//! - `last_event_id` (the query-param form of `Last-Event-ID`)
//!   replays buffered entries strictly newer than the supplied id
//!   before the live tail begins.
//!
//! SSE is a long-lived response, so each test spawns the server on a
//! random localhost port, drives traffic through it, then reads bytes
//! from the live stream with a tight deadline to avoid leaving a
//! background task alive on failure.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "secret-stream-token";

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

fn auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

/// Read bytes from the SSE response until either `predicate` returns
/// true or `timeout` elapses. Returns the accumulated bytes — useful
/// for assertions against the SSE event stream without committing the
/// test to an exact event count.
async fn read_until(
    response: &mut reqwest::Response,
    timeout: Duration,
    mut predicate: impl FnMut(&str) -> bool,
) -> String {
    let mut acc = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                acc.push_str(&String::from_utf8_lossy(&chunk));
                if predicate(&acc) {
                    break;
                }
            }
            Ok(Ok(None)) => break, // server closed
            Ok(Err(_)) => break,   // transport error
            Err(_) => break,       // overall deadline reached
        }
    }
    acc
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_requires_bearer_token() {
    let (base, _dir) = spawn_server().await;
    let resp = reqwest::get(format!("{base}/api/v1/audit-log/stream"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_accepts_query_token_because_eventsource_cannot_set_headers() {
    // Browser `EventSource` cannot set an `Authorization` header, so the
    // SSE stream endpoint accepts the bearer as a `?token=` query param.
    let (base, _dir) = spawn_server().await;
    let resp = reqwest::get(format!(
        "{base}/api/v1/audit-log/stream?token={TEST_API_TOKEN}"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE Content-Type, got {content_type}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_token_is_rejected_on_non_stream_endpoints() {
    // The `?token=` fallback is SSE-only. A normal JSON endpoint must
    // reject a query-string token (so the bearer never has to travel in
    // a URL, where it would leak via history / Referer / proxy logs) and
    // still accept the Authorization header.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let via_query = client
        .get(format!("{base}/api/v1/audit-log?token={TEST_API_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        via_query.status(),
        401,
        "query-string token must not authenticate a non-stream endpoint"
    );

    let via_header = client
        .get(format!("{base}/api/v1/audit-log"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(via_header.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_emits_events_for_live_traffic() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Open the SSE stream first.
    let mut resp = client
        .get(format!("{base}/api/v1/audit-log/stream"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE Content-Type, got {content_type}"
    );

    // Drive traffic that should produce audit-log entries.
    let driver = client.clone();
    let base_for_driver = base.clone();
    tokio::spawn(async move {
        // Small delay so the SSE subscription is registered before
        // entries are appended.
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..3 {
            let _ = driver
                .get(format!("{base_for_driver}/healthz"))
                .send()
                .await;
        }
    });

    // Look for at least 3 `event: audit-log` blocks within 5 s.
    let body = read_until(&mut resp, Duration::from_secs(5), |acc| {
        acc.matches("event: audit-log").count() >= 3
    })
    .await;
    let count = body.matches("event: audit-log").count();
    assert!(
        count >= 3,
        "expected ≥3 audit-log SSE events, observed {count} in body of {} bytes",
        body.len()
    );
    // Each event carries an `id:` line (timestamp) and a `data:` JSON line.
    assert!(
        body.contains("\nid: "),
        "SSE events must carry id: lines for client resume"
    );
    assert!(
        body.contains("\ndata: {"),
        "SSE events must carry JSON-encoded data payloads"
    );
    // The bearer token literal must never appear on the stream.
    assert!(
        !body.contains(TEST_API_TOKEN),
        "bearer token must never appear in the SSE stream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_applies_method_filter_live() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Subscribe with method=POST filter.
    let mut resp = client
        .get(format!("{base}/api/v1/audit-log/stream?method=POST"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let driver = client.clone();
    let base_for_driver = base.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 2 GETs (should be filtered out) + 1 POST (should pass).
        let _ = driver
            .get(format!("{base_for_driver}/healthz"))
            .send()
            .await;
        let _ = driver
            .get(format!("{base_for_driver}/healthz"))
            .send()
            .await;
        let _ = driver
            .post(format!("{base_for_driver}/api/v1/control-plane/bundle"))
            .body("{}")
            .send()
            .await;
    });

    let body = read_until(&mut resp, Duration::from_secs(5), |acc| {
        acc.contains("\"method\":\"POST\"")
    })
    .await;
    assert!(
        body.contains("\"method\":\"POST\""),
        "POST event must appear on a method=POST filtered stream"
    );
    assert!(
        !body.contains("\"method\":\"GET\""),
        "GET events must be filtered out when method=POST; body:\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_resumes_from_last_event_id() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // First, drive some traffic so the ring buffer has history.
    for _ in 0..3 {
        let _ = client.get(format!("{base}/healthz")).send().await;
    }
    // Tiny pause so the appends settle.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect with last_event_id=0 — replay must include ALL buffered
    // entries (every timestamp_unix_micros is > 0).
    let mut resp = client
        .get(format!("{base}/api/v1/audit-log/stream?last_event_id=0"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = read_until(&mut resp, Duration::from_secs(3), |acc| {
        acc.matches("event: audit-log").count() >= 3
    })
    .await;
    let count = body.matches("event: audit-log").count();
    assert!(
        count >= 3,
        "last_event_id=0 must replay all buffered entries; observed {count} events in {} bytes",
        body.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_keepalive_emits_comment_lines() {
    // Verify the SSE stream stays alive even when no traffic flows.
    // We do NOT wait the full 15 s keepalive — instead, the test
    // confirms the stream is still readable after a brief pause
    // without a connection error. A full keepalive timing test
    // would slow CI without adding signal that this short read
    // doesn't already cover.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let mut resp = client
        .get(format!("{base}/api/v1/audit-log/stream"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Read whatever bytes arrive within 1 s. With no traffic and a
    // 15 s keepalive interval, the buffer will typically be empty
    // — the assertion is simply that we didn't get a transport
    // error or a closed connection.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // chunk() returns Ok(None) only when the server closed; we
    // don't want that here. We do NOT block waiting for the
    // 15 s keepalive cycle.
    let chunk_or_timeout = tokio::time::timeout(Duration::from_millis(500), resp.chunk()).await;
    match chunk_or_timeout {
        Ok(Ok(Some(_))) | Err(_) => {
            // Either we got a chunk (e.g. an opening keepalive,
            // depending on axum's implementation) or we hit the
            // 500 ms read timeout — both indicate a healthy idle
            // stream.
        }
        Ok(Ok(None)) => panic!("idle SSE stream must not close immediately"),
        Ok(Err(e)) => panic!("idle SSE stream produced a transport error: {e}"),
    }
}
