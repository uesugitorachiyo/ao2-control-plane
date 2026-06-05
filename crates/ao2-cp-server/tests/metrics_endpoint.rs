//! Integration test for the `/api/v1/metrics` Prometheus exposition endpoint.
//!
//! Verifies that the metrics middleware records request counts + durations
//! across the whole router (including unauthenticated `/healthz`), that
//! `/api/v1/metrics` itself is bearer-token gated, and that the returned
//! body parses as Prometheus text exposition format 0.0.4 with the
//! expected metric families and labels.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "secret-metrics-token";

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

#[tokio::test]
async fn metrics_endpoint_requires_bearer_token() {
    let (base, _dir) = spawn_server().await;
    let resp = reqwest::get(format!("{base}/api/v1/metrics"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text_exposition() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Generate some recorded traffic.
    for _ in 0..3 {
        let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }
    let unauth = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    let metrics_resp = client
        .get(format!("{base}/api/v1/metrics"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(metrics_resp.status(), 200);
    let content_type = metrics_resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("text/plain"),
        "metrics endpoint must return text/plain; got {}",
        content_type
    );
    assert!(
        content_type.contains("version=0.0.4"),
        "metrics endpoint must announce Prometheus exposition v0.0.4; got {}",
        content_type
    );

    let body = metrics_resp.text().await.unwrap();
    assert!(
        body.contains("ao2_cp_requests_total{method=\"GET\",status_class=\"2xx\"}"),
        "metrics body must label by method + status_class; got body of {} bytes",
        body.len()
    );
    assert!(
        body.contains("ao2_cp_requests_total{method=\"GET\",status_class=\"4xx\"}"),
        "metrics body must record the 401 we just produced as 4xx"
    );
    assert!(
        body.contains("ao2_cp_request_duration_seconds_sum"),
        "metrics body must include duration sum"
    );
    assert!(
        body.contains("ao2_cp_request_duration_seconds_count"),
        "metrics body must include duration count"
    );
    assert!(
        body.contains("ao2_cp_in_flight_requests"),
        "metrics body must include in-flight gauge"
    );
    assert!(
        body.contains("ao2_cp_storage_total_index_entries 0"),
        "fresh storage must report zero index entries"
    );

    // Help and TYPE lines: required by Prometheus exposition format.
    assert!(
        body.contains("# HELP ao2_cp_requests_total"),
        "missing HELP line for ao2_cp_requests_total"
    );
    assert!(
        body.contains("# TYPE ao2_cp_requests_total counter"),
        "missing TYPE counter line for ao2_cp_requests_total"
    );
    assert!(
        body.contains("# TYPE ao2_cp_in_flight_requests gauge"),
        "missing TYPE gauge line for in-flight"
    );

    // Audit-log counter families: appended/rotated/persistence_errors/dropped.
    for name in [
        "ao2_cp_audit_log_appended_total",
        "ao2_cp_audit_log_rotated_total",
        "ao2_cp_audit_log_persistence_errors_total",
        "ao2_cp_audit_log_dropped_total",
    ] {
        assert!(
            body.contains(&format!("# HELP {name}")),
            "missing HELP line for {name}"
        );
        assert!(
            body.contains(&format!("# TYPE {name} counter")),
            "missing TYPE counter line for {name}"
        );
        assert!(
            body.contains(name),
            "metrics body missing audit-log family {name}"
        );
    }
    // Audit-log gauge families: file_bytes (persistence) and
    // oldest_resident_age_seconds (ring buffer retention horizon).
    for name in [
        "ao2_cp_audit_log_file_bytes",
        "ao2_cp_audit_log_oldest_resident_age_seconds",
    ] {
        assert!(
            body.contains(&format!("# HELP {name}")),
            "missing HELP line for {name}"
        );
        assert!(
            body.contains(&format!("# TYPE {name} gauge")),
            "missing TYPE gauge line for {name}"
        );
    }
    // Without persistence enabled, file_bytes must report 0.
    assert!(
        body.contains("ao2_cp_audit_log_file_bytes 0"),
        "file_bytes must be 0 on a server booted without persistence"
    );
    // The traffic above (4 healthz + 1 unauth call) plus the scrape
    // itself produces at least 5 appended audit-log entries before this
    // scrape runs. The exact count depends on whether the scrape is
    // counted on this render or the next one, so assert a lower bound
    // rather than equality to keep the test resilient to that
    // ordering.
    let appended_line = body
        .lines()
        .find(|line| line.starts_with("ao2_cp_audit_log_appended_total "))
        .expect("appended counter line present");
    let appended_value: u64 = appended_line
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .expect("appended counter is an integer");
    assert!(
        appended_value >= 4,
        "audit-log appended counter must reflect prior traffic; got {appended_value}"
    );
    assert!(
        body.contains("ao2_cp_audit_log_rotated_total 0"),
        "no rotation has occurred on a fresh boot without persistence"
    );
    assert!(
        body.contains("ao2_cp_audit_log_persistence_errors_total 0"),
        "no persistence errors on a server booted without persistence"
    );
    assert!(
        body.contains("ao2_cp_audit_log_dropped_total 0"),
        "no drops yet — buffer has plenty of headroom"
    );
}

#[tokio::test]
async fn metrics_records_post_method_separately_from_get() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // POST without auth → 401, counted as POST/4xx.
    let resp = client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let metrics_resp = client
        .get(format!("{base}/api/v1/metrics"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(metrics_resp.status(), 200);
    let body = metrics_resp.text().await.unwrap();
    assert!(
        body.contains("ao2_cp_requests_total{method=\"POST\",status_class=\"4xx\"} 1"),
        "POST/4xx counter must reflect the unauth POST attempt"
    );
}
