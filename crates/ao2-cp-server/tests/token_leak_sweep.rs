//! Systematic trust-boundary guard: the bearer token never appears in a body.
//!
//! The control-plane trust boundary states that bearer tokens "never appear in
//! URLs, logs, or response bodies." Individual handlers assert a version of
//! this piecemeal (control_plane, phase1_promotion, access_log). This test
//! makes it *systematic*: it drives every GET/HEAD route in the canonical
//! route catalog with a high-entropy canary token and asserts the token is
//! absent from every response body. The payoff is coverage of routes that
//! don't exist yet — a future handler that echoes the `Authorization` header
//! into its response is caught here automatically, with no per-handler test to
//! remember to write.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::route_catalog::ROUTES;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// High-entropy token that cannot plausibly collide with legitimate body
/// content, so any occurrence is unambiguously a leak.
const CANARY: &str = "tok-LEAKCANARY-9f3c2a1b8e7d6c5f-d34db33fc4f3b4b3";

async fn spawn() -> (String, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: CANARY.to_string(),
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

/// Replace any `:param` path segment with a syntactically valid sha256 so sha
/// routes resolve to a clean 404 instead of a 400; harmless for other params.
fn concretize(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.starts_with(':') {
                "a".repeat(64)
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[tokio::test]
async fn bearer_token_never_appears_in_any_get_or_head_response_body() {
    let (base, _dir) = spawn().await;
    // The canary IS the configured token, so these requests authenticate and we
    // observe the handlers' real output, not a 401.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut checked = 0usize;
    for route in ROUTES {
        // POST/PUT/DELETE need request bodies (and most are signed mutations);
        // the response-body invariant is exercised via the read surface here.
        if route.method != "GET" && route.method != "HEAD" {
            continue;
        }
        // The SSE stream never completes; a GET would hang the sweep.
        if route.path.ends_with("/stream") {
            continue;
        }

        let url = format!("{base}{}", concretize(route.path));
        let req = if route.method == "HEAD" {
            client.head(&url)
        } else {
            client.get(&url)
        };
        let resp = match req
            .header("Authorization", format!("Bearer {CANARY}"))
            .send()
            .await
        {
            Ok(r) => r,
            // A transport hiccup leaves no body to inspect; nothing to assert.
            Err(_) => continue,
        };

        let body = resp.text().await.unwrap_or_default();
        assert!(
            !body.contains(CANARY),
            "route {} {} leaked the bearer token in its response body:\n{}",
            route.method,
            route.path,
            body.chars().take(400).collect::<String>()
        );
        checked += 1;
    }

    // Defend against the sweep silently degrading to a no-op (e.g. a catalog
    // refactor that filters everything out).
    assert!(
        checked >= 20,
        "expected to sweep many routes; only checked {checked}"
    );
}
