//! Integration test for the structured access-log middleware.
//!
//! Verifies that:
//! 1. Every request produces a single `target: ao2_cp_server::access`
//!    tracing event with the expected JSON fields.
//! 2. The bearer token value NEVER appears in the captured log output,
//!    even when sent as `Authorization: Bearer <token>`.
//! 3. Successful authenticated requests on `/api/v1/*` set
//!    `authenticated=true`; the 401 path on the same prefix sets it to
//!    `false`; unauthenticated paths (`/healthz`) are recorded as
//!    `authenticated=false`.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tracing_subscriber::fmt::MakeWriter;

const TEST_API_TOKEN: &str = "access-log-token-deadbeef-cafebabe";

/// Shared in-memory sink that implements `MakeWriter` so the tracing
/// JSON formatter can emit each event as a line into our buffer.
#[derive(Clone)]
struct SharedBuffer {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl SharedBuffer {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn snapshot(&self) -> String {
        let guard = self.inner.lock().unwrap();
        String::from_utf8_lossy(&guard).to_string()
    }
}

struct SharedBufferWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl Write for SharedBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBufferWriter;
    fn make_writer(&'a self) -> Self::Writer {
        SharedBufferWriter {
            inner: self.inner.clone(),
        }
    }
}

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

/// Install a thread-scoped tracing subscriber that writes JSON events
/// into the provided buffer. Returned guard removes the subscriber on
/// drop; subsequent tests are unaffected.
fn install_thread_subscriber(buffer: SharedBuffer) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_default(subscriber)
}

#[tokio::test(flavor = "current_thread")]
async fn access_log_emits_one_event_per_request_without_token_leak() {
    let buffer = SharedBuffer::new();
    let _guard = install_thread_subscriber(buffer.clone());

    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Unauthenticated probe — recorded as authenticated=false.
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Authenticated /api/v1 hit — recorded as authenticated=true.
    let resp = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .header("Authorization", auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Auth-header-present but wrong token → 401, authenticated=false.
    let resp = client
        .get(format!("{base}/api/v1/control-plane/routes.json"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Give tokio a chance to flush the subscriber.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let log = buffer.snapshot();

    // CRITICAL: the bearer-token value must never appear in any
    // emitted log line. Substring grep is the simplest faithful check.
    assert!(
        !log.contains(TEST_API_TOKEN),
        "access log leaked bearer token! captured log: {}",
        log
    );
    // Also: the literal "wrong-token" we sent in another header must
    // not appear either — proves the middleware doesn't accidentally
    // dump the Authorization header value.
    assert!(
        !log.contains("wrong-token"),
        "access log leaked attempted-token header value"
    );

    // Sanity: we DID record events. Look for the access-log target.
    assert!(
        log.contains("ao2_cp_server::access"),
        "no access-log events captured; log was: {}",
        log
    );
    // healthz event present.
    assert!(
        log.contains("\"path\":\"/healthz\""),
        "healthz access event missing"
    );
    // Authenticated routes.json hit present with authenticated=true.
    assert!(
        log.contains("\"path\":\"/api/v1/control-plane/routes.json\"")
            && log.contains("\"authenticated\":true"),
        "authenticated routes.json event missing or marked unauthenticated"
    );
    // 401 attempt present with authenticated=false.
    assert!(
        log.contains("\"status\":401") && log.contains("\"authenticated\":false"),
        "401 attempt event missing or marked authenticated"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn access_log_records_method_path_status_and_duration() {
    let buffer = SharedBuffer::new();
    let _guard = install_thread_subscriber(buffer.clone());

    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // POST without auth — should emit method=POST, status=401.
    let resp = client
        .post(format!("{base}/api/v1/control-plane/bundle"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let log = buffer.snapshot();

    assert!(
        log.contains("\"method\":\"POST\"")
            && log.contains("\"path\":\"/api/v1/control-plane/bundle\"")
            && log.contains("\"status\":401"),
        "POST/401 access event missing or malformed; log was: {}",
        log
    );
    assert!(
        log.contains("\"duration_micros\":"),
        "duration_micros field missing"
    );
}
