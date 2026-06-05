//! Enabled-path coverage for the sec-4 destructive-prune gate, isolated in its
//! own test binary.
//!
//! The gate is read from the `AO2_CP_ALLOW_DESTRUCTIVE_PRUNE` process env at
//! request time. Verifying the *enabled* path therefore requires setting that
//! env var — which is process-global and unsafe to mutate while other tests run
//! concurrently. Keeping this as the ONLY test in its own binary means it runs
//! in a dedicated process with no concurrent env readers: the `set_var` happens
//! on the single current-thread runtime before the server is spawned, so there
//! is no data race. The default (disabled) path is covered race-free in
//! `storage.rs` (which never touches env).

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, Storage};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "redacted-value";

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

async fn seed_memory_export(dir: &tempfile::TempDir, sha: &str, age_seconds: i64) {
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    storage
        .bundles
        .write(BundleKind::MemoryExport, sha, b"{}")
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

#[tokio::test]
async fn storage_prune_execute_runs_when_destructive_prune_is_enabled() {
    // Opt in BEFORE spawning the server. This is the only test in this binary
    // and the runtime is single-threaded here, so no other code reads the env
    // concurrently.
    std::env::set_var("AO2_CP_ALLOW_DESTRUCTIVE_PRUNE", "1");

    let (base, dir) = spawn_server().await;
    let old_sha = "a".repeat(64);
    let new_sha = "b".repeat(64);
    seed_memory_export(&dir, &old_sha, 120).await;
    seed_memory_export(&dir, &new_sha, 10).await;
    let client = reqwest::Client::new();

    let executed = client
        .post(format!(
            "{base}/api/v1/storage/prune?keep_latest=1&execute=true"
        ))
        .header("authorization", format!("Bearer {TEST_API_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        executed.status(),
        200,
        "with the gate enabled, execute=true must be permitted"
    );
    let body: serde_json::Value = executed.json().await.unwrap();
    assert_eq!(
        body["dry_run"], false,
        "this is a real prune, not a dry run"
    );
    assert_eq!(body["pruned"][0]["sha256"], old_sha);

    // The destructive prune actually deleted the oldest bundle and kept the
    // newest — i.e. the gate, once enabled, falls through to the real prune.
    assert!(
        !dir.path()
            .join("memory-export")
            .join(format!("{old_sha}.json"))
            .exists(),
        "enabled execute must delete the old bundle"
    );
    assert!(
        dir.path()
            .join("memory-export")
            .join(format!("{new_sha}.json"))
            .exists(),
        "the newest bundle within keep_latest must be retained"
    );
}
