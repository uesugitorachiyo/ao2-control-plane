//! Integration test for `scripts/ship-audit-log.{sh,ps1}` — the
//! NDJSON shipper integration helper introduced in v0.1.9.
//!
//! Verifies that:
//!
//! 1. The helper streams the live audit-log NDJSON file to stdout
//!    when the bearer is supplied and persistence is enabled.
//! 2. The helper exits with a non-zero exit code (and a useful
//!    stderr message) when no bearer is supplied.
//! 3. With `--include-rotated`, the helper prefixes its stdout
//!    with the contents of `<path>.1` when a rotated sidecar
//!    exists.
//! 4. The bearer-token value NEVER appears on stdout or stderr.
//!
//! The same test logic runs on both unix (bash) and Windows
//! (PowerShell), so the helper's cross-OS parity is exercised by
//! `scripts/smoke-three-os.sh`.

use ao2_cp_server::audit_log::AuditLog;
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use tempfile::tempdir;

const TEST_API_TOKEN: &str = "ship-audit-log-token-cafebabe-deadbeef";

struct Server {
    base: String,
    _dir: tempfile::TempDir,
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

fn shipper_script() -> PathBuf {
    let root = workspace_root();
    if cfg!(windows) {
        root.join("scripts").join("ship-audit-log.ps1")
    } else {
        root.join("scripts").join("ship-audit-log.sh")
    }
}

/// Pick the PowerShell interpreter available on the Windows host.
/// `pwsh` (PowerShell 7+) is not guaranteed to be on PATH, but
/// `powershell.exe` (Windows PowerShell 5.1) ships with every modern
/// Windows install — the rest of the smoke harness already targets it.
fn windows_powershell() -> &'static str {
    if std::process::Command::new("pwsh")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("$null")
        .output()
        .is_ok()
    {
        "pwsh"
    } else {
        "powershell"
    }
}

/// Invoke the OS-appropriate shipper helper with the supplied flags
/// translated for the target shell. Returns the full process output.
///
/// `include_rotated` and `follow` are surfaced as flags; all other
/// flags are taken verbatim. The helper is always invoked without
/// `--follow`/`-Follow` because the integration tests assert
/// terminal output, not stream behaviour.
fn run_shipper(
    base_url: &str,
    token: Option<&str>,
    include_rotated: bool,
    extra_path: Option<&Path>,
) -> Output {
    let script = shipper_script();
    if cfg!(windows) {
        let mut cmd = Command::new(windows_powershell());
        cmd.arg("-NoProfile")
            .arg("-File")
            .arg(&script)
            .arg("-BaseUrl")
            .arg(base_url);
        if let Some(tok) = token {
            cmd.arg("-Token").arg(tok);
        }
        if let Some(p) = extra_path {
            cmd.arg("-Path").arg(p);
        }
        if include_rotated {
            cmd.arg("-IncludeRotated");
        }
        cmd.output().expect("invoke ship-audit-log.ps1")
    } else {
        let mut cmd = Command::new("bash");
        cmd.arg(&script).arg("--base-url").arg(base_url);
        if let Some(tok) = token {
            cmd.arg("--token").arg(tok);
        }
        if let Some(p) = extra_path {
            cmd.arg("--path").arg(p);
        }
        if include_rotated {
            cmd.arg("--include-rotated");
        }
        cmd.output().expect("invoke ship-audit-log.sh")
    }
}

async fn spawn_server_with_persistence(capacity: usize, persistence_path: &Path) -> Server {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let audit_log = AuditLog::with_persistence(capacity, persistence_path)
        .expect("open persistence file in shipper test");
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

fn bearer() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ship_audit_log_streams_live_file_to_stdout_and_redacts_token() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");
    let s = spawn_server_with_persistence(64, &path).await;
    let client = reqwest::Client::new();

    // Drive a small mixed batch of authenticated + unauthenticated
    // requests so the live NDJSON file has known content for the
    // helper to stream back.
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
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let out = run_shipper(&s.base, Some(TEST_API_TOKEN), false, None);
    assert!(
        out.status.success(),
        "shipper exited non-zero: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("shipper stdout is utf-8");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // The shipper's own /api/v1/status round-trip is also audit-logged,
    // so the file legitimately gains one extra line beyond the 3 driven
    // by the test client. Assert the lower bound and the exact prefix.
    assert!(
        lines.len() >= 3,
        "expected at least 3 ndjson lines (one per driven request), got {} (stdout: {stdout:?})",
        lines.len()
    );
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("shipper stdout line is valid JSON");
        assert!(
            v["method"].is_string(),
            "ndjson line missing method: {line}"
        );
        assert!(v["path"].is_string(), "ndjson line missing path: {line}");
    }
    let paths: Vec<&str> = lines
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["path"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|s| Box::leak(s.into_boxed_str()) as &str)
        .collect();
    assert_eq!(
        &paths[..3],
        &["/healthz", "/api/v1/acceptance", "/api/v1/audit-log"],
        "first 3 streamed paths must match the driven request sequence"
    );
    // If the helper's status round-trip lands in the file, it must be
    // last and the path must be /api/v1/status — never a credential.
    if let Some(extra) = paths.get(3) {
        assert_eq!(
            *extra, "/api/v1/status",
            "trailing line must be the shipper's own status round-trip"
        );
    }

    assert!(
        !stdout.contains(TEST_API_TOKEN),
        "shipper stdout leaked bearer token"
    );
    assert!(
        !stderr.contains(TEST_API_TOKEN),
        "shipper stderr leaked bearer token"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ship_audit_log_includes_rotated_sidecar_when_flag_set() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");

    // Manually plant a rotated sidecar BEFORE spawning the server,
    // so the helper can stream <path>.1 + live in a single run.
    let rotated = persist_dir.path().join("audit.ndjson.1");
    std::fs::write(
        &rotated,
        "{\"method\":\"GET\",\"path\":\"/legacy\",\"status\":200}\n",
    )
    .unwrap();

    let s = spawn_server_with_persistence(64, &path).await;
    let client = reqwest::Client::new();
    client
        .get(format!("{}/healthz", s.base))
        .send()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let out = run_shipper(&s.base, Some(TEST_API_TOKEN), true, None);
    assert!(
        out.status.success(),
        "shipper exited non-zero: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("shipper stdout is utf-8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // Lines: rotated sidecar + live /healthz + shipper's own /api/v1/status
    // round-trip. The exact total is >=2 (sidecar + live) with the
    // sidecar leading.
    assert!(
        lines.len() >= 2,
        "expected at least sidecar + live, got {} (stdout: {stdout:?})",
        lines.len()
    );
    assert!(
        lines[0].contains("\"path\":\"/legacy\""),
        "rotated sidecar should appear first, got: {stdout:?}"
    );
    assert!(
        lines[1].contains("\"path\":\"/healthz\""),
        "live file's first line should be /healthz, got: {stdout:?}"
    );
    if let Some(extra) = lines.get(2) {
        assert!(
            extra.contains("\"path\":\"/api/v1/status\""),
            "trailing line must be the shipper's own status round-trip, got: {extra}"
        );
    }
    assert!(
        !stdout.contains(TEST_API_TOKEN),
        "shipper stdout leaked bearer token"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ship_audit_log_fails_when_bearer_missing() {
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");
    let s = spawn_server_with_persistence(64, &path).await;

    // Invoke the helper without any bearer (token=None and no env
    // var) and without a --path override so the helper is forced
    // through the /api/v1/status round-trip. It must reject with a
    // non-zero exit code and a stderr message that does not contain
    // a bearer string. We rely on the helper's documented exit code
    // 2 ("missing or invalid argument") for the empty-bearer case.
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new(windows_powershell());
        c.arg("-NoProfile")
            .arg("-File")
            .arg(shipper_script())
            .arg("-BaseUrl")
            .arg(&s.base);
        c
    } else {
        let mut c = Command::new("bash");
        c.arg(shipper_script()).arg("--base-url").arg(&s.base);
        c
    };
    // Explicitly clear AO2_CP_API_TOKEN from the child env so a
    // developer running these tests with an exported token still
    // exercises the empty-bearer path.
    cmd.env_remove("AO2_CP_API_TOKEN");
    cmd.env_remove("AO2_CP_AUDIT_LOG_FILE");

    let out = cmd.output().expect("invoke shipper without bearer");
    assert!(
        !out.status.success(),
        "shipper must fail without bearer; got status={:?} stdout={}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bearer required")
            || stderr.contains("--token")
            || stderr.contains("-Token"),
        "shipper stderr should explain the missing bearer; got: {stderr:?}"
    );
    assert!(
        !stderr.contains(TEST_API_TOKEN),
        "shipper stderr leaked bearer token"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ship_audit_log_path_override_skips_status_roundtrip() {
    // The helper should never hit /api/v1/status when --path /
    // -Path is supplied. Drive it against a deliberately wrong
    // base-url to prove the round-trip is skipped: any network
    // attempt would fail, but the helper should still succeed by
    // reading the explicit file path.
    let persist_dir = tempdir().unwrap();
    let path = persist_dir.path().join("audit.ndjson");
    std::fs::write(
        &path,
        "{\"method\":\"GET\",\"path\":\"/api/v1/audit-log\",\"status\":200}\n",
    )
    .unwrap();

    let out = run_shipper(
        "http://127.0.0.1:1", // unreachable on purpose
        None,
        false,
        Some(&path),
    );
    assert!(
        out.status.success(),
        "shipper with --path must skip status; got status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("shipper stdout is utf-8");
    assert!(
        stdout.contains("\"path\":\"/api/v1/audit-log\""),
        "shipper stdout should contain the planted line; got: {stdout:?}"
    );
}
