//! Cross-OS bounded-growth smoke for the `ao2-cp-gc` operator binary.
//!
//! Builds a populated data directory through the public `Storage` API,
//! runs the binary as a subprocess, and asserts the index + on-disk
//! state match the documented contract:
//!
//! * `--dry-run` reports candidates but leaves files untouched.
//! * `--apply` removes pruned bundle files, rewrites the index, and
//!   keeps the `keep_latest` newest entries per prunable kind plus
//!   their related-kind signatures.
//! * Missing mode flags exit 64 (`EX_USAGE`).
//!
//! This runs under `cargo test --workspace` on every OS in the
//! release-smoke matrix, so any future drift in `prune_retention`
//! semantics flips a red signal on Mac, Ubuntu, and Windows together.

use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, Storage};
use chrono::{Duration, Utc};
use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

const GC_BIN: &str = env!("CARGO_BIN_EXE_ao2-cp-gc");

fn entry(schema: &str, sha256: &str, age_seconds: i64) -> IndexEntry {
    IndexEntry {
        ingested_at: Utc::now() - Duration::seconds(age_seconds),
        schema: schema.to_string(),
        provider: None,
        sha256: sha256.to_string(),
        status: Some("accepted".to_string()),
        size_bytes: 2,
    }
}

async fn write_indexed(storage: &Storage, kind: BundleKind, schema: &str, sha: &str, age: i64) {
    storage.bundles.write(kind, sha, b"{}").await.unwrap();
    storage.index.append(entry(schema, sha, age)).await.unwrap();
}

fn run_gc(args: &[&str]) -> std::process::Output {
    Command::new(GC_BIN)
        .args(args)
        .output()
        .expect("failed to spawn ao2-cp-gc binary")
}

#[tokio::test]
async fn gc_dry_run_reports_candidates_without_deleting() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    // Five evidence packs, oldest first. With --keep-latest=2 the three
    // oldest should appear as candidates.
    let shas = ["a", "b", "c", "d", "e"];
    for (i, c) in shas.iter().enumerate() {
        let sha = c.repeat(64);
        write_indexed(
            &storage,
            BundleKind::EvidencePack,
            "ao2.evidence-pack.v1",
            &sha,
            ((5 - i) * 100) as i64,
        )
        .await;
        storage
            .bundles
            .write(BundleKind::EvidencePackSignature, &sha, b"{}")
            .await
            .unwrap();
    }
    drop(storage);

    let out = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "2",
        "--dry-run",
    ]);
    assert!(
        out.status.success(),
        "dry-run exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let report: Value = serde_json::from_slice(&out.stdout).expect("gc emits JSON on stdout");
    assert_eq!(report["schema_version"], "ao2.cp-storage-prune.v1");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["keep_latest"], 2);
    let pruned = report["pruned"].as_array().expect("pruned is array");
    assert_eq!(pruned.len(), 3, "expect 3 oldest evidence-packs candidates");

    // Re-open and confirm nothing was actually removed.
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    for c in shas.iter() {
        let sha = c.repeat(64);
        assert!(
            storage.bundles.exists(BundleKind::EvidencePack, &sha).await,
            "dry-run must not delete primary bundle {}",
            c
        );
        assert!(
            storage
                .bundles
                .exists(BundleKind::EvidencePackSignature, &sha)
                .await,
            "dry-run must not delete signature bundle {}",
            c
        );
    }
}

#[tokio::test]
async fn gc_apply_prunes_oldest_per_kind_and_rewrites_index() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    let shas = ["1", "2", "3", "4", "5"];
    for (i, c) in shas.iter().enumerate() {
        let sha = c.repeat(64);
        write_indexed(
            &storage,
            BundleKind::EvidencePack,
            "ao2.evidence-pack.v1",
            &sha,
            ((5 - i) * 100) as i64,
        )
        .await;
        storage
            .bundles
            .write(BundleKind::EvidencePackSignature, &sha, b"{}")
            .await
            .unwrap();
    }
    drop(storage);

    let out = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "2",
        "--apply",
    ]);
    assert!(
        out.status.success(),
        "apply exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let report: Value = serde_json::from_slice(&out.stdout).expect("gc emits JSON on stdout");
    assert_eq!(report["dry_run"], false);
    let pruned = report["pruned"].as_array().expect("pruned is array");
    assert_eq!(pruned.len(), 3, "apply must prune 3 oldest evidence-packs");
    let retained = report["retained_index_entries"]
        .as_u64()
        .expect("retained_index_entries u64");
    assert_eq!(
        retained, 2,
        "index must retain only the keep_latest=2 entries"
    );

    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    // Oldest three (shas "1","2","3") must be gone — primary AND signature.
    for c in &shas[0..3] {
        let sha = c.repeat(64);
        assert!(
            !storage.bundles.exists(BundleKind::EvidencePack, &sha).await,
            "primary bundle for {} should be pruned",
            c
        );
        assert!(
            !storage
                .bundles
                .exists(BundleKind::EvidencePackSignature, &sha)
                .await,
            "signature for {} should be pruned with its primary",
            c
        );
    }
    // Newest two (shas "4","5") must remain.
    for c in &shas[3..5] {
        let sha = c.repeat(64);
        assert!(
            storage.bundles.exists(BundleKind::EvidencePack, &sha).await,
            "primary bundle for {} must be retained",
            c
        );
        assert!(
            storage
                .bundles
                .exists(BundleKind::EvidencePackSignature, &sha)
                .await,
            "signature for {} must be retained",
            c
        );
    }

    let remaining = storage.index.read_all().await.unwrap();
    assert_eq!(
        remaining.len(),
        2,
        "index file must be rewritten to keep only retained entries; got {} lines",
        remaining.len()
    );
}

#[tokio::test]
async fn gc_apply_is_idempotent_on_already_pruned_store() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    for (i, c) in ["a", "b", "c"].iter().enumerate() {
        let sha = c.repeat(64);
        write_indexed(
            &storage,
            BundleKind::EvidencePack,
            "ao2.evidence-pack.v1",
            &sha,
            ((3 - i) * 100) as i64,
        )
        .await;
    }
    drop(storage);

    // First apply prunes the oldest.
    let first = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "2",
        "--apply",
    ]);
    assert!(first.status.success());
    let r1: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(r1["pruned"].as_array().unwrap().len(), 1);

    // Second apply with the same policy must be a no-op.
    let second = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "2",
        "--apply",
    ]);
    assert!(second.status.success());
    let r2: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(
        r2["pruned"].as_array().unwrap().len(),
        0,
        "second apply must be a no-op (bounded-growth invariant)"
    );
    assert_eq!(r2["retained_index_entries"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn gc_keep_latest_floor_above_population_keeps_everything() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    for (i, c) in ["e", "f"].iter().enumerate() {
        let sha = c.repeat(64);
        write_indexed(
            &storage,
            BundleKind::EvidencePack,
            "ao2.evidence-pack.v1",
            &sha,
            ((2 - i) * 100) as i64,
        )
        .await;
    }
    drop(storage);

    let out = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "100",
        "--apply",
    ]);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["pruned"].as_array().unwrap().len(), 0);
    assert_eq!(report["retained_index_entries"].as_u64().unwrap(), 2);
}

#[test]
fn gc_missing_mode_exits_with_ex_usage() {
    let dir = tempdir().unwrap();
    let out = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "5",
    ]);
    assert!(!out.status.success());
    assert_eq!(
        out.status.code(),
        Some(64),
        "missing --dry-run/--apply must exit 64 (EX_USAGE); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn gc_conflicting_modes_rejected_by_clap() {
    let dir = tempdir().unwrap();
    let out = run_gc(&[
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--keep-latest",
        "5",
        "--dry-run",
        "--apply",
    ]);
    assert!(!out.status.success(), "clap must reject conflicting flags");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "stderr should explain the conflict; got: {}",
        stderr
    );
}
