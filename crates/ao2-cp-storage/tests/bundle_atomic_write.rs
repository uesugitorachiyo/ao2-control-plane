//! Atomic-write guarantees for the content-addressed bundle store.
//!
//! `BundleStore::write` publishes via temp-file + atomic `rename`, so the
//! durability properties below must hold even under concurrency. The store is
//! content-addressed, so it is *legal* for two writers to race on the same sha
//! (they carry byte-identical content); the contract is that no reader ever
//! observes a torn, truncated, or otherwise partial file at the canonical path.
//!
//! These tests pin three properties a non-atomic `fs::write` truncate-in-place
//! could violate:
//!
//!   1. a reader concurrent with repeated overwrites sees either NotFound or
//!      the *complete* payload — never a short/torn read;
//!   2. many writers of the same sha all succeed (no temp-path collision) and
//!      leave the complete payload in place;
//!   3. in-flight temp files never surface through `list()`.

use ao2_cp_storage::bundle::{BundleKind, BundleStore};
use std::sync::Arc;
use tempfile::tempdir;

/// Large enough that a torn (truncated) read would be unmistakable: a partial
/// `fs::write` would yield a length other than this, and the byte pattern lets
/// us assert the content is whole, not just the right size.
const PAYLOAD_LEN: usize = 512 * 1024;

fn payload() -> Vec<u8> {
    // A non-trivial, position-dependent pattern so any splice/truncation shows
    // up as a content mismatch, not just a length mismatch.
    (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_never_observe_a_torn_write() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BundleStore::new(dir.path().to_path_buf()));
    let sha = "a1b2c3d4".repeat(8); // 64 hex chars
    let bytes = payload();

    // Seed an initial complete copy so readers can start immediately.
    store
        .write(BundleKind::EvidencePack, &sha, &bytes)
        .await
        .unwrap();

    // One writer overwrites the same sha many times (each overwrite is the
    // moment a truncate-in-place implementation would expose a torn file).
    let writer = {
        let store = Arc::clone(&store);
        let sha = sha.clone();
        let bytes = bytes.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                store
                    .write(BundleKind::EvidencePack, &sha, &bytes)
                    .await
                    .unwrap();
            }
        })
    };

    // Several readers hammer the same sha throughout the writer's run. Every
    // *successful* read must return the exact, whole payload.
    let mut readers = Vec::new();
    for _ in 0..4 {
        let store = Arc::clone(&store);
        let sha = sha.clone();
        let expected = bytes.clone();
        readers.push(tokio::spawn(async move {
            for _ in 0..400 {
                match store.read(BundleKind::EvidencePack, &sha).await {
                    Ok(got) => assert_eq!(
                        got,
                        expected,
                        "reader observed a torn/partial bundle (len {})",
                        got.len()
                    ),
                    // A NotFound would be a contract miss here (we seeded it),
                    // but it is categorically not a *torn* read, so surface it
                    // distinctly rather than masking it.
                    Err(e) => panic!("unexpected read error during overwrite: {e}"),
                }
            }
        }));
    }

    writer.await.unwrap();
    for r in readers {
        r.await.unwrap();
    }

    // Final state is the complete payload.
    let final_bytes = store.read(BundleKind::EvidencePack, &sha).await.unwrap();
    assert_eq!(final_bytes, bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_of_same_sha_all_succeed() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BundleStore::new(dir.path().to_path_buf()));
    let sha = "feedface".repeat(8);
    let bytes = payload();

    // 16 writers race on the identical sha. With a shared temp path they would
    // clobber one another and a rename could fail; with unique temp names every
    // write completes and the canonical file is whole.
    let mut handles = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let sha = sha.clone();
        let bytes = bytes.clone();
        handles.push(tokio::spawn(async move {
            store
                .write(BundleKind::ControlPlaneBundle, &sha, &bytes)
                .await
        }));
    }
    for h in handles {
        h.await
            .unwrap()
            .expect("concurrent write of identical content");
    }

    let got = store
        .read(BundleKind::ControlPlaneBundle, &sha)
        .await
        .unwrap();
    assert_eq!(got, bytes);

    // Exactly one canonical bundle exists for the sha — temps were renamed away,
    // not left behind as extra entries.
    assert_eq!(
        store.list(BundleKind::ControlPlaneBundle).await.unwrap(),
        vec![sha]
    );
}

#[tokio::test]
async fn list_never_surfaces_in_flight_temp_files() {
    // Even directly after writes, `list()` only reports `.json` bundles; the
    // `.json.tmp.*` temps are renamed atomically and never matched by the
    // `.json` suffix filter, so a concurrent `list()` can't leak a temp name.
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "0f1e2d3c".repeat(8);
    store
        .write(BundleKind::MemoryExport, &sha, b"{\"k\":\"v\"}")
        .await
        .unwrap();

    let listed = store.list(BundleKind::MemoryExport).await.unwrap();
    assert_eq!(listed, vec![sha]);
    assert!(
        listed.iter().all(|s| !s.contains(".tmp")),
        "list() leaked a temp file: {listed:?}"
    );
}
