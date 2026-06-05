use ao2_cp_storage::bundle::{BundleKind, BundleStore};
use tempfile::tempdir;

#[tokio::test]
async fn writes_and_reads_back() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "deadbeef".repeat(8);
    let bytes = b"{\"hello\":\"world\"}";
    store
        .write(BundleKind::AcceptanceCodex, &sha, bytes)
        .await
        .unwrap();
    let read = store.read(BundleKind::AcceptanceCodex, &sha).await.unwrap();
    assert_eq!(read, bytes);
}

#[tokio::test]
async fn read_returns_not_found_for_missing() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let result = store.read(BundleKind::AcceptanceCodex, "nope").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn exists_returns_true_after_write() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "feedface".repeat(8);
    assert!(!store.exists(BundleKind::ControlPlaneBundle, &sha).await);
    store
        .write(BundleKind::ControlPlaneBundle, &sha, b"{}")
        .await
        .unwrap();
    assert!(store.exists(BundleKind::ControlPlaneBundle, &sha).await);
}

#[tokio::test]
async fn memory_export_uses_dedicated_kind() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "0123456789abcdef".repeat(4);
    store
        .write(BundleKind::MemoryExport, &sha, b"{}")
        .await
        .unwrap();

    assert!(store.exists(BundleKind::MemoryExport, &sha).await);
    assert!(!store.exists(BundleKind::ControlPlaneBundle, &sha).await);
    assert_eq!(
        store.list(BundleKind::MemoryExport).await.unwrap(),
        vec![sha]
    );
}

#[tokio::test]
async fn evidence_pack_uses_dedicated_kind_and_signature_sidecar() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "1234567890abcdef".repeat(4);
    store
        .write(BundleKind::EvidencePack, &sha, b"{}")
        .await
        .unwrap();
    store
        .write(BundleKind::EvidencePackSignature, &sha, b"{}")
        .await
        .unwrap();

    assert!(store.exists(BundleKind::EvidencePack, &sha).await);
    assert!(store.exists(BundleKind::EvidencePackSignature, &sha).await);
    assert!(!store.exists(BundleKind::MemoryExport, &sha).await);
}

#[tokio::test]
async fn list_returns_all_files_in_kind() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha_a = "a".repeat(64);
    let sha_b = "b".repeat(64);
    store
        .write(BundleKind::AcceptanceClaude, &sha_a, b"{}")
        .await
        .unwrap();
    store
        .write(BundleKind::AcceptanceClaude, &sha_b, b"{}")
        .await
        .unwrap();
    let mut listed = store.list(BundleKind::AcceptanceClaude).await.unwrap();
    listed.sort();
    assert_eq!(listed, vec![sha_a, sha_b]);
}

#[tokio::test]
async fn size_returns_byte_length() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "c0ffee00".repeat(8);
    let bytes = br#"{"k":"value-with-known-length"}"#;
    store
        .write(BundleKind::AcceptanceCodex, &sha, bytes)
        .await
        .unwrap();
    let size = store.size(BundleKind::AcceptanceCodex, &sha).await.unwrap();
    assert_eq!(size, bytes.len() as u64);
}

#[tokio::test]
async fn size_returns_not_found_for_missing() {
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let result = store.size(BundleKind::AcceptanceCodex, "absent").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn remove_if_exists_is_idempotent() {
    // remove_if_exists is the deletion primitive retention/prune relies on. Its
    // contract is idempotent: true the first time (something was removed), false
    // thereafter (nothing to remove) — never an error for an absent bundle.
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "deadc0de".repeat(8);

    // Absent up front → false, no error.
    assert!(!store
        .remove_if_exists(BundleKind::ReleasePublication, &sha)
        .await
        .unwrap());

    store
        .write(BundleKind::ReleasePublication, &sha, b"{}")
        .await
        .unwrap();
    assert!(store.exists(BundleKind::ReleasePublication, &sha).await);

    // First removal reports it did something; the bundle is then gone.
    assert!(store
        .remove_if_exists(BundleKind::ReleasePublication, &sha)
        .await
        .unwrap());
    assert!(!store.exists(BundleKind::ReleasePublication, &sha).await);
    assert!(store
        .read(BundleKind::ReleasePublication, &sha)
        .await
        .is_err());

    // Second removal is a no-op → false, still no error.
    assert!(!store
        .remove_if_exists(BundleKind::ReleasePublication, &sha)
        .await
        .unwrap());
}

/// Every `BundleKind`. Kept in sync by hand so the layout guards below cover the
/// full enum; if a variant is added, those tests must be extended (the count
/// assertion fails otherwise).
const ALL_KINDS: &[BundleKind] = &[
    BundleKind::AcceptanceCodex,
    BundleKind::AcceptanceClaude,
    BundleKind::AcceptanceAntigravity,
    BundleKind::ControlPlaneBundle,
    BundleKind::EvidencePack,
    BundleKind::EvidencePackSignature,
    BundleKind::HermesWatchdogPanel,
    BundleKind::MemoryExport,
    BundleKind::MemoryExportSignature,
    BundleKind::Phase1PromotionChecklist,
    BundleKind::Phase1PromotionDecision,
    BundleKind::Phase1PromotionDecisionSignature,
    BundleKind::ProviderReadiness,
    BundleKind::ProviderReadinessSignature,
    BundleKind::ProviderRegistry,
    BundleKind::ProviderRegistrySignature,
    BundleKind::ReleaseEvaluatorDecision,
    BundleKind::ReleaseEvaluatorDecisionSignature,
    BundleKind::ReleasePublication,
    BundleKind::ThreeOsReleaseSmoke,
];

#[test]
fn bundle_kind_subdirs_are_unique() {
    // The on-disk subdir is the layout contract: every kind must map to a
    // DISTINCT directory. If two kinds collided on a subdir, a bundle of one
    // kind could silently overwrite a same-sha bundle of another — cross-kind
    // corruption. (20 distinct subdirs as of writing; the count also guards
    // against an added variant slipping past these tests.)
    use std::collections::BTreeSet;
    let subdirs: BTreeSet<&str> = ALL_KINDS.iter().map(|k| k.subdir()).collect();
    assert_eq!(
        subdirs.len(),
        ALL_KINDS.len(),
        "every BundleKind must map to a unique on-disk subdir"
    );
    assert_eq!(ALL_KINDS.len(), 20, "ALL_KINDS must list every variant");

    // Subdirs must be safe, relative path fragments (no leading slash, no `..`),
    // so a kind can never escape the storage root.
    for kind in ALL_KINDS {
        let sub = kind.subdir();
        assert!(!sub.is_empty(), "subdir must be non-empty");
        assert!(!sub.starts_with('/'), "subdir {sub} must be relative");
        assert!(!sub.contains(".."), "subdir {sub} must not traverse up");
    }
}

#[tokio::test]
async fn distinct_kinds_with_same_sha_do_not_collide_on_disk() {
    // The functional counterpart to the uniqueness guard: writing the same sha
    // under two different kinds must produce two independent bundles, each
    // readable as its own bytes.
    let dir = tempdir().unwrap();
    let store = BundleStore::new(dir.path().to_path_buf());
    let sha = "5ca1ab1e".repeat(8);

    store
        .write(BundleKind::AcceptanceCodex, &sha, b"codex")
        .await
        .unwrap();
    store
        .write(BundleKind::EvidencePack, &sha, b"evidence")
        .await
        .unwrap();

    assert_eq!(
        store.read(BundleKind::AcceptanceCodex, &sha).await.unwrap(),
        b"codex"
    );
    assert_eq!(
        store.read(BundleKind::EvidencePack, &sha).await.unwrap(),
        b"evidence"
    );
    // Removing one leaves the other intact.
    assert!(store
        .remove_if_exists(BundleKind::AcceptanceCodex, &sha)
        .await
        .unwrap());
    assert!(store.exists(BundleKind::EvidencePack, &sha).await);
}
