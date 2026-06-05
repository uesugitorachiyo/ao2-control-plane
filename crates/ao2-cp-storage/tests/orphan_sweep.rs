use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, Storage};
use chrono::Utc;
use tempfile::tempdir;

#[tokio::test]
async fn sweeps_files_not_in_index() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // Open storage and write 2 bundles legitimately
    let storage = Storage::open(root.clone()).await.unwrap();
    let legit_sha = "a".repeat(64);
    let bytes = b"{\"hello\":\"world\"}";
    storage
        .bundles
        .write(BundleKind::AcceptanceCodex, &legit_sha, bytes)
        .await
        .unwrap();
    storage
        .index
        .append(IndexEntry {
            ingested_at: Utc::now(),
            schema: "ao2.codex-provider-pilot-acceptance.v1".to_string(),
            provider: Some("codex".to_string()),
            sha256: legit_sha.clone(),
            status: Some("passed".to_string()),
            size_bytes: bytes.len() as u64,
        })
        .await
        .unwrap();

    // Drop and write an orphan file directly (simulating crash before index append)
    let orphan_sha = "f".repeat(64);
    storage
        .bundles
        .write(BundleKind::AcceptanceCodex, &orphan_sha, b"{}")
        .await
        .unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::AcceptanceCodex, &orphan_sha)
            .await
    );
    drop(storage);

    // Re-open — sweep should run and remove the orphan
    let storage = Storage::open(root.clone()).await.unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::AcceptanceCodex, &legit_sha)
            .await
    );
    assert!(
        !storage
            .bundles
            .exists(BundleKind::AcceptanceCodex, &orphan_sha)
            .await
    );
}

#[tokio::test]
async fn sweeps_orphan_memory_exports() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let storage = Storage::open(root.clone()).await.unwrap();
    let legit_sha = "b".repeat(64);
    let orphan_sha = "c".repeat(64);
    storage
        .bundles
        .write(BundleKind::MemoryExport, &legit_sha, b"{}")
        .await
        .unwrap();
    storage
        .index
        .append(IndexEntry {
            ingested_at: Utc::now(),
            schema: "ao2.memory-export.v1".to_string(),
            provider: None,
            sha256: legit_sha.clone(),
            status: Some("accepted".to_string()),
            size_bytes: 2,
        })
        .await
        .unwrap();
    storage
        .bundles
        .write(BundleKind::MemoryExport, &orphan_sha, b"{}")
        .await
        .unwrap();
    drop(storage);

    let storage = Storage::open(root.clone()).await.unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::MemoryExport, &legit_sha)
            .await
    );
    assert!(
        !storage
            .bundles
            .exists(BundleKind::MemoryExport, &orphan_sha)
            .await
    );
}

#[tokio::test]
async fn sweeps_orphan_release_evaluator_decisions() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let storage = Storage::open(root.clone()).await.unwrap();
    let orphan_sha = "e".repeat(64);
    storage
        .bundles
        .write(BundleKind::ReleaseEvaluatorDecision, &orphan_sha, b"{}")
        .await
        .unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecision, &orphan_sha)
            .await
    );
    drop(storage);

    let storage = Storage::open(root.clone()).await.unwrap();
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecision, &orphan_sha)
            .await
    );
}

#[tokio::test]
async fn sweeps_orphan_release_evaluator_decision_signatures() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let storage = Storage::open(root.clone()).await.unwrap();
    let orphan_sha = "9".repeat(64);
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &orphan_sha,
            b"{}",
        )
        .await
        .unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecisionSignature, &orphan_sha)
            .await
    );
    drop(storage);

    let storage = Storage::open(root.clone()).await.unwrap();
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecisionSignature, &orphan_sha)
            .await
    );
}

#[tokio::test]
async fn sweeps_orphan_provider_readiness_signatures() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let storage = Storage::open(root.clone()).await.unwrap();
    let orphan_sha = "8".repeat(64);
    storage
        .bundles
        .write(BundleKind::ProviderReadinessSignature, &orphan_sha, b"{}")
        .await
        .unwrap();
    assert!(
        storage
            .bundles
            .exists(BundleKind::ProviderReadinessSignature, &orphan_sha)
            .await
    );
    drop(storage);

    let storage = Storage::open(root.clone()).await.unwrap();
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ProviderReadinessSignature, &orphan_sha)
            .await
    );
}
