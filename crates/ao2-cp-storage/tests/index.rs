use ao2_cp_storage::index::{IndexEntry, IndexStore};
use chrono::Utc;
use tempfile::tempdir;

fn entry(sha: &str, schema: &str) -> IndexEntry {
    IndexEntry {
        ingested_at: Utc::now(),
        schema: schema.to_string(),
        provider: Some("codex".to_string()),
        sha256: sha.to_string(),
        status: Some("passed".to_string()),
        size_bytes: 100,
    }
}

fn sha(byte: u8) -> String {
    format!("{byte:064x}")
}

#[tokio::test]
async fn appends_and_reads_back() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    let entry_sha = sha(0xab);
    store
        .append(entry(&entry_sha, "ao2.codex-provider-pilot-acceptance.v1"))
        .await
        .unwrap();
    let all = store.read_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].sha256, entry_sha);
}

#[tokio::test]
async fn idempotent_append_skips_duplicate_sha() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    let entry_sha = sha(0xcd);
    let inserted_first = store
        .append_if_absent(entry(&entry_sha, "ao2.codex-provider-pilot-acceptance.v1"))
        .await
        .unwrap();
    let inserted_second = store
        .append_if_absent(entry(&entry_sha, "ao2.codex-provider-pilot-acceptance.v1"))
        .await
        .unwrap();
    assert!(inserted_first);
    assert!(!inserted_second);
    let all = store.read_all().await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn skips_malformed_lines_with_warning() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("index.jsonl");
    let entry_sha = sha(0xef);
    tokio::fs::write(
        &path,
        format!(
            "not json\n{{\"ingested_at\":\"2026-05-19T00:00:00Z\",\"schema\":\"x\",\"sha256\":\"{}\",\"size_bytes\":1}}\n",
            entry_sha
        ),
    )
    .await
    .unwrap();
    let store = IndexStore::new(path);
    let all = store.read_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].sha256, entry_sha);
}

#[tokio::test]
async fn skips_index_entries_with_invalid_sha256() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("index.jsonl");
    let valid_sha = sha(42);
    tokio::fs::write(
        &path,
        format!(
            "{{\"ingested_at\":\"2026-05-19T00:00:00Z\",\"schema\":\"x\",\"sha256\":\"short\",\"size_bytes\":1}}\n\
             {{\"ingested_at\":\"2026-05-19T00:00:01Z\",\"schema\":\"x\",\"sha256\":\"{}\",\"size_bytes\":1}}\n",
            valid_sha
        ),
    )
    .await
    .unwrap();
    let store = IndexStore::new(path);
    let all = store.read_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].sha256, valid_sha);
}

#[tokio::test]
async fn read_all_returns_empty_when_file_absent() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    let all = store.read_all().await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn filters_by_schema_prefix() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    store
        .append(entry(&sha(0xaa), "ao2.codex-provider-pilot-acceptance.v1"))
        .await
        .unwrap();
    store
        .append(entry(&sha(0xbb), "ao2.claude-provider-pilot-acceptance.v1"))
        .await
        .unwrap();
    store
        .append(entry(&sha(0xcc), "ao2.control-plane-fleet-bundle.v1"))
        .await
        .unwrap();
    let acceptance: Vec<_> = store
        .read_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.schema.contains("acceptance"))
        .collect();
    assert_eq!(acceptance.len(), 2);
}
