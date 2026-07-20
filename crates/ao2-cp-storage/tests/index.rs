use ao2_cp_storage::index::{IndexEntry, IndexPageRequest, IndexStore};
use chrono::{TimeZone, Utc};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
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

fn generated_entry(index: usize, schema: &str, provider: &str, status: &str) -> IndexEntry {
    IndexEntry {
        ingested_at: Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
            + chrono::Duration::seconds(index as i64),
        schema: schema.to_string(),
        provider: Some(provider.to_string()),
        sha256: format!("{index:064x}"),
        status: Some(status.to_string()),
        size_bytes: 100 + index as u64,
    }
}

fn generated_fixture_entries(count: usize) -> Vec<IndexEntry> {
    (0..count)
        .map(|index| {
            let schema = if index % 2 == 0 {
                "ao2.memory-export.v1"
            } else {
                "ao2.release-publication.v1"
            };
            let provider = if index % 3 == 0 { "codex" } else { "ao2" };
            let status = if index % 5 == 0 {
                "attention"
            } else {
                "passed"
            };
            generated_entry(index, schema, provider, status)
        })
        .collect()
}

#[test]
fn index_metrics_accepts_pre_digest_index_v1_payload() {
    let metrics: ao2_cp_storage::index::IndexMetrics = serde_json::from_value(json!({
        "schema_version": "ao2.cp-storage-index-metrics.v1",
        "resident_entries": 3,
        "resident_unique_sha256": 3,
        "jsonl_bytes": 120,
        "malformed_lines_skipped": 0,
        "invalid_sha256_lines_skipped": 0
    }))
    .unwrap();

    assert_eq!(metrics.resident_digest_index_entries, 0);
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

#[tokio::test]
async fn generated_fixture_pages_latest_entries_without_rescanning_jsonl() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    for entry in generated_fixture_entries(12) {
        store.append(entry).await.unwrap();
    }

    let page = store
        .read_page(IndexPageRequest {
            offset: 3,
            limit: 4,
            schema_prefix: None,
            provider: None,
            status: None,
        })
        .await
        .unwrap();

    assert_eq!(page.schema_version, "ao2.cp-storage-index-page.v1");
    assert_eq!(page.offset, 3);
    assert_eq!(page.limit, 4);
    assert_eq!(page.total_entries, 12);
    assert_eq!(page.entries.len(), 4);
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.sha256.as_str())
            .collect::<Vec<_>>(),
        vec![
            format!("{:064x}", 8),
            format!("{:064x}", 7),
            format!("{:064x}", 6),
            format!("{:064x}", 5),
        ]
    );

    let metrics = store.metrics().await.unwrap();
    assert_eq!(metrics.schema_version, "ao2.cp-storage-index-metrics.v1");
    assert_eq!(metrics.resident_entries, 12);
    assert_eq!(metrics.resident_unique_sha256, 12);
    assert_eq!(metrics.malformed_lines_skipped, 0);
    assert_eq!(metrics.invalid_sha256_lines_skipped, 0);
    assert!(metrics.jsonl_bytes > 0);
}

#[tokio::test]
async fn page_filters_by_schema_provider_and_status() {
    let dir = tempdir().unwrap();
    let store = IndexStore::new(dir.path().join("index.jsonl"));
    for entry in generated_fixture_entries(18) {
        store.append(entry).await.unwrap();
    }

    let page = store
        .read_page(IndexPageRequest {
            offset: 0,
            limit: 10,
            schema_prefix: Some("ao2.memory".to_string()),
            provider: Some("codex".to_string()),
            status: Some("passed".to_string()),
        })
        .await
        .unwrap();

    assert_eq!(page.total_entries, 2);
    assert_eq!(page.entries.len(), 2);
    assert!(page
        .entries
        .iter()
        .all(|entry| entry.schema.starts_with("ao2.memory")
            && entry.provider.as_deref() == Some("codex")
            && entry.status.as_deref() == Some("passed")));
}

#[tokio::test]
async fn metrics_reports_skipped_jsonl_lines_from_initial_load() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("index.jsonl");
    let valid = generated_entry(7, "ao2.memory-export.v1", "codex", "passed");
    tokio::fs::write(
        &path,
        format!(
            "not json\n\
             {{\"ingested_at\":\"2026-07-19T12:00:00Z\",\"schema\":\"ao2.memory-export.v1\",\"sha256\":\"short\",\"size_bytes\":1}}\n\
             {}\n",
            serde_json::to_string(&valid).unwrap(),
        ),
    )
    .await
    .unwrap();

    let store = IndexStore::new(path);
    let page = store
        .read_page(IndexPageRequest {
            offset: 0,
            limit: 10,
            schema_prefix: None,
            provider: None,
            status: None,
        })
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);

    let metrics = store.metrics().await.unwrap();
    assert_eq!(metrics.resident_entries, 1);
    assert_eq!(metrics.malformed_lines_skipped, 1);
    assert_eq!(metrics.invalid_sha256_lines_skipped, 1);
}

#[tokio::test]
async fn concurrent_append_if_absent_updates_single_resident_index() {
    let dir = tempdir().unwrap();
    let store = Arc::new(IndexStore::new(dir.path().join("index.jsonl")));
    let mut tasks = tokio::task::JoinSet::new();

    for index in 0..96 {
        let store = Arc::clone(&store);
        tasks.spawn(async move {
            let unique_index = index % 24;
            store
                .append_if_absent(generated_entry(
                    unique_index,
                    "ao2.memory-export.v1",
                    "codex",
                    "passed",
                ))
                .await
                .unwrap()
        });
    }

    let mut inserted = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() {
            inserted += 1;
        }
    }

    assert_eq!(inserted, 24);
    let metrics = store.metrics().await.unwrap();
    assert_eq!(metrics.resident_entries, 24);
    assert_eq!(metrics.resident_unique_sha256, 24);
    assert_eq!(metrics.resident_digest_index_entries, 24);
    assert_eq!(store.read_all().await.unwrap().len(), 24);
}

#[tokio::test]
#[ignore = "records deterministic 10,000 and 100,000 entry scale measurements"]
async fn records_resident_index_scale_measurements() {
    let mut cases = Vec::new();
    for count in [10_000, 100_000] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.jsonl");
        let store = IndexStore::new(path.clone());
        let entries = generated_fixture_entries(count);

        let rewrite_started = Instant::now();
        store.rewrite(&entries).await.unwrap();
        let rewrite_ms = rewrite_started.elapsed().as_secs_f64() * 1000.0;
        drop(store);

        let store = IndexStore::new(path);
        let load_and_page_started = Instant::now();
        let page = store
            .read_page(IndexPageRequest {
                offset: count / 2,
                limit: 25,
                schema_prefix: None,
                provider: None,
                status: None,
            })
            .await
            .unwrap();
        let load_and_page_ms = load_and_page_started.elapsed().as_secs_f64() * 1000.0;

        let duplicate_started = Instant::now();
        let inserted = store
            .append_if_absent(generated_entry(
                count - 1,
                "ao2.memory-export.v1",
                "codex",
                "passed",
            ))
            .await
            .unwrap();
        let duplicate_lookup_us = duplicate_started.elapsed().as_secs_f64() * 1_000_000.0;

        let metrics = store.metrics().await.unwrap();
        assert!(!inserted);
        assert_eq!(page.total_entries, count);
        assert_eq!(page.entries.len(), 25);
        assert_eq!(metrics.resident_entries, count);
        assert_eq!(metrics.resident_unique_sha256, count);
        assert_eq!(metrics.resident_digest_index_entries, count);
        cases.push(json!({
            "entries": count,
            "rewrite_ms": rewrite_ms,
            "cold_load_and_page_ms": load_and_page_ms,
            "resident_duplicate_lookup_us": duplicate_lookup_us,
            "page_entries": page.entries.len(),
            "resident_digest_index_entries": metrics.resident_digest_index_entries,
        }));
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema_version": "ao2.cp-storage-index-scale.v1",
            "cases": cases,
            "status": "passed"
        }))
        .unwrap()
    );
}
