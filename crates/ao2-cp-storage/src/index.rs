use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub ingested_at: DateTime<Utc>,
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct IndexPageRequest {
    pub offset: usize,
    pub limit: usize,
    pub schema_prefix: Option<String>,
    pub provider: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexPage {
    pub schema_version: String,
    pub offset: usize,
    pub limit: usize,
    pub total_entries: usize,
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMetrics {
    pub schema_version: String,
    pub resident_entries: usize,
    pub resident_unique_sha256: usize,
    #[serde(default)]
    pub resident_digest_index_entries: usize,
    pub jsonl_bytes: u64,
    pub malformed_lines_skipped: usize,
    pub invalid_sha256_lines_skipped: usize,
}

#[derive(Debug, Error)]
pub enum IndexStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid sha256 in index entry: {0}")]
    InvalidSha256(String),
}

pub struct IndexStore {
    path: PathBuf,
    state: Mutex<IndexState>,
}

#[derive(Debug, Default)]
struct IndexState {
    loaded: bool,
    entries: Vec<IndexEntry>,
    digest_index: HashSet<String>,
    jsonl_bytes: u64,
    jsonl_modified_unix_nanos: Option<u128>,
    malformed_lines_skipped: usize,
    invalid_sha256_lines_skipped: usize,
}

impl IndexStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(IndexState::default()),
        }
    }

    pub async fn append(&self, entry: IndexEntry) -> Result<(), IndexStoreError> {
        let mut state = self.state.lock().await;
        self.ensure_loaded(&mut state).await?;
        self.append_inner(&entry).await?;
        state.digest_index.insert(entry.sha256.clone());
        state.entries.push(entry);
        let fingerprint = file_fingerprint(&self.path).await?;
        state.jsonl_bytes = fingerprint.len;
        state.jsonl_modified_unix_nanos = fingerprint.modified_unix_nanos;
        Ok(())
    }

    /// Returns true if newly appended, false if sha256 already present (no append).
    pub async fn append_if_absent(&self, entry: IndexEntry) -> Result<bool, IndexStoreError> {
        let mut state = self.state.lock().await;
        self.ensure_loaded(&mut state).await?;
        if state.digest_index.contains(&entry.sha256) {
            return Ok(false);
        }
        self.append_inner(&entry).await?;
        state.digest_index.insert(entry.sha256.clone());
        state.entries.push(entry);
        let fingerprint = file_fingerprint(&self.path).await?;
        state.jsonl_bytes = fingerprint.len;
        state.jsonl_modified_unix_nanos = fingerprint.modified_unix_nanos;
        Ok(true)
    }

    async fn append_inner(&self, entry: &IndexEntry) -> Result<(), IndexStoreError> {
        validate_entry_sha256(entry)?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        let line = serde_json::to_string(entry)?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.sync_data().await?;
        Ok(())
    }

    pub async fn read_all(&self) -> Result<Vec<IndexEntry>, IndexStoreError> {
        let mut state = self.state.lock().await;
        self.ensure_loaded(&mut state).await?;
        Ok(state.entries.clone())
    }

    pub async fn read_page(&self, request: IndexPageRequest) -> Result<IndexPage, IndexStoreError> {
        let mut state = self.state.lock().await;
        self.ensure_loaded(&mut state).await?;
        let mut filtered: Vec<IndexEntry> = state
            .entries
            .iter()
            .filter(|entry| {
                request
                    .schema_prefix
                    .as_deref()
                    .is_none_or(|prefix| entry.schema.starts_with(prefix))
                    && request
                        .provider
                        .as_deref()
                        .is_none_or(|provider| entry.provider.as_deref() == Some(provider))
                    && request
                        .status
                        .as_deref()
                        .is_none_or(|status| entry.status.as_deref() == Some(status))
            })
            .cloned()
            .collect();
        filtered.sort_by(|left, right| {
            right
                .ingested_at
                .cmp(&left.ingested_at)
                .then_with(|| left.sha256.cmp(&right.sha256))
        });
        let total_entries = filtered.len();
        let entries = filtered
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect();
        Ok(IndexPage {
            schema_version: "ao2.cp-storage-index-page.v1".to_string(),
            offset: request.offset,
            limit: request.limit,
            total_entries,
            entries,
        })
    }

    pub async fn metrics(&self) -> Result<IndexMetrics, IndexStoreError> {
        let mut state = self.state.lock().await;
        self.ensure_loaded(&mut state).await?;
        let resident_unique_sha256 = state.digest_index.len();
        Ok(IndexMetrics {
            schema_version: "ao2.cp-storage-index-metrics.v1".to_string(),
            resident_entries: state.entries.len(),
            resident_unique_sha256,
            resident_digest_index_entries: state.digest_index.len(),
            jsonl_bytes: state.jsonl_bytes,
            malformed_lines_skipped: state.malformed_lines_skipped,
            invalid_sha256_lines_skipped: state.invalid_sha256_lines_skipped,
        })
    }

    pub async fn rewrite(&self, entries: &[IndexEntry]) -> Result<(), IndexStoreError> {
        let mut state = self.state.lock().await;
        for entry in entries {
            validate_entry_sha256(entry)?;
        }
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut file = File::create(&tmp).await?;
            for entry in entries {
                let line = serde_json::to_string(entry)?;
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
            file.sync_data().await?;
        }
        tokio::fs::rename(tmp, &self.path).await?;
        state.loaded = true;
        state.entries = entries.to_vec();
        state.digest_index = entries.iter().map(|entry| entry.sha256.clone()).collect();
        let fingerprint = file_fingerprint(&self.path).await?;
        state.jsonl_bytes = fingerprint.len;
        state.jsonl_modified_unix_nanos = fingerprint.modified_unix_nanos;
        state.malformed_lines_skipped = 0;
        state.invalid_sha256_lines_skipped = 0;
        Ok(())
    }

    async fn ensure_loaded(&self, state: &mut IndexState) -> Result<(), IndexStoreError> {
        let fingerprint = file_fingerprint(&self.path).await?;
        if state.loaded
            && state.jsonl_bytes == fingerprint.len
            && state.jsonl_modified_unix_nanos == fingerprint.modified_unix_nanos
        {
            return Ok(());
        }
        let load = self.load_from_disk().await?;
        state.loaded = true;
        state.entries = load.entries;
        state.digest_index = state
            .entries
            .iter()
            .map(|entry| entry.sha256.clone())
            .collect();
        state.jsonl_bytes = load.jsonl_bytes;
        state.jsonl_modified_unix_nanos = load.jsonl_modified_unix_nanos;
        state.malformed_lines_skipped = load.malformed_lines_skipped;
        state.invalid_sha256_lines_skipped = load.invalid_sha256_lines_skipped;
        Ok(())
    }

    async fn load_from_disk(&self) -> Result<IndexLoad, IndexStoreError> {
        let fingerprint = file_fingerprint(&self.path).await?;
        let file = match File::open(&self.path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(IndexLoad {
                    entries: vec![],
                    jsonl_bytes: 0,
                    jsonl_modified_unix_nanos: None,
                    malformed_lines_skipped: 0,
                    invalid_sha256_lines_skipped: 0,
                });
            }
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file).lines();
        let mut out = Vec::new();
        let mut line_no = 0usize;
        let mut malformed_lines_skipped = 0usize;
        let mut invalid_sha256_lines_skipped = 0usize;
        while let Some(line) = reader.next_line().await? {
            line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<IndexEntry>(&line) {
                Ok(e) if is_valid_sha256_hex(&e.sha256) => out.push(e),
                Ok(e) => {
                    invalid_sha256_lines_skipped += 1;
                    tracing::warn!(
                        path = %self.path.display(),
                        line = line_no,
                        sha256 = %e.sha256,
                        "skipping index.jsonl line with invalid sha256",
                    );
                }
                Err(e) => {
                    malformed_lines_skipped += 1;
                    tracing::warn!(
                        path = %self.path.display(),
                        line = line_no,
                        error = %e,
                        "skipping malformed index.jsonl line",
                    );
                }
            }
        }
        Ok(IndexLoad {
            entries: out,
            jsonl_bytes: fingerprint.len,
            jsonl_modified_unix_nanos: fingerprint.modified_unix_nanos,
            malformed_lines_skipped,
            invalid_sha256_lines_skipped,
        })
    }
}

#[derive(Debug)]
struct IndexLoad {
    entries: Vec<IndexEntry>,
    jsonl_bytes: u64,
    jsonl_modified_unix_nanos: Option<u128>,
    malformed_lines_skipped: usize,
    invalid_sha256_lines_skipped: usize,
}

fn validate_entry_sha256(entry: &IndexEntry) -> Result<(), IndexStoreError> {
    if is_valid_sha256_hex(&entry.sha256) {
        Ok(())
    } else {
        Err(IndexStoreError::InvalidSha256(entry.sha256.clone()))
    }
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
struct FileFingerprint {
    len: u64,
    modified_unix_nanos: Option<u128>,
}

async fn file_fingerprint(path: &PathBuf) -> Result<FileFingerprint, IndexStoreError> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(FileFingerprint {
            len: metadata.len(),
            modified_unix_nanos: metadata.modified().ok().and_then(system_time_unix_nanos),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileFingerprint {
            len: 0,
            modified_unix_nanos: None,
        }),
        Err(e) => Err(e.into()),
    }
}

fn system_time_unix_nanos(time: SystemTime) -> Option<u128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}
