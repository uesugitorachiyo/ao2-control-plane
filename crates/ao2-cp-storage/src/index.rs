use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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
    lock: Mutex<()>,
}

impl IndexStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub async fn append(&self, entry: IndexEntry) -> Result<(), IndexStoreError> {
        let _guard = self.lock.lock().await;
        self.append_inner(&entry).await
    }

    /// Returns true if newly appended, false if sha256 already present (no append).
    pub async fn append_if_absent(&self, entry: IndexEntry) -> Result<bool, IndexStoreError> {
        let _guard = self.lock.lock().await;
        let existing = self.read_all_inner().await?;
        if existing.iter().any(|e| e.sha256 == entry.sha256) {
            return Ok(false);
        }
        self.append_inner(&entry).await?;
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
        self.read_all_inner().await
    }

    pub async fn rewrite(&self, entries: &[IndexEntry]) -> Result<(), IndexStoreError> {
        let _guard = self.lock.lock().await;
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
        Ok(())
    }

    async fn read_all_inner(&self) -> Result<Vec<IndexEntry>, IndexStoreError> {
        let file = match File::open(&self.path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file).lines();
        let mut out = Vec::new();
        let mut line_no = 0usize;
        while let Some(line) = reader.next_line().await? {
            line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<IndexEntry>(&line) {
                Ok(e) if is_valid_sha256_hex(&e.sha256) => out.push(e),
                Ok(e) => {
                    tracing::warn!(
                        path = %self.path.display(),
                        line = line_no,
                        sha256 = %e.sha256,
                        "skipping index.jsonl line with invalid sha256",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %self.path.display(),
                        line = line_no,
                        error = %e,
                        "skipping malformed index.jsonl line",
                    );
                }
            }
        }
        Ok(out)
    }
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
