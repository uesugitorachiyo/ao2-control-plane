use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SCHEMA_INGEST_RECEIPT: &str = "ao2.cp-ingest-receipt.v1";
pub const SCHEMA_ACCEPTANCE_LIST: &str = "ao2.cp-acceptance-list.v1";
pub const SCHEMA_BUNDLE_LIST: &str = "ao2.cp-bundle-list.v1";
pub const SCHEMA_MEMORY_EXPORT_LIST: &str = "ao2.cp-memory-export-list.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestReceipt {
    pub schema_version: String,
    pub sha256: String,
    pub stored_at: DateTime<Utc>,
    pub ingested_schema_version: String,
}

impl IngestReceipt {
    pub fn new(sha256: String, ingested_schema_version: String) -> Self {
        Self {
            schema_version: SCHEMA_INGEST_RECEIPT.to_string(),
            sha256,
            stored_at: Utc::now(),
            ingested_schema_version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceListEntry {
    pub sha256: String,
    pub provider: String,
    pub status: String,
    pub ingested_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceListResponse {
    pub schema_version: String,
    pub total_count: usize,
    pub limit: usize,
    pub offset: usize,
    pub entries: Vec<AcceptanceListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleListEntry {
    pub sha256: String,
    pub ingested_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleListResponse {
    pub schema_version: String,
    pub total_count: usize,
    pub limit: usize,
    pub offset: usize,
    pub entries: Vec<BundleListEntry>,
}
