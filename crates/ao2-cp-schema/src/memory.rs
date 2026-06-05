use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA: &str = "ao2.memory-export.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExport {
    pub schema_version: String,
    #[serde(default)]
    pub record_count: u64,
    #[serde(default)]
    pub link_count: u64,
    #[serde(default)]
    pub records: Vec<serde_json::Value>,
    #[serde(default)]
    pub links: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum MemoryExportParseError {
    #[error("json parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("expected schema_version {expected}, got {actual}")]
    WrongSchema { expected: String, actual: String },
    #[error("record_count {declared} does not match records length {actual}")]
    RecordCountMismatch { declared: u64, actual: usize },
    #[error("link_count {declared} does not match links length {actual}")]
    LinkCountMismatch { declared: u64, actual: usize },
}

pub fn parse_memory_export(raw: &str) -> Result<MemoryExport, MemoryExportParseError> {
    let export: MemoryExport = serde_json::from_str(raw)?;
    if export.schema_version != SCHEMA {
        return Err(MemoryExportParseError::WrongSchema {
            expected: SCHEMA.to_string(),
            actual: export.schema_version.clone(),
        });
    }
    if export.record_count != export.records.len() as u64 {
        return Err(MemoryExportParseError::RecordCountMismatch {
            declared: export.record_count,
            actual: export.records.len(),
        });
    }
    if export.link_count != export.links.len() as u64 {
        return Err(MemoryExportParseError::LinkCountMismatch {
            declared: export.link_count,
            actual: export.links.len(),
        });
    }
    Ok(export)
}

pub fn is_memory_export_schema(schema_version: &str) -> bool {
    schema_version == SCHEMA
}
