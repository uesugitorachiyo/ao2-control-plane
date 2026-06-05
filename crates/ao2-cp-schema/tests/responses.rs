use ao2_cp_schema::responses::{
    AcceptanceListEntry, AcceptanceListResponse, BundleListResponse, IngestReceipt,
    SCHEMA_MEMORY_EXPORT_LIST,
};
use chrono::{TimeZone, Utc};

#[test]
fn ingest_receipt_serializes() {
    let r = IngestReceipt {
        schema_version: "ao2.cp-ingest-receipt.v1".to_string(),
        sha256: "abc123".to_string(),
        stored_at: Utc.with_ymd_and_hms(2026, 5, 19, 13, 0, 0).unwrap(),
        ingested_schema_version: "ao2.codex-provider-pilot-acceptance.v1".to_string(),
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(json["sha256"], "abc123");
}

#[test]
fn acceptance_list_response_serializes() {
    let resp = AcceptanceListResponse {
        schema_version: "ao2.cp-acceptance-list.v1".to_string(),
        total_count: 1,
        limit: 50,
        offset: 0,
        entries: vec![AcceptanceListEntry {
            sha256: "abc".to_string(),
            provider: "codex".to_string(),
            status: "passed".to_string(),
            ingested_at: Utc.with_ymd_and_hms(2026, 5, 19, 13, 0, 0).unwrap(),
            size_bytes: 1234,
            schema_version: "ao2.codex-provider-pilot-acceptance.v1".to_string(),
        }],
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["entries"][0]["provider"], "codex");
    assert_eq!(json["total_count"], 1);
}

#[test]
fn bundle_list_response_serializes() {
    let resp = BundleListResponse {
        schema_version: "ao2.cp-bundle-list.v1".to_string(),
        total_count: 0,
        limit: 50,
        offset: 0,
        entries: vec![],
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["schema_version"], "ao2.cp-bundle-list.v1");
    assert!(json["entries"].as_array().unwrap().is_empty());
}

#[test]
fn memory_export_list_response_uses_dedicated_schema() {
    let resp = BundleListResponse {
        schema_version: SCHEMA_MEMORY_EXPORT_LIST.to_string(),
        total_count: 0,
        limit: 50,
        offset: 0,
        entries: vec![],
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["schema_version"], "ao2.cp-memory-export-list.v1");
}
