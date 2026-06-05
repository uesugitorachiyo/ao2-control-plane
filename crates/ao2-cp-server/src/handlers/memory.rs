use crate::signing::{annotate_trust_policy, sha256_hex, verify_rsa_sha256_signature};
use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::memory::parse_memory_export;
use ao2_cp_schema::responses::{
    BundleListEntry, BundleListResponse, IngestReceipt, SCHEMA_MEMORY_EXPORT_LIST,
};
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_limit() -> usize {
    50
}

const SIGNED_UPLOAD_SCHEMA: &str = "ao2.cp-memory-export-signed-upload.v1";
const SIGNATURE_SCHEMA: &str = "ao2.cp-memory-export-signature.v1";

#[derive(Debug, Deserialize)]
struct SignedMemoryExportUpload {
    schema_version: String,
    export: serde_json::Value,
    /// Base64 of the producer's exact signed bytes. When present the signature is
    /// verified over these bytes verbatim; when absent (legacy producers) the server
    /// falls back to re-serializing `export`, which can fail-close on lossy round-trips.
    #[serde(default)]
    export_b64: Option<String>,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SignatureSidecar {
    schema_version: String,
    export_sha256: String,
    signature: serde_json::Value,
}

pub async fn post_memory_export(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let export = parse_memory_export(raw).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("expected schema_version") {
            AppError::SchemaUnknown(msg)
        } else {
            AppError::SchemaInvalid(msg)
        }
    })?;
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let sha = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;

    let kind = BundleKind::MemoryExport;
    if !state.storage.bundles.exists(kind, &sha).await {
        state
            .storage
            .bundles
            .write(kind, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: export.schema_version.clone(),
        provider: None,
        sha256: sha.clone(),
        status: Some("accepted".to_string()),
        size_bytes: raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(sha, export.schema_version)))
}

pub async fn post_signed_memory_export(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedMemoryExportUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    // Recover the exact bytes the producer signed. With `export_b64` we verify over
    // those bytes verbatim, so a lossy serde_json round-trip (whitespace reflow, float
    // re-formatting) can no longer fail-close an untampered upload. Legacy producers
    // omit it; fall back to re-serializing `export` (byte-identical to prior behavior).
    let signed_bytes = match &upload.export_b64 {
        Some(encoded) => decode_export_b64(encoded)?,
        None => serde_json::to_string_pretty(&upload.export)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .into_bytes(),
    };
    let mut signature = upload.signature;
    // Verify before parsing or trusting any structure derived from the bytes.
    verify_signed_memory_export(&signed_bytes, &signature)?;
    let export_raw = std::str::from_utf8(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(format!("signed memory export is not utf-8: {e}")))?;
    let export = parse_memory_export(export_raw).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("expected schema_version") {
            AppError::SchemaUnknown(msg)
        } else {
            AppError::SchemaInvalid(msg)
        }
    })?;
    let export_value: serde_json::Value = serde_json::from_slice(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let sha = sha256_of_canonical(&export_value).map_err(|e| AppError::Internal(e.to_string()))?;
    annotate_trust_policy(&mut signature, &state.signed_artifact_trusted_key_sha256s);

    if !state
        .storage
        .bundles
        .exists(BundleKind::MemoryExport, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::MemoryExport, &sha, export_raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = SignatureSidecar {
        schema_version: SIGNATURE_SCHEMA.to_string(),
        export_sha256: sha.clone(),
        signature,
    };
    let sidecar_raw =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    // Write-once: the signature sidecar records who signed this content sha.
    // A conflicting re-sign (same content, different provenance) is rejected
    // rather than allowed to overwrite the first signer's record; an identical
    // re-upload is a no-op. Mirrors provider_readiness / provider_registry.
    if state
        .storage
        .bundles
        .exists(BundleKind::MemoryExportSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::MemoryExportSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "memory export signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(BundleKind::MemoryExportSignature, &sha, &sidecar_raw)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: export.schema_version.clone(),
        provider: None,
        sha256: sha.clone(),
        status: Some("signed".to_string()),
        size_bytes: export_raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(sha, export.schema_version)))
}

fn verify_signed_memory_export(
    signed_bytes: &[u8],
    signature: &serde_json::Value,
) -> Result<(), AppError> {
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported memory export signature algorithm: {algorithm}"
        )));
    }
    let signature_hex = required_signature_string(signature, "signature_hex")?;
    let public_key_pem = required_signature_string(signature, "public_key_pem")?;
    let signature_bytes = decode_hex(signature_hex)?;

    if let Some(expected) = signature
        .get("signature_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    {
        let actual = sha256_hex(&signature_bytes);
        if actual != expected {
            return Err(AppError::SchemaInvalid(format!(
                "signature_sha256 mismatch: expected {expected}, got {actual}"
            )));
        }
    }
    if let Some(expected) = signature
        .get("public_key_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    {
        let actual = sha256_hex(public_key_pem.as_bytes());
        if actual != expected {
            return Err(AppError::SchemaInvalid(format!(
                "public_key_sha256 mismatch: expected {expected}, got {actual}"
            )));
        }
    }

    verify_rsa_sha256_signature(signed_bytes, &signature_bytes, public_key_pem)
}

fn required_signature_string<'a>(
    signature: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AppError> {
    signature
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::SchemaInvalid(format!("signed memory export missing {field}")))
}

fn decode_export_b64(encoded: &str) -> Result<Vec<u8>, AppError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| AppError::SchemaInvalid(format!("export_b64 is not valid base64: {e}")))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AppError> {
    if !value.len().is_multiple_of(2) {
        return Err(AppError::SchemaInvalid(
            "signature_hex must have an even number of characters".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| AppError::SchemaInvalid("signature_hex is not utf-8".to_string()))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| AppError::SchemaInvalid("signature_hex is not valid hex".to_string()))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub async fn list_memory_exports(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BundleListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == "ao2.memory-export.v1");
    if let Some(since) = q.since {
        all.retain(|e| e.ingested_at >= since);
    }
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));
    let total_count = all.len();
    let limit = q.limit.min(500);
    let entries: Vec<BundleListEntry> = all
        .into_iter()
        .skip(q.offset)
        .take(limit)
        .map(|e| BundleListEntry {
            sha256: e.sha256,
            ingested_at: e.ingested_at,
            size_bytes: e.size_bytes,
            schema_version: e.schema,
            status: e.status,
        })
        .collect();

    Ok(Json(BundleListResponse {
        schema_version: SCHEMA_MEMORY_EXPORT_LIST.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn get_memory_export_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    if !state
        .storage
        .bundles
        .exists(BundleKind::MemoryExportSignature, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::MemoryExportSignature, &sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

pub async fn memory_export_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == "ao2.memory-export.v1");
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));
    let mut rows = String::new();
    for entry in all {
        let status = entry.status.unwrap_or_else(|| "accepted".to_string());
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&entry.sha256),
            escape_html(&entry.schema),
            escape_html(&status),
            entry.size_bytes,
            escape_html(&entry.ingested_at.to_rfc3339())
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No memory exports ingested.</td></tr>");
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Memory Exports</title></head><body><main><h1>AO2 Memory Exports</h1><table><thead><tr><th>SHA256</th><th>Schema</th><th>Status</th><th>Bytes</th><th>Ingested</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>"
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub async fn get_memory_export(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::MemoryExport, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let etag = caching::format_etag(&sha);
    if caching::etag_matches(&headers, &etag) {
        return Ok(caching::not_modified_response(&etag));
    }
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::MemoryExport, &sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let actual = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha,
            actual,
        });
    }
    Ok(caching::cacheable_json_response(&etag, bytes))
}

/// HEAD-equivalent for `/api/v1/memory/export/:sha`.
pub async fn head_memory_export(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::MemoryExport, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let etag = caching::format_etag(&sha);
    if caching::etag_matches(&headers, &etag) {
        return Ok(caching::not_modified_response(&etag));
    }
    Ok(caching::cacheable_head_response(&etag))
}
