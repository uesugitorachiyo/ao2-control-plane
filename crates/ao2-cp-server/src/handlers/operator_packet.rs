use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::{BundleListEntry, BundleListResponse, IngestReceipt};
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
use std::{collections::BTreeMap, sync::Arc};

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;
use crate::signing::{annotate_trust_policy, sha256_hex, verify_rsa_sha256_signature};

const OPERATOR_PACKET_SCHEMA: &str = "ao2.operator-evidence-packet.v1";
const SIGNED_UPLOAD_SCHEMA: &str = "ao2.cp-operator-packet-signed-upload.v1";
const SIGNATURE_SCHEMA: &str = "ao2.cp-operator-packet-signature.v1";
const OPERATOR_PACKET_LIST_SCHEMA: &str = "ao2.cp-operator-packet-list.v1";
const OPERATOR_PACKET_DETAIL_SCHEMA: &str = "ao2.cp-operator-packet-detail.v1";
const OPERATOR_PACKET_DASHBOARD_SCHEMA: &str = "ao2.cp-operator-packet-dashboard.v1";

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Deserialize)]
struct SignedOperatorPacketUpload {
    schema_version: String,
    operator_packet: serde_json::Value,
    #[serde(default)]
    operator_packet_b64: Option<String>,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SignatureSidecar {
    schema_version: String,
    operator_packet_sha256: String,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct OperatorPacketDashboardResponse {
    schema_version: String,
    summary: OperatorPacketDashboardSummary,
    entry_count: usize,
    entries: Vec<OperatorPacketDashboardEntry>,
}

#[derive(Debug, Serialize)]
pub struct OperatorPacketDashboardSummary {
    total_entries: usize,
    status_counts: BTreeMap<String, usize>,
    signature_unverified_count: usize,
    read_only_observer: bool,
}

#[derive(Debug, Serialize)]
pub struct OperatorPacketDashboardEntry {
    sha256: String,
    run_id: String,
    status: String,
    operator_id: String,
    signer_id: String,
    signature_verified: bool,
    size_bytes: u64,
    ingested_at: chrono::DateTime<Utc>,
    detail_url: String,
    signature_url: String,
}

pub async fn post_signed_operator_packet(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedOperatorPacketUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    let signed_bytes = match &upload.operator_packet_b64 {
        Some(encoded) => decode_operator_packet_b64(encoded)?,
        None => serde_json::to_string_pretty(&upload.operator_packet)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .into_bytes(),
    };
    let mut signature = upload.signature;
    verify_signed_operator_packet(&signed_bytes, &signature)?;
    let raw = std::str::from_utf8(&signed_bytes).map_err(|e| {
        AppError::SchemaInvalid(format!("signed operator packet is not utf-8: {e}"))
    })?;
    let packet: serde_json::Value = serde_json::from_slice(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = packet
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != OPERATOR_PACKET_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {OPERATOR_PACKET_SCHEMA}, got {schema}"
        )));
    }
    let sha = sha256_of_canonical(&packet).map_err(|e| AppError::Internal(e.to_string()))?;
    annotate_trust_policy(&mut signature, &state.signed_artifact_trusted_key_sha256s);

    if !state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacket, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::OperatorPacket, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = SignatureSidecar {
        schema_version: SIGNATURE_SCHEMA.to_string(),
        operator_packet_sha256: sha.clone(),
        signature,
    };
    let sidecar_raw =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    if state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacketSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::OperatorPacketSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "operator packet signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(BundleKind::OperatorPacketSignature, &sha, &sidecar_raw)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let status = packet
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    state
        .storage
        .index
        .append_if_absent(IndexEntry {
            ingested_at: Utc::now(),
            schema: OPERATOR_PACKET_SCHEMA.to_string(),
            provider: None,
            sha256: sha.clone(),
            status,
            size_bytes: raw.len() as u64,
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        OPERATOR_PACKET_SCHEMA.to_string(),
    )))
}

pub async fn list_operator_packets(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BundleListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == OPERATOR_PACKET_SCHEMA);
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));
    let total_count = all.len();
    let limit = q.limit.min(500);
    let entries = all
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
        schema_version: OPERATOR_PACKET_LIST_SCHEMA.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn operator_packet_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<OperatorPacketDashboardResponse>, AppError> {
    Ok(Json(operator_packet_dashboard_response(&state).await?))
}

pub async fn operator_packet_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let dashboard = operator_packet_dashboard_response(&state).await?;
    let mut rows = String::new();
    for entry in &dashboard.entries {
        rows.push_str(&format!(
            "<tr><td><a href=\"/api/v1/operator-packet/{sha}/detail\"><code>{short_sha}</code></a></td><td>{run_id}</td><td>{status}</td><td>{operator_id}</td><td>{signer_id}</td><td>{verified}</td><td>{ingested}</td></tr>",
            sha = escape_html(&entry.sha256),
            short_sha = escape_html(&entry.sha256[..12]),
            run_id = escape_html(&entry.run_id),
            status = escape_html(&entry.status),
            operator_id = escape_html(&entry.operator_id),
            signer_id = escape_html(&entry.signer_id),
            verified = entry.signature_verified,
            ingested = escape_html(&entry.ingested_at.to_rfc3339()),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"7\">No signed AO2 operator packets observed.</td></tr>");
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Operator Packets</title><style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace}}</style></head><body><main><h1>AO2 Operator Packets</h1><p>Read-only observer dashboard for signed operator evidence packets. This control plane never approves runs or mutates AO2 evidence.</p><p><a href=\"/api/v1/operator-packet/dashboard.json\">Dashboard JSON</a></p><table><thead><tr><th>SHA256</th><th>Run</th><th>Status</th><th>Operator</th><th>Signer</th><th>Signature Verified</th><th>Ingested</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>"
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn operator_packet_detail(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    let (packet, signature) = read_verified_operator_packet_and_signature(&state, &sha).await?;
    let value = operator_packet_detail_value(&sha, packet, signature);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Operator Packet Detail</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:72rem}}code,pre{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;background:#f6f8fa;border:1px solid #ddd;padding:.75rem}}</style></head><body><main><p><a href=\"/api/v1/operator-packet/dashboard\">Dashboard</a></p><h1>AO2 Operator Packet Detail</h1><p>Read-only observer detail. Verification here never approves, mutates, or closes AO2 runs.</p><pre>{body}</pre></main></body></html>",
        body = escape_html(&serde_json::to_string_pretty(&value).map_err(|e| AppError::Internal(e.to_string()))?)
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn operator_packet_detail_json(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (packet, signature) = read_verified_operator_packet_and_signature(&state, &sha).await?;
    Ok(Json(operator_packet_detail_value(&sha, packet, signature)))
}

pub async fn latest_operator_packet_detail_for_run(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == OPERATOR_PACKET_SCHEMA);
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));

    for entry in all {
        let (packet, signature) =
            read_verified_operator_packet_and_signature(&state, &entry.sha256).await?;
        if json_str(&packet, "run_id") == Some(run_id.as_str()) {
            return Ok(Json(operator_packet_detail_value(
                &entry.sha256,
                packet,
                signature,
            )));
        }
    }
    Err(AppError::NotFound)
}

pub async fn get_operator_packet_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    validate_sha256(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacketSignature, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let sidecar = read_signature_sidecar(&state, &sha).await?;
    let bytes =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

pub async fn get_operator_packet(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacket, &sha)
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
        .read(BundleKind::OperatorPacket, &sha)
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

pub async fn head_operator_packet(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacket, &sha)
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

async fn operator_packet_dashboard_response(
    state: &AppState,
) -> Result<OperatorPacketDashboardResponse, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == OPERATOR_PACKET_SCHEMA);
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));

    let mut entries = Vec::new();
    for entry in all {
        let packet = read_json_bundle(state, BundleKind::OperatorPacket, &entry.sha256).await?;
        let actual = sha256_of_canonical(&packet).map_err(|e| AppError::Internal(e.to_string()))?;
        if actual != entry.sha256 {
            return Err(AppError::BundleTampered {
                expected: entry.sha256,
                actual,
            });
        }
        let signature = read_signature_sidecar(state, &entry.sha256).await.ok();
        let signer_id = signature
            .as_ref()
            .and_then(|sidecar| sidecar.get("signature"))
            .and_then(|sig| json_str(sig, "signer_id"))
            .unwrap_or("unknown")
            .to_string();
        let signature_verified = signature
            .as_ref()
            .and_then(|sidecar| sidecar.get("signature"))
            .and_then(|sig| sig.get("signature_verified"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        entries.push(OperatorPacketDashboardEntry {
            detail_url: format!("/api/v1/operator-packet/{}/detail", entry.sha256),
            signature_url: format!("/api/v1/operator-packet/{}/signature", entry.sha256),
            sha256: entry.sha256,
            run_id: json_str(&packet, "run_id").unwrap_or("unknown").to_string(),
            status: entry
                .status
                .as_deref()
                .unwrap_or_else(|| json_str(&packet, "status").unwrap_or("unknown"))
                .to_string(),
            operator_id: json_str(&packet, "operator_id")
                .unwrap_or("unknown")
                .to_string(),
            signer_id,
            signature_verified,
            size_bytes: entry.size_bytes,
            ingested_at: entry.ingested_at,
        });
    }

    let mut status_counts = BTreeMap::new();
    let mut signature_unverified_count = 0;
    for entry in &entries {
        *status_counts.entry(entry.status.clone()).or_insert(0) += 1;
        if !entry.signature_verified {
            signature_unverified_count += 1;
        }
    }

    Ok(OperatorPacketDashboardResponse {
        schema_version: OPERATOR_PACKET_DASHBOARD_SCHEMA.to_string(),
        summary: OperatorPacketDashboardSummary {
            total_entries: entries.len(),
            status_counts,
            signature_unverified_count,
            read_only_observer: true,
        },
        entry_count: entries.len(),
        entries,
    })
}

fn operator_packet_detail_value(
    sha: &str,
    packet: serde_json::Value,
    signature: serde_json::Value,
) -> serde_json::Value {
    let sig = signature
        .get("signature")
        .unwrap_or(&serde_json::Value::Null);
    let verified = sig
        .get("signature_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    serde_json::json!({
        "schema_version": OPERATOR_PACKET_DETAIL_SCHEMA,
        "sha256": sha,
        "run_id": json_str(&packet, "run_id").unwrap_or("unknown"),
        "status": json_str(&packet, "status").unwrap_or("unknown"),
        "operator_id": json_str(&packet, "operator_id").unwrap_or("unknown"),
        "signature": {
            "signer_id": json_str(sig, "signer_id").unwrap_or("unknown"),
            "verified": verified,
            "public_key_sha256": json_str(sig, "public_key_sha256").unwrap_or("not provided"),
            "signature_sha256": json_str(sig, "signature_sha256").unwrap_or("not provided"),
        },
        "links": {
            "raw_packet": format!("/api/v1/operator-packet/{sha}"),
            "signature": format!("/api/v1/operator-packet/{sha}/signature"),
            "html_detail": format!("/api/v1/operator-packet/{sha}/detail"),
        },
        "trust_boundary": {
            "role": "read_only_observer_for_signed_operator_packets",
            "can_approve_runs": false,
            "can_mutate_ao2_evidence": false,
        },
        "operator_packet": packet,
    })
}

async fn read_verified_operator_packet_and_signature(
    state: &AppState,
    sha: &str,
) -> Result<(serde_json::Value, serde_json::Value), AppError> {
    validate_sha256(sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::OperatorPacket, sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let packet = read_json_bundle(state, BundleKind::OperatorPacket, sha).await?;
    let actual = sha256_of_canonical(&packet).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    let signature = read_signature_sidecar(state, sha).await?;
    Ok((packet, signature))
}

async fn read_signature_sidecar(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let sidecar = read_json_bundle(state, BundleKind::OperatorPacketSignature, sha).await?;
    let sidecar_sha = sidecar
        .get("operator_packet_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if sidecar_sha != sha {
        return Err(AppError::SchemaInvalid(format!(
            "operator packet signature sidecar sha mismatch: expected {sha}, got {sidecar_sha}"
        )));
    }
    let schema = sidecar
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    Ok(sidecar)
}

async fn read_json_bundle(
    state: &AppState,
    kind: BundleKind,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(kind, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

fn verify_signed_operator_packet(
    signed_bytes: &[u8],
    signature: &serde_json::Value,
) -> Result<(), AppError> {
    let schema = signature
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported operator packet signature algorithm: {algorithm}"
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
        .ok_or_else(|| AppError::SchemaInvalid(format!("signed operator packet missing {field}")))
}

fn decode_operator_packet_b64(encoded: &str) -> Result<Vec<u8>, AppError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    BASE64_STANDARD.decode(encoded.as_bytes()).map_err(|e| {
        AppError::SchemaInvalid(format!("operator_packet_b64 is not valid base64: {e}"))
    })
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

fn validate_sha256(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(serde_json::Value::as_str)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
