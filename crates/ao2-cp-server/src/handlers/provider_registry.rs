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
use std::sync::Arc;

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;
use crate::signing::{annotate_trust_policy, sha256_hex, verify_rsa_sha256_signature};

const PROVIDER_REGISTRY_SCHEMA: &str = "ao2.provider-plugin-registry.v1";
const PROVIDER_REGISTRY_LIST_SCHEMA: &str = "ao2.cp-provider-registry-list.v1";
const PROVIDER_REGISTRY_DETAIL_SCHEMA: &str = "ao2.cp-provider-registry-detail.v1";
const PROVIDER_REGISTRY_DASHBOARD_SCHEMA: &str = "ao2.cp-provider-registry-dashboard.v1";
const SIGNED_UPLOAD_SCHEMA: &str = "ao2.cp-provider-registry-signed-upload.v1";
const SIGNATURE_SCHEMA: &str = "ao2.cp-provider-registry-signature.v1";

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

#[derive(Debug, Deserialize)]
struct SignedProviderRegistryUpload {
    schema_version: String,
    registry: serde_json::Value,
    registry_b64: Option<String>,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SignatureSidecar {
    schema_version: String,
    provider_registry_sha256: String,
    signature: serde_json::Value,
}

pub async fn post_provider_registry(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let registry: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_provider_registry(&registry)?;
    let sha = sha256_of_canonical(&registry).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::ProviderRegistry, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ProviderRegistry, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PROVIDER_REGISTRY_SCHEMA.to_string(),
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

    Ok(Json(IngestReceipt::new(
        sha,
        PROVIDER_REGISTRY_SCHEMA.to_string(),
    )))
}

pub async fn post_signed_provider_registry(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedProviderRegistryUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    let signed_bytes = match &upload.registry_b64 {
        Some(encoded) => decode_registry_b64(encoded)?,
        None => serde_json::to_string_pretty(&upload.registry)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .into_bytes(),
    };
    let mut signature = upload.signature;
    let registry_raw = std::str::from_utf8(&signed_bytes).map_err(|e| {
        AppError::SchemaInvalid(format!("signed provider registry is not utf-8: {e}"))
    })?;
    verify_signed_provider_registry(registry_raw, &signature)?;
    let registry: serde_json::Value = serde_json::from_slice(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    validate_provider_registry(&registry)?;
    let sha = sha256_of_canonical(&registry).map_err(|e| AppError::Internal(e.to_string()))?;
    annotate_trust_policy(&mut signature, &state.signed_artifact_trusted_key_sha256s);

    if !state
        .storage
        .bundles
        .exists(BundleKind::ProviderRegistry, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ProviderRegistry, &sha, registry_raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = SignatureSidecar {
        schema_version: SIGNATURE_SCHEMA.to_string(),
        provider_registry_sha256: sha.clone(),
        signature,
    };
    let sidecar_raw =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    // Write-once provenance guard: the sidecar records *who signed* this content
    // sha. If one already exists for this sha, a re-upload carrying a different
    // signature (different key/provenance) must be rejected rather than silently
    // overwriting the recorded signer. Re-uploading the identical signed artifact
    // is idempotent. Mirrors the provider-readiness signature-sidecar guard.
    if state
        .storage
        .bundles
        .exists(BundleKind::ProviderRegistrySignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::ProviderRegistrySignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "provider registry signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(BundleKind::ProviderRegistrySignature, &sha, &sidecar_raw)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PROVIDER_REGISTRY_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: Some("signed".to_string()),
        size_bytes: registry_raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        PROVIDER_REGISTRY_SCHEMA.to_string(),
    )))
}

fn validate_provider_registry(registry: &serde_json::Value) -> Result<(), AppError> {
    let schema = registry
        .get("schema")
        .or_else(|| registry.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PROVIDER_REGISTRY_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {PROVIDER_REGISTRY_SCHEMA}, got {schema}"
        )));
    }
    let execution_owner = registry
        .get("trust_boundary")
        .and_then(|value| value.get("execution_owner"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if execution_owner != "ao2-local-cli" {
        return Err(AppError::SchemaInvalid(
            "provider registry must declare trust_boundary.execution_owner=ao2-local-cli"
                .to_string(),
        ));
    }
    let providers = registry
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AppError::SchemaInvalid("provider registry missing providers".into()))?;
    if providers.is_empty() {
        return Err(AppError::SchemaInvalid(
            "provider registry must include at least one provider".into(),
        ));
    }
    Ok(())
}

fn verify_signed_provider_registry(
    registry_raw: &str,
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
            "unsupported provider registry signature algorithm: {algorithm}"
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

    verify_rsa_sha256_signature(registry_raw.as_bytes(), &signature_bytes, public_key_pem)
}

fn required_signature_string<'a>(
    signature: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AppError> {
    signature
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::SchemaInvalid(format!("signed provider registry missing {field}")))
}

fn decode_registry_b64(encoded: &str) -> Result<Vec<u8>, AppError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| AppError::SchemaInvalid(format!("registry_b64 is not valid base64: {e}")))
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

pub async fn list_provider_registries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BundleListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|entry| entry.schema == PROVIDER_REGISTRY_SCHEMA);
    if let Some(since) = q.since {
        all.retain(|entry| entry.ingested_at >= since);
    }
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let total_count = all.len();
    let limit = q.limit.min(500);
    let entries = all
        .into_iter()
        .skip(q.offset)
        .take(limit)
        .map(|entry| BundleListEntry {
            sha256: entry.sha256,
            ingested_at: entry.ingested_at,
            size_bytes: entry.size_bytes,
            schema_version: entry.schema,
            status: entry.status,
        })
        .collect();

    Ok(Json(BundleListResponse {
        schema_version: PROVIDER_REGISTRY_LIST_SCHEMA.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn latest_provider_registry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|entry| entry.schema == PROVIDER_REGISTRY_SCHEMA);
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = all.first() else {
        return Err(AppError::NotFound);
    };
    get_provider_registry_by_sha_with_cache(&state, &entry.sha256, &headers).await
}

pub async fn get_provider_registry(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_provider_registry_by_sha_with_cache(&state, &sha, &headers).await
}

/// HEAD-equivalent that emits only the ETag + Cache-Control headers
/// without the response body. Saves bandwidth for pollers that just
/// want to learn whether the cached snapshot is still current.
pub async fn head_latest_provider_registry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|entry| entry.schema == PROVIDER_REGISTRY_SCHEMA);
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = all.first() else {
        return Err(AppError::NotFound);
    };
    head_provider_registry_by_sha(&entry.sha256, &headers)
}

pub async fn head_provider_registry(
    State(_state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    head_provider_registry_by_sha(&sha, &headers)
}

fn head_provider_registry_by_sha(sha: &str, headers: &HeaderMap) -> Result<Response, AppError> {
    if let Some(not_modified) = caching::check_if_none_match(sha, headers)? {
        return Ok(not_modified);
    }
    Ok(caching::cacheable_head_response(&caching::format_etag(sha)))
}

async fn get_provider_registry_by_sha_with_cache(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    if let Some(not_modified) = caching::check_if_none_match(sha, headers)? {
        // existence check still required so a 304 cannot be served for
        // a sha the server has never seen
        if !state
            .storage
            .bundles
            .exists(BundleKind::ProviderRegistry, sha)
            .await
        {
            return Err(AppError::NotFound);
        }
        return Ok(not_modified);
    }
    if !state
        .storage
        .bundles
        .exists(BundleKind::ProviderRegistry, sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderRegistry, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let actual = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    Ok(caching::cacheable_json_response(
        &caching::format_etag(sha),
        bytes,
    ))
}

pub async fn provider_registry_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|entry| entry.schema == PROVIDER_REGISTRY_SCHEMA);
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut rows = String::new();
    for entry in all {
        let registry = read_registry_value(&state, &entry.sha256).await?;
        let phase = registry
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let provider_count = registry
            .get("providers")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        rows.push_str(&format!(
            "<tr><td><a href=\"/api/v1/provider/registry/{sha}/detail\"><code>{short}</code></a></td><td>{phase}</td><td>{provider_count}</td><td>{status}</td><td>{ingested}</td></tr>",
            sha = escape_html(&entry.sha256),
            short = escape_html(&entry.sha256[..12]),
            phase = escape_html(phase),
            provider_count = provider_count,
            status = escape_html(entry.status.as_deref().unwrap_or("accepted")),
            ingested = escape_html(&entry.ingested_at.to_rfc3339())
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No AO2 provider registries ingested.</td></tr>");
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Provider Registry</title></head><body><main><h1>AO2 Provider Registry</h1><p>read-only observer view. The control plane never approves, mutates, or executes provider adapters.</p><p><a href=\"/api/v1/provider/registry/latest\">Latest registry JSON</a> · <a href=\"/api/v1/provider/registry/dashboard.json\">Dashboard JSON</a></p><table><thead><tr><th>SHA256</th><th>Phase</th><th>Providers</th><th>Status</th><th>Ingested</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>"
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn provider_registry_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(provider_registry_dashboard_value(&state).await?))
}

pub async fn provider_registry_detail(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    let registry = read_registry_value(&state, &sha).await?;
    let signature = read_signature_sidecar(&state, &sha).await.ok();
    let sig = signature
        .as_ref()
        .and_then(|sidecar| sidecar.get("signature"))
        .unwrap_or(&serde_json::Value::Null);
    let signer_id = sig
        .get("signer_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unsigned");
    let signature_verified = sig
        .get("signature_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let signature_label = if signature_verified {
        "Signature verified"
    } else {
        "Unsigned or signature unavailable"
    };
    let public_key_sha256 = sig
        .get("public_key_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("not provided");
    let signature_sha256 = sig
        .get("signature_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("not provided");
    let phase = registry
        .get("phase")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let mut provider_rows = String::new();
    for provider in registry
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = provider
            .get("provider")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let live_guard = provider
            .get("guards")
            .and_then(|guards| guards.get("explicit_live_env"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not required");
        let lifecycle = provider
            .get("lifecycle_gate")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let slots = provider
            .get("extension_slots")
            .and_then(serde_json::Value::as_array)
            .map(|slots| {
                slots
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        provider_rows.push_str(&format!(
            "<tr><td>{name}</td><td>{live_guard}</td><td>{lifecycle}</td><td>{slots}</td></tr>",
            name = escape_html(name),
            live_guard = escape_html(live_guard),
            lifecycle = escape_html(lifecycle),
            slots = escape_html(&slots),
        ));
    }
    if provider_rows.is_empty() {
        provider_rows.push_str("<tr><td colspan=\"4\">No providers declared.</td></tr>");
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Provider Registry Detail</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:72rem}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.5rem 1rem}}dt{{font-weight:700}}table{{border-collapse:collapse;width:100%;margin-top:.5rem}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}.verified{{color:#096b36;font-weight:700}}.muted{{color:#555}}</style></head><body><main><p><a href=\"/api/v1/provider/registry/dashboard\">Registry Dashboard</a></p><h1>AO2 Provider Registry Detail</h1><p class=\"muted\">Read-only observer detail. The control plane correlates registry metadata with evidence surfaces but never executes providers.</p><dl><dt>SHA256</dt><dd><code>{sha}</code></dd><dt>Phase</dt><dd>{phase}</dd><dt>Signer</dt><dd>{signer_id}</dd><dt>Signature</dt><dd><span class=\"verified\">{signature_label}</span></dd><dt>Public key SHA256</dt><dd><code>{public_key_sha256}</code></dd><dt>Signature SHA256</dt><dd><code>{signature_sha256}</code></dd><dt>Raw registry</dt><dd><a href=\"/api/v1/provider/registry/{sha}\">JSON</a></dd><dt>Signature sidecar</dt><dd><a href=\"/api/v1/provider/registry/{sha}/signature\">signature JSON</a></dd><dt>Evidence correlation</dt><dd><a href=\"/api/v1/evidence-pack/dashboard\">Signed evidence dashboard</a></dd><dt>Memory correlation</dt><dd><a href=\"/api/v1/memory/export/dashboard\">Memory export dashboard</a></dd></dl><h2>Providers</h2><table><thead><tr><th>Provider</th><th>Live Guard</th><th>Lifecycle</th><th>Extension Slots</th></tr></thead><tbody>{provider_rows}</tbody></table></main></body></html>",
        sha = escape_html(&sha),
        phase = escape_html(phase),
        signer_id = escape_html(signer_id),
        signature_label = escape_html(signature_label),
        public_key_sha256 = escape_html(public_key_sha256),
        signature_sha256 = escape_html(signature_sha256),
        provider_rows = provider_rows,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn provider_registry_detail_json(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    let registry = read_registry_value(&state, &sha).await?;
    let signature = read_signature_sidecar(&state, &sha).await.ok();
    let sig = signature
        .as_ref()
        .and_then(|sidecar| sidecar.get("signature"))
        .unwrap_or(&serde_json::Value::Null);
    let providers = registry
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .map(|providers| {
            providers
                .iter()
                .map(|provider| {
                    let name = provider
                        .get("provider")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let live_guard = provider
                        .get("guards")
                        .and_then(|guards| guards.get("explicit_live_env"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("not required");
                    let lifecycle = provider
                        .get("lifecycle_gate")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let adapter_crate = provider
                        .get("crate")
                        .or_else(|| provider.get("adapter_crate"))
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| match name {
                            "codex" => "ao2-adapter-codex".to_string(),
                            "claude" => "ao2-adapter-claude".to_string(),
                            "scripted" => "ao2-adapters".to_string(),
                            _ => "built-in".to_string(),
                        });
                    let metadata_source = provider
                        .get("metadata_source")
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| adapter_crate.clone());
                    let adapter_kind = provider
                        .get("adapter_kind")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let doctor_metadata_source = provider
                        .get("doctor")
                        .and_then(|doctor| doctor.get("metadata_source"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(&metadata_source);
                    let doctor_args = provider
                        .get("doctor")
                        .and_then(|doctor| doctor.get("doctor_args"))
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([]));
                    serde_json::json!({
                        "provider": name,
                        "metadata_source": metadata_source,
                        "adapter_crate": adapter_crate,
                        "adapter_kind": adapter_kind,
                        "doctor_metadata_source": doctor_metadata_source,
                        "doctor_args": doctor_args,
                        "live_guard": live_guard,
                        "lifecycle_gate": lifecycle,
                        "evidence_dashboard_url": "/api/v1/evidence-pack/dashboard",
                        "evidence_dashboard_json_url": "/api/v1/evidence-pack/dashboard.json",
                        "memory_dashboard_url": "/api/v1/memory/export/dashboard",
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let body = serde_json::json!({
        "schema_version": PROVIDER_REGISTRY_DETAIL_SCHEMA,
        "sha256": sha,
        "phase": registry
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
        "signature": {
            "present": signature.is_some(),
            "signature_verified": sig
                .get("signature_verified")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            "signer_id": sig
                .get("signer_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unsigned"),
            "public_key_sha256": sig
                .get("public_key_sha256")
                .and_then(serde_json::Value::as_str),
            "signature_sha256": sig
                .get("signature_sha256")
                .and_then(serde_json::Value::as_str),
        },
        "provider_count": providers.len(),
        "providers": providers,
        "links": {
            "raw_registry": format!("/api/v1/provider/registry/{sha}"),
            "signature": format!("/api/v1/provider/registry/{sha}/signature"),
            "html_detail": format!("/api/v1/provider/registry/{sha}/detail"),
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "evidence_dashboard_json": "/api/v1/evidence-pack/dashboard.json",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        }
    });
    Ok(Json(body).into_response())
}

async fn provider_registry_dashboard_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PROVIDER_REGISTRY_SCHEMA);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));

    let mut provider_counts = serde_json::Map::new();
    let mut latest = serde_json::Value::Null;
    let mut providers = Vec::new();
    if let Some(entry) = entries.first() {
        let registry = read_registry_value(state, &entry.sha256).await?;
        providers = registry
            .get("providers")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|provider| {
                        let name = provider
                            .get("provider")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        let count = provider_counts
                            .get(name)
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0)
                            + 1;
                        provider_counts.insert(name.to_string(), serde_json::json!(count));
                        let adapter_crate = provider
                            .get("crate")
                            .or_else(|| provider.get("adapter_crate"))
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string)
                            .unwrap_or_else(|| match name {
                                "codex" => "ao2-adapter-codex".to_string(),
                                "claude" => "ao2-adapter-claude".to_string(),
                                "scripted" => "ao2-adapters".to_string(),
                                _ => "built-in".to_string(),
                            });
                        let metadata_source = provider
                            .get("metadata_source")
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string)
                            .unwrap_or_else(|| adapter_crate.clone());
                        let doctor_metadata_source = provider
                            .get("doctor")
                            .and_then(|doctor| doctor.get("metadata_source"))
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(&metadata_source);
                        serde_json::json!({
                            "provider": name,
                            "metadata_source": metadata_source,
                            "adapter_crate": adapter_crate,
                            "adapter_kind": provider
                                .get("adapter_kind")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown"),
                            "doctor_metadata_source": doctor_metadata_source,
                            "doctor_args": provider
                                .get("doctor")
                                .and_then(|doctor| doctor.get("doctor_args"))
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!([])),
                            "live_guard": provider
                                .get("guards")
                                .and_then(|guards| guards.get("explicit_live_env"))
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("not required"),
                            "lifecycle_gate": provider
                                .get("lifecycle_gate")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown"),
                            "extension_slots": provider
                                .get("extension_slots")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!([])),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let signature = read_signature_sidecar(state, &entry.sha256).await.ok();
        let sig = signature
            .as_ref()
            .and_then(|sidecar| sidecar.get("signature"))
            .unwrap_or(&serde_json::Value::Null);
        latest = serde_json::json!({
            "sha256": entry.sha256,
            "phase": registry
                .get("phase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
            "provider_count": providers.len(),
            "status": entry.status.as_deref().unwrap_or("accepted"),
            "ingested_at": entry.ingested_at,
            "signature": {
                "present": signature.is_some(),
                "signature_verified": sig
                    .get("signature_verified")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                "signer_id": sig
                    .get("signer_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unsigned"),
            },
        });
    }

    Ok(serde_json::json!({
        "schema_version": PROVIDER_REGISTRY_DASHBOARD_SCHEMA,
        "status": if entries.is_empty() { "missing" } else { "observed" },
        "registry_count": entries.len(),
        "latest": latest,
        "provider_counts": provider_counts,
        "providers": providers,
        "links": {
            "dashboard": "/api/v1/provider/registry/dashboard",
            "dashboard_json": "/api/v1/provider/registry/dashboard.json",
            "latest_registry": "/api/v1/provider/registry/latest",
            "acceptance_dashboard": "/api/v1/acceptance/dashboard",
            "acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
            "provider_readiness_dashboard": "/api/v1/provider/readiness/dashboard",
            "provider_readiness_dashboard_json": "/api/v1/provider/readiness/dashboard.json",
            "phase1_operator_panel": "/api/v1/phase1/promotion/operator-panel",
            "phase1_operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        },
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "execution_owner": "ao2-local-cli",
            "release_acceptance_owner": "factory-v3 evaluator-closer",
        },
        "next_action": if entries.is_empty() {
            "publish signed AO2 provider registry evidence to the observer control plane"
        } else {
            "correlate latest provider registry with provider readiness and live acceptance evidence"
        }
    }))
}

pub async fn get_provider_registry_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
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

async fn read_registry_value(state: &AppState, sha: &str) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderRegistry, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn read_signature_sidecar(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderRegistrySignature, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    let sidecar: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let sidecar_sha = sidecar
        .get("provider_registry_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if sidecar_sha != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual: sidecar_sha.to_string(),
        });
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

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
