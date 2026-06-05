use ao2_cp_schema::canonical::{canonical_json, sha256_of_canonical};
use ao2_cp_schema::responses::IngestReceipt;
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
use crate::signing::{sha256_hex, verify_rsa_sha256_signature};

const PROVIDER_READINESS_SCHEMA: &str = "factory-v3/hermes-provider-phase1-readiness/v1";
const PROVIDER_READINESS_LIST_SCHEMA: &str = "ao2.cp-provider-readiness-list.v1";
const PROVIDER_READINESS_DETAIL_SCHEMA: &str = "ao2.cp-provider-readiness-detail.v1";
const PROVIDER_READINESS_DASHBOARD_SCHEMA: &str = "ao2.cp-provider-readiness-dashboard.v1";
const PROVIDER_READINESS_SUPPORT_BUNDLE_SCHEMA: &str =
    "ao2.cp-provider-readiness-support-bundle.v1";
const PROVIDER_READINESS_SUPPORT_BUNDLE_CHECKSUMS_SCHEMA: &str =
    "ao2.cp-provider-readiness-support-bundle-checksums.v1";
const PROVIDER_READINESS_SIGNED_UPLOAD_SCHEMA: &str = "ao2.cp-provider-readiness-signed-upload.v1";
const PROVIDER_READINESS_SIGNATURE_SCHEMA: &str = "ao2.cp-provider-readiness-signature.v1";

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
struct SignedProviderReadinessUpload {
    schema_version: String,
    readiness: serde_json::Value,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ProviderReadinessSignatureSidecar {
    schema_version: String,
    provider_readiness_sha256: String,
    signature: serde_json::Value,
}

/// Accepted schemas on this handler (Phase 2 migration window):
/// - `factory-v3/hermes-provider-phase1-readiness/v1` — accepted for
///   `migration_window=phase2_in_progress`; sunset target = end of
///   Phase 2 W1 burn-down. An AO2-native producer
///   (`scripts/build-provider-readiness.sh` + `ao2 release
///   build-provider-readiness`) is already authoritative; this handler
///   keeps accepting the factory-v3-tagged variant for in-flight
///   Phase 1 evidence compatibility.
///
/// Emits a `tracing::info!` line with `migration_window` and the
/// accepted `schema` so operators can grep audit trails.
pub async fn post_provider_readiness(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let readiness: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_provider_readiness(&readiness)?;
    let sha = sha256_of_canonical(&readiness).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::ProviderReadiness, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ProviderReadiness, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PROVIDER_READINESS_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: readiness
            .get("status")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        size_bytes: raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        migration_window = "phase2_in_progress",
        schema = PROVIDER_READINESS_SCHEMA,
        handler = "provider_readiness::post_provider_readiness",
        "accepted factory-v3-tagged provider readiness payload"
    );

    Ok(Json(IngestReceipt::new(
        sha,
        PROVIDER_READINESS_SCHEMA.to_string(),
    )))
}

pub async fn post_signed_provider_readiness(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedProviderReadinessUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != PROVIDER_READINESS_SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PROVIDER_READINESS_SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    validate_provider_readiness(&upload.readiness)?;
    let readiness_raw =
        canonical_json(&upload.readiness).map_err(|e| AppError::Internal(e.to_string()))?;
    let sha =
        sha256_of_canonical(&upload.readiness).map_err(|e| AppError::Internal(e.to_string()))?;
    let signature = verified_provider_readiness_signature(
        readiness_raw.as_bytes(),
        &upload.signature,
        &state.provider_readiness_trusted_key_sha256s,
    )?;

    state
        .storage
        .bundles
        .write(
            BundleKind::ProviderReadiness,
            &sha,
            readiness_raw.as_bytes(),
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let sidecar = ProviderReadinessSignatureSidecar {
        schema_version: PROVIDER_READINESS_SIGNATURE_SCHEMA.to_string(),
        provider_readiness_sha256: sha.clone(),
        signature,
    };
    let sidecar_raw =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    if state
        .storage
        .bundles
        .exists(BundleKind::ProviderReadinessSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::ProviderReadinessSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "provider readiness signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(BundleKind::ProviderReadinessSignature, &sha, &sidecar_raw)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PROVIDER_READINESS_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: Some("signed".to_string()),
        size_bytes: readiness_raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        PROVIDER_READINESS_SCHEMA.to_string(),
    )))
}

pub async fn list_provider_readiness(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut all = provider_readiness_entries(&state).await?;
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
        .map(|entry| {
            let sha = entry.sha256;
            serde_json::json!({
                "sha256": sha,
                "ingested_at": entry.ingested_at,
                "size_bytes": entry.size_bytes,
                "schema_version": entry.schema,
                "status": entry.status,
                "raw_url": format!("/api/v1/provider/readiness/{sha}"),
                "detail_url": format!("/api/v1/provider/readiness/{sha}/detail"),
                "detail_json_url": format!("/api/v1/provider/readiness/{sha}/detail.json"),
                "signature_url": format!("/api/v1/provider/readiness/{sha}/signature"),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "schema_version": PROVIDER_READINESS_LIST_SCHEMA,
        "total_count": total_count,
        "limit": limit,
        "offset": q.offset,
        "entries": entries,
    })))
}

pub async fn latest_provider_readiness(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut all = provider_readiness_entries(&state).await?;
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = all.first() else {
        return Err(AppError::NotFound);
    };
    get_provider_readiness_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_provider_readiness(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_provider_readiness_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/provider/readiness/:sha`.
pub async fn head_provider_readiness(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ProviderReadiness, &sha)
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

pub async fn provider_readiness_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let mut all = provider_readiness_entries(&state).await?;
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut trend_inputs = Vec::new();
    let mut rows = String::new();
    for entry in all {
        let readiness = read_provider_readiness_value(&state, &entry.sha256).await?;
        trend_inputs.push((entry.sha256.clone(), readiness.clone()));
        let live_policy = readiness
            .get("live_provider_policy")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let codex_gate = readiness_status(&readiness, "codex_gate");
        let codex_pilot = readiness_status(&readiness, "codex_pilot");
        let required_live = readiness
            .get("required_live_provider_pilots")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        rows.push_str(&format!(
            "<tr><td><a href=\"/api/v1/provider/readiness/{sha}/detail\"><code>{short}</code></a></td><td>{status}</td><td>{live_policy}</td><td>{required_live}</td><td>codex</td><td>{codex_gate}</td><td>{codex_pilot}</td><td>{ingested}</td></tr>",
            sha = escape_html(&entry.sha256),
            short = escape_html(&entry.sha256[..12]),
            status = escape_html(entry.status.as_deref().unwrap_or("unknown")),
            live_policy = escape_html(live_policy),
            required_live = escape_html(&required_live),
            codex_gate = escape_html(&codex_gate),
            codex_pilot = escape_html(&codex_pilot),
            ingested = escape_html(&entry.ingested_at.to_rfc3339()),
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"8\">No AO2 provider readiness artifacts ingested.</td></tr>",
        );
    }
    let trend = provider_readiness_trend(&trend_inputs);
    let latest_codex_gate = trend
        .get("latest_codex_gate")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let latest_codex_pilot = trend
        .get("latest_codex_pilot")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let total_count = trend
        .get("total_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let codex_ready_count = trend
        .get("codex_ready_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let codex_blocked_count = trend
        .get("codex_blocked_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let latest_phase1_state = trend
        .get("latest_phase1_state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let latest_readiness = trend_inputs.first().map(|(_, readiness)| readiness);
    let phase1_next_actions = latest_readiness
        .map(provider_phase1_next_actions)
        .unwrap_or_else(|| {
            vec!["publish provider readiness evidence before Phase 1 promotion".to_string()]
        });
    let phase1_blockers = provider_phase1_dashboard_blockers(&trend_inputs);
    let next_actions_html = render_list_html(&phase1_next_actions);
    let blockers_html = render_list_html(&phase1_blockers);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Provider Phase 1 Readiness</title></head><body><main><h1>AO2 Provider Phase 1 Readiness</h1><p>read-only observer view. The control plane stores readiness evidence but never starts provider execution or approves a run.</p><p><a href=\"/api/v1/provider/readiness/latest\">Latest readiness JSON</a> · <a href=\"/api/v1/provider/readiness/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/acceptance/dashboard\">Provider Pilot Acceptance</a></p><section><h2>Readiness Trend</h2><dl><dt>Total Artifacts</dt><dd>{total_count}</dd><dt>Phase 1 State</dt><dd>{latest_phase1_state}</dd><dt>Latest Codex Gate</dt><dd>{latest_codex_gate}</dd><dt>Latest Codex Pilot</dt><dd>{latest_codex_pilot}</dd><dt>Codex Ready Count</dt><dd>{codex_ready_count}</dd><dt>Codex Blocked Count</dt><dd>{codex_blocked_count}</dd></dl></section><section><h2>Phase 1 Blockers</h2>{blockers_html}</section><section><h2>Safe Next Actions</h2>{next_actions_html}</section><table><thead><tr><th>SHA256</th><th>Status</th><th>Live Policy</th><th>Required Live</th><th>Provider</th><th>Gate</th><th>Pilot</th><th>Ingested</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        total_count = total_count,
        latest_phase1_state = escape_html(latest_phase1_state),
        latest_codex_gate = escape_html(latest_codex_gate),
        latest_codex_pilot = escape_html(latest_codex_pilot),
        codex_ready_count = codex_ready_count,
        codex_blocked_count = codex_blocked_count,
        blockers_html = blockers_html,
        next_actions_html = next_actions_html,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn provider_readiness_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(provider_readiness_dashboard_value(&state).await?))
}

pub async fn provider_readiness_support_bundle_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(provider_readiness_support_bundle_value(&state).await?))
}

pub async fn provider_readiness_support_bundle_download(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let bundle = provider_readiness_support_bundle_value(&state).await?;
    let bundle_sha256 =
        sha256_of_canonical(&bundle).map_err(|e| AppError::Internal(e.to_string()))?;
    let filename = provider_readiness_support_bundle_filename(&bundle);
    let body = serde_json::to_vec_pretty(&bundle).map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (
                header::HeaderName::from_static("x-ao2-cp-support-bundle-sha256"),
                bundle_sha256,
            ),
            (
                header::HeaderName::from_static("x-ao2-cp-control-plane-role"),
                "read-only-observer".to_string(),
            ),
        ],
        body,
    )
        .into_response())
}

pub async fn provider_readiness_support_bundle_checksums(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let bundle = provider_readiness_support_bundle_value(&state).await?;
    let body = provider_readiness_support_bundle_checksums_text(&bundle)?;

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"SHA256SUMS\"".to_string(),
            ),
            (
                header::HeaderName::from_static("x-ao2-cp-control-plane-role"),
                "read-only-observer".to_string(),
            ),
        ],
        body,
    )
        .into_response())
}

pub async fn provider_readiness_detail(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    validate_sha(&sha)?;
    let readiness = read_provider_readiness_value(&state, &sha).await?;
    let signature = read_signature_sidecar(&state, &sha).await.ok();
    let detail = provider_readiness_detail_json_value(&sha, &readiness, signature.as_ref());
    let provider_gates = detail
        .get("provider_gates")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for provider in ["codex", "claude", "antigravity", "scripted"] {
        let gate = provider_gates
            .get(provider)
            .and_then(|value| value.get("gate"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let pilot = provider_gates
            .get(provider)
            .and_then(|value| value.get("pilot"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not required");
        rows.push_str(&format!(
            "<tr><td>{provider}</td><td>{gate}</td><td>{pilot}</td></tr>",
            provider = escape_html(provider),
            gate = escape_html(gate),
            pilot = escape_html(pilot)
        ));
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Provider Readiness Detail</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:72rem}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.5rem 1rem}}dt{{font-weight:700}}table{{border-collapse:collapse;width:100%;margin-top:.5rem}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}.muted{{color:#555}}</style></head><body><main><p><a href=\"/api/v1/provider/readiness/dashboard\">Readiness Dashboard</a></p><h1>AO2 Provider Readiness Detail</h1><p class=\"muted\">Read-only observer detail. This page exposes Phase 1 readiness evidence without starting provider execution.</p><dl><dt>SHA256</dt><dd><code>{sha}</code></dd><dt>Status</dt><dd>{status}</dd><dt>Live Policy</dt><dd>{live_policy}</dd><dt>Signature</dt><dd>{signature_label} by {signer_id}</dd><dt>Raw JSON</dt><dd><a href=\"/api/v1/provider/readiness/{sha}\">JSON</a></dd><dt>Signature JSON</dt><dd><a href=\"/api/v1/provider/readiness/{sha}/signature\">signature JSON</a></dd><dt>Detail JSON</dt><dd><a href=\"/api/v1/provider/readiness/{sha}/detail.json\">detail JSON</a></dd><dt>Latest Readiness JSON</dt><dd><a href=\"/api/v1/provider/readiness/latest\">Latest Readiness JSON</a></dd><dt>Evidence Dashboard</dt><dd><a href=\"/api/v1/evidence-pack/dashboard\">Evidence Dashboard</a></dd><dt>Memory Dashboard</dt><dd><a href=\"/api/v1/memory/export/dashboard\">Memory Dashboard</a></dd></dl><h2>Provider Gates</h2><table><thead><tr><th>Provider</th><th>Gate</th><th>Pilot</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        sha = escape_html(&sha),
        status = escape_html(readiness.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        live_policy = escape_html(readiness.get("live_provider_policy").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        signature_label = escape_html(detail.get("signature").and_then(|s| s.get("signature_verified")).and_then(serde_json::Value::as_bool).map(|v| if v { "Signature verified" } else { "Unsigned or signature unavailable" }).unwrap_or("Unsigned or signature unavailable")),
        signer_id = escape_html(detail.get("signature").and_then(|s| s.get("signer_id")).and_then(serde_json::Value::as_str).unwrap_or("unsigned")),
        rows = rows,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn provider_readiness_detail_json(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    validate_sha(&sha)?;
    let readiness = read_provider_readiness_value(&state, &sha).await?;
    let signature = read_signature_sidecar(&state, &sha).await.ok();
    Ok(Json(provider_readiness_detail_json_value(
        &sha,
        &readiness,
        signature.as_ref(),
    )))
}

async fn provider_readiness_dashboard_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let mut all = provider_readiness_entries(state).await?;
    all.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut entries = Vec::new();
    let mut trend_inputs = Vec::new();
    for entry in all {
        let readiness = read_provider_readiness_value(state, &entry.sha256).await?;
        let sha = entry.sha256;
        trend_inputs.push((sha.clone(), readiness.clone()));
        entries.push(serde_json::json!({
            "sha256": sha,
            "ingested_at": entry.ingested_at,
            "status": entry.status,
            "phase1_status": provider_phase1_status(&readiness),
            "phase1_blockers": provider_phase1_blockers(&readiness),
            "phase1_next_actions": provider_phase1_next_actions(&readiness),
            "live_provider_policy": readiness
                .get("live_provider_policy")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
            "required_live_provider_pilots": readiness
                .get("required_live_provider_pilots")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            "provider_gates": provider_gate_summary(&readiness),
            "raw_url": format!("/api/v1/provider/readiness/{sha}"),
            "detail_url": format!("/api/v1/provider/readiness/{sha}/detail"),
            "detail_json_url": format!("/api/v1/provider/readiness/{sha}/detail.json"),
            "signature_url": format!("/api/v1/provider/readiness/{sha}/signature"),
            "signature": provider_readiness_signature_summary(state, &sha).await,
        }));
    }
    let trend = provider_readiness_trend(&trend_inputs);
    Ok(serde_json::json!({
        "schema_version": PROVIDER_READINESS_DASHBOARD_SCHEMA,
        "total_count": entries.len(),
        "trend": trend,
        "phase1_status": trend_inputs
            .first()
            .map(|(_, readiness)| provider_phase1_status(readiness))
            .unwrap_or_else(|| provider_phase1_status(&serde_json::json!({}))),
        "phase1_blockers": provider_phase1_dashboard_blockers(&trend_inputs),
        "phase1_next_actions": trend_inputs
            .first()
            .map(|(_, readiness)| provider_phase1_next_actions(readiness))
            .unwrap_or_else(|| vec!["publish provider readiness evidence before Phase 1 promotion".to_string()]),
        "entries": entries,
        "links": {
            "dashboard": "/api/v1/provider/readiness/dashboard",
            "latest": "/api/v1/provider/readiness/latest",
            "support_bundle_json": "/api/v1/provider/readiness/support-bundle.json",
            "support_bundle_download": "/api/v1/provider/readiness/support-bundle/download",
            "support_bundle_checksums": "/api/v1/provider/readiness/support-bundle/SHA256SUMS",
            "acceptance_dashboard": "/api/v1/acceptance/dashboard",
            "acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        }
    }))
}

async fn provider_readiness_support_bundle_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let dashboard = provider_readiness_dashboard_value(state).await?;
    let latest_sha = dashboard
        .get("trend")
        .and_then(|trend| trend.get("latest_sha256"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let latest_readiness = if latest_sha.is_empty() {
        serde_json::json!({})
    } else {
        read_provider_readiness_value(state, latest_sha).await?
    };
    let latest_signature = if latest_sha.is_empty() {
        serde_json::json!({
            "signature_verified": false,
            "signer_id": "unsigned",
            "public_key_sha256": ""
        })
    } else {
        provider_readiness_signature_summary(state, latest_sha).await
    };
    let latest_detail = if latest_sha.is_empty() {
        serde_json::json!({})
    } else {
        let latest_signature_sidecar = serde_json::json!({ "signature": latest_signature });
        provider_readiness_detail_json_value(
            latest_sha,
            &latest_readiness,
            Some(&latest_signature_sidecar),
        )
    };

    Ok(serde_json::json!({
        "schema_version": PROVIDER_READINESS_SUPPORT_BUNDLE_SCHEMA,
        "bundle_kind": "provider_readiness_support_bundle",
        "generated_at": Utc::now(),
        "control_plane_role": "read_only_observer",
        "mutates_ao_artifacts": false,
        "contains_bearer_token": false,
        "credential_handling": "bearer tokens are required only in HTTP Authorization headers and are never embedded in this bundle",
        "latest_provider_readiness_sha256": latest_sha,
        "latest_provider_readiness": latest_readiness,
        "latest_signature": latest_signature,
        "latest_detail": latest_detail,
        "dashboard": dashboard,
        "offline_review": {
            "purpose": "portable Phase 1 provider readiness observer evidence for factory-v3 evaluator/closer review",
            "trust_boundary": "read-only observer support bundle; no provider execution, no AO2 artifact mutation, no release approval",
            "cross_platform_commands": {
                "macos_ubuntu": [
                    "python3 -m json.tool provider-readiness-support-bundle.json >/dev/null",
                    "sha256sum -c SHA256SUMS"
                ],
                "windows_powershell": [
                    "python -m json.tool provider-readiness-support-bundle.json > $null",
                    "Get-FileHash -Algorithm SHA256 provider-readiness-support-bundle.json"
                ]
            }
        },
        "links": {
            "support_bundle_json": "/api/v1/provider/readiness/support-bundle.json",
            "support_bundle_download": "/api/v1/provider/readiness/support-bundle/download",
            "support_bundle_checksums": "/api/v1/provider/readiness/support-bundle/SHA256SUMS",
            "dashboard_json": "/api/v1/provider/readiness/dashboard.json",
            "latest": "/api/v1/provider/readiness/latest"
        }
    }))
}

fn provider_readiness_support_bundle_filename(bundle: &serde_json::Value) -> String {
    let latest_sha = bundle
        .get("latest_provider_readiness_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|sha| !sha.is_empty())
        .unwrap_or("none");
    let short_sha = latest_sha.get(..12).unwrap_or(latest_sha);
    format!("ao2-provider-readiness-support-bundle-{short_sha}.json")
}

fn provider_readiness_support_bundle_checksums_text(
    bundle: &serde_json::Value,
) -> Result<String, AppError> {
    let filename = provider_readiness_support_bundle_filename(bundle);
    let bundle_sha256 =
        sha256_of_canonical(bundle).map_err(|e| AppError::Internal(e.to_string()))?;
    let dashboard_sha256 = bundle
        .get("dashboard")
        .map(sha256_of_canonical)
        .transpose()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or_else(|| "missing".to_string());
    let latest_sha256 = bundle
        .get("latest_provider_readiness")
        .map(sha256_of_canonical)
        .transpose()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or_else(|| "missing".to_string());

    Ok([
        "# ao2-control-plane provider readiness support bundle SHA256SUMS".to_string(),
        format!("# schema: {PROVIDER_READINESS_SUPPORT_BUNDLE_CHECKSUMS_SCHEMA}"),
        "# algorithm: sha256-ao2-cp-canonical-json-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        format!("{bundle_sha256}  {filename}"),
        format!("{dashboard_sha256}  surfaces/provider-readiness-dashboard.json"),
        format!("{latest_sha256}  surfaces/latest-provider-readiness.json"),
        String::new(),
    ]
    .join("\n"))
}

async fn provider_readiness_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|entry| entry.schema == PROVIDER_READINESS_SCHEMA);
    Ok(all)
}

async fn get_provider_readiness_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderReadiness, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    if caching::etag_matches(headers, &etag) {
        return Ok(caching::not_modified_response(&etag));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let actual = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    Ok(caching::cacheable_json_response(&etag, bytes))
}

async fn read_provider_readiness_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderReadiness, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get_provider_readiness_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    validate_sha(&sha)?;
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderReadinessSignature, &sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

async fn read_signature_sidecar(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderReadinessSignature, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn provider_readiness_signature_summary(state: &AppState, sha: &str) -> serde_json::Value {
    read_signature_sidecar(state, sha)
        .await
        .ok()
        .and_then(|sidecar| sidecar.get("signature").cloned())
        .map(|signature| {
            serde_json::json!({
                "signature_verified": signature.get("signature_verified").and_then(serde_json::Value::as_bool).unwrap_or(false),
                "signer_id": signature.get("signer_id").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "public_key_sha256": signature.get("public_key_sha256").and_then(serde_json::Value::as_str).unwrap_or(""),
            })
        })
        .unwrap_or_else(|| serde_json::json!({
            "signature_verified": false,
            "signer_id": "unsigned",
            "public_key_sha256": "",
        }))
}

fn verified_provider_readiness_signature(
    readiness_bytes: &[u8],
    signature: &serde_json::Value,
    trusted_key_sha256s: &[String],
) -> Result<serde_json::Value, AppError> {
    let object = signature.as_object().ok_or_else(|| {
        AppError::SchemaInvalid("provider readiness signature must be an object".to_string())
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "schema_version"
                | "signature_algorithm"
                | "signature_hex"
                | "signature_sha256"
                | "public_key_pem"
                | "public_key_sha256"
                | "signer_id"
        ) {
            return Err(AppError::SchemaInvalid(format!(
                "provider readiness signature contains unsupported field {key}"
            )));
        }
    }
    let schema = signature
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PROVIDER_READINESS_SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PROVIDER_READINESS_SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported provider readiness signature algorithm: {algorithm}"
        )));
    }
    let signature_hex = required_signature_string(signature, "signature_hex")?;
    let public_key_pem = required_signature_string(signature, "public_key_pem")?;
    let signer_id = required_signature_string(signature, "signer_id")?;
    let signature_bytes = decode_hex(signature_hex)?;
    let signature_sha256 = sha256_hex(&signature_bytes);
    if let Some(expected) = signature
        .get("signature_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    {
        if signature_sha256 != expected {
            return Err(AppError::SchemaInvalid(format!(
                "signature_sha256 mismatch: expected {expected}, got {signature_sha256}"
            )));
        }
    }
    let public_key_sha256 = sha256_hex(public_key_pem.as_bytes());
    if let Some(expected) = signature
        .get("public_key_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    {
        if public_key_sha256 != expected {
            return Err(AppError::SchemaInvalid(format!(
                "public_key_sha256 mismatch: expected {expected}, got {public_key_sha256}"
            )));
        }
    }
    verify_rsa_sha256_signature(readiness_bytes, &signature_bytes, public_key_pem)?;

    let trusted_key_match = trusted_key_sha256s
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(&public_key_sha256));
    let (verification_scope, trust_anchor, policy, matched_public_key_sha256) = if trusted_key_match
    {
        (
            "cryptographic-and-pinned-key",
            "configured-provider-readiness-public-key-sha256",
            "pinned-public-key-sha256",
            public_key_sha256.as_str(),
        )
    } else {
        (
            "cryptographic-only",
            "upload-public-key-not-authority",
            "observer-only-upload-key",
            "",
        )
    };

    Ok(serde_json::json!({
        "schema_version": PROVIDER_READINESS_SIGNATURE_SCHEMA,
        "signature_algorithm": "RSA/SHA-256",
        "signature_hex": signature_hex,
        "signature_sha256": signature_sha256,
        "public_key_sha256": public_key_sha256,
        "signer_id": signer_id,
        "signature_verified": true,
        "verification_scope": verification_scope,
        "trust_anchor": trust_anchor,
        "trust_policy": {
            "policy": policy,
            "trusted_key_match": trusted_key_match,
            "release_authoritative": trusted_key_match,
            "matched_public_key_sha256": matched_public_key_sha256
        }
    }))
}

fn required_signature_string<'a>(
    signature: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AppError> {
    signature
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::SchemaInvalid(format!("signed provider readiness missing {field}"))
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

fn validate_provider_readiness(readiness: &serde_json::Value) -> Result<(), AppError> {
    let schema = readiness
        .get("schema")
        .or_else(|| readiness.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PROVIDER_READINESS_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {PROVIDER_READINESS_SCHEMA}, got {schema}"
        )));
    }
    let contracts = readiness
        .get("contracts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::SchemaInvalid("provider readiness missing contracts".into()))?;
    for provider in ["codex", "claude", "antigravity"] {
        let status = contracts
            .get(provider)
            .and_then(|contract| contract.get("status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if status != "verified" {
            return Err(AppError::SchemaInvalid(format!(
                "{provider} provider contract must be verified"
            )));
        }
    }
    Ok(())
}

fn validate_sha(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}

fn provider_readiness_detail_json_value(
    sha: &str,
    readiness: &serde_json::Value,
    signature_sidecar: Option<&serde_json::Value>,
) -> serde_json::Value {
    let signature = signature_sidecar
        .and_then(|sidecar| sidecar.get("signature"))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "signature_verified": false,
                "signer_id": "unsigned",
                "public_key_sha256": "",
            })
        });
    serde_json::json!({
        "schema_version": PROVIDER_READINESS_DETAIL_SCHEMA,
        "sha256": sha,
        "status": readiness
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
        "live_provider_policy": readiness
            .get("live_provider_policy")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
        "phase1_status": provider_phase1_status(readiness),
        "required_live_provider_pilots": readiness
            .get("required_live_provider_pilots")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
        "provider_gates": provider_gate_summary(readiness),
        "signature": signature,
        "links": {
            "raw_readiness": format!("/api/v1/provider/readiness/{sha}"),
            "html_detail": format!("/api/v1/provider/readiness/{sha}/detail"),
            "latest": "/api/v1/provider/readiness/latest",
            "dashboard": "/api/v1/provider/readiness/dashboard",
            "dashboard_json": "/api/v1/provider/readiness/dashboard.json",
            "signature": format!("/api/v1/provider/readiness/{sha}/signature"),
            "acceptance_dashboard": "/api/v1/acceptance/dashboard",
            "acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "evidence_dashboard_json": "/api/v1/evidence-pack/dashboard.json",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        }
    })
}

fn provider_gate_summary(readiness: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "scripted": {
            "gate": readiness_status(readiness, "scripted_gate"),
            "pilot": "not required",
        },
        "codex": {
            "gate": readiness_status(readiness, "codex_gate"),
            "pilot": readiness_status(readiness, "codex_pilot"),
        },
        "claude": {
            "gate": readiness_status(readiness, "claude_gate"),
            "pilot": readiness_status(readiness, "claude_pilot"),
        },
        "antigravity": {
            "gate": readiness_status(readiness, "antigravity_gate"),
            "pilot": readiness_status(readiness, "antigravity_pilot"),
        }
    })
}

fn provider_phase1_status(readiness: &serde_json::Value) -> serde_json::Value {
    let artifact_status = readiness
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let codex_gate = readiness_status(readiness, "codex_gate");
    let codex_pilot = readiness_status(readiness, "codex_pilot");
    let required_live_provider_pilot = readiness
        .get("required_live_provider_pilots")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|provider| provider == "codex")
        })
        .unwrap_or(false);

    let (state, reason, next_action) = if artifact_status != "passed" {
        (
            "failed",
            "readiness_artifact_not_passed",
            "fix provider readiness artifact generation before Phase 1 promotion",
        )
    } else if codex_gate != "ready" {
        (
            "blocked",
            "codex_gate_not_ready",
            "run guarded Codex provider smoke only after explicit operator approval",
        )
    } else if codex_pilot == "blocked" || codex_pilot == "not_ready" {
        (
            "blocked",
            "codex_pilot_not_ready",
            "run guarded Codex provider pilot only after explicit operator approval",
        )
    } else if codex_pilot == "ready" && required_live_provider_pilot {
        (
            "pilot_complete",
            "codex_pilot_ready_and_required",
            "review signed provider-pilot acceptance evidence for Phase 1 promotion",
        )
    } else if codex_pilot == "ready" {
        (
            "ready",
            "codex_gate_and_pilot_ready",
            "require a live Codex provider pilot before Phase 1 promotion",
        )
    } else {
        (
            "blocked",
            "codex_pilot_unknown",
            "publish a provider readiness artifact with a ready Codex pilot",
        )
    };

    serde_json::json!({
        "state": state,
        "reason": reason,
        "provider": "codex",
        "gate": codex_gate,
        "pilot": codex_pilot,
        "required_live_provider_pilot": required_live_provider_pilot,
        "next_action": next_action,
    })
}

fn provider_phase1_blockers(readiness: &serde_json::Value) -> Vec<String> {
    let mut blockers = Vec::new();
    let artifact_status = readiness
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let codex_gate = readiness_status(readiness, "codex_gate");
    let codex_pilot = readiness_status(readiness, "codex_pilot");
    let required_live_provider_pilot = readiness
        .get("required_live_provider_pilots")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|provider| provider == "codex")
        })
        .unwrap_or(false);

    if artifact_status != "passed" {
        blockers.push("Provider readiness artifact has not passed".to_string());
    }
    if codex_gate != "ready" {
        blockers.push("Codex readiness gate is not ready".to_string());
    }
    if codex_pilot != "ready" {
        blockers.push("Codex provider pilot is not ready".to_string());
    }
    if codex_gate == "ready" && codex_pilot == "ready" && !required_live_provider_pilot {
        blockers.push(
            "Live Codex provider pilot is not marked as required for Phase 1 promotion".to_string(),
        );
    }
    blockers
}

fn provider_phase1_next_actions(readiness: &serde_json::Value) -> Vec<String> {
    let status = provider_phase1_status(readiness);
    let next_action = status
        .get("next_action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("publish provider readiness evidence before Phase 1 promotion");
    vec![next_action.to_string()]
}

fn provider_phase1_dashboard_blockers(
    readiness_items: &[(String, serde_json::Value)],
) -> Vec<String> {
    let mut blockers = readiness_items
        .first()
        .map(|(_, readiness)| provider_phase1_blockers(readiness))
        .unwrap_or_else(|| vec!["No provider readiness artifacts have been ingested".to_string()]);
    let blocked_history_count = readiness_items
        .iter()
        .skip(1)
        .filter(|(_, readiness)| {
            provider_phase1_status(readiness)
                .get("state")
                .and_then(serde_json::Value::as_str)
                == Some("blocked")
        })
        .count();
    if blocked_history_count > 0 {
        blockers
            .push("blocked readiness artifacts remain in provider readiness history".to_string());
    }
    blockers
}

fn render_list_html(items: &[String]) -> String {
    if items.is_empty() {
        return "<p>None.</p>".to_string();
    }
    let mut html = String::from("<ul>");
    for item in items {
        html.push_str(&format!("<li>{}</li>", escape_html(item)));
    }
    html.push_str("</ul>");
    html
}

fn provider_readiness_trend(readiness_items: &[(String, serde_json::Value)]) -> serde_json::Value {
    let latest = readiness_items.first();
    let codex_ready_count = readiness_items
        .iter()
        .filter(|(_, readiness)| {
            readiness_status(readiness, "codex_gate") == "ready"
                && readiness_status(readiness, "codex_pilot") == "ready"
        })
        .count();
    let codex_blocked_count = readiness_items
        .iter()
        .filter(|(_, readiness)| readiness_status(readiness, "codex_pilot") == "blocked")
        .count();
    let required_live_provider_pilot_count = readiness_items
        .iter()
        .filter(|(_, readiness)| {
            readiness
                .get("required_live_provider_pilots")
                .and_then(serde_json::Value::as_array)
                .map(|items| !items.is_empty())
                .unwrap_or(false)
        })
        .count();
    serde_json::json!({
        "total_count": readiness_items.len(),
        "latest_sha256": latest.map(|(sha, _)| sha.as_str()).unwrap_or(""),
        "latest_status": latest
            .and_then(|(_, readiness)| readiness.get("status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
        "latest_codex_gate": latest
            .map(|(_, readiness)| readiness_status(readiness, "codex_gate"))
            .unwrap_or_else(|| "unknown".to_string()),
        "latest_codex_pilot": latest
            .map(|(_, readiness)| readiness_status(readiness, "codex_pilot"))
            .unwrap_or_else(|| "unknown".to_string()),
        "latest_phase1_state": latest
            .map(|(_, readiness)| {
                provider_phase1_status(readiness)
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".to_string()),
        "codex_ready_count": codex_ready_count,
        "codex_blocked_count": codex_blocked_count,
        "required_live_provider_pilot_count": required_live_provider_pilot_count,
    })
}

fn readiness_status(readiness: &serde_json::Value, key: &str) -> String {
    readiness
        .get(key)
        .and_then(|value| value.get("status").or_else(|| value.get("verdict")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
