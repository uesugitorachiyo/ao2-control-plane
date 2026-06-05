use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::control_plane::parse_control_plane_bundle;
use ao2_cp_schema::responses::{
    BundleListEntry, BundleListResponse, IngestReceipt, SCHEMA_BUNDLE_LIST,
};
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
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

pub async fn route_index() -> Json<serde_json::Value> {
    let routes = crate::route_catalog::route_index_entries();
    let portable_artifacts = crate::route_catalog::portable_artifact_groups();

    Json(json!({
        "schema_version": "ao2.cp-route-index.v1",
        "generated_at": Utc::now().to_rfc3339(),
        "control_plane_role": "read-only-observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "auth": {
            "required": true,
            "scheme": "bearer",
            "credential_material_included": false,
            "credential_material_in_urls": false,
        },
        "trust_boundary": {
            "frontend": "Hermes schedules, queues, and displays this index",
            "trusted_execution_and_closure": "ao2 local signed evidence and digest replay",
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "observer": "ao2-control-plane",
        },
        "routes": routes,
        "portable_artifacts": portable_artifacts,
        "recommended_frontend_usage": [
            "Use this route index to discover portable observer surfaces without hard-coding bearer tokens or approval semantics.",
            "Use download and SHA256SUMS routes for offline handoff bundles; verify digests before operator review.",
            "Do not treat any ao2-control-plane route as release approval; factory-v3 evaluator-closer remains authoritative.",
        ],
    }))
}

pub async fn post_bundle(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let bundle = parse_control_plane_bundle(raw).map_err(|e| {
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

    let kind = BundleKind::ControlPlaneBundle;
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
        schema: bundle.schema_version.clone(),
        provider: None,
        sha256: sha.clone(),
        status: None,
        size_bytes: raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(sha, bundle.schema_version)))
}

pub async fn list_bundles(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BundleListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == "ao2.control-plane-fleet-bundle.v1");
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
        schema_version: SCHEMA_BUNDLE_LIST.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn get_bundle(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ControlPlaneBundle, &sha)
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
        .read(BundleKind::ControlPlaneBundle, &sha)
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

/// HEAD-equivalent for `/api/v1/control-plane/bundle/:sha`.
pub async fn head_bundle(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ControlPlaneBundle, &sha)
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
