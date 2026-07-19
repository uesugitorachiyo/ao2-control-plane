use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::IngestReceipt;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;

const PROGRESS_SCHEMA: &str = "ao2.windows-stack-qualification-progress.v1";
const PROGRESS_READBACK_SCHEMA: &str = "ao2.cp-windows-stack-qualification-progress-readback.v1";
const PROGRESS_DASHBOARD_SCHEMA: &str = "ao2.cp-windows-stack-qualification-progress-dashboard.v1";

pub async fn post_windows_qualification_progress(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let progress: Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_progress(&progress)?;

    let sha = sha256_of_canonical(&progress).map_err(|e| AppError::Internal(e.to_string()))?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::WindowsStackQualificationProgress, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(
                BundleKind::WindowsStackQualificationProgress,
                &sha,
                raw.as_bytes(),
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    state
        .storage
        .index
        .append_if_absent(IndexEntry {
            ingested_at: Utc::now(),
            schema: PROGRESS_SCHEMA.to_string(),
            provider: None,
            sha256: sha.clone(),
            status: progress
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_string),
            size_bytes: raw.len() as u64,
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(sha, PROGRESS_SCHEMA.to_string())))
}

pub async fn latest_windows_qualification_progress(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let entry = latest_progress_entry(&state).await?;
    let progress = read_progress(&state, &entry.sha256).await?;
    Ok(Json(progress_readback_value(&entry, &progress)))
}

pub async fn windows_qualification_progress_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PROGRESS_SCHEMA);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));

    let mut dashboard_entries = Vec::new();
    let mut running_requests = 0usize;
    let mut completed_requests = 0usize;
    for entry in entries {
        let progress = read_progress(&state, &entry.sha256).await?;
        let state_value = json_str(&progress, "state").unwrap_or("");
        if state_value == "running" {
            running_requests += 1;
        }
        if is_completed_state(state_value) {
            completed_requests += 1;
        }
        dashboard_entries.push(json!({
            "sha256": entry.sha256,
            "ingested_at": entry.ingested_at,
            "request_id": json_str(&progress, "request_id").unwrap_or(""),
            "profile_digest": json_str(&progress, "profile_digest").unwrap_or(""),
            "state": state_value,
            "completed_shards": json_u64(&progress, "completed_shards").unwrap_or(0),
            "total_shards": json_u64(&progress, "total_shards").unwrap_or(0),
            "updated_at": json_str(&progress, "updated_at").unwrap_or(""),
            "links": {
                "readback": format!("/api/v1/windows/qualification/progress/{}", entry.sha256),
                "latest": "/api/v1/windows/qualification/progress/latest",
            }
        }));
    }

    Ok(Json(json!({
        "schema_version": PROGRESS_DASHBOARD_SCHEMA,
        "generated_at": Utc::now(),
        "summary": {
            "total_progress_records": dashboard_entries.len(),
            "running_requests": running_requests,
            "completed_requests": completed_requests,
            "read_only_observer": true,
            "stores_credentials": false,
            "mutates_ao2_artifacts": false,
            "control_plane_approves_release": false,
        },
        "entries": dashboard_entries,
    })))
}

pub async fn get_windows_qualification_progress(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::WindowsStackQualificationProgress, &sha)
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
        .read(BundleKind::WindowsStackQualificationProgress, &sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let value: Value =
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

pub async fn head_windows_qualification_progress(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::WindowsStackQualificationProgress, &sha)
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

async fn latest_progress_entry(state: &AppState) -> Result<IndexEntry, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PROGRESS_SCHEMA);
    entries
        .into_iter()
        .max_by_key(|entry| entry.ingested_at)
        .ok_or(AppError::NotFound)
}

async fn read_progress(state: &AppState, sha: &str) -> Result<Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::WindowsStackQualificationProgress, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let progress: Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let actual = sha256_of_canonical(&progress).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    Ok(progress)
}

fn progress_readback_value(entry: &IndexEntry, progress: &Value) -> Value {
    json!({
        "schema_version": PROGRESS_READBACK_SCHEMA,
        "artifact_schema_version": PROGRESS_SCHEMA,
        "sha256": entry.sha256,
        "ingested_at": entry.ingested_at,
        "request_id": progress.get("request_id").cloned().unwrap_or(Value::Null),
        "profile_digest": progress.get("profile_digest").cloned().unwrap_or(Value::Null),
        "source_heads": progress.get("source_heads").cloned().unwrap_or_else(|| json!({})),
        "state": progress.get("state").cloned().unwrap_or(Value::Null),
        "started_at": progress.get("started_at").cloned().unwrap_or(Value::Null),
        "updated_at": progress.get("updated_at").cloned().unwrap_or(Value::Null),
        "elapsed_seconds": progress.get("elapsed_seconds").cloned().unwrap_or(Value::Null),
        "completed_shards": progress.get("completed_shards").cloned().unwrap_or(Value::Null),
        "total_shards": progress.get("total_shards").cloned().unwrap_or(Value::Null),
        "current_shards": progress.get("current_shards").cloned().unwrap_or_else(|| json!([])),
        "last_completed_shard": progress.get("last_completed_shard").cloned().unwrap_or(Value::Null),
        "cache_hits": progress.get("cache_hits").cloned().unwrap_or(Value::Null),
        "cache_misses": progress.get("cache_misses").cloned().unwrap_or(Value::Null),
        "bounded_eta_seconds_or_unknown": progress
            .get("bounded_eta_seconds_or_unknown")
            .cloned()
            .unwrap_or(Value::Null),
        "global_deadline_at": progress.get("global_deadline_at").cloned().unwrap_or(Value::Null),
        "release_readiness": false,
        "control_plane_readback": {
            "role": "read_only_observer",
            "requires_credentials": false,
            "can_mutate_ao2_artifacts": false,
            "can_mutate_release_metadata": false,
            "can_claim_release_readiness": false,
        },
        "trust_boundary": {
            "read_only": true,
            "stores_credentials": false,
            "mutates_releases": false,
            "control_plane_approves_release": false,
        },
        "links": {
            "raw_progress": format!("/api/v1/windows/qualification/progress/{}", entry.sha256),
            "dashboard": "/api/v1/windows/qualification/progress/dashboard.json",
        },
    })
}

fn validate_progress(progress: &Value) -> Result<(), AppError> {
    let schema = json_str(progress, "schema_version").unwrap_or("");
    if schema != PROGRESS_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }

    let mut blockers = Vec::new();
    for field in [
        "request_id",
        "profile_digest",
        "state",
        "started_at",
        "updated_at",
        "global_deadline_at",
    ] {
        if json_str(progress, field).unwrap_or("").trim().is_empty() {
            blockers.push(format!("missing_{field}"));
        }
    }

    if progress
        .get("source_heads")
        .and_then(Value::as_object)
        .is_none_or(|heads| heads.is_empty())
    {
        blockers.push("missing_source_heads".to_string());
    }
    if progress
        .get("current_shards")
        .and_then(Value::as_array)
        .is_none()
    {
        blockers.push("missing_current_shards".to_string());
    }

    for field in [
        "elapsed_seconds",
        "completed_shards",
        "total_shards",
        "cache_hits",
        "cache_misses",
    ] {
        if json_u64(progress, field).is_none() {
            blockers.push(format!("missing_numeric_{field}"));
        }
    }
    if let (Some(completed), Some(total)) = (
        json_u64(progress, "completed_shards"),
        json_u64(progress, "total_shards"),
    ) {
        if completed > total {
            blockers.push("completed_shards_exceeds_total_shards".to_string());
        }
    }

    let readback = progress
        .get("control_plane_readback")
        .unwrap_or(&Value::Null);
    require_false(readback, "requires_credentials", &mut blockers);
    require_false(readback, "can_mutate_ao2_artifacts", &mut blockers);
    require_false(readback, "can_mutate_release_metadata", &mut blockers);
    require_false(readback, "can_claim_release_readiness", &mut blockers);
    require_false(progress, "release_readiness", &mut blockers);

    if blockers.is_empty() {
        Ok(())
    } else {
        Err(AppError::SchemaInvalid(blockers.join(",")))
    }
}

fn require_false(value: &Value, field: &str, blockers: &mut Vec<String>) {
    match value.get(field).and_then(Value::as_bool) {
        Some(false) | None => {}
        Some(true) => blockers.push(field.to_string()),
    }
}

fn is_completed_state(state: &str) -> bool {
    matches!(state, "completed" | "accepted" | "succeeded")
}

fn json_str<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn json_u64(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}
