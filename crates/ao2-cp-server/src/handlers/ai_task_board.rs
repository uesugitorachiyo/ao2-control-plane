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

const AI_TASK_BOARD_SCHEMA: &str = "ao2.ai-task-board.v1";
const AI_TASK_BOARD_READBACK_SCHEMA: &str = "ao2.cp-ai-task-board-readback.v1";
const AI_TASK_BOARD_DASHBOARD_SCHEMA: &str = "ao2.cp-ai-task-board-dashboard.v1";

pub async fn post_ai_task_board(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let board: Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_ai_task_board(&board)?;

    let sha = sha256_of_canonical(&board).map_err(|e| AppError::Internal(e.to_string()))?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::AiTaskBoard, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::AiTaskBoard, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    state
        .storage
        .index
        .append_if_absent(IndexEntry {
            ingested_at: Utc::now(),
            schema: AI_TASK_BOARD_SCHEMA.to_string(),
            provider: None,
            sha256: sha.clone(),
            status: board
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string),
            size_bytes: raw.len() as u64,
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        AI_TASK_BOARD_SCHEMA.to_string(),
    )))
}

pub async fn latest_ai_task_board(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let entry = latest_ai_task_board_entry(&state).await?;
    let board = read_ai_task_board(&state, &entry.sha256).await?;
    Ok(Json(ai_task_board_readback_value(&entry, &board)))
}

pub async fn ai_task_board_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == AI_TASK_BOARD_SCHEMA);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));

    let mut dashboard_entries = Vec::new();
    let mut total_tasks = 0usize;
    for entry in entries {
        let board = read_ai_task_board(&state, &entry.sha256).await?;
        let task_count = task_count(&board);
        total_tasks += task_count;
        dashboard_entries.push(json!({
            "sha256": entry.sha256,
            "ingested_at": entry.ingested_at,
            "status": entry.status,
            "release_objective": json_str(&board, "release_objective").unwrap_or(""),
            "release_train": board.get("release_train").cloned().unwrap_or(Value::Null),
            "task_count": task_count,
            "links": {
                "readback": format!("/api/v1/ai/task-board/{}", entry.sha256),
                "latest": "/api/v1/ai/task-board/latest",
            }
        }));
    }

    Ok(Json(json!({
        "schema_version": AI_TASK_BOARD_DASHBOARD_SCHEMA,
        "generated_at": Utc::now(),
        "summary": {
            "total_boards": dashboard_entries.len(),
            "total_tasks": total_tasks,
            "read_only_observer": true,
            "stores_credentials": false,
            "mutates_releases": false,
            "control_plane_approves_release": false,
        },
        "entries": dashboard_entries,
    })))
}

pub async fn get_ai_task_board(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::AiTaskBoard, &sha)
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
        .read(BundleKind::AiTaskBoard, &sha)
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

pub async fn head_ai_task_board(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::AiTaskBoard, &sha)
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

async fn latest_ai_task_board_entry(state: &AppState) -> Result<IndexEntry, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == AI_TASK_BOARD_SCHEMA);
    entries
        .into_iter()
        .max_by_key(|entry| entry.ingested_at)
        .ok_or(AppError::NotFound)
}

async fn read_ai_task_board(state: &AppState, sha: &str) -> Result<Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::AiTaskBoard, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let board: Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let actual = sha256_of_canonical(&board).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    Ok(board)
}

fn ai_task_board_readback_value(entry: &IndexEntry, board: &Value) -> Value {
    json!({
        "schema_version": AI_TASK_BOARD_READBACK_SCHEMA,
        "artifact_schema_version": AI_TASK_BOARD_SCHEMA,
        "sha256": entry.sha256,
        "ingested_at": entry.ingested_at,
        "status": board.get("status").cloned().unwrap_or(Value::Null),
        "release_objective": json_str(board, "release_objective").unwrap_or(""),
        "source_recommendation": json_str(board, "source_recommendation").unwrap_or(""),
        "release_train": board.get("release_train").cloned().unwrap_or(Value::Null),
        "task_count": task_count(board),
        "tasks": board.get("tasks").cloned().unwrap_or_else(|| json!([])),
        "control_plane_readback": {
            "role": board
                .get("control_plane_readback")
                .and_then(|value| json_str(value, "role"))
                .unwrap_or("read_only_observer"),
            "requires_credentials": false,
            "can_mutate_ao2_artifacts": false,
            "can_mutate_release_metadata": false,
        },
        "trust_boundary": {
            "read_only": true,
            "local_only": board
                .get("trust_boundary")
                .and_then(|value| json_bool(value, "local_only"))
                .unwrap_or(true),
            "stores_credentials": false,
            "mutates_releases": false,
            "control_plane_approves_release": false,
        },
        "links": {
            "raw_task_board": format!("/api/v1/ai/task-board/{}", entry.sha256),
            "dashboard": "/api/v1/ai/task-board/dashboard.json",
        },
    })
}

fn validate_ai_task_board(board: &Value) -> Result<(), AppError> {
    let schema = json_str(board, "schema_version").unwrap_or("");
    if schema != AI_TASK_BOARD_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }

    let mut blockers = Vec::new();
    if json_str(board, "release_objective")
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        blockers.push("missing_release_objective".to_string());
    }

    let tasks: &[Value] = match board.get("tasks").and_then(Value::as_array) {
        Some(tasks) if !tasks.is_empty() => tasks,
        _ => {
            blockers.push("missing_tasks".to_string());
            &[]
        }
    };
    for (idx, task) in tasks.iter().enumerate() {
        let task_id = json_str(task, "task_id")
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("task-{idx}"));
        if !nonempty_string_array(task, "required_evidence") {
            blockers.push(format!("task_missing_required_evidence:{task_id}"));
        }
        if !nonempty_string_array(task, "stop_conditions") {
            blockers.push(format!("task_missing_stop_conditions:{task_id}"));
        }
    }

    let readback = board.get("control_plane_readback").unwrap_or(&Value::Null);
    require_false(readback, "requires_credentials", &mut blockers);
    require_false(readback, "can_mutate_ao2_artifacts", &mut blockers);
    require_false(readback, "can_mutate_release_metadata", &mut blockers);

    let trust_boundary = board.get("trust_boundary").unwrap_or(&Value::Null);
    require_false(trust_boundary, "stores_credentials", &mut blockers);
    require_false(trust_boundary, "mutates_releases", &mut blockers);

    if blockers.is_empty() {
        Ok(())
    } else {
        Err(AppError::SchemaInvalid(blockers.join(",")))
    }
}

fn require_false(value: &Value, field: &str, blockers: &mut Vec<String>) {
    match value.get(field).and_then(Value::as_bool) {
        Some(false) => {}
        _ => blockers.push(field.to_string()),
    }
}

fn nonempty_string_array(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.as_str().is_some_and(|s| !s.trim().is_empty()))
        })
}

fn task_count(board: &Value) -> usize {
    board
        .get("tasks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn json_str<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn json_bool(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}
