use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::IngestReceipt;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::error::AppError;
use crate::server::AppState;

const WATCHDOG_PANEL_SCHEMA: &str = "factory-v3/hermes-ao2-watchdog-panel/v1";

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    25
}

pub async fn post_watchdog_panel(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let value = parse_watchdog_panel(raw)?;
    let sha = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::HermesWatchdogPanel, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::HermesWatchdogPanel, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    state
        .storage
        .index
        .append_if_absent(IndexEntry {
            ingested_at: Utc::now(),
            schema: WATCHDOG_PANEL_SCHEMA.to_string(),
            provider: None,
            sha256: sha.clone(),
            status: value
                .get("backend_route")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            size_bytes: raw.len() as u64,
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        WATCHDOG_PANEL_SCHEMA.to_string(),
    )))
}

pub async fn latest_watchdog_panel_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let latest = load_watchdog_panels(&state, 1).await?;
    let Some(entry) = latest.into_iter().next() else {
        return Err(AppError::NotFound);
    };
    Ok(Json(wrap_latest_panel(entry)))
}

pub async fn watchdog_history_json(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = query.limit.clamp(1, 100);
    let entries = load_watchdog_panels(&state, limit).await?;
    Ok(Json(json!({
        "schema_version": "ao2.cp-hermes-watchdog-history.v1",
        "generated_at": Utc::now().to_rfc3339(),
        "control_plane_role": "read-only-observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "total_count": entries.len(),
        "entries": entries,
        "links": {
            "panel_html": "/api/v1/hermes/watchdog/panel",
            "latest_json": "/api/v1/hermes/watchdog/panel/latest.json"
        }
    })))
}

pub async fn watchdog_panel(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let latest = load_watchdog_panels(&state, 1).await?;
    let Some(entry) = latest.into_iter().next() else {
        return Err(AppError::NotFound);
    };
    let body = render_panel_html(&entry);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

fn parse_watchdog_panel(raw: &str) -> Result<serde_json::Value, AppError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AppError::SchemaInvalid("watchdog panel missing schema".to_string()))?;
    if schema != WATCHDOG_PANEL_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }
    Ok(value)
}

async fn load_watchdog_panels(
    state: &AppState,
    limit: usize,
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == WATCHDOG_PANEL_SCHEMA);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));

    let mut panels = Vec::new();
    for entry in entries {
        let bytes = state
            .storage
            .bundles
            .read(BundleKind::HermesWatchdogPanel, &entry.sha256)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let panel: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
        panels.push(json!({
            "sha256": entry.sha256,
            "ingested_at": entry.ingested_at.to_rfc3339(),
            "panel": panel,
        }));
    }

    panels.sort_by(|a, b| {
        let a_ms = a["panel"]["generated_at_ms"].as_i64().unwrap_or_default();
        let b_ms = b["panel"]["generated_at_ms"].as_i64().unwrap_or_default();
        b_ms.cmp(&a_ms).then_with(|| {
            b["ingested_at"]
                .as_str()
                .unwrap_or_default()
                .cmp(a["ingested_at"].as_str().unwrap_or_default())
        })
    });
    panels.truncate(limit);
    Ok(panels)
}

fn wrap_latest_panel(entry: serde_json::Value) -> serde_json::Value {
    json!({
        "schema_version": "ao2.cp-hermes-watchdog-panel-latest.v1",
        "generated_at": Utc::now().to_rfc3339(),
        "control_plane_role": "read-only-observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "trust_boundary": {
            "frontend": "Hermes",
            "trusted_execution": "ao2 local signed evidence and digest replay",
            "governed_backend": "factory-v3 / AO Operator evaluator-closer",
            "observer": "ao2-control-plane"
        },
        "sha256": entry["sha256"],
        "ingested_at": entry["ingested_at"],
        "panel": entry["panel"],
        "links": {
            "panel_html": "/api/v1/hermes/watchdog/panel",
            "history_json": "/api/v1/hermes/watchdog/history.json"
        }
    })
}

fn render_panel_html(entry: &serde_json::Value) -> String {
    let panel = &entry["panel"];
    let selected = &panel["selected_evidence"];
    let trust = &panel["trust_boundary"];
    let selected_path = json_str(selected, "path").unwrap_or("");
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Hermes AO2 Watchdog Panel</title></head>
<body>
<h1>Hermes AO2 Watchdog Panel</h1>
<dl>
<dt>Status</dt><dd>{status}</dd>
<dt>Backend route</dt><dd>{route}</dd>
<dt>Reason</dt><dd>{reason}</dd>
<dt>Selected run</dt><dd>{run}</dd>
<dt>Selected verdict</dt><dd>{verdict}</dd>
<dt>Selected evidence</dt><dd><a href="{evidence_href}">Open selected evidence</a> {evidence}</dd>
<dt>Prompt snapshot</dt><dd>{prompt}</dd>
<dt>Control plane role</dt><dd>{control_plane}</dd>
<dt>Trusted execution</dt><dd>{trusted_execution}</dd>
<dt>Governed backend</dt><dd>{governed_backend}</dd>
</dl>
<p><a href="/api/v1/hermes/watchdog/panel/latest.json">Latest JSON</a></p>
<p><a href="/api/v1/hermes/watchdog/history.json">Decision history JSON</a></p>
</body>
</html>"#,
        status = escape_html(json_str(panel, "watchdog_status").unwrap_or("unknown")),
        route = escape_html(json_str(panel, "backend_route").unwrap_or("unknown")),
        reason = escape_html(json_str(panel, "reason").unwrap_or("unknown")),
        run = escape_html(json_str(selected, "run_id").unwrap_or("unknown")),
        verdict = escape_html(json_str(selected, "verdict").unwrap_or("unknown")),
        evidence_href = escape_html(selected_path),
        evidence = escape_html(selected_path),
        prompt = escape_html(json_str(panel, "prompt_snapshot").unwrap_or("")),
        control_plane = escape_html(
            json_str(trust, "control_plane").unwrap_or("ao2-control-plane read-only observer")
        ),
        trusted_execution = escape_html(json_str(trust, "trusted_execution").unwrap_or("")),
        governed_backend = escape_html(json_str(trust, "governed_backend").unwrap_or("")),
    )
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
