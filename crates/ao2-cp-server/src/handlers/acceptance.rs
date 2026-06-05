use ao2_cp_schema::acceptance::{parse_acceptance, AcceptanceProvider};
use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::{
    AcceptanceListEntry, AcceptanceListResponse, IngestReceipt, SCHEMA_ACCEPTANCE_LIST,
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
use serde::Deserialize;
use std::sync::Arc;

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;

const ACCEPTANCE_DASHBOARD_SCHEMA: &str = "ao2.cp-acceptance-dashboard.v1";

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_limit() -> usize {
    50
}

pub async fn post_acceptance(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let bundle = parse_acceptance(raw).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown schema_version") {
            AppError::SchemaUnknown(msg)
        } else {
            AppError::SchemaInvalid(msg)
        }
    })?;

    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let sha = sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))?;

    let kind = match bundle.provider {
        AcceptanceProvider::Codex => BundleKind::AcceptanceCodex,
        AcceptanceProvider::Claude => BundleKind::AcceptanceClaude,
        AcceptanceProvider::Antigravity => BundleKind::AcceptanceAntigravity,
    };

    let already = state.storage.bundles.exists(kind, &sha).await;
    if !already {
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
        provider: Some(bundle.provider.as_str().to_string()),
        sha256: sha.clone(),
        status: Some(bundle.status.clone()),
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

pub async fn list_acceptance(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<AcceptanceListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    all.retain(|e| e.schema.contains("acceptance"));
    if let Some(p) = &q.provider {
        all.retain(|e| e.provider.as_deref() == Some(p.as_str()));
    }
    if let Some(since) = q.since {
        all.retain(|e| e.ingested_at >= since);
    }
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));
    let total_count = all.len();
    let limit = q.limit.min(500);
    let entries: Vec<AcceptanceListEntry> = all
        .into_iter()
        .skip(q.offset)
        .take(limit)
        .map(|e| AcceptanceListEntry {
            sha256: e.sha256,
            provider: e.provider.unwrap_or_default(),
            status: e.status.unwrap_or_default(),
            ingested_at: e.ingested_at,
            size_bytes: e.size_bytes,
            schema_version: e.schema,
        })
        .collect();

    Ok(Json(AcceptanceListResponse {
        schema_version: SCHEMA_ACCEPTANCE_LIST.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn acceptance_dashboard(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let dashboard = acceptance_dashboard_value(&state, &q).await?;
    let entries = dashboard
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for entry in entries {
        let sha = json_str(&entry, "sha256").unwrap_or("unknown");
        let short = sha.get(..12).unwrap_or(sha);
        rows.push_str(&format!(
            "<tr><td><a href=\"/api/v1/acceptance/{sha}\"><code>{short}</code></a></td><td>{provider}</td><td>{status}</td><td>{source_class}</td><td>{score}</td><td>{run_id}</td><td>{ingested_at}</td></tr>",
            sha = escape_html(sha),
            short = escape_html(short),
            provider = escape_html(json_str(&entry, "provider").unwrap_or("unknown")),
            status = escape_html(json_str(&entry, "status").unwrap_or("unknown")),
            source_class = escape_html(json_str(&entry, "source_class").unwrap_or("unknown")),
            score = entry.get("score").and_then(serde_json::Value::as_u64).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
            run_id = escape_html(json_str(&entry, "run_id").unwrap_or("unknown")),
            ingested_at = escape_html(json_str(&entry, "ingested_at").unwrap_or("unknown")),
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"7\">No provider-pilot acceptance evidence ingested.</td></tr>",
        );
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Provider Pilot Acceptance</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:84rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}</style></head><body><main><h1>AO2 Provider Pilot Acceptance</h1><p>Read-only observer dashboard. The control plane stores accepted pilot evidence but never starts providers or approves AO2 runs.</p><p><a href=\"/api/v1/acceptance/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/provider/readiness/dashboard\">Provider Readiness</a> · <a href=\"/api/v1/evidence-pack/dashboard\">Signed Evidence</a></p><section><h2>Acceptance Trend</h2><dl><dt>Total</dt><dd>{total_count}</dd><dt>Passed</dt><dd>{passed_count}</dd><dt>Live</dt><dd>{live_count}</dd><dt>Fixture</dt><dd>{fixture_count}</dd><dt>Latest Codex</dt><dd>{latest_codex}</dd><dt>Latest Claude</dt><dd>{latest_claude}</dd><dt>Latest Antigravity</dt><dd>{latest_antigravity}</dd></dl></section><section><h2>Phase 1 Acceptance</h2><dl><dt>State</dt><dd>{phase1_acceptance_state}</dd></dl></section><table><thead><tr><th>SHA256</th><th>Provider</th><th>Status</th><th>Source</th><th>Score</th><th>Run</th><th>Ingested</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        total_count = dashboard
            .get("total_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        passed_count = dashboard
            .get("passed_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        live_count = dashboard
            .get("source_class_counts")
            .and_then(|value| value.get("live"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        fixture_count = dashboard
            .get("source_class_counts")
            .and_then(|value| value.get("fixture"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        latest_codex = escape_html(
            dashboard
                .get("latest_by_provider")
                .and_then(|value| value.get("codex"))
                .and_then(|value| value.get("sha256"))
                .and_then(serde_json::Value::as_str)
                .and_then(|sha| sha.get(..12))
                .unwrap_or("none")
        ),
        latest_claude = escape_html(
            dashboard
                .get("latest_by_provider")
                .and_then(|value| value.get("claude"))
                .and_then(|value| value.get("sha256"))
                .and_then(serde_json::Value::as_str)
                .and_then(|sha| sha.get(..12))
                .unwrap_or("none")
        ),
        latest_antigravity = escape_html(
            dashboard
                .get("latest_by_provider")
                .and_then(|value| value.get("antigravity"))
                .and_then(|value| value.get("sha256"))
                .and_then(serde_json::Value::as_str)
                .and_then(|sha| sha.get(..12))
                .unwrap_or("none")
        ),
        phase1_acceptance_state = escape_html(
            dashboard
                .get("phase1_acceptance")
                .and_then(|value| value.get("state"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
        ),
        rows = rows,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn acceptance_dashboard_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(acceptance_dashboard_value(&state, &q).await?))
}

pub async fn get_acceptance(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    let kind = acceptance_kind_for_sha(&state, &sha).await?;
    let etag = caching::format_etag(&sha);
    if caching::etag_matches(&headers, &etag) {
        return Ok(caching::not_modified_response(&etag));
    }
    let bytes = state
        .storage
        .bundles
        .read(kind, &sha)
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

/// HEAD-equivalent: ETag + Cache-Control, no body. Supports
/// `If-None-Match` → 304 short-circuit.
pub async fn head_acceptance(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    let _ = acceptance_kind_for_sha(&state, &sha).await?;
    let etag = caching::format_etag(&sha);
    if caching::etag_matches(&headers, &etag) {
        return Ok(caching::not_modified_response(&etag));
    }
    Ok(caching::cacheable_head_response(&etag))
}

/// Picks the first acceptance BundleKind that contains this sha,
/// returning `AppError::NotFound` if none match.
async fn acceptance_kind_for_sha(state: &AppState, sha: &str) -> Result<BundleKind, AppError> {
    for kind in [
        BundleKind::AcceptanceCodex,
        BundleKind::AcceptanceClaude,
        BundleKind::AcceptanceAntigravity,
    ] {
        if state.storage.bundles.exists(kind, sha).await {
            return Ok(kind);
        }
    }
    Err(AppError::NotFound)
}

async fn acceptance_dashboard_value(
    state: &AppState,
    q: &ListQuery,
) -> Result<serde_json::Value, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema.contains("acceptance"));
    if let Some(p) = &q.provider {
        all.retain(|e| e.provider.as_deref() == Some(p.as_str()));
    }
    if let Some(since) = q.since {
        all.retain(|e| e.ingested_at >= since);
    }
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));
    let total_count = all.len();
    let limit = q.limit.min(500);
    let selected: Vec<IndexEntry> = all.into_iter().skip(q.offset).take(limit).collect();
    let mut entries = Vec::new();
    let mut codex_count = 0_u64;
    let mut claude_count = 0_u64;
    let mut antigravity_count = 0_u64;
    let mut passed_count = 0_u64;
    let mut live_count = 0_u64;
    let mut fixture_count = 0_u64;
    let mut unknown_source_count = 0_u64;
    let mut latest_codex = serde_json::Value::Null;
    let mut latest_claude = serde_json::Value::Null;
    let mut latest_antigravity = serde_json::Value::Null;
    for entry in selected {
        let bundle = read_acceptance_value(state, &entry.sha256).await?;
        let provider = entry.provider.unwrap_or_default();
        if provider == "codex" {
            codex_count += 1;
        }
        if provider == "claude" {
            claude_count += 1;
        }
        if provider == "antigravity" {
            antigravity_count += 1;
        }
        let status = entry.status.unwrap_or_default();
        if status == "passed" {
            passed_count += 1;
        }
        let source_class = acceptance_source_class(&bundle);
        match source_class {
            "live" => live_count += 1,
            "fixture" => fixture_count += 1,
            _ => unknown_source_count += 1,
        }
        let summary = serde_json::json!({
            "sha256": entry.sha256,
            "provider": provider,
            "status": status,
            "source_class": source_class,
            "schema_version": entry.schema,
            "run_id": json_str(&bundle, "run_id").unwrap_or("unknown"),
            "score": acceptance_score(&bundle),
            "minimum_score": bundle
                .get("smoke")
                .and_then(|smoke| smoke.get("minimum_score"))
                .and_then(serde_json::Value::as_u64),
            "evidence_pack": bundle
                .get("evidence_pack")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "raw_url": format!("/api/v1/acceptance/{}", entry.sha256),
            "ingested_at": entry.ingested_at,
            "size_bytes": entry.size_bytes,
        });
        if summary["provider"] == "codex" && latest_codex.is_null() {
            latest_codex = summary.clone();
        }
        if summary["provider"] == "claude" && latest_claude.is_null() {
            latest_claude = summary.clone();
        }
        if summary["provider"] == "antigravity" && latest_antigravity.is_null() {
            latest_antigravity = summary.clone();
        }
        entries.push(summary);
    }
    let phase1_acceptance =
        provider_acceptance_phase1_status(&latest_codex, &latest_claude, &latest_antigravity);
    Ok(serde_json::json!({
        "schema_version": ACCEPTANCE_DASHBOARD_SCHEMA,
        "total_count": total_count,
        "limit": limit,
        "offset": q.offset,
        "passed_count": passed_count,
        "provider_counts": {
            "codex": codex_count,
            "claude": claude_count,
            "antigravity": antigravity_count,
        },
        "source_class_counts": {
            "live": live_count,
            "fixture": fixture_count,
            "unknown": unknown_source_count,
        },
        "latest_by_provider": {
            "codex": latest_codex,
            "claude": latest_claude,
            "antigravity": latest_antigravity,
        },
        "phase1_acceptance": phase1_acceptance,
        "entries": entries,
        "links": {
            "dashboard": "/api/v1/acceptance/dashboard",
            "dashboard_json": "/api/v1/acceptance/dashboard.json",
            "provider_readiness_dashboard": "/api/v1/provider/readiness/dashboard",
            "provider_readiness_dashboard_json": "/api/v1/provider/readiness/dashboard.json",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "evidence_dashboard_json": "/api/v1/evidence-pack/dashboard.json",
        }
    }))
}

fn provider_acceptance_phase1_status(
    latest_codex: &serde_json::Value,
    latest_claude: &serde_json::Value,
    latest_antigravity: &serde_json::Value,
) -> serde_json::Value {
    let codex_ready = live_acceptance_ready(latest_codex);
    let claude_ready = live_acceptance_ready(latest_claude);
    let (state, reason, next_action) = if codex_ready && claude_ready {
        (
            "live_acceptance_complete",
            "live_codex_and_claude_acceptance_passed",
            "review signed evidence and run the guarded release gate before Phase 1 promotion",
        )
    } else {
        (
            "blocked",
            "missing_live_provider_acceptance",
            "publish passing live Codex and Claude provider-pilot acceptance evidence",
        )
    };
    serde_json::json!({
        "state": state,
        "reason": reason,
        "codex": provider_acceptance_state(latest_codex),
        "claude": provider_acceptance_state(latest_claude),
        "antigravity": provider_acceptance_state(latest_antigravity),
        "source_class": if codex_ready && claude_ready { "live" } else { "mixed" },
        "next_action": next_action,
    })
}

fn live_acceptance_ready(entry: &serde_json::Value) -> bool {
    json_str(entry, "status") == Some("passed")
        && json_str(entry, "source_class") == Some("live")
        && entry
            .get("score")
            .and_then(serde_json::Value::as_u64)
            .zip(
                entry
                    .get("minimum_score")
                    .and_then(serde_json::Value::as_u64)
                    .or(Some(90)),
            )
            .map(|(score, minimum)| score >= minimum)
            .unwrap_or(false)
}

fn provider_acceptance_state(entry: &serde_json::Value) -> &'static str {
    if live_acceptance_ready(entry) {
        "passed"
    } else if entry.is_null() {
        "missing"
    } else if json_str(entry, "source_class") != Some("live") {
        "not_live"
    } else {
        "not_ready"
    }
}

async fn read_acceptance_value(state: &AppState, sha: &str) -> Result<serde_json::Value, AppError> {
    for kind in [
        BundleKind::AcceptanceCodex,
        BundleKind::AcceptanceClaude,
        BundleKind::AcceptanceAntigravity,
    ] {
        if state.storage.bundles.exists(kind, sha).await {
            let bytes = state
                .storage
                .bundles
                .read(kind, sha)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            return serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()));
        }
    }
    Err(AppError::NotFound)
}

fn acceptance_source_class(bundle: &serde_json::Value) -> &'static str {
    if let Some(source_class) = json_str(bundle, "source_class") {
        return match source_class {
            "live" => "live",
            "fixture" => "fixture",
            _ => "unknown",
        };
    }
    let root = json_str(bundle, "root").unwrap_or("");
    let target = json_str(bundle, "target").unwrap_or("");
    let evidence_pack = json_str(bundle, "evidence_pack").unwrap_or("");
    if [root, target, evidence_pack]
        .iter()
        .any(|value| provider_acceptance_path(value))
        && !root.starts_with('<')
        && !target.starts_with('<')
        && !evidence_pack.starts_with('<')
    {
        return "live";
    }
    if [root, target, evidence_pack]
        .iter()
        .any(|value| value.starts_with('<') || fixture_path(value))
    {
        return "fixture";
    }
    "unknown"
}

fn provider_acceptance_path(value: &str) -> bool {
    value
        .replace('\\', "/")
        .contains("/target/provider-pilot-acceptance/")
}

fn fixture_path(value: &str) -> bool {
    value.replace('\\', "/").contains("/tests/fixtures/")
}

fn acceptance_score(bundle: &serde_json::Value) -> Option<u64> {
    bundle
        .get("smoke")
        .and_then(|smoke| smoke.get("providers"))
        .and_then(serde_json::Value::as_array)
        .and_then(|providers| {
            let provider = json_str(bundle, "provider")?;
            providers
                .iter()
                .find(|item| json_str(item, "provider") == Some(provider))
                .and_then(|item| item.get("score"))
                .and_then(serde_json::Value::as_u64)
        })
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
