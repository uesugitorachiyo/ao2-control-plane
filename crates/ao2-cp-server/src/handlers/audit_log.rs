//! `GET /api/v1/audit-log` — token-gated read of the in-process
//! bounded ring buffer of recent requests.
//!
//! See [`crate::audit_log`] for the buffer's trust-boundary discussion.
//! This handler is a thin filter/serialize layer on top of
//! [`AuditLog::snapshot`].

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::IntoResponse,
    Json,
};
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};

use crate::audit_log::AuditEntry;
use crate::server::AppState;

/// Hard ceiling on how many entries one response may contain.
/// Defends against pathological `?limit=...` values forcing large JSON
/// responses even though the in-memory buffer itself is bounded.
const MAX_RESPONSE_ENTRIES: usize = 1024;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditLogQuery {
    /// Max entries to return. Clamped to [1, MAX_RESPONSE_ENTRIES].
    pub limit: Option<usize>,
    /// Only return entries whose `timestamp_unix_micros >=` this value.
    pub since_unix_micros: Option<u64>,
    /// Exact HTTP method match (case-insensitive, e.g. `GET`, `POST`).
    pub method: Option<String>,
    /// Exact status code match (e.g. `200`, `404`).
    pub status: Option<u16>,
    /// Status class match: `2xx`, `3xx`, `4xx`, `5xx`.
    pub status_class: Option<String>,
    /// Match entries whose `path` starts with this prefix.
    pub path_prefix: Option<String>,
    /// Restrict to authenticated (`true`) or unauthenticated (`false`)
    /// requests.
    pub authenticated: Option<bool>,
}

pub async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditLogQuery>,
) -> Json<Value> {
    let snapshot = state.audit_log.snapshot();
    let total = snapshot.len();
    let capacity = state.audit_log.capacity();

    let class_filter = q.status_class.as_deref().and_then(class_bucket);
    let method_filter = q.method.as_deref().map(str::to_ascii_uppercase);

    // Newest-first is what an operator scanning the dashboard wants.
    let filtered: Vec<&AuditEntry> = snapshot
        .iter()
        .rev()
        .filter(|e| matches_filters(e, &q, class_filter, method_filter.as_deref()))
        .collect();
    let filtered_total = filtered.len();

    let limit = q.limit.unwrap_or(100).clamp(1, MAX_RESPONSE_ENTRIES);
    let entries: Vec<&AuditEntry> = filtered.into_iter().take(limit).collect();

    Json(json!({
        "schema_version": "ao2.cp-audit-log.v1",
        "buffer": {
            "capacity": capacity,
            "total_buffered": total,
            "total_appended_since_boot": state.audit_log.total_appended_since_boot(),
            "persistence": {
                "enabled": state.audit_log.persistence_path().is_some(),
                "path": state.audit_log.persistence_path().map(|p| p.display().to_string()),
                "last_error": state.audit_log.persistence_last_error(),
                "rotation": {
                    "max_bytes": state.audit_log.rotation_max_bytes(),
                    "count": state.audit_log.rotation_count(),
                    "last_rotated_unix_micros": state.audit_log.last_rotated_unix_micros(),
                },
            },
        },
        "filtered_total": filtered_total,
        "returned": entries.len(),
        "limit": limit,
        "entries": entries,
    }))
}

pub(crate) fn matches_filters(
    e: &AuditEntry,
    q: &AuditLogQuery,
    class_filter: Option<(u16, u16)>,
    method_filter: Option<&str>,
) -> bool {
    if let Some(since) = q.since_unix_micros {
        if e.timestamp_unix_micros < since {
            return false;
        }
    }
    if let Some(m) = method_filter {
        if !e.method.eq_ignore_ascii_case(m) {
            return false;
        }
    }
    if let Some(s) = q.status {
        if e.status != s {
            return false;
        }
    }
    if let Some((lo, hi)) = class_filter {
        if e.status < lo || e.status > hi {
            return false;
        }
    }
    if let Some(p) = q.path_prefix.as_deref() {
        if !e.path.starts_with(p) {
            return false;
        }
    }
    if let Some(a) = q.authenticated {
        if e.authenticated != a {
            return false;
        }
    }
    true
}

/// Map a status_class shorthand to an inclusive (lo, hi) status range.
/// Returns `None` for unknown shorthands so the filter is treated as
/// a no-op rather than silently matching nothing.
pub(crate) fn class_bucket(s: &str) -> Option<(u16, u16)> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1xx" => Some((100, 199)),
        "2xx" => Some((200, 299)),
        "3xx" => Some((300, 399)),
        "4xx" => Some((400, 499)),
        "5xx" => Some((500, 599)),
        _ => None,
    }
}

const AUDIT_LOG_DASHBOARD_SCHEMA: &str = "ao2.cp-audit-log-dashboard.v1";

/// Build the structured JSON document that the HTML dashboard renders
/// from. Kept as a separate function so `/api/v1/audit-log/dashboard.json`
/// can serve the same shape directly and dashboard-aggregator scripts
/// can consume a stable schema without HTML-scraping.
pub async fn audit_log_dashboard_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditLogQuery>,
) -> Json<Value> {
    Json(audit_log_dashboard_value(&state, &q))
}

fn audit_log_dashboard_value(state: &AppState, q: &AuditLogQuery) -> Value {
    let snapshot = state.audit_log.snapshot();
    let total = snapshot.len();
    let capacity = state.audit_log.capacity();
    let class_filter = q.status_class.as_deref().and_then(class_bucket);
    let method_filter = q.method.as_deref().map(str::to_ascii_uppercase);
    let filtered: Vec<&AuditEntry> = snapshot
        .iter()
        .rev()
        .filter(|e| matches_filters(e, q, class_filter, method_filter.as_deref()))
        .collect();
    let filtered_total = filtered.len();
    let limit = q.limit.unwrap_or(100).clamp(1, MAX_RESPONSE_ENTRIES);
    let entries: Vec<&AuditEntry> = filtered.into_iter().take(limit).collect();

    json!({
        "schema_version": AUDIT_LOG_DASHBOARD_SCHEMA,
        "buffer": {
            "capacity": capacity,
            "total_buffered": total,
            "total_appended_since_boot": state.audit_log.total_appended_since_boot(),
            "persistence": {
                "enabled": state.audit_log.persistence_path().is_some(),
                "path": state.audit_log.persistence_path().map(|p| p.display().to_string()),
                "last_error": state.audit_log.persistence_last_error(),
                "rotation": {
                    "max_bytes": state.audit_log.rotation_max_bytes(),
                    "count": state.audit_log.rotation_count(),
                    "last_rotated_unix_micros": state.audit_log.last_rotated_unix_micros(),
                },
            },
        },
        "filtered_total": filtered_total,
        "returned": entries.len(),
        "limit": limit,
        "links": {
            "dashboard": "/api/v1/audit-log/dashboard",
            "dashboard_json": "/api/v1/audit-log/dashboard.json",
            "audit_log_json": "/api/v1/audit-log",
            "status_json": "/api/v1/status",
        },
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "local_credentials": "OAuth/CLI/local AO2_CP_API_TOKEN only; no provider API-key authentication",
            "release_approval_owner": "factory-v3 evaluator-closer",
        },
        "entries": entries,
    })
}

/// `GET /api/v1/audit-log/dashboard` — token-gated HTML view of the
/// audit-log ring buffer for human operators.
///
/// # Trust boundary preserved
///
/// The bearer token is not rendered into the HTML. Only the metadata
/// already exposed by [`AuditLog::snapshot`] reaches the page. The
/// `path`, `method`, `status`, and other fields are escaped through
/// [`escape_html`] before being interpolated so a malicious upstream
/// path containing HTML can't break out of its cell.
pub async fn audit_log_dashboard(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let dashboard = audit_log_dashboard_value(&state, &q);

    let buffer = dashboard.get("buffer").cloned().unwrap_or(json!({}));
    let persistence = buffer.get("persistence").cloned().unwrap_or(json!({}));
    let rotation = persistence.get("rotation").cloned().unwrap_or(json!({}));
    let entries = dashboard
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut rows = String::new();
    for entry in &entries {
        let timestamp = json_u64(entry, "timestamp_unix_micros");
        let method = escape_html(json_str(entry, "method").unwrap_or("?"));
        let path = escape_html(json_str(entry, "path").unwrap_or("?"));
        let status = json_u64(entry, "status");
        let duration = json_u64(entry, "duration_micros");
        let auth_attempted = entry
            .get("auth_attempted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let authenticated = entry
            .get("authenticated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let status_class = match status {
            100..=199 => "info",
            200..=299 => "ok",
            300..=399 => "warn",
            400..=499 => "bad",
            500..=599 => "bad",
            _ => "muted",
        };
        let auth_label = match (auth_attempted, authenticated) {
            (true, true) => "<span class=\"ok\">authenticated</span>",
            (true, false) => "<span class=\"bad\">rejected</span>",
            (false, _) => "<span class=\"muted\">none</span>",
        };
        rows.push_str(&format!(
            "<tr><td>{timestamp}</td><td>{method}</td><td><code>{path}</code></td><td class=\"{status_class}\">{status}</td><td>{duration}</td><td>{auth_label}</td></tr>"
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No buffered audit-log entries (yet).</td></tr>",
        );
    }

    let persistence_enabled = persistence
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let persistence_path = escape_html(json_str(&persistence, "path").unwrap_or("(disabled)"));
    let persistence_last_error_raw = json_str(&persistence, "last_error").unwrap_or("");
    let persistence_last_error_label = if persistence_last_error_raw.is_empty() {
        "<span class=\"ok\">none</span>".to_string()
    } else {
        format!(
            "<span class=\"bad\">{}</span>",
            escape_html(persistence_last_error_raw)
        )
    };
    let persistence_enabled_class = if persistence_enabled { "ok" } else { "muted" };
    let persistence_enabled_label = if persistence_enabled {
        "enabled"
    } else {
        "disabled"
    };

    let rotation_max_bytes_label = rotation
        .get("max_bytes")
        .and_then(serde_json::Value::as_u64)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "(no rotation configured)".to_string());
    let rotation_count = json_u64(&rotation, "count");
    let rotation_last_label = rotation
        .get("last_rotated_unix_micros")
        .and_then(serde_json::Value::as_u64)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "never".to_string());

    let capacity = json_u64(&buffer, "capacity");
    let buffered = json_u64(&buffer, "total_buffered");
    let total_appended = json_u64(&buffer, "total_appended_since_boot");
    let filtered_total = json_u64(&dashboard, "filtered_total");
    let returned = json_u64(&dashboard, "returned");
    let limit = json_u64(&dashboard, "limit");

    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Control Plane Audit Log</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:96rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(20rem,1fr));gap:1rem;margin:1rem 0}}.card{{border:1px solid #ddd;border-radius:.5rem;padding:.75rem 1rem;background:#fafafa}}.card h3{{margin:0 0 .5rem 0;font-size:1rem}}.ok{{color:#0a7f28}}.warn{{color:#9a5b00}}.bad{{color:#b00020}}.info{{color:#1565c0}}.muted{{color:#666}}.links a{{margin-right:1rem}}</style></head><body><main><h1>AO2 Control Plane Audit Log</h1><p>Read-only observer dashboard for recent HTTP requests against the control plane. The ring buffer is bounded; the persistence file (if configured) is the durable record. This page never renders the bearer token — only request metadata (method, path, status, duration, auth outcome).</p><p class=\"links\"><a href=\"/api/v1/audit-log/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/audit-log\">Audit-log JSON</a> · <a href=\"/api/v1/status\">Status JSON</a></p><section><h2>Buffer Telemetry</h2><div class=\"cards\"><div class=\"card\"><h3>Ring Buffer</h3><dl><dt>Capacity</dt><dd>{capacity}</dd><dt>Buffered now</dt><dd>{buffered}</dd><dt>Total since boot</dt><dd>{total_appended}</dd></dl></div><div class=\"card\"><h3>Persistence</h3><dl><dt>State</dt><dd class=\"{persistence_enabled_class}\">{persistence_enabled_label}</dd><dt>Path</dt><dd><code>{persistence_path}</code></dd><dt>Last error</dt><dd>{persistence_last_error_label}</dd></dl></div><div class=\"card\"><h3>Rotation</h3><dl><dt>Max bytes</dt><dd>{rotation_max_bytes_label}</dd><dt>Count since boot</dt><dd>{rotation_count}</dd><dt>Last rotated (μs)</dt><dd>{rotation_last_label}</dd></dl></div><div class=\"card\"><h3>Filtering</h3><dl><dt>Filtered total</dt><dd>{filtered_total}</dd><dt>Returned</dt><dd>{returned}</dd><dt>Limit</dt><dd>{limit}</dd></dl></div></div></section><section><h2>Recent Requests (newest first)</h2><table><thead><tr><th>Timestamp (μs)</th><th>Method</th><th>Path</th><th>Status</th><th>Duration (μs)</th><th>Auth</th></tr></thead><tbody>{rows}</tbody></table></section><section><h2>Trust Boundary</h2><dl><dt>Role</dt><dd class=\"ok\">read-only observer</dd><dt>Mutates AO artifacts</dt><dd class=\"ok\">false</dd><dt>Local credentials</dt><dd>OAuth/CLI/local <code>AO2_CP_API_TOKEN</code> only — no provider API-key authentication</dd><dt>Release approval owner</dt><dd>factory-v3 evaluator-closer</dd></dl></section></main></body></html>"
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Heartbeat interval for the SSE stream. Sends a `:` comment line on
/// each tick so reverse proxies and EventSource clients can detect a
/// dead connection promptly without piling up idle keepalives. 15 s is
/// short enough that most proxy idle timers stay below their default
/// 60–120 s cutoff and long enough that an idle stream doesn't
/// churn the wire.
const STREAM_KEEPALIVE_SECS: u64 = 15;

/// `GET /api/v1/audit-log/stream` — token-gated server-sent-events
/// stream of audit-log entries as they are appended.
///
/// Each entry is rendered as one SSE event:
///
/// ```text
/// id: <timestamp_unix_micros>
/// event: audit-log
/// data: {"timestamp_unix_micros":...,"method":"GET",...}
///
/// ```
///
/// `Last-Event-ID` (or the equivalent `last_event_id` query param —
/// curl users find the query form less awkward than constructing a
/// custom header) replays buffered entries strictly newer than the
/// supplied ID before the live tail starts, giving an EventSource
/// client an automatic resume on reconnect. Filter query params
/// (`method`, `status`, `status_class`, `path_prefix`,
/// `authenticated`, `since_unix_micros`) match the JSON
/// `/api/v1/audit-log` semantics one-for-one.
///
/// # Backpressure
///
/// The broadcast channel is bounded ([`STREAM_BROADCAST_CAPACITY`]).
/// A subscriber that can't keep up observes
/// `BroadcastStreamRecvError::Lagged(n)`, which we render as a
/// `event: lagged` SSE event with the gap size as data. Clients
/// should respond by polling `/api/v1/audit-log?since_unix_micros=<id>`
/// to backfill, then continue streaming.
///
/// # Trust boundary
///
/// The bearer token is not echoed into any SSE event — entries on the
/// stream carry the same fields as the JSON surface, which never
/// included the `Authorization` header value to begin with.
pub async fn audit_log_stream(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditLogStreamQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // The EventSource API auto-sets `Last-Event-ID` on reconnect; a
    // curl-style consumer can pass `last_event_id` as a query param
    // instead because crafting a custom header in shell pipelines is
    // awkward. Query param wins on collision.
    let resume_from = q.last_event_id.or_else(|| {
        headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
    });

    // Snapshot the filter parameters up front so the streaming
    // closure does not have to clone the full Query on every entry.
    let filter = q.filter.clone();
    let class_filter = filter.status_class.as_deref().and_then(class_bucket);
    let method_filter = filter.method.as_deref().map(str::to_ascii_uppercase);

    // Optional resume tail: replay buffered entries strictly newer
    // than the supplied event ID. We snapshot the ring buffer once
    // here; entries arriving between the snapshot and the live
    // subscription are still delivered via the broadcast channel
    // because we subscribe BEFORE iterating the snapshot.
    let rx = state.audit_log.subscribe();
    let resume_entries: Vec<AuditEntry> = match resume_from {
        Some(last_id) => {
            let snapshot = state.audit_log.snapshot();
            let f = filter.clone();
            let mf = method_filter.clone();
            snapshot
                .into_iter()
                .filter(|e| e.timestamp_unix_micros > last_id)
                .filter(|e| matches_filters(e, &f, class_filter, mf.as_deref()))
                .collect()
        }
        None => Vec::new(),
    };

    let resume_stream = stream::iter(
        resume_entries
            .into_iter()
            .map(|e| Ok::<Event, Infallible>(entry_to_sse_event(e))),
    );

    let live_stream = BroadcastStream::new(rx).filter_map(move |res| {
        let filter = filter.clone();
        let method_filter = method_filter.clone();
        async move {
            match res {
                Ok(entry) => {
                    if matches_filters(&entry, &filter, class_filter, method_filter.as_deref()) {
                        Some(Ok::<Event, Infallible>(entry_to_sse_event(entry)))
                    } else {
                        None
                    }
                }
                Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok::<Event, Infallible>(
                    // Subscriber fell behind by `n` entries. Emit a
                    // `lagged` SSE event so the client can fall back
                    // to /api/v1/audit-log polling for the gap.
                    Event::default().event("lagged").data(n.to_string()),
                )),
            }
        }
    });

    let merged = resume_stream.chain(live_stream);
    Sse::new(merged).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(STREAM_KEEPALIVE_SECS))
            .text(""),
    )
}

fn entry_to_sse_event(entry: AuditEntry) -> Event {
    let id = entry.timestamp_unix_micros.to_string();
    // serde_json::to_string on the AuditEntry never fails because the
    // struct's fields are all primitive serde-derived; if it did, an
    // empty data line is a safe degraded surface.
    let data = serde_json::to_string(&entry).unwrap_or_default();
    Event::default().id(id).event("audit-log").data(data)
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditLogStreamQuery {
    /// Resume from the supplied event ID (timestamp_unix_micros).
    /// Equivalent to the SSE `Last-Event-ID` header but works from
    /// shell pipelines that find custom headers awkward.
    pub last_event_id: Option<u64>,
    /// Filter parameters shared with `/api/v1/audit-log`.
    #[serde(flatten)]
    pub filter: AuditLogQuery,
}
