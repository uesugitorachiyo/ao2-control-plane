use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;
use std::sync::Arc;

use crate::server::AppState;

/// Schema tag for the extended healthz payload. Distinct from the
/// liveness `/healthz` (untagged JSON) and the broader
/// `/api/v1/status` (`ao2.cp-status.v1`).
const HEALTHZ_EXTENDED_SCHEMA: &str = "ao2.cp-healthz-extended.v1";

/// Soft cap on index entries; matches the bound used by gc + storage docs.
/// Stored here so `/api/v1/status` can compute retention pressure without
/// coupling to storage-internal constants.
const RETENTION_SOFT_CAP_ENTRIES: u64 = 100_000;

pub async fn healthz() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn readyz(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let data_dir = state.storage.bundles.root();
    let probe = data_dir.join(".readyz-write-probe");
    let storage_writable = match tokio::fs::write(&probe, b"ok").await {
        Ok(()) => {
            let _ = tokio::fs::remove_file(&probe).await;
            true
        }
        Err(_) => false,
    };
    let api_token_configured = !state.api_token.trim().is_empty();
    let ready = storage_writable && api_token_configured && state.max_body_bytes > 0;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "schema_version": "ao2.cp-readiness.v1",
            "status": if ready { "ready" } else { "not_ready" },
            "version": env!("CARGO_PKG_VERSION"),
            "max_body_bytes": state.max_body_bytes,
            "checks": {
                "api_token_configured": api_token_configured,
                "storage_writable": storage_writable,
                "data_dir": data_dir.display().to_string()
            }
        })),
    )
}

/// Slim health surface for dashboards. Token-gated (mounted under
/// `/api/v1/*`). Returns the smallest payload an operator dashboard
/// needs to render "this CP is healthy and has been healthy since X":
/// - `uptime_seconds`: monotonic seconds since process start
/// - `started_at_utc`: wall-clock UTC time the process started
/// - `last_error_utc`: wall-clock UTC time of most recent 4xx/5xx,
///   or `null` if no error has been recorded
/// - `request_count`: total finished requests across all methods
/// - `error_request_count`: 4xx + 5xx subtotal
///
/// Distinct from `/api/v1/status` (broader dashboard payload, includes
/// storage + audit-log internals).
pub async fn healthz_extended(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let started_at_utc = state
        .metrics
        .started_at_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let last_error_utc = state
        .metrics
        .last_error_utc()
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    Json(json!({
        "schema_version": HEALTHZ_EXTENDED_SCHEMA,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.metrics.uptime_seconds(),
        "started_at_utc": started_at_utc,
        "last_error_utc": last_error_utc,
        "request_count": state.metrics.total_requests(),
        "error_request_count": state.metrics.error_request_count(),
    }))
}

/// Structured status report for operators and dashboards. Token-gated
/// (mounted under `/api/v1/*`). Returns a single JSON document tagged
/// with `ao2.cp-status.v1` covering build info, storage stats, retention
/// pressure, request totals, and process uptime.
///
/// Distinct from `/healthz` (binary liveness, no auth) and `/readyz`
/// (binary readiness probe, no auth) — this endpoint is the
/// human-and-dashboard read of the same underlying state.
pub async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let index_entries = state
        .storage
        .index
        .read_all()
        .await
        .map(|v| v.len() as u64)
        .unwrap_or(0);

    let data_dir = state.storage.bundles.root();
    let data_dir_bytes = directory_size_bytes(data_dir).await;

    let total_requests = state.metrics.total_requests();
    let error_requests = state.metrics.error_requests();
    let in_flight = state.metrics.in_flight_count();
    let duration_sum_seconds = state.metrics.duration_sum_seconds();
    let avg_duration_seconds = if total_requests > 0 {
        duration_sum_seconds / total_requests as f64
    } else {
        0.0
    };
    let error_rate = if total_requests > 0 {
        error_requests as f64 / total_requests as f64
    } else {
        0.0
    };
    let retention_pressure_pct = if RETENTION_SOFT_CAP_ENTRIES > 0 {
        (index_entries as f64 / RETENTION_SOFT_CAP_ENTRIES as f64) * 100.0
    } else {
        0.0
    };

    Json(json!({
        "schema_version": "ao2.cp-status.v1",
        "build": {
            "version": env!("CARGO_PKG_VERSION"),
            "rustc_target": env!("AO2_CP_BUILD_TARGET"),
            "profile": env!("AO2_CP_BUILD_PROFILE"),
        },
        "uptime_seconds": state.metrics.uptime_seconds(),
        "storage": {
            "data_dir": data_dir.display().to_string(),
            "index_entries": index_entries,
            "data_dir_bytes": data_dir_bytes,
        },
        "retention": {
            "soft_cap_index_entries": RETENTION_SOFT_CAP_ENTRIES,
            "pressure_pct": retention_pressure_pct,
        },
        "requests": {
            "total": total_requests,
            "errors_4xx_5xx": error_requests,
            "error_rate": error_rate,
            "in_flight": in_flight,
            "duration_sum_seconds": duration_sum_seconds,
            "avg_duration_seconds": avg_duration_seconds,
        },
        "config": {
            "max_body_bytes": state.max_body_bytes,
        },
        "audit_log": {
            "capacity": state.audit_log.capacity(),
            "buffered": state.audit_log.len(),
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
    }))
}

/// Best-effort recursive size of a directory, in bytes. Symlinks and IO
/// errors during traversal are skipped silently — the status endpoint
/// must never fail just because one file became inaccessible mid-scan.
async fn directory_size_bytes(root: &std::path::Path) -> u64 {
    fn walk(p: &std::path::Path) -> u64 {
        let mut total = 0u64;
        let Ok(read) = std::fs::read_dir(p) else {
            return 0;
        };
        for entry in read.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                total = total.saturating_add(walk(&entry.path()));
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
        total
    }
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || walk(&root))
        .await
        .unwrap_or(0)
}
