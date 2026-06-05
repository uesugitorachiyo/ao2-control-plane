use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_storage::RetentionPolicy;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::error::AppError;
use crate::server::AppState;

const STORAGE_DASHBOARD_SCHEMA: &str = "ao2.cp-storage-dashboard.v1";

#[derive(Debug, Deserialize)]
pub struct StorageRetentionQuery {
    #[serde(default = "default_keep_latest")]
    pub keep_latest: usize,
}

#[derive(Debug, Deserialize)]
pub struct StoragePruneQuery {
    #[serde(default = "default_keep_latest")]
    pub keep_latest: usize,
    #[serde(default)]
    pub execute: bool,
}

fn default_keep_latest() -> usize {
    25
}

fn policy(keep_latest: usize) -> Result<RetentionPolicy, AppError> {
    if keep_latest == 0 {
        return Err(AppError::BadRequest(
            "keep_latest must be greater than zero".to_string(),
        ));
    }
    Ok(RetentionPolicy { keep_latest })
}

/// Env var that must be explicitly enabled for the REMOTE prune endpoint to run
/// a destructive (`execute=true`) prune. Default off: a remote API caller cannot
/// delete stored evidence unless the operator opted in on the server process.
/// The local `ao2-cp-gc` operator binary is unaffected by this gate.
const ALLOW_DESTRUCTIVE_PRUNE_ENV: &str = "AO2_CP_ALLOW_DESTRUCTIVE_PRUNE";

/// Whether the given env value enables remote destructive prune. Pure, so the
/// policy is unit-testable without mutating process env. Only an explicit,
/// trimmed, case-insensitive truthy value enables it; anything else — including
/// an absent var — keeps it disabled.
fn destructive_prune_enabled(env_value: Option<&str>) -> bool {
    matches!(
        env_value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

pub async fn storage_support_bundle_contract() -> Json<serde_json::Value> {
    Json(json!({
        "schema_version": "ao2.cp-storage-support-bundle-contract.v1",
        "describes_schema_version": "ao2.cp-support-bundle.v1",
        "control_plane_role": "read-only-observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "credential_material_included": false,
        "release_acceptance_owner": "factory-v3 evaluator-closer",
        "canonical_digest_algorithm": "sha256-ao2-cp-canonical-json-v1",
        "required_top_level_fields": [
            "schema_version",
            "generated_at",
            "trust_boundary",
            "operator_handoff",
            "phase1_release_readiness",
            "retention_report",
            "latest_index_entries"
        ],
        "required_phase1_release_readiness_fields": [
            "schema_version",
            "trust_boundary",
            "operator_links",
            "observed_artifacts",
            "readiness_status",
            "release_decision_allowed",
            "total_open_gaps",
            "gap_summary",
            "critical_path",
            "blocking_gaps",
            "next_recommended_action"
        ],
        "required_gap_summary_fields": [
            "schema_version",
            "total_blocking",
            "missing_artifact_count",
            "stale_artifact_count",
            "failed_status_count",
            "trust_boundary"
        ],
        "required_blocking_gap_fields": [
            "id",
            "severity",
            "gap_kind",
            "evidence_needed",
            "next_action"
        ],
        "required_critical_path_fields": [
            "operator_step",
            "id",
            "severity",
            "gap_kind",
            "evidence_needed",
            "next_action"
        ],
        "gap_kind_values": [
            "missing_artifact",
            "stale_artifact",
            "failed_status"
        ],
        "observer_contract": {
            "frontend": "Hermes may display and queue follow-up from this contract",
            "governed_backend": "factory-v3 evaluator-closer owns release acceptance",
            "trusted_execution": "ao2 signed evidence and digest replay remain the trusted execution boundary",
            "observer": "ao2-control-plane exposes authenticated read-only evidence copies"
        },
        "portable_endpoints": {
            "json": "/api/v1/storage/support-bundle.json",
            "download": "/api/v1/storage/support-bundle/download",
            "checksums": "/api/v1/storage/support-bundle/SHA256SUMS",
            "contract_json": "/api/v1/storage/support-bundle/contract.json"
        },
        "recommended_consumer_checks": [
            "Reject bundles whose schema_version is not ao2.cp-support-bundle.v1.",
            "Require phase1_release_readiness.gap_summary totals to match blocking_gaps by gap_kind.",
            "Treat release_decision_allowed as observer status only; final acceptance remains factory-v3 evaluator-closer owned.",
            "Verify downloaded bundle digests with SHA256SUMS before offline operator review.",
            "Never persist bearer tokens in copied URLs, logs, reports, or committed artifacts."
        ]
    }))
}

pub async fn storage_report(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Json<ao2_cp_storage::RetentionReport>, AppError> {
    let report = state
        .storage
        .retention_report(policy(q.keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(report))
}

pub async fn storage_support_bundle(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Json<ao2_cp_storage::SupportBundle>, AppError> {
    let bundle = state
        .storage
        .support_bundle(policy(q.keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(bundle))
}

pub async fn storage_support_bundle_download(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Response, AppError> {
    let bundle = state
        .storage
        .support_bundle(policy(q.keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let bundle_sha256 = storage_support_bundle_sha256(&bundle)?;
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
                "attachment; filename=\"ao2-storage-support-bundle.json\"".to_string(),
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

pub async fn storage_support_bundle_checksums(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Response, AppError> {
    let bundle = state
        .storage
        .support_bundle(policy(q.keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let bundle_sha256 = storage_support_bundle_sha256(&bundle)?;
    let body = [
        "# ao2-control-plane storage support bundle SHA256SUMS".to_string(),
        "# schema: ao2.cp-storage-support-bundle-checksums.v1".to_string(),
        "# algorithm: sha256-ao2-cp-canonical-json-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        format!("{bundle_sha256}  ao2-storage-support-bundle.json"),
        String::new(),
    ]
    .join("\n");

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

pub async fn storage_dashboard_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(storage_dashboard_value(&state, q.keep_latest).await?))
}

pub async fn storage_dashboard(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StorageRetentionQuery>,
) -> Result<Response, AppError> {
    let dashboard = storage_dashboard_value(&state, q.keep_latest).await?;
    let report = dashboard
        .get("retention_report")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let trust_boundary = dashboard
        .get("trust_boundary")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let phase1_readiness = dashboard
        .get("phase1_release_readiness")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let mut kind_rows = String::new();
    for kind in report
        .get("kinds")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        kind_rows.push_str(&format!(
            "<tr><td>{kind}</td><td>{indexed}</td><td>{files}</td><td>{size}</td><td>{candidates}</td></tr>",
            kind = escape_html(json_str(kind, "kind").unwrap_or("unknown")),
            indexed = json_usize(kind, "indexed_entries"),
            files = json_usize(kind, "bundle_files"),
            size = json_u64(kind, "size_bytes"),
            candidates = json_usize(kind, "prune_candidates"),
        ));
    }
    if kind_rows.is_empty() {
        kind_rows.push_str("<tr><td colspan=\"5\">No storage kinds observed.</td></tr>");
    }

    let mut candidate_rows = String::new();
    for candidate in report
        .get("prune_candidates")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(25)
    {
        let sha = json_str(candidate, "sha256").unwrap_or("unknown");
        let short = sha.get(..12).unwrap_or(sha);
        candidate_rows.push_str(&format!(
            "<tr><td>{kind}</td><td><code>{short}</code></td><td>{schema}</td><td>{size}</td><td>{ingested}</td></tr>",
            kind = escape_html(json_str(candidate, "kind").unwrap_or("unknown")),
            short = escape_html(short),
            schema = escape_html(json_str(candidate, "schema").unwrap_or("unknown")),
            size = json_u64(candidate, "size_bytes"),
            ingested = escape_html(json_str(candidate, "ingested_at").unwrap_or("unknown")),
        ));
    }
    if candidate_rows.is_empty() {
        candidate_rows.push_str(
            "<tr><td colspan=\"5\">No prune candidates for this retention policy.</td></tr>",
        );
    }

    let mut readiness_rows = String::new();
    for (id, artifact) in phase1_readiness
        .get("observed_artifacts")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
    {
        if artifact.is_null() {
            readiness_rows.push_str(&format!(
                "<tr><td>{id}</td><td class=\"bad\">missing</td><td colspan=\"6\">No indexed support-bundle evidence observed.</td></tr>",
                id = escape_html(id),
            ));
            continue;
        }

        let sha = json_str(artifact, "sha256").unwrap_or("unknown");
        let short = sha.get(..12).unwrap_or(sha);
        let stale = artifact
            .get("is_stale")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let freshness_class = if stale { "bad" } else { "ok" };
        let freshness_label = if stale { "stale" } else { "fresh" };
        let raw_url = json_str(artifact, "raw_url").unwrap_or("");
        let raw_link = if raw_url.is_empty() {
            String::new()
        } else {
            format!("<a href=\"{url}\">raw</a>", url = escape_html(raw_url))
        };
        readiness_rows.push_str(&format!(
            "<tr><td>{id}</td><td class=\"{freshness_class}\">{freshness_label}</td><td><code>{short}</code></td><td>{schema}</td><td>{status}</td><td>{age}</td><td>{stale_after}</td><td>{raw_link}</td></tr>",
            id = escape_html(id),
            freshness_class = freshness_class,
            freshness_label = freshness_label,
            short = escape_html(short),
            schema = escape_html(json_str(artifact, "schema").unwrap_or("unknown")),
            status = escape_html(json_str(artifact, "status").unwrap_or("")),
            age = json_i64(artifact, "age_seconds")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            stale_after = json_i64(artifact, "stale_after_seconds")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            raw_link = raw_link,
        ));
    }
    if readiness_rows.is_empty() {
        readiness_rows
            .push_str("<tr><td colspan=\"8\">No Phase 1 readiness artifacts observed.</td></tr>");
    }

    let mut gap_rows = String::new();
    for gap in phase1_readiness
        .get("blocking_gaps")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        gap_rows.push_str(&format!(
            "<tr><td>{id}</td><td class=\"bad\">{severity}</td><td>{gap_kind}</td><td>{evidence}</td><td>{next_action}</td></tr>",
            id = escape_html(json_str(gap, "id").unwrap_or("unknown")),
            severity = escape_html(json_str(gap, "severity").unwrap_or("unknown")),
            gap_kind = escape_html(json_str(gap, "gap_kind").unwrap_or("unknown")),
            evidence = escape_html(json_str(gap, "evidence_needed").unwrap_or("")),
            next_action = escape_html(json_str(gap, "next_action").unwrap_or("")),
        ));
    }
    let mut critical_path_rows = String::new();
    for step in phase1_readiness
        .get("critical_path")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        critical_path_rows.push_str(&format!(
            "<tr><td>{operator_step}</td><td>{id}</td><td class=\"bad\">{severity}</td><td>{gap_kind}</td><td>{next_action}</td></tr>",
            operator_step = json_usize(step, "operator_step"),
            id = escape_html(json_str(step, "id").unwrap_or("unknown")),
            severity = escape_html(json_str(step, "severity").unwrap_or("unknown")),
            gap_kind = escape_html(json_str(step, "gap_kind").unwrap_or("unknown")),
            next_action = escape_html(json_str(step, "next_action").unwrap_or("")),
        ));
    }
    let release_evaluator_gap_callout = if phase1_readiness
        .get("blocking_gaps")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|gap| json_str(gap, "id") == Some("release_evaluator_decision"))
    {
        format!(
            "<aside class=\"callout bad\"><h3>Release evaluator decision required</h3><p>The support bundle is still blocked on <code>release_evaluator_decision</code>. Factory v3 evaluator-closer acceptance remains the release authority; this control plane only observes the signed decision evidence.</p><p><a href=\"/api/v1/release/evaluator-decision/dashboard\">Release evaluator dashboard</a> · <a href=\"/api/v1/storage/support-bundle.json?keep_latest={keep_latest}\">Support Bundle JSON</a></p></aside>",
            keep_latest = json_usize(&dashboard, "keep_latest"),
        )
    } else {
        String::new()
    };
    if gap_rows.is_empty() {
        gap_rows
            .push_str("<tr><td colspan=\"5\">No blocking support-bundle readiness gaps.</td></tr>");
    }
    if critical_path_rows.is_empty() {
        critical_path_rows
            .push_str("<tr><td colspan=\"5\">No critical path steps required.</td></tr>");
    }

    let mut latest_rows = String::new();
    for entry in dashboard
        .get("latest_index_entries")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(25)
    {
        let sha = json_str(entry, "sha256").unwrap_or("unknown");
        let short = sha.get(..12).unwrap_or(sha);
        latest_rows.push_str(&format!(
            "<tr><td><code>{short}</code></td><td>{schema}</td><td>{provider}</td><td>{status}</td><td>{size}</td><td>{ingested}</td></tr>",
            short = escape_html(short),
            schema = escape_html(json_str(entry, "schema").unwrap_or("unknown")),
            provider = escape_html(json_str(entry, "provider").unwrap_or("")),
            status = escape_html(json_str(entry, "status").unwrap_or("")),
            size = json_u64(entry, "size_bytes"),
            ingested = escape_html(json_str(entry, "ingested_at").unwrap_or("unknown")),
        ));
    }
    if latest_rows.is_empty() {
        latest_rows.push_str("<tr><td colspan=\"6\">No index entries observed.</td></tr>");
    }

    let total_prune_candidates = report
        .get("total_prune_candidates")
        .and_then(serde_json::Value::as_u64)
        .and_then(|raw| usize::try_from(raw).ok())
        .or_else(|| {
            report
                .get("prune_candidates")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
        })
        .unwrap_or(0);
    let prune_candidates_limit = json_usize(&report, "prune_candidates_limit");
    let candidate_preview_notice = if report
        .get("prune_candidates_truncated")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        format!(
            "<p class=\"warn\"><strong>Prune candidate preview truncated:</strong> showing {shown} of {total} candidates. Open Retention Report JSON for machine-readable totals and keep storage mutations inside the governed operator workflow.</p>",
            shown = prune_candidates_limit,
            total = total_prune_candidates,
        )
    } else {
        String::new()
    };

    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Control Plane Storage</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:90rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#0a7f28}}.warn{{color:#9a5b00}}.bad{{color:#b00020}}</style></head><body><main><h1>AO2 Control Plane Storage</h1><p>Read-only observer dashboard for support bundles, retention pressure, and latest signed evidence index entries. It reports storage state only; it does not approve AO2 runs or mutate AO artifacts.</p><p><a href=\"/api/v1/storage/dashboard.json?keep_latest={keep_latest}\">Dashboard JSON</a> · <a href=\"/api/v1/storage/support-bundle.json?keep_latest={keep_latest}\">Support Bundle JSON</a> · <a href=\"/api/v1/storage/support-bundle/download?keep_latest={keep_latest}\">Download Support Bundle</a> · <a href=\"/api/v1/storage/support-bundle/SHA256SUMS?keep_latest={keep_latest}\">SHA256SUMS</a> · <a href=\"/api/v1/storage/report?keep_latest={keep_latest}\">Retention Report JSON</a> · <a href=\"/api/v1/evidence-pack/dashboard\">Signed Evidence</a> · <a href=\"/api/v1/phase1/promotion/dashboard\">Phase 1 Promotion</a></p><section><h2>Summary</h2><dl><dt>Generated</dt><dd>{generated_at}</dd><dt>Keep latest</dt><dd>{keep_latest}</dd><dt>Total index entries</dt><dd>{total_index_entries}</dd><dt>Total bundle files</dt><dd>{total_bundle_files}</dd><dt>Total size bytes</dt><dd>{total_size_bytes}</dd><dt>Reclaimable bytes</dt><dd>{reclaimable_bytes}</dd><dt>Prune candidates</dt><dd>{prune_count}</dd></dl></section><section><h2>Trust Boundary</h2><dl><dt>Frontend</dt><dd>{frontend}</dd><dt>Governed backend</dt><dd>{governed_backend}</dd><dt>Trusted execution</dt><dd>{trusted_execution}</dd><dt>Role</dt><dd class=\"ok\">{role}</dd><dt>Mutates AO artifacts</dt><dd class=\"ok\">{mutates}</dd></dl></section><section><h2>Storage Kinds</h2><table><thead><tr><th>Kind</th><th>Indexed</th><th>Files</th><th>Bytes</th><th>Prune candidates</th></tr></thead><tbody>{kind_rows}</tbody></table></section>{candidate_preview_notice}<section><h2>Prune Candidate Preview</h2><table><thead><tr><th>Kind</th><th>SHA</th><th>Schema</th><th>Bytes</th><th>Ingested</th></tr></thead><tbody>{candidate_rows}</tbody></table></section><section><h2>Phase 1 Release Readiness</h2><dl><dt>Readiness status</dt><dd class=\"{readiness_status_class}\">{readiness_status}</dd><dt>Release decision allowed</dt><dd>{release_decision_allowed}</dd><dt>Blocking gaps</dt><dd>{readiness_gap_count}</dd><dt>Next action</dt><dd>{readiness_next_action}</dd></dl><h3>Gap Summary</h3><dl><dt>Missing artifacts</dt><dd>{missing_artifact_count}</dd><dt>Stale artifacts</dt><dd>{stale_artifact_count}</dd><dt>Failed statuses</dt><dd>{failed_status_count}</dd></dl>{release_evaluator_gap_callout}<h3>Observed Artifacts</h3><table><thead><tr><th>ID</th><th>Freshness</th><th>SHA</th><th>Schema</th><th>Status</th><th>Age seconds</th><th>Stale after</th><th>Raw</th></tr></thead><tbody>{readiness_rows}</tbody></table><h3>Critical Path</h3><table><thead><tr><th>Step</th><th>ID</th><th>Severity</th><th>Gap kind</th><th>Next action</th></tr></thead><tbody>{critical_path_rows}</tbody></table><h3>Blocking Gaps</h3><table><thead><tr><th>ID</th><th>Severity</th><th>Gap kind</th><th>Evidence needed</th><th>Next action</th></tr></thead><tbody>{gap_rows}</tbody></table></section><section><h2>Latest Index Entries</h2><table><thead><tr><th>SHA</th><th>Schema</th><th>Provider</th><th>Status</th><th>Bytes</th><th>Ingested</th></tr></thead><tbody>{latest_rows}</tbody></table></section></main></body></html>",
        keep_latest = json_usize(&dashboard, "keep_latest"),
        generated_at = escape_html(json_str(&dashboard, "generated_at").unwrap_or("unknown")),
        total_index_entries = json_usize(&report, "total_index_entries"),
        total_bundle_files = json_usize(&report, "total_bundle_files"),
        total_size_bytes = json_u64(&report, "total_size_bytes"),
        reclaimable_bytes = json_u64(&report, "reclaimable_bytes"),
        prune_count = report
            .get("total_prune_candidates")
            .and_then(serde_json::Value::as_u64)
            .and_then(|raw| usize::try_from(raw).ok())
            .or_else(|| {
                report
                    .get("prune_candidates")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len)
            })
            .unwrap_or(0),
        frontend = escape_html(json_str(&trust_boundary, "frontend").unwrap_or("unknown")),
        governed_backend = escape_html(
            json_str(&trust_boundary, "governed_backend").unwrap_or("unknown")
        ),
        trusted_execution = escape_html(
            json_str(&trust_boundary, "trusted_execution").unwrap_or("unknown")
        ),
        role = escape_html(json_str(&trust_boundary, "role").unwrap_or("unknown")),
        mutates = trust_boundary
            .get("mutates_ao_artifacts")
            .and_then(serde_json::Value::as_bool)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        kind_rows = kind_rows,
        candidate_preview_notice = candidate_preview_notice,
        candidate_rows = candidate_rows,
        readiness_status = escape_html(
            json_str(&phase1_readiness, "readiness_status").unwrap_or("unknown")
        ),
        readiness_status_class = if phase1_readiness
            .get("release_decision_allowed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            "ok"
        } else {
            "bad"
        },
        release_decision_allowed = phase1_readiness
            .get("release_decision_allowed")
            .and_then(serde_json::Value::as_bool)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        readiness_gap_count = json_usize(&phase1_readiness, "total_open_gaps"),
        missing_artifact_count = phase1_readiness
            .get("gap_summary")
            .map(|summary| json_usize(summary, "missing_artifact_count"))
            .unwrap_or(0),
        stale_artifact_count = phase1_readiness
            .get("gap_summary")
            .map(|summary| json_usize(summary, "stale_artifact_count"))
            .unwrap_or(0),
        failed_status_count = phase1_readiness
            .get("gap_summary")
            .map(|summary| json_usize(summary, "failed_status_count"))
            .unwrap_or(0),
        readiness_next_action = escape_html(
            json_str(&phase1_readiness, "next_recommended_action").unwrap_or("unknown")
        ),
        release_evaluator_gap_callout = release_evaluator_gap_callout,
        readiness_rows = readiness_rows,
        critical_path_rows = critical_path_rows,
        gap_rows = gap_rows,
        latest_rows = latest_rows,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn storage_prune(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StoragePruneQuery>,
) -> Result<Json<ao2_cp_storage::RetentionPruneResult>, AppError> {
    if q.execute {
        let enabled =
            destructive_prune_enabled(std::env::var(ALLOW_DESTRUCTIVE_PRUNE_ENV).ok().as_deref());
        // High-visibility security log on EVERY destructive (execute=true)
        // attempt, permitted or blocked, so an operator can always see that a
        // remote caller tried to delete stored evidence.
        tracing::warn!(
            target: "ao2_cp_server::security",
            endpoint = "/api/v1/storage/prune",
            keep_latest = q.keep_latest,
            allow_env = ALLOW_DESTRUCTIVE_PRUNE_ENV,
            enabled = enabled,
            "remote destructive storage prune (execute=true) requested"
        );
        if !enabled {
            return Err(AppError::Forbidden(format!(
                "destructive prune (execute=true) is disabled on this server; \
                 set {ALLOW_DESTRUCTIVE_PRUNE_ENV}=1 to enable, or omit execute for a dry run"
            )));
        }
    }
    let result = state
        .storage
        .prune_retention(policy(q.keep_latest)?, !q.execute)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(result))
}

async fn storage_dashboard_value(
    state: &AppState,
    keep_latest: usize,
) -> Result<serde_json::Value, AppError> {
    let bundle = state
        .storage
        .support_bundle(policy(keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(serde_json::json!({
        "schema_version": STORAGE_DASHBOARD_SCHEMA,
        "generated_at": bundle.generated_at,
        "keep_latest": bundle.retention_report.keep_latest,
        "trust_boundary": bundle.trust_boundary,
        "operator_handoff": bundle.operator_handoff,
        "phase1_release_readiness": bundle.phase1_release_readiness,
        "retention_report": bundle.retention_report,
        "latest_index_entries": bundle.latest_index_entries,
        "links": {
            "dashboard": format!("/api/v1/storage/dashboard?keep_latest={}", keep_latest),
            "dashboard_json": format!("/api/v1/storage/dashboard.json?keep_latest={}", keep_latest),
            "support_bundle_json": format!("/api/v1/storage/support-bundle.json?keep_latest={}", keep_latest),
            "support_bundle_download": format!("/api/v1/storage/support-bundle/download?keep_latest={}", keep_latest),
            "support_bundle_checksums": format!("/api/v1/storage/support-bundle/SHA256SUMS?keep_latest={}", keep_latest),
            "retention_report_json": format!("/api/v1/storage/report?keep_latest={}", keep_latest),
            "prune_dry_run": format!("/api/v1/storage/prune?keep_latest={}", keep_latest),
            "signed_evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "phase1_promotion_dashboard": "/api/v1/phase1/promotion/dashboard"
        }
    }))
}

fn storage_support_bundle_sha256(
    bundle: &ao2_cp_storage::SupportBundle,
) -> Result<String, AppError> {
    let value = serde_json::to_value(bundle).map_err(|e| AppError::Internal(e.to_string()))?;
    sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))
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

fn json_usize(value: &serde_json::Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|raw| usize::try_from(raw).ok())
        .unwrap_or(0)
}

fn json_i64(value: &serde_json::Value, key: &str) -> Option<i64> {
    value.get(key).and_then(serde_json::Value::as_i64)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::destructive_prune_enabled;

    #[test]
    fn destructive_prune_is_disabled_by_default_and_for_falsy_values() {
        // Absent env (None) is the production default: the REMOTE destructive
        // prune is off unless the operator explicitly opts in on the server.
        assert!(
            !destructive_prune_enabled(None),
            "absent env must default to disabled"
        );
        for falsy in [
            "", "   ", "0", "false", "FALSE", "no", "off", "2", "enabled?",
        ] {
            assert!(
                !destructive_prune_enabled(Some(falsy)),
                "{falsy:?} must NOT enable destructive prune"
            );
        }
    }

    #[test]
    fn destructive_prune_is_enabled_only_for_explicit_truthy_values() {
        // Operator-friendly truthy set, trimmed + case-insensitive.
        for truthy in ["1", "true", "TRUE", "  true  ", "yes", "Yes", "on", "ON"] {
            assert!(
                destructive_prune_enabled(Some(truthy)),
                "{truthy:?} must enable destructive prune"
            );
        }
    }
}
