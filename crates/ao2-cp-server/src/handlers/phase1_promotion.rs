use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::IngestReceipt;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;
use crate::signing::{annotate_trust_policy, sha256_hex, verify_rsa_sha256_signature};

const PHASE1_PROMOTION_DASHBOARD_SCHEMA: &str = "ao2.cp-phase1-promotion-dashboard.v1";
const PHASE1_OPERATOR_PANEL_SCHEMA: &str = "ao2.cp-phase1-operator-panel.v1";
const PHASE1_OPERATOR_SUPPORT_BUNDLE_SCHEMA: &str = "ao2.cp-phase1-operator-support-bundle.v1";
const PHASE1_OPERATOR_SUPPORT_BUNDLE_VERIFICATION_SCHEMA: &str =
    "ao2.cp-phase1-operator-support-bundle-verification.v1";
const PHASE1_PORTABLE_MANIFEST_SCHEMA: &str = "ao2.cp-phase1-portable-manifest.v1";
const PHASE1_PORTABLE_MANIFEST_VERIFICATION_UPLOAD_SCHEMA: &str =
    "ao2.cp-phase1-portable-manifest-verification-upload.v1";
const PHASE1_PORTABLE_MANIFEST_VERIFICATION_SCHEMA: &str =
    "ao2.cp-phase1-portable-manifest-verification.v1";
const PHASE1_PROMOTION_CHECKLIST_SCHEMA: &str = "factory-v3/ao2-phase1-promotion-checklist/v1";
const PHASE1_PROMOTION_DECISION_SCHEMA: &str = "factory-v3/ao2-phase1-promotion-decision/v1";
const PHASE1_PROMOTION_DECISION_SIGNED_UPLOAD_SCHEMA: &str =
    "ao2.cp-phase1-promotion-decision-signed-upload.v1";
const PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA: &str =
    "ao2.cp-phase1-promotion-decision-signature.v1";
const PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA: &str =
    "ao2.phase1-replacement-promotion-inputs-verification.v1";
const PHASE1_PROMOTION_HISTORY_SCHEMA: &str = "ao2.cp-phase1-promotion-history.v1";
const PROVIDER_READINESS_SCHEMA: &str = "factory-v3/hermes-provider-phase1-readiness/v1";
const THREE_OS_RELEASE_SMOKE_SCHEMA: &str = "ao2-control-plane.three-os-release-smoke.v1";
const PHASE1_PROMOTION_HISTORY_LIMIT: usize = 20;

#[derive(Debug, Deserialize)]
struct SignedPhase1PromotionDecisionUpload {
    schema_version: String,
    decision: serde_json::Value,
    decision_b64: Option<String>,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct DecisionSignatureSidecar {
    schema_version: String,
    phase1_promotion_decision_sha256: String,
    signature: serde_json::Value,
}

/// Accepted schemas on this handler (Phase 2 migration window):
/// - `factory-v3/ao2-phase1-promotion-checklist/v1` — accepted for
///   `migration_window=phase2_in_progress`; sunset target = end of
///   Phase 2 W2 (per docs/roadmap/PHASE-2-W2-SCHEMA-REPLACEMENT.md
///   the AO2-native producer landed in W2; this handler keeps the
///   factory-v3-prefixed schema name for downstream stability per
///   the W2 audit findings).
///
/// Emits a `tracing::info!` line with `migration_window` and the
/// accepted `schema` so operators can grep audit trails.
pub async fn post_phase1_promotion_checklist(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let checklist: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_phase1_promotion_checklist(&checklist)?;
    let sha = sha256_of_canonical(&checklist).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionChecklist, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::Phase1PromotionChecklist, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PHASE1_PROMOTION_CHECKLIST_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: checklist
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
        schema = PHASE1_PROMOTION_CHECKLIST_SCHEMA,
        handler = "phase1_promotion::post_phase1_promotion_checklist",
        "accepted factory-v3-tagged phase1 promotion checklist"
    );

    Ok(Json(IngestReceipt::new(
        sha,
        PHASE1_PROMOTION_CHECKLIST_SCHEMA.to_string(),
    )))
}

pub async fn latest_phase1_promotion_checklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_checklist_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_phase1_promotion_checklist_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_phase1_promotion_checklist(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_phase1_promotion_checklist_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/phase1/promotion/checklist/:sha`.
pub async fn head_phase1_promotion_checklist(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionChecklist, &sha)
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

pub async fn post_phase1_promotion_inputs_verification(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let report: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_phase1_promotion_inputs_verification(&report)?;
    let sha = sha256_of_canonical(&report).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionInputsVerification, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(
                BundleKind::Phase1PromotionInputsVerification,
                &sha,
                raw.as_bytes(),
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: report
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

    Ok(Json(IngestReceipt::new(
        sha,
        PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA.to_string(),
    )))
}

pub async fn latest_phase1_promotion_inputs_verification(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_inputs_verification_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_phase1_promotion_inputs_verification_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_phase1_promotion_inputs_verification(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_phase1_promotion_inputs_verification_by_sha_cached(&state, &sha, &headers).await
}

pub async fn head_phase1_promotion_inputs_verification(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionInputsVerification, &sha)
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

pub async fn post_signed_phase1_promotion_decision(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedPhase1PromotionDecisionUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != PHASE1_PROMOTION_DECISION_SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PHASE1_PROMOTION_DECISION_SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    let signed_bytes = match &upload.decision_b64 {
        Some(encoded) => decode_decision_b64(encoded)?,
        None => serde_json::to_string_pretty(&upload.decision)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .into_bytes(),
    };
    let mut signature = upload.signature;
    let decision_raw = std::str::from_utf8(&signed_bytes).map_err(|e| {
        AppError::SchemaInvalid(format!(
            "signed Phase 1 promotion decision is not utf-8: {e}"
        ))
    })?;
    verify_signed_phase1_promotion_decision(decision_raw, &signature)?;
    let decision: serde_json::Value = serde_json::from_slice(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    validate_phase1_promotion_decision(&decision)?;
    let checklist_sha = required_json_str(&decision, "checklist_sha256")?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionChecklist, checklist_sha)
        .await
    {
        return Err(AppError::SchemaInvalid(format!(
            "Phase 1 promotion decision references unknown checklist_sha256 {checklist_sha}"
        )));
    }
    let sha = sha256_of_canonical(&decision).map_err(|e| AppError::Internal(e.to_string()))?;
    annotate_trust_policy(&mut signature, &state.signed_artifact_trusted_key_sha256s);

    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionDecision, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(
                BundleKind::Phase1PromotionDecision,
                &sha,
                decision_raw.as_bytes(),
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = DecisionSignatureSidecar {
        schema_version: PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA.to_string(),
        phase1_promotion_decision_sha256: sha.clone(),
        signature,
    };
    let sidecar_raw =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    // Write-once: the signature sidecar records who signed this content sha.
    // A conflicting re-sign (same content, different provenance) is rejected
    // rather than allowed to overwrite the first signer's record; an identical
    // re-upload is a no-op. Mirrors provider_readiness / provider_registry.
    if state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionDecisionSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::Phase1PromotionDecisionSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "phase1 promotion decision signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(
                BundleKind::Phase1PromotionDecisionSignature,
                &sha,
                &sidecar_raw,
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: PHASE1_PROMOTION_DECISION_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: Some("signed".to_string()),
        size_bytes: decision_raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        PHASE1_PROMOTION_DECISION_SCHEMA.to_string(),
    )))
}

pub async fn latest_phase1_promotion_decision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_decision_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_phase1_promotion_decision_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_phase1_promotion_decision(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_phase1_promotion_decision_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/phase1/promotion/decision/:sha`.
pub async fn head_phase1_promotion_decision(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionDecision, &sha)
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

pub async fn get_phase1_promotion_decision_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    validate_sha(&sha)?;
    let sidecar = read_decision_signature_sidecar(&state, &sha).await?;
    let bytes =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

pub async fn phase1_promotion_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let dashboard = phase1_promotion_dashboard_value(&state).await?;
    let checklist = dashboard
        .get("checklist")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let row = |key: &str, label: &str| {
        let item = checklist
            .get(key)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(json_str(&item, "status").unwrap_or("missing")),
            escape_html(
                json_str(&item, "state")
                    .unwrap_or_else(|| { json_str(&item, "phase1_state").unwrap_or("unknown") })
            ),
        )
    };
    let gap_rows = dashboard
        .get("gap_report")
        .and_then(|report| report.get("blocking_gaps"))
        .and_then(serde_json::Value::as_array)
        .map(|gaps| {
            if gaps.is_empty() {
                "<tr><td colspan=\"4\">No open blocking gaps observed by the read-only control plane.</td></tr>"
                    .to_string()
            } else {
                gaps.iter()
                    .map(|gap| {
                        format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                            escape_html(json_str(gap, "id").unwrap_or("unknown")),
                            escape_html(json_str(gap, "severity").unwrap_or("unknown")),
                            escape_html(json_str(gap, "evidence_needed").unwrap_or("unknown")),
                            escape_html(json_str(gap, "next_action").unwrap_or("unknown")),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            }
        })
        .unwrap_or_else(|| {
            "<tr><td colspan=\"4\">Gap report unavailable.</td></tr>".to_string()
        });
    let three_os_smoke = checklist
        .get("three_os_smoke")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let remote_command_file_rows = html_object_rows(
        three_os_smoke.get("remote_command_files"),
        "No remote command files have been observed yet.",
        false,
    );
    let rerun_command_rows = html_object_rows(
        three_os_smoke.get("rerun_commands"),
        "No rerun commands have been observed yet.",
        true,
    );
    let correlation = dashboard
        .get("candidate_correlation")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let correlation_status = json_str(&correlation, "status").unwrap_or("missing");
    let correlation_status_class = if correlation_status == "matched" {
        "ok"
    } else {
        "warn"
    };
    let correlation_blocker_items: String = correlation
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            if items.is_empty() {
                "<li>no blockers</li>".to_string()
            } else {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(|blocker| format!("<li>{}</li>", escape_html(blocker)))
                    .collect::<String>()
            }
        })
        .unwrap_or_else(|| "<li>no blockers</li>".to_string());
    let correlation_section = format!(
        "<section><h2>Candidate Correlation</h2><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Release version</dt><dd><code>{release_version}</code></dd><dt>Release tag</dt><dd><code>{release_tag}</code></dd><dt>Three-OS smoke version</dt><dd><code>{three_os_version}</code></dd><dt>Evaluator version</dt><dd><code>{evaluator_version}</code></dd><dt>Codex acceptance version</dt><dd><code>{codex_version}</code></dd><dt>Claude acceptance version</dt><dd><code>{claude_version}</code></dd></dl><h3>Blockers</h3><ul>{blockers}</ul></section>",
        status_class = correlation_status_class,
        status = escape_html(correlation_status),
        release_version = escape_html(json_str(&correlation, "release_version").unwrap_or("unknown")),
        release_tag = escape_html(json_str(&correlation, "release_tag").unwrap_or("unknown")),
        three_os_version = escape_html(json_str(&correlation, "three_os_version").unwrap_or("unknown")),
        evaluator_version = escape_html(json_str(&correlation, "release_evaluator_version").unwrap_or("unknown")),
        codex_version = escape_html(json_str(&correlation, "codex_acceptance_version").unwrap_or("unknown")),
        claude_version = escape_html(json_str(&correlation, "claude_acceptance_version").unwrap_or("unknown")),
        blockers = correlation_blocker_items,
    );
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Phase 1 Promotion Checklist</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:84rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Phase 1 Promotion Checklist</h1><p>Read-only observer view. The control plane correlates published evidence but never starts runs, approves gates, or mutates AO2 state.</p><dl><dt>State</dt><dd>{state}</dd><dt>Next action</dt><dd>{next_action}</dd><dt>Decision mode</dt><dd><code>{decision_mode}</code> (governed-run evidence files: {governed_run_evidence_count})</dd><dt>Open blocking gaps</dt><dd class=\"warn\">{open_gaps}</dd></dl><section><h2>Phase readiness gap report</h2><p>{gap_next_action}</p><table><thead><tr><th>Gap</th><th>Severity</th><th>Evidence needed</th><th>Next action</th></tr></thead><tbody>{gap_rows}</tbody></table></section>{correlation_section}<table><thead><tr><th>Check</th><th>Status</th><th>State</th></tr></thead><tbody>{rows}</tbody></table><section><h2>Remote smoke rerun metadata</h2><p>Observed command-file paths and token-redacted rerun commands for governed macOS/Ubuntu/Windows smoke follow-up. These rows are observer metadata only; use factory-v3/AO2 governed paths to execute or publish evidence.</p><h3>Remote command files</h3><table><thead><tr><th>Target</th><th>Path</th></tr></thead><tbody>{remote_command_file_rows}</tbody></table><h3>Rerun commands</h3><table><thead><tr><th>Name</th><th>Command</th></tr></thead><tbody>{rerun_command_rows}</tbody></table></section><p><a href=\"/api/v1/phase1/promotion/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/phase1/promotion/gap-report.json\">Gap Report JSON</a> · <a href=\"/api/v1/phase1/promotion/history.json\">Promotion History JSON</a> · <a href=\"/api/v1/phase1/promotion/three-os-smoke/latest\">Latest Three-OS Smoke</a> · <a href=\"/api/v1/release/publication/dashboard\">Release Publication Dashboard</a> · <a href=\"/api/v1/provider/readiness/dashboard\">Provider Readiness</a> · <a href=\"/api/v1/acceptance/dashboard\">Provider Acceptance</a> · <a href=\"/api/v1/evidence-pack/dashboard\">Signed Evidence</a></p></main></body></html>",
        state = escape_html(json_str(&dashboard, "state").unwrap_or("unknown")),
        next_action = escape_html(json_str(&dashboard, "next_action").unwrap_or("unknown")),
        decision_mode = escape_html(
            dashboard
                .get("decision_artifact")
                .and_then(|d| json_str(d, "decision_mode"))
                .unwrap_or("missing"),
        ),
        governed_run_evidence_count = dashboard
            .get("decision_artifact")
            .and_then(|d| d.get("governed_run_evidence_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        open_gaps = dashboard
            .get("gap_report")
            .and_then(|report| report.get("total_open_gaps"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        gap_next_action = escape_html(
            dashboard
                .get("gap_report")
                .and_then(|report| json_str(report, "next_recommended_action"))
                .unwrap_or("Review dashboard JSON for machine-readable phase readiness gaps."),
        ),
        gap_rows = gap_rows,
        correlation_section = correlation_section,
        remote_command_file_rows = remote_command_file_rows,
        rerun_command_rows = rerun_command_rows,
        rows = [
            row("provider_readiness", "Provider readiness"),
            row("live_provider_acceptance", "Live provider acceptance"),
            row("release_gate", "Release gate"),
            row("three_os_smoke", "Three-OS smoke"),
        ]
        .join(""),
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn phase1_promotion_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_promotion_dashboard_value(&state).await?))
}

pub async fn phase1_operator_panel(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let panel = phase1_operator_panel_value(&state).await?;
    let badges = panel
        .get("badges")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let badge_row = |key: &str, label: &str| {
        format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(
                badges
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing"),
            ),
        )
    };
    let correlation = panel
        .get("candidate_correlation")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let correlation_status = json_str(&correlation, "status").unwrap_or("missing");
    let correlation_status_class = if correlation_status == "matched" {
        "ok"
    } else {
        "warn"
    };
    let correlation_blocker_items: String = correlation
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            if items.is_empty() {
                "<li>no blockers</li>".to_string()
            } else {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(|blocker| format!("<li>{}</li>", escape_html(blocker)))
                    .collect::<String>()
            }
        })
        .unwrap_or_else(|| "<li>no blockers</li>".to_string());
    let correlation_section = format!(
        "<section><h2>Candidate Correlation</h2><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Release version</dt><dd><code>{release_version}</code></dd><dt>Release tag</dt><dd><code>{release_tag}</code></dd><dt>Three-OS smoke version</dt><dd><code>{three_os_version}</code></dd><dt>Evaluator version</dt><dd><code>{evaluator_version}</code></dd><dt>Codex acceptance version</dt><dd><code>{codex_version}</code></dd><dt>Claude acceptance version</dt><dd><code>{claude_version}</code></dd></dl><h3>Blockers</h3><ul>{blockers}</ul></section>",
        status_class = correlation_status_class,
        status = escape_html(correlation_status),
        release_version = escape_html(json_str(&correlation, "release_version").unwrap_or("unknown")),
        release_tag = escape_html(json_str(&correlation, "release_tag").unwrap_or("unknown")),
        three_os_version = escape_html(json_str(&correlation, "three_os_version").unwrap_or("unknown")),
        evaluator_version = escape_html(json_str(&correlation, "release_evaluator_version").unwrap_or("unknown")),
        codex_version = escape_html(json_str(&correlation, "codex_acceptance_version").unwrap_or("unknown")),
        claude_version = escape_html(json_str(&correlation, "claude_acceptance_version").unwrap_or("unknown")),
        blockers = correlation_blocker_items,
    );
    let action_queue = panel
        .get("operator_action_queue")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let action_rows = if action_queue.is_empty() {
        "<tr><td colspan=\"6\">No open operator actions observed. Continue monitoring signed AO2 evidence and factory-v3 evaluator closure.</td></tr>"
            .to_string()
    } else {
        action_queue
            .iter()
            .map(|action| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(json_str(action, "id").unwrap_or("unknown")),
                    escape_html(json_str(action, "severity").unwrap_or("unknown")),
                    escape_html(json_str(action, "owner").unwrap_or("factory-v3 evaluator-closer")),
                    escape_html(json_str(action, "control_plane_action").unwrap_or("observe_only")),
                    escape_html(
                        json_str(action, "evidence_needed").unwrap_or("governed release evidence")
                    ),
                    escape_html(
                        json_str(action, "next_action").unwrap_or("review phase readiness gap")
                    ),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let links = panel
        .get("links")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let link_items = [
        ("operator_panel_json", "Panel JSON"),
        ("dashboard", "Promotion dashboard"),
        ("history_json", "Promotion history JSON"),
        ("latest_decision", "Latest signed decision"),
        ("latest_three_os_smoke", "Latest Three-OS smoke"),
    ]
    .iter()
    .filter_map(|(key, label)| {
        links
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(|href| {
                format!(
                    "<li><a href=\"{}\">{}</a> <code>{}</code></li>",
                    escape_html(href),
                    escape_html(label),
                    escape_html(href),
                )
            })
    })
    .collect::<Vec<_>>()
    .join("");
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Phase 1 Operator Panel</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:84rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Phase 1 Operator Panel</h1><p>Read-only observer panel for Hermes and factory-v3 operators. The control plane correlates signed evidence and memory exports, but it does not approve, start, cancel, or mutate governed runs.</p><dl><dt>Status</dt><dd>{status}</dd><dt>State</dt><dd>{state}</dd><dt>Phase 1 state</dt><dd>{phase1_state}</dd><dt>Next action</dt><dd>{next_action}</dd></dl><section><h2>Readiness Badges</h2><table><thead><tr><th>Signal</th><th>Status</th></tr></thead><tbody>{badge_rows}</tbody></table></section>{correlation_section}<section><h2>Operator Action Queue</h2><p>Governed follow-up work remains owned by factory-v3 evaluator-closer; control-plane action is observe-only.</p><table><thead><tr><th>Gap</th><th>Severity</th><th>Owner</th><th>Control-plane action</th><th>Evidence needed</th><th>Next action</th></tr></thead><tbody>{action_rows}</tbody></table></section><section><h2>Trust Boundary</h2><p>Role: <code>{role}</code>. Mutates AO artifacts: <code>{mutates}</code>. Release acceptance owner: <code>{owner}</code>.</p></section><section><h2>Operator Links</h2><ul>{links}</ul></section></main></body></html>",
        status = escape_html(json_str(&panel, "status").unwrap_or("unknown")),
        state = escape_html(
            panel
                .get("operator_status")
                .and_then(|status| json_str(status, "state"))
                .unwrap_or("unknown"),
        ),
        phase1_state = escape_html(
            panel
                .get("operator_status")
                .and_then(|status| json_str(status, "phase1_state"))
                .unwrap_or("unknown"),
        ),
        next_action = escape_html(
            panel
                .get("operator_status")
                .and_then(|status| json_str(status, "next_action"))
                .unwrap_or("unknown"),
        ),
        badge_rows = [
            badge_row("checklist", "Checklist"),
            badge_row("signed_decision", "Signed decision"),
            badge_row("signature", "Signature"),
            badge_row("three_os", "Three-OS"),
            badge_row("candidate_correlation", "Candidate correlation"),
            badge_row("decision_mode", "Decision mode"),
        ]
        .join(""),
        correlation_section = correlation_section,
        action_rows = action_rows,
        role = escape_html(
            panel
                .get("trust_boundary")
                .and_then(|boundary| json_str(boundary, "role"))
                .unwrap_or("unknown"),
        ),
        mutates = panel
            .get("trust_boundary")
            .and_then(|boundary| boundary.get("mutates_ao_artifacts"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        owner = escape_html(
            panel
                .get("trust_boundary")
                .and_then(|boundary| json_str(boundary, "release_acceptance_owner"))
                .unwrap_or("unknown"),
        ),
        links = link_items,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn phase1_operator_panel_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_operator_panel_value(&state).await?))
}

pub async fn phase1_operator_support_bundle_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_operator_support_bundle_value(&state).await?))
}

pub async fn phase1_operator_support_bundle_download(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let bundle = phase1_operator_support_bundle_value(&state).await?;
    let filename = phase1_operator_support_bundle_filename();
    let body = serde_json::to_vec_pretty(&bundle).map_err(|e| AppError::Internal(e.to_string()))?;
    let bundle_sha256 = sha256_hex(&body);

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

pub async fn phase1_operator_support_bundle_checksums(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let bundle = phase1_operator_support_bundle_value(&state).await?;
    let body = phase1_operator_support_bundle_checksums_text(&bundle)?;

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

pub async fn phase1_operator_support_bundle_verify_json(
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let bundle = parse_support_bundle_verification_body(&body)?;
    Ok(Json(phase1_operator_support_bundle_verification_value(
        &bundle,
    )?))
}

pub async fn phase1_operator_support_bundle_verify(body: Bytes) -> Result<Response, AppError> {
    let bundle = parse_support_bundle_verification_body(&body)?;
    let verification = phase1_operator_support_bundle_verification_value(&bundle)?;
    let status = json_str(&verification, "status").unwrap_or("unknown");
    let rows = verification
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(|result| {
                    format!(
                        "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                        escape_html(json_str(result, "artifact_kind").unwrap_or("unknown")),
                        escape_html(json_str(result, "sha256").unwrap_or("unknown")),
                        escape_html(json_str(result, "expected_canonical_sha256").unwrap_or("missing")),
                        escape_html(json_str(result, "actual_canonical_sha256").unwrap_or("missing")),
                        if result.get("verified").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                            "verified"
                        } else {
                            "mismatch"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_else(|| "<tr><td colspan=\"5\">No timeline integrity entries.</td></tr>".to_string());
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Phase 1 Operator Support Bundle Verification</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:92rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}</style></head><body><main><h1>Phase 1 Operator Support Bundle Verification</h1><p><strong>Status:</strong> {status}</p><p><strong>Control-plane role:</strong> read-only-observer; <strong>mutates AO artifacts:</strong> false; <strong>release acceptance owner:</strong> factory-v3 evaluator-closer</p><table><thead><tr><th>Artifact kind</th><th>Artifact SHA-256</th><th>Expected canonical SHA-256</th><th>Actual canonical SHA-256</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        status = escape_html(status),
        rows = rows
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn phase1_gap_report_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_gap_report_value(&state).await?))
}

pub async fn phase1_portable_manifest_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_portable_manifest_value(&state).await?))
}

pub async fn phase1_portable_manifest_download(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest = phase1_portable_manifest_value(&state).await?;
    let filename = phase1_portable_manifest_filename();
    let body =
        serde_json::to_vec_pretty(&manifest).map_err(|e| AppError::Internal(e.to_string()))?;
    let manifest_sha256 = sha256_hex(&body);

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
                header::HeaderName::from_static("x-ao2-cp-portable-manifest-sha256"),
                manifest_sha256,
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

pub async fn phase1_portable_manifest_checksums(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest = phase1_portable_manifest_value(&state).await?;
    let body = phase1_portable_manifest_checksums_text(&manifest)?;

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

pub async fn phase1_portable_manifest_verify_json(
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let upload = parse_portable_manifest_verification_body(&body)?;
    Ok(Json(phase1_portable_manifest_verification_value(&upload)?))
}

pub async fn phase1_portable_manifest_verify(body: Bytes) -> Result<Response, AppError> {
    let upload = parse_portable_manifest_verification_body(&body)?;
    let verification = phase1_portable_manifest_verification_value(&upload)?;
    let status = json_str(&verification, "status").unwrap_or("unknown");
    let rows = verification
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(|result| {
                    format!(
                        "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                        escape_html(json_str(result, "artifact_name").unwrap_or("unknown")),
                        escape_html(json_str(result, "expected_sha256").unwrap_or("missing")),
                        escape_html(json_str(result, "actual_sha256").unwrap_or("missing")),
                        escape_html(json_str(result, "expected_size_bytes").unwrap_or("missing")),
                        if result.get("verified").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                            "verified"
                        } else {
                            "mismatch"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_else(|| "<tr><td colspan=\"5\">No manifest artifacts supplied.</td></tr>".to_string());
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Phase 1 Portable Manifest Verification</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:92rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}</style></head><body><main><h1>Phase 1 Portable Manifest Verification</h1><p><strong>Status:</strong> {status}</p><p><strong>Control-plane role:</strong> read-only-observer; <strong>mutates AO artifacts:</strong> false; <strong>release acceptance owner:</strong> factory-v3 evaluator-closer</p><table><thead><tr><th>Artifact</th><th>Expected SHA-256</th><th>Actual SHA-256</th><th>Expected size</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        status = escape_html(status),
        rows = rows
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn phase1_portable_manifest(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest = phase1_portable_manifest_value(&state).await?;
    let artifact_rows = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .map(|artifacts| {
            artifacts
                .iter()
                .map(|artifact| {
                    let name = json_str(artifact, "name").unwrap_or("unknown");
                    let filename = json_str(artifact, "filename").unwrap_or("unknown");
                    let sha = json_str(artifact, "sha256").unwrap_or("unknown");
                    let download_url = json_str(artifact, "download_url").unwrap_or("#");
                    let checksums_url = json_str(artifact, "checksums_url").unwrap_or("#");
                    format!(
                        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td><a href=\"{}\">download</a> · <a href=\"{}\">SHA256SUMS</a></td></tr>",
                        escape_html(name),
                        escape_html(filename),
                        escape_html(sha),
                        escape_html(download_url),
                        escape_html(checksums_url)
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_else(|| "<tr><td colspan=\"4\">No portable artifacts available.</td></tr>".to_string());
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Phase 1 Portable Manifest</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:84rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}</style></head><body><main><h1>AO2 Phase 1 Portable Manifest</h1><p>{summary}</p><p><strong>Role:</strong> {role}; <strong>release acceptance owner:</strong> {owner}</p><p><a href=\"/api/v1/phase1/promotion/portable-manifest.json\">JSON manifest</a></p><table><thead><tr><th>Name</th><th>Filename</th><th>SHA-256</th><th>Links</th></tr></thead><tbody>{artifact_rows}</tbody></table></main></body></html>",
        summary = escape_html(json_str(&manifest, "summary").unwrap_or("Portable Phase 1 manifest")),
        role = escape_html(
            manifest
                .get("trust_boundary")
                .and_then(|boundary| json_str(boundary, "role"))
                .unwrap_or("read_only_observer")
        ),
        owner = escape_html(
            manifest
                .get("trust_boundary")
                .and_then(|boundary| json_str(boundary, "release_acceptance_owner"))
                .unwrap_or("factory-v3 evaluator-closer")
        ),
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn phase1_gap_report_download(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let report = phase1_gap_report_value(&state).await?;
    let filename = phase1_gap_report_filename();
    let body = serde_json::to_vec_pretty(&report).map_err(|e| AppError::Internal(e.to_string()))?;
    let report_sha256 = sha256_hex(&body);

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
                header::HeaderName::from_static("x-ao2-cp-gap-report-sha256"),
                report_sha256,
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

pub async fn phase1_gap_report_checksums(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let report = phase1_gap_report_value(&state).await?;
    let body = phase1_gap_report_checksums_text(&report)?;

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

pub async fn phase1_promotion_history_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(phase1_promotion_history_value(&state).await?))
}

const REJECTED_SMOKE_AUDIT_FILENAME: &str = "rejected-three-os-smoke.jsonl";
const REJECTED_SMOKE_AUDIT_SCHEMA: &str = "ao2.cp-rejected-three-os-smoke.v1";

// Lane UU: cap the audit log at 1 MiB so a long-running control
// plane that sees regular tampering attempts cannot accumulate the
// file unbounded. When an append would push the file past the cap,
// the file is rewritten with the newest records that fit. Operators
// keep the most-recent forensic record set; older records age out.
//
// 1 MiB ≈ 2000+ audit records given the redacted-summary shape
// (~450 bytes/record). Long enough that ordinary operator workflows
// see every recent tampering attempt; small enough that the file
// stays grep-friendly on every supported platform.
const REJECTED_SMOKE_AUDIT_MAX_BYTES: usize = 1024 * 1024;
// Lane CCC: rotate to a lower target than the hard cap. Rebuilding to
// just under 1 MiB makes every following rejection in the same burst
// rotate again; on Windows that serializes repeated 1 MiB read/rewrite
// work under the writer lock.
const REJECTED_SMOKE_AUDIT_ROTATE_TARGET_BYTES: usize = REJECTED_SMOKE_AUDIT_MAX_BYTES * 3 / 4;

/// Lane WW-rotation: a process-global serializer for the rejected-
/// smoke audit log writer. The Lane UU rotation path uses
/// tokio::fs::write (truncate + write); two concurrent rotations
/// would race read-modify-write windows and the "loser" would
/// overwrite the "winner", losing records and potentially leaving
/// the file above the 1 MiB cap. This mutex serializes the
/// read-projection-write region so the file size cap is always
/// observed and no record is silently lost to a race.
///
/// Process-global is acceptable because (a) in production each
/// host runs exactly one AppState, so the contention is identical
/// to per-AppState locking; (b) audit log operations are rare in
/// the normal path (only on a 422 ingestion), so cross-test
/// serialization adds negligible test runtime.
static REJECTED_SMOKE_AUDIT_WRITER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Lane LL: build a redacted summary of the rejected smoke payload for
/// the audit log. Only a strict allowlist of fields is captured so an
/// accidental bearer/credential anywhere in the payload cannot leak.
/// `source_commit` is truncated to 12 chars to identify the candidate
/// without exposing the full SHA in the audit log.
fn redacted_smoke_summary(raw_body: &str) -> serde_json::Value {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw_body) else {
        return serde_json::json!({"parse_status": "invalid_json"});
    };
    let object = parsed.as_object();
    let pick_str = |key: &str| -> Option<String> {
        object
            .and_then(|o| o.get(key))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    };
    let pick_bool = |key: &str| -> Option<bool> {
        object
            .and_then(|o| o.get(key))
            .and_then(serde_json::Value::as_bool)
    };
    let source_commit_short = pick_str("source_commit").as_ref().map(|sha| {
        sha.chars()
            .take(12)
            .collect::<String>()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
    });
    let mut target_statuses = serde_json::Map::new();
    for target in ["macos", "ubuntu", "windows"] {
        if let Some(status) = object
            .and_then(|o| o.get("targets"))
            .and_then(|targets| targets.get(target))
            .and_then(|target_value| target_value.get("status"))
            .and_then(serde_json::Value::as_str)
        {
            target_statuses.insert(
                target.to_string(),
                serde_json::Value::String(status.to_string()),
            );
        }
    }
    serde_json::json!({
        "schema": pick_str("schema"),
        "status": pick_str("status"),
        "version": pick_str("version"),
        "release_candidate_version": pick_str("release_candidate_version"),
        "source_commit_short": source_commit_short,
        "source_dirty": pick_bool("source_dirty"),
        "candidate_correlation_parity": pick_str("candidate_correlation_parity"),
        "surface_content_hash_parity": pick_str("surface_content_hash_parity"),
        "target_statuses": target_statuses,
    })
}

/// Lane LL: append one JSON-line record to the rejected-smoke audit
/// log at <storage-root>/rejected-three-os-smoke.jsonl. Best-effort —
/// IO failure is intentionally swallowed (the upstream 422 response is
/// the authoritative outcome; the audit log is forensic, not gating).
///
/// Lane UU: if the post-append file size would exceed
/// REJECTED_SMOKE_AUDIT_MAX_BYTES (1 MiB), the file is rewritten
/// with the newest records that fit. The single new record is always
/// retained; older records age out FIFO. A pathological case where
/// the single record itself exceeds the cap leaves only that record
/// (the operator-facing surface still renders, even if the file is
/// larger than usual).
async fn append_rejected_smoke_audit(state: &AppState, raw_body: &str, rejection_reason: &str) {
    // Lane WW-rotation: hold the writer lock for the entire
    // read-projection-write region. Without this, two concurrent
    // appenders both read the file before either has written,
    // both compute rotated content, and the second writer
    // overwrites the first's record — silent record loss + the
    // file briefly going above cap. The lock scope is wide
    // (encompasses both the append and rotation paths) so the
    // "did this need to rotate?" decision and the "rebuild and
    // write" step are atomic with respect to other writers.
    let _writer_guard = REJECTED_SMOKE_AUDIT_WRITER_LOCK.lock().await;
    let path = state
        .storage
        .bundles
        .root()
        .join(REJECTED_SMOKE_AUDIT_FILENAME);
    let body_sha256 = sha256_hex(raw_body.as_bytes());
    let record = serde_json::json!({
        "schema": REJECTED_SMOKE_AUDIT_SCHEMA,
        "timestamp_utc": Utc::now().to_rfc3339(),
        "rejection_reason": rejection_reason,
        "body_sha256": body_sha256,
        "body_size_bytes": raw_body.len(),
        "posted_summary": redacted_smoke_summary(raw_body),
    });
    let line = match serde_json::to_string(&record) {
        Ok(serialized) => format!("{serialized}\n"),
        Err(_) => return,
    };

    // Fast path: use metadata for the common append decision. Reading
    // the full file under the writer lock on every rejection serialized
    // large bursts behind repeated full-file reads on native Windows.
    // The full read is only needed when the append would cross the cap
    // and the rotation path must rebuild retained lines.
    let existing_size = tokio::fs::metadata(&path)
        .await
        .map(|metadata| metadata.len() as usize)
        .unwrap_or(0);
    let projected_size = existing_size.saturating_add(line.len());

    if projected_size <= REJECTED_SMOKE_AUDIT_MAX_BYTES {
        // Common path: a plain append is enough; the file stays
        // under the cap.
        use tokio::io::AsyncWriteExt;
        let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        else {
            return;
        };
        let _ = file.write_all(line.as_bytes()).await;
        let _ = file.flush().await;
        return;
    }

    // Lane UU rotation: the post-append file would exceed the cap.
    // Rebuild the file in memory: start with the new record, then
    // append existing records from newest-back-to-oldest until the
    // Lane CCC target is reached. The target is below the hard cap so
    // a rejection burst has room for many ordinary appends before the
    // next read/projection/write rotation.
    let existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    let mut kept: Vec<&str> = Vec::new();
    let mut kept_bytes: usize = line.len();
    // The new line is always retained — it is what the rotation was
    // triggered by. Older lines are then evaluated newest-first.
    let rotate_target = REJECTED_SMOKE_AUDIT_ROTATE_TARGET_BYTES.max(line.len());
    for old_line in existing
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<&str>>()
        .into_iter()
        .rev()
    {
        // +1 for the newline the line will be written with.
        let with_newline = old_line.len().saturating_add(1);
        if kept_bytes.saturating_add(with_newline) > rotate_target {
            break;
        }
        kept.push(old_line);
        kept_bytes = kept_bytes.saturating_add(with_newline);
    }
    // Re-order: newest record first (the just-written one), then
    // older records in original chronological order. Easier to keep
    // chronological since operators expect oldest-first JSONL.
    kept.reverse();
    let mut rebuilt = String::with_capacity(kept_bytes);
    for old_line in kept {
        rebuilt.push_str(old_line);
        rebuilt.push('\n');
    }
    rebuilt.push_str(&line);

    let _ = tokio::fs::write(&path, rebuilt.as_bytes()).await;
}

/// Lane MM: read the rejected-smoke audit log (written by Lane LL) and
/// return a small summary value for operator-facing surfaces. Returns
/// `{count, latest_timestamp_utc, latest_rejection_reason}`. When the
/// log is missing or unreadable the count is zero and the latest fields
/// are `null` — the audit log is forensic, not gating, so a missing
/// file is normal on a freshly-provisioned control plane.
///
/// `latest_rejection_reason` is truncated to 240 chars so a future
/// long-form diagnostic cannot bloat the cockpit HTML.
pub(crate) async fn rejected_smoke_audit_summary(state: &AppState) -> serde_json::Value {
    let path = state
        .storage
        .bundles
        .root()
        .join(REJECTED_SMOKE_AUDIT_FILENAME);
    let Ok(contents) = tokio::fs::read_to_string(&path).await else {
        return serde_json::json!({
            "count": 0,
            "latest_timestamp_utc": serde_json::Value::Null,
            "latest_rejection_reason": serde_json::Value::Null,
            // Lane VV: include the rotation-budget fields on the
            // empty-log return path so the operator-facing HTML can
            // render them uniformly (showing 0 / 1 MiB). Without this,
            // operators landing on a freshly-provisioned control plane
            // would see the section pre-rotation but with no capacity
            // context.
            "audit_log_size_bytes": 0u64,
            "audit_log_cap_bytes": REJECTED_SMOKE_AUDIT_MAX_BYTES as u64,
        });
    };
    let non_empty_lines: Vec<&str> = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let count = non_empty_lines.len();
    let (latest_timestamp_utc, latest_rejection_reason) = non_empty_lines
        .last()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|record| {
            let ts = record
                .get("timestamp_utc")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            let reason = record
                .get("rejection_reason")
                .and_then(serde_json::Value::as_str)
                .map(|raw| raw.chars().take(240).collect::<String>());
            (ts, reason)
        })
        .unwrap_or((None, None));
    // Lane VV: surface the audit-log capacity so operators can see
    // when the Lane UU rotation is approaching or just happened.
    // `audit_log_size_bytes` is the current on-disk file size;
    // `audit_log_cap_bytes` is the rotation threshold. Rotation
    // events do not preserve a persistent counter — instead operators
    // infer "rotation imminent" from size near cap and "rotation
    // recent" from size dropped after a burst. Both signals are
    // observable from the two raw fields without extra state.
    serde_json::json!({
        "count": count,
        "latest_timestamp_utc": latest_timestamp_utc,
        "latest_rejection_reason": latest_rejection_reason,
        "audit_log_size_bytes": contents.len() as u64,
        "audit_log_cap_bytes": REJECTED_SMOKE_AUDIT_MAX_BYTES as u64,
    })
}

pub async fn post_phase1_three_os_smoke(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let smoke: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if let Err(err) = validate_three_os_release_smoke(&smoke) {
        // Lane LL: append-only audit trail for rejected three-OS smoke
        // ingestions. The 422 response body already names the rejection
        // reason but disappears as soon as the client closes the
        // connection; without a persistent record, operators have no
        // forensic visibility into accumulated tampering attempts.
        // Each rejection writes a redacted record to
        // <storage-root>/rejected-three-os-smoke.jsonl. The record
        // contains only an allowlist of fields (status, version,
        // release_candidate_version, source_commit_short, source_dirty,
        // candidate_correlation_parity, target_statuses) so an
        // accidental bearer/credential anywhere in the payload cannot
        // leak via the audit log. Best-effort: any IO failure is
        // logged via tracing but does NOT mask the upstream 422.
        let reason = err.to_string();
        append_rejected_smoke_audit(&state, raw, &reason).await;
        return Err(err);
    }
    let sha = sha256_of_canonical(&smoke).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::ThreeOsReleaseSmoke, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ThreeOsReleaseSmoke, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: THREE_OS_RELEASE_SMOKE_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: smoke
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

    Ok(Json(IngestReceipt::new(
        sha,
        THREE_OS_RELEASE_SMOKE_SCHEMA.to_string(),
    )))
}

pub async fn latest_phase1_three_os_smoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_three_os_smoke_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_phase1_three_os_smoke_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_phase1_three_os_smoke(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_phase1_three_os_smoke_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/phase1/promotion/three-os-smoke/:sha`.
pub async fn head_phase1_three_os_smoke(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ThreeOsReleaseSmoke, &sha)
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

async fn phase1_promotion_dashboard_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let readiness = latest_provider_readiness(state).await?;
    let acceptance = latest_acceptance_by_provider(state).await?;
    let checklist_artifact = latest_checklist_entry_value(state).await?;
    let decision_artifact = latest_decision_entry_value(state).await?;
    let three_os_smoke_artifact = latest_three_os_smoke_entry_value(state).await?;
    let acceptance_status = live_provider_acceptance_check(
        acceptance.get("codex").unwrap_or(&serde_json::Value::Null),
        acceptance.get("claude").unwrap_or(&serde_json::Value::Null),
        acceptance
            .get("antigravity")
            .unwrap_or(&serde_json::Value::Null),
    );
    let acceptance_complete =
        json_str(&acceptance_status, "state") == Some("live_acceptance_complete");
    let readiness_status = readiness
        .as_ref()
        .map(|artifact| provider_readiness_check(artifact, acceptance_complete))
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "missing",
                "phase1_state": "missing",
                "next_action": "publish provider readiness evidence"
            })
        });
    let readiness_satisfied = matches!(
        json_str(&readiness_status, "status"),
        Some("observed") | Some("superseded_by_live_acceptance")
    );
    let checklist_summary = checklist_artifact
        .as_ref()
        .map(|(entry, checklist)| checklist_artifact_summary(entry, checklist))
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "missing",
                "phase1_state": "missing",
                "next_action": "publish the factory-v3 Phase 1 promotion checklist artifact"
            })
        });
    let checklist_passed = json_str(&checklist_summary, "status") == Some("passed")
        && json_str(&checklist_summary, "phase1_state") == Some("phase1_candidate_ready");
    let decision_summary = match decision_artifact.as_ref() {
        Some((entry, decision)) => decision_artifact_summary(state, entry, decision).await?,
        None => serde_json::json!({
            "status": "missing",
            "decision": "missing",
            "next_action": "publish a signed Phase 1 promotion decision after checklist review"
        }),
    };
    let signed_promotion_decision = json_str(&decision_summary, "decision")
        == Some("promote_phase1_candidate")
        && decision_summary
            .get("signature")
            .and_then(|value| value.get("signature_verified"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let state_value = if signed_promotion_decision {
        "promotion_decision_observed"
    } else if checklist_passed {
        "release_candidate_observed"
    } else if readiness_satisfied && acceptance_complete {
        "release_gate_ready"
    } else {
        "collecting_evidence"
    };
    let next_action = match state_value {
        "promotion_decision_observed" => {
            "signed Phase 1 promotion decision observed; proceed with release packaging or patch bump according to operator decision"
        }
        "release_candidate_observed" => {
            "review the ingested Phase 1 promotion checklist and publish a signed release-line decision"
        }
        "release_gate_ready" => {
            "run the guarded release gate with the latest factory-v3 three-OS evidence before Phase 1 promotion"
        }
        _ => "publish provider readiness and live provider acceptance evidence before Phase 1 promotion",
    };
    let release_gate_status = serde_json::json!({
        "status": "external_required",
        "state": "pending_operator_gate",
        "next_action": "run factory-v3 release-gate dry-run or final AO2 release gate"
    });
    let three_os_smoke_status = three_os_smoke_artifact
        .as_ref()
        .map(|(entry, smoke)| three_os_smoke_artifact_summary(entry, smoke))
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "external_required",
                "state": "pending_factory_evidence",
                "next_action": "attach latest factory-v3 three-OS smoke summary with macOS, Ubuntu, and Windows proof"
            })
        });
    let gap_report = phase1_gap_report(Phase1GapInputs {
        state: state_value,
        next_action,
        readiness_status: &readiness_status,
        acceptance_status: &acceptance_status,
        checklist_summary: &checklist_summary,
        decision_summary: &decision_summary,
        release_gate_status: &release_gate_status,
        three_os_smoke_status: &three_os_smoke_status,
    });
    let candidate_correlation =
        super::release_publication::release_publication_dashboard_value(state)
            .await
            .ok()
            .and_then(|dash| dash.get("candidate_correlation").cloned())
            .unwrap_or_else(|| {
                serde_json::json!({
                    "status": "missing",
                    "blockers": ["release publication dashboard unavailable"]
                })
            });
    Ok(serde_json::json!({
        "schema_version": PHASE1_PROMOTION_DASHBOARD_SCHEMA,
        "state": state_value,
        "next_action": next_action,
        "gap_report": gap_report,
        "checklist_artifact": checklist_summary,
        "decision_artifact": decision_summary,
        "candidate_correlation": candidate_correlation,
        "checklist": {
            "provider_readiness": readiness_status,
            "live_provider_acceptance": acceptance_status,
            "release_gate": release_gate_status,
            "three_os_smoke": three_os_smoke_status
        },
        "links": {
            "dashboard": "/api/v1/phase1/promotion/dashboard",
            "dashboard_json": "/api/v1/phase1/promotion/dashboard.json",
            "operator_support_bundle_json": "/api/v1/phase1/promotion/operator-support-bundle.json",
            "gap_report_json": "/api/v1/phase1/promotion/gap-report.json",
            "gap_report_download": "/api/v1/phase1/promotion/gap-report/download",
            "gap_report_checksums": "/api/v1/phase1/promotion/gap-report/SHA256SUMS",
            "portable_manifest": "/api/v1/phase1/promotion/portable-manifest",
            "portable_manifest_json": "/api/v1/phase1/promotion/portable-manifest.json",
            "portable_manifest_download": "/api/v1/phase1/promotion/portable-manifest/download",
            "portable_manifest_checksums": "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS",
            "portable_manifest_verify": "/api/v1/phase1/promotion/portable-manifest/verify",
            "portable_manifest_verify_json": "/api/v1/phase1/promotion/portable-manifest/verify.json",
            "history_json": "/api/v1/phase1/promotion/history.json",
            "latest_three_os_smoke": "/api/v1/phase1/promotion/three-os-smoke/latest",
            "latest_checklist": "/api/v1/phase1/promotion/checklist/latest",
            "latest_decision": "/api/v1/phase1/promotion/decision/latest",
            "provider_readiness_dashboard": "/api/v1/provider/readiness/dashboard",
            "acceptance_dashboard": "/api/v1/acceptance/dashboard",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        }
    }))
}

async fn phase1_operator_panel_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let dashboard = phase1_promotion_dashboard_value(state).await?;
    let candidate_correlation = dashboard
        .get("candidate_correlation")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let gap_report = dashboard
        .get("gap_report")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "total_open_gaps": 0, "blocking_gaps": [] }));
    let checklist_artifact = dashboard
        .get("checklist_artifact")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "status": "missing" }));
    let decision_artifact = dashboard
        .get("decision_artifact")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "status": "missing" }));
    let three_os = dashboard
        .get("checklist")
        .and_then(|checklist| checklist.get("three_os_smoke"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "status": "missing" }));
    let total_open_gaps = gap_report
        .get("total_open_gaps")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let signature_verified = decision_artifact
        .get("signature")
        .and_then(|signature| signature.get("signature_verified"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // A cryptographically-verified signature is NOT sufficient to call a
    // candidate release-ready: the signer must be a configured trust anchor.
    // Gating "ready" on signature_verified alone would let a token holder
    // self-sign a "promote" decision with an arbitrary key and have the
    // control plane present it as authoritative. release_authoritative is
    // true only when annotate_trust_policy matched the signing key against
    // the operator-configured allowlist.
    let release_authoritative = decision_artifact
        .get("signature")
        .and_then(|signature| signature.get("trust_policy"))
        .and_then(|trust_policy| trust_policy.get("release_authoritative"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let status = if json_str(&dashboard, "state") == Some("promotion_decision_observed")
        && total_open_gaps == 0
        && release_authoritative
        && json_str(&three_os, "status") == Some("passed")
    {
        "ready"
    } else if total_open_gaps > 0 {
        "attention"
    } else {
        "review"
    };
    let checklist_status = json_str(&checklist_artifact, "status").unwrap_or("missing");
    let decision_status = json_str(&decision_artifact, "status").unwrap_or("missing");
    let three_os_status = json_str(&three_os, "status").unwrap_or("missing");
    let signed_decision_badge = if decision_status == "passed"
        && json_str(&decision_artifact, "decision") == Some("promote_phase1_candidate")
    {
        "passed"
    } else {
        decision_status
    };
    let operator_action_queue = gap_report
        .get("operator_action_queue")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .map(serde_json::Value::Array)
        .unwrap_or_else(|| serde_json::json!([]));

    Ok(serde_json::json!({
        "schema_version": PHASE1_OPERATOR_PANEL_SCHEMA,
        "status": status,
        "summary": "Read-only Phase 1 operator panel for Hermes/factory-v3 handoff; AO2 remains the trusted signed evidence boundary.",
        "operator_status": {
            "state": json_str(&dashboard, "state").unwrap_or("unknown"),
            "phase1_state": json_str(&decision_artifact, "phase1_state")
                .or_else(|| json_str(&checklist_artifact, "phase1_state"))
                .unwrap_or("unknown"),
            "checklist_status": checklist_status,
            "signed_decision_status": decision_status,
            "decision": json_str(&decision_artifact, "decision").unwrap_or("missing"),
            "signature_verified": signature_verified,
            "release_authoritative": release_authoritative,
            "three_os_status": three_os_status,
            "three_os_state": json_str(&three_os, "state").unwrap_or("unknown"),
            "next_action": json_str(&dashboard, "next_action").unwrap_or("review Phase 1 promotion dashboard"),
        },
        "badges": {
            "checklist": checklist_status,
            "signed_decision": signed_decision_badge,
            "signature": if signature_verified { "verified" } else { "missing" },
            "three_os": three_os_status,
            "candidate_correlation": json_str(&candidate_correlation, "status").unwrap_or("missing"),
            "decision_mode": json_str(&decision_artifact, "decision_mode").unwrap_or("missing"),
        },
        "candidate_correlation": candidate_correlation,
        "gap_report": gap_report,
        "operator_action_queue": operator_action_queue,
        "links": {
            "operator_panel": "/api/v1/phase1/promotion/operator-panel",
            "operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
            "operator_support_bundle_json": "/api/v1/phase1/promotion/operator-support-bundle.json",
            "dashboard": "/api/v1/phase1/promotion/dashboard",
            "dashboard_json": "/api/v1/phase1/promotion/dashboard.json",
            "gap_report_json": "/api/v1/phase1/promotion/gap-report.json",
            "gap_report_download": "/api/v1/phase1/promotion/gap-report/download",
            "gap_report_checksums": "/api/v1/phase1/promotion/gap-report/SHA256SUMS",
            "portable_manifest": "/api/v1/phase1/promotion/portable-manifest",
            "portable_manifest_json": "/api/v1/phase1/promotion/portable-manifest.json",
            "portable_manifest_download": "/api/v1/phase1/promotion/portable-manifest/download",
            "portable_manifest_checksums": "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS",
            "portable_manifest_verify": "/api/v1/phase1/promotion/portable-manifest/verify",
            "portable_manifest_verify_json": "/api/v1/phase1/promotion/portable-manifest/verify.json",
            "history_json": "/api/v1/phase1/promotion/history.json",
            "latest_three_os_smoke": "/api/v1/phase1/promotion/three-os-smoke/latest",
            "latest_checklist": "/api/v1/phase1/promotion/checklist/latest",
            "latest_decision": "/api/v1/phase1/promotion/decision/latest",
            "provider_readiness_dashboard": "/api/v1/provider/readiness/dashboard",
            "acceptance_dashboard": "/api/v1/acceptance/dashboard",
            "evidence_dashboard": "/api/v1/evidence-pack/dashboard",
            "memory_dashboard": "/api/v1/memory/export/dashboard",
        },
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
            "front_end": "Hermes and factory-v3 operator surfaces",
        },
        "source": {
            "dashboard_schema_version": PHASE1_PROMOTION_DASHBOARD_SCHEMA,
            "dashboard_state": json_str(&dashboard, "state").unwrap_or("unknown"),
        },
    }))
}

async fn phase1_operator_support_bundle_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let (generated_at, generated_at_source) =
        phase1_operator_support_bundle_generated_at(state).await?;
    let dashboard = phase1_promotion_dashboard_value(state).await?;
    let gap_report = dashboard.get("gap_report").cloned().unwrap_or_else(
        || serde_json::json!({ "total_open_gaps": 0, "operator_action_queue": [] }),
    );
    let operator_panel = phase1_operator_panel_value(state).await?;
    let operator_action_queue = operator_panel
        .get("operator_action_queue")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .map(serde_json::Value::Array)
        .unwrap_or_else(|| serde_json::json!([]));
    let mut promotion_history = phase1_promotion_history_value(state).await?;
    if let Some(history) = promotion_history.as_object_mut() {
        history.insert("generated_at".to_string(), serde_json::json!(generated_at));
        history.insert(
            "generated_at_source".to_string(),
            serde_json::json!(generated_at_source),
        );
    }
    let promotion_timeline = promotion_history
        .get("timeline")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .map(serde_json::Value::Array)
        .unwrap_or_else(|| serde_json::json!([]));
    let timeline_integrity = phase1_timeline_integrity_entries(&promotion_timeline)?;

    Ok(serde_json::json!({
        "schema_version": PHASE1_OPERATOR_SUPPORT_BUNDLE_SCHEMA,
        "generated_at": generated_at,
        "generated_at_source": generated_at_source,
        "portable": true,
        "summary": "Portable read-only operator support bundle for Hermes/factory-v3 Phase 1 handoff review.",
        "mutates_ao_artifacts": false,
        "release_acceptance_owner": "factory-v3 evaluator-closer",
        "trusted_execution": "ao2 signed evidence boundary",
        "bundle_manifest": {
            "entries": [
                "dashboard",
                "gap_report",
                "operator_panel",
                "operator_action_queue",
                "promotion_history",
                "promotion_timeline",
                "timeline_integrity",
                "trust_boundary"
            ],
            "portable_json": true,
            "contains_credentials": false,
            "read_only_observer": true
        },
        "timeline_integrity": timeline_integrity,
        "snapshots": {
            "dashboard": dashboard,
            "gap_report": gap_report,
            "operator_panel": operator_panel,
            "operator_action_queue": operator_action_queue,
            "promotion_history": promotion_history,
            "promotion_timeline": promotion_timeline
        },
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
            "front_end": "Hermes scheduler and operator queue surface"
        },
        "next_steps": [
            "Review this bundle as observer context only; it is not release approval.",
            "Use factory-v3 evaluator-closer for release acceptance decisions.",
            "Use AO2 signed evidence as the trusted execution and closure boundary."
        ],
        "links": {
            "operator_support_bundle_json": "/api/v1/phase1/promotion/operator-support-bundle.json",
            "operator_support_bundle_download": "/api/v1/phase1/promotion/operator-support-bundle/download",
            "operator_support_bundle_checksums": "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS",
            "operator_support_bundle_verify": "/api/v1/phase1/promotion/operator-support-bundle/verify",
            "operator_support_bundle_verify_json": "/api/v1/phase1/promotion/operator-support-bundle/verify.json",
            "portable_manifest_verify": "/api/v1/phase1/promotion/portable-manifest/verify",
            "portable_manifest_verify_json": "/api/v1/phase1/promotion/portable-manifest/verify.json",
            "operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
            "dashboard_json": "/api/v1/phase1/promotion/dashboard.json",
            "gap_report_json": "/api/v1/phase1/promotion/gap-report.json",
            "gap_report_download": "/api/v1/phase1/promotion/gap-report/download",
            "gap_report_checksums": "/api/v1/phase1/promotion/gap-report/SHA256SUMS",
            "history_json": "/api/v1/phase1/promotion/history.json",
            "portable_manifest": "/api/v1/phase1/promotion/portable-manifest",
            "portable_manifest_json": "/api/v1/phase1/promotion/portable-manifest.json"
        }
    }))
}

async fn phase1_portable_manifest_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let support_bundle = phase1_operator_support_bundle_value(state).await?;
    let gap_report = phase1_gap_report_value(state).await?;
    let support_body = serde_json::to_vec_pretty(&support_bundle)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let gap_body =
        serde_json::to_vec_pretty(&gap_report).map_err(|e| AppError::Internal(e.to_string()))?;
    let (generated_at, generated_at_source) =
        phase1_operator_support_bundle_generated_at(state).await?;
    let candidate_correlation = support_bundle
        .get("snapshots")
        .and_then(|snapshots| snapshots.get("dashboard"))
        .and_then(|dashboard| dashboard.get("candidate_correlation"))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "missing",
                "blockers": ["phase1 dashboard candidate_correlation unavailable"]
            })
        });
    Ok(serde_json::json!({
        "schema_version": PHASE1_PORTABLE_MANIFEST_SCHEMA,
        "generated_at": generated_at,
        "generated_at_source": generated_at_source,
        "summary": "Portable Phase 1 observer manifest for Hermes/factory-v3 handoff artifacts; AO2 signed evidence remains the trusted boundary.",
        "portable": true,
        "contains_credentials": false,
        "mutates_ao_artifacts": false,
        "candidate_correlation": candidate_correlation,
        "artifacts": [
            {
                "name": "phase1_operator_support_bundle",
                "schema_version": PHASE1_OPERATOR_SUPPORT_BUNDLE_SCHEMA,
                "filename": phase1_operator_support_bundle_filename(),
                "content_type": "application/json; charset=utf-8",
                "sha256": sha256_hex(&support_body),
                "size_bytes": support_body.len(),
                "digest_scope": "manifest_snapshot_pretty_json_bytes",
                "download_recomputes_generated_at": false,
                "download_url": "/api/v1/phase1/promotion/operator-support-bundle/download",
                "json_url": "/api/v1/phase1/promotion/operator-support-bundle.json",
                "checksums_url": "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS",
                "control_plane_role": "read-only-observer",
                "mutates_ao_artifacts": false,
                "release_acceptance_owner": "factory-v3 evaluator-closer"
            },
            {
                "name": "phase1_gap_report",
                "schema_version": "ao2.cp-phase1-gap-report.v1",
                "filename": phase1_gap_report_filename(),
                "content_type": "application/json; charset=utf-8",
                "sha256": sha256_hex(&gap_body),
                "size_bytes": gap_body.len(),
                "digest_scope": "manifest_snapshot_pretty_json_bytes",
                "download_recomputes_generated_at": false,
                "download_url": "/api/v1/phase1/promotion/gap-report/download",
                "json_url": "/api/v1/phase1/promotion/gap-report.json",
                "checksums_url": "/api/v1/phase1/promotion/gap-report/SHA256SUMS",
                "control_plane_role": "read-only-observer",
                "mutates_ao_artifacts": false,
                "release_acceptance_owner": "factory-v3 evaluator-closer"
            }
        ],
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
            "front_end": "Hermes scheduler and operator queue surface"
        },
        "links": {
            "portable_manifest": "/api/v1/phase1/promotion/portable-manifest",
            "portable_manifest_json": "/api/v1/phase1/promotion/portable-manifest.json",
            "portable_manifest_download": "/api/v1/phase1/promotion/portable-manifest/download",
            "portable_manifest_checksums": "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS",
            "portable_manifest_verify": "/api/v1/phase1/promotion/portable-manifest/verify",
            "portable_manifest_verify_json": "/api/v1/phase1/promotion/portable-manifest/verify.json",
            "operator_support_bundle_download": "/api/v1/phase1/promotion/operator-support-bundle/download",
            "operator_support_bundle_checksums": "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS",
            "gap_report_download": "/api/v1/phase1/promotion/gap-report/download",
            "gap_report_checksums": "/api/v1/phase1/promotion/gap-report/SHA256SUMS"
        }
    }))
}

fn phase1_operator_support_bundle_filename() -> &'static str {
    "ao2-phase1-operator-support-bundle.json"
}

fn parse_portable_manifest_verification_body(body: &Bytes) -> Result<serde_json::Value, AppError> {
    if body.is_empty() {
        return Err(AppError::BadRequest(
            "portable manifest verification requires a JSON upload body".into(),
        ));
    }
    let upload: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let schema = json_str(&upload, "schema_version").unwrap_or("missing");
    if schema != PHASE1_PORTABLE_MANIFEST_VERIFICATION_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PHASE1_PORTABLE_MANIFEST_VERIFICATION_UPLOAD_SCHEMA}, got {schema}"
        )));
    }
    Ok(upload)
}

fn phase1_portable_manifest_verification_value(
    upload: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    let manifest = upload.get("manifest").ok_or_else(|| {
        AppError::SchemaInvalid("portable manifest upload missing manifest".into())
    })?;
    if json_str(manifest, "schema_version") != Some(PHASE1_PORTABLE_MANIFEST_SCHEMA) {
        return Err(AppError::SchemaInvalid(format!(
            "manifest schema_version must be {PHASE1_PORTABLE_MANIFEST_SCHEMA}"
        )));
    }
    let supplied_artifacts = upload
        .get("artifacts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::SchemaInvalid("portable manifest upload missing artifacts object".into())
        })?;
    let manifest_artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let manifest_artifact_names = manifest_artifacts
        .iter()
        .filter_map(|artifact| json_str(artifact, "name"))
        .collect::<std::collections::HashSet<_>>();
    let unexpected_artifacts = supplied_artifacts
        .keys()
        .filter(|name| !manifest_artifact_names.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    let mut verified_artifacts = 0usize;
    let mut mismatched_artifacts = 0usize;
    let mut missing_artifacts = 0usize;
    let mut results = Vec::with_capacity(manifest_artifacts.len());

    for artifact in manifest_artifacts {
        let name = json_str(artifact, "name").unwrap_or("unknown");
        let expected_sha256 = json_str(artifact, "sha256").map(str::to_string);
        let expected_size_bytes = artifact
            .get("size_bytes")
            .and_then(serde_json::Value::as_u64);
        let expected_schema_version = json_str(artifact, "schema_version").map(str::to_string);
        let supplied = supplied_artifacts.get(name);
        let (actual_sha256, actual_size_bytes, actual_schema_version) = match supplied {
            Some(value) => {
                let body = serde_json::to_vec_pretty(value)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                (
                    Some(sha256_hex(&body)),
                    Some(body.len() as u64),
                    json_str(value, "schema_version")
                        .or_else(|| json_str(value, "schema"))
                        .map(str::to_string),
                )
            }
            None => {
                missing_artifacts += 1;
                (None, None, None)
            }
        };
        let verified = supplied.is_some()
            && expected_sha256.is_some()
            && expected_size_bytes.is_some()
            && actual_sha256 == expected_sha256
            && actual_size_bytes == expected_size_bytes
            && actual_schema_version == expected_schema_version;
        if verified {
            verified_artifacts += 1;
        } else {
            mismatched_artifacts += 1;
        }
        results.push(serde_json::json!({
            "artifact_name": name,
            "filename": json_str(artifact, "filename").unwrap_or("unknown"),
            "expected_schema_version": expected_schema_version,
            "actual_schema_version": actual_schema_version,
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "expected_size_bytes": expected_size_bytes,
            "actual_size_bytes": actual_size_bytes,
            "digest_scope": json_str(artifact, "digest_scope").unwrap_or("manifest_snapshot_pretty_json_bytes"),
            "verified": verified,
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
        }));
    }

    let status =
        if mismatched_artifacts == 0 && missing_artifacts == 0 && unexpected_artifacts.is_empty() {
            "verified"
        } else {
            "tampered"
        };
    Ok(serde_json::json!({
        "schema_version": PHASE1_PORTABLE_MANIFEST_VERIFICATION_SCHEMA,
        "status": status,
        "counts": {
            "manifest_artifacts": manifest_artifacts.len(),
            "supplied_artifacts": supplied_artifacts.len(),
            "verified_artifacts": verified_artifacts,
            "mismatched_artifacts": mismatched_artifacts,
            "missing_artifacts": missing_artifacts,
            "unexpected_artifacts": unexpected_artifacts.len(),
        },
        "unexpected_artifacts": unexpected_artifacts,
        "results": results,
        "trust_boundary": {
            "role": "read_only_observer",
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary"
        },
        "summary": "Recomputes pretty JSON byte SHA-256 and size for supplied portable manifest artifacts; this is observer verification only, not release approval."
    }))
}

fn parse_support_bundle_verification_body(body: &Bytes) -> Result<serde_json::Value, AppError> {
    if body.is_empty() {
        return Err(AppError::BadRequest(
            "operator support bundle verification requires a JSON bundle body".into(),
        ));
    }
    serde_json::from_slice(body).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn phase1_operator_support_bundle_verification_value(
    bundle: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    let timeline_entries = bundle
        .get("snapshots")
        .and_then(|snapshots| snapshots.get("promotion_timeline"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let integrity_entries = bundle
        .get("timeline_integrity")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let max_len = timeline_entries.len().max(integrity_entries.len());
    let mut results = Vec::with_capacity(max_len);
    let mut verified_entries = 0usize;
    let mut mismatched_entries = 0usize;

    for idx in 0..max_len {
        let timeline_entry = timeline_entries.get(idx);
        let integrity_entry = integrity_entries.get(idx);
        let actual_canonical_sha256 = timeline_entry
            .map(|entry| sha256_of_canonical(entry).map_err(|e| AppError::Internal(e.to_string())))
            .transpose()?;
        let expected_canonical_sha256 = integrity_entry
            .and_then(|entry| json_str(entry, "canonical_sha256"))
            .map(str::to_string);
        let verified = actual_canonical_sha256.is_some()
            && expected_canonical_sha256.is_some()
            && actual_canonical_sha256 == expected_canonical_sha256;
        if verified {
            verified_entries += 1;
        } else {
            mismatched_entries += 1;
        }
        results.push(serde_json::json!({
            "index": idx,
            "artifact_kind": integrity_entry
                .and_then(|entry| json_str(entry, "artifact_kind"))
                .or_else(|| timeline_entry.and_then(|entry| json_str(entry, "artifact_kind")))
                .unwrap_or("unknown"),
            "sha256": integrity_entry
                .and_then(|entry| json_str(entry, "sha256"))
                .or_else(|| timeline_entry.and_then(|entry| json_str(entry, "sha256")))
                .unwrap_or("unknown"),
            "expected_canonical_sha256": expected_canonical_sha256,
            "actual_canonical_sha256": actual_canonical_sha256,
            "digest_scope": integrity_entry
                .and_then(|entry| json_str(entry, "digest_scope"))
                .unwrap_or("timeline_entry_canonical_json"),
            "verified": verified,
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
        }));
    }

    let status = if mismatched_entries == 0 {
        "verified"
    } else {
        "tampered"
    };
    Ok(serde_json::json!({
        "schema_version": PHASE1_OPERATOR_SUPPORT_BUNDLE_VERIFICATION_SCHEMA,
        "status": status,
        "counts": {
            "timeline_entries": timeline_entries.len(),
            "integrity_entries": integrity_entries.len(),
            "verified_entries": verified_entries,
            "mismatched_entries": mismatched_entries
        },
        "results": results,
        "trust_boundary": {
            "role": "read_only_observer",
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary"
        },
        "summary": "Recomputes canonical SHA-256 for embedded promotion timeline entries and compares them with bundled timeline_integrity; this is observer verification only, not release approval."
    }))
}

fn phase1_timeline_integrity_entries(
    timeline: &serde_json::Value,
) -> Result<Vec<serde_json::Value>, AppError> {
    let entries = timeline
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let canonical_sha256 =
                sha256_of_canonical(entry).map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(serde_json::json!({
                "artifact_kind": json_str(entry, "artifact_kind").unwrap_or("unknown"),
                "sha256": json_str(entry, "sha256").unwrap_or("unknown"),
                "canonical_sha256": canonical_sha256,
                "digest_scope": "timeline_entry_canonical_json",
                "control_plane_role": "read-only-observer",
                "mutates_ao_artifacts": false,
            }))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(entries)
}

async fn phase1_operator_support_bundle_generated_at(
    state: &AppState,
) -> Result<(chrono::DateTime<Utc>, &'static str), AppError> {
    let entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let generated_at = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.schema.as_str(),
                PROVIDER_READINESS_SCHEMA
                    | "ao2.codex-provider-pilot-acceptance.v1"
                    | "ao2.claude-provider-pilot-acceptance.v1"
                    | PHASE1_PROMOTION_CHECKLIST_SCHEMA
                    | PHASE1_PROMOTION_DECISION_SCHEMA
                    | THREE_OS_RELEASE_SMOKE_SCHEMA
            )
        })
        .map(|entry| entry.ingested_at)
        .max();

    Ok(match generated_at {
        Some(timestamp) => (timestamp, "latest_observed_phase1_index_entry"),
        None => (
            // Epoch fallback when nothing has been observed yet. `unwrap_or_default()`
            // (the Unix epoch for `DateTime<Utc>`) keeps this request-path code panic-free
            // even though `timestamp_opt(0, 0)` is infallible today — a read-only observer
            // must never be able to panic while building a dashboard response.
            Utc.timestamp_opt(0, 0).single().unwrap_or_default(),
            "no_observed_phase1_index_entry_epoch_fallback",
        ),
    })
}

async fn phase1_gap_report_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let dashboard = phase1_promotion_dashboard_value(state).await?;
    dashboard
        .get("gap_report")
        .cloned()
        .ok_or_else(|| AppError::Internal("phase1 dashboard missing gap_report".to_string()))
}

fn phase1_gap_report_filename() -> &'static str {
    "ao2-phase1-gap-report.json"
}

fn phase1_portable_manifest_filename() -> &'static str {
    "ao2-phase1-portable-manifest.json"
}

fn phase1_portable_manifest_checksums_text(
    manifest: &serde_json::Value,
) -> Result<String, AppError> {
    let body =
        serde_json::to_vec_pretty(manifest).map_err(|e| AppError::Internal(e.to_string()))?;
    let manifest_sha256 = sha256_hex(&body);
    let lines = [
        "# ao2-control-plane Phase 1 portable manifest SHA256SUMS".to_string(),
        "# schema: ao2.cp-phase1-portable-manifest-checksums.v1".to_string(),
        "# algorithm: sha256-pretty-json-bytes-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        "# release-acceptance-owner: factory-v3 evaluator-closer".to_string(),
        format!("{manifest_sha256}  {}", phase1_portable_manifest_filename()),
        String::new(),
    ];
    Ok(lines.join("\n"))
}

fn phase1_gap_report_checksums_text(report: &serde_json::Value) -> Result<String, AppError> {
    let body = serde_json::to_vec_pretty(report).map_err(|e| AppError::Internal(e.to_string()))?;
    let report_sha256 = sha256_hex(&body);
    let lines = [
        "# ao2-control-plane Phase 1 gap report SHA256SUMS".to_string(),
        "# schema: ao2.cp-phase1-gap-report-checksums.v1".to_string(),
        "# algorithm: sha256-pretty-json-bytes-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        "# release-acceptance-owner: factory-v3 evaluator-closer".to_string(),
        format!("{report_sha256}  {}", phase1_gap_report_filename()),
        String::new(),
    ];
    Ok(lines.join("\n"))
}

fn phase1_operator_support_bundle_checksums_text(
    bundle: &serde_json::Value,
) -> Result<String, AppError> {
    let body = serde_json::to_vec_pretty(bundle).map_err(|e| AppError::Internal(e.to_string()))?;
    let bundle_sha256 = sha256_hex(&body);
    let lines = [
        "# ao2-control-plane Phase 1 operator support bundle SHA256SUMS".to_string(),
        "# schema: ao2.cp-phase1-operator-support-bundle-checksums.v1".to_string(),
        "# algorithm: sha256-pretty-json-bytes-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        "# release-acceptance-owner: factory-v3 evaluator-closer".to_string(),
        format!(
            "{bundle_sha256}  {}",
            phase1_operator_support_bundle_filename()
        ),
        String::new(),
    ];
    Ok(lines.join("\n"))
}

async fn phase1_promotion_history_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let mut checklist_entries = phase1_promotion_checklist_entries(state).await?;
    checklist_entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut decision_entries = phase1_promotion_decision_entries(state).await?;
    decision_entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut inputs_verification_entries =
        phase1_promotion_inputs_verification_entries(state).await?;
    inputs_verification_entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut smoke_entries = three_os_smoke_entries(state).await?;
    smoke_entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));

    let mut checklists = Vec::new();
    for entry in checklist_entries
        .iter()
        .take(PHASE1_PROMOTION_HISTORY_LIMIT)
    {
        let checklist = read_phase1_promotion_checklist_value(state, &entry.sha256).await?;
        checklists.push(checklist_artifact_summary(entry, &checklist));
    }

    let mut decisions = Vec::new();
    for entry in decision_entries.iter().take(PHASE1_PROMOTION_HISTORY_LIMIT) {
        let decision = read_phase1_promotion_decision_value(state, &entry.sha256).await?;
        decisions.push(decision_artifact_summary(state, entry, &decision).await?);
    }

    let mut inputs_verifications = Vec::new();
    for entry in inputs_verification_entries
        .iter()
        .take(PHASE1_PROMOTION_HISTORY_LIMIT)
    {
        let report = read_phase1_promotion_inputs_verification_value(state, &entry.sha256).await?;
        inputs_verifications.push(inputs_verification_artifact_summary(entry, &report));
    }

    let mut three_os_smokes = Vec::new();
    for entry in smoke_entries.iter().take(PHASE1_PROMOTION_HISTORY_LIMIT) {
        let smoke = read_three_os_smoke_value(state, &entry.sha256).await?;
        three_os_smokes.push(three_os_smoke_artifact_summary(entry, &smoke));
    }

    let mut timeline = phase1_promotion_timeline(
        &checklists,
        &decisions,
        &inputs_verifications,
        &three_os_smokes,
    );
    timeline.sort_by(|left, right| {
        let left_ingested = json_str(left, "ingested_at").unwrap_or("");
        let right_ingested = json_str(right, "ingested_at").unwrap_or("");
        right_ingested.cmp(left_ingested)
    });
    timeline.truncate(PHASE1_PROMOTION_HISTORY_LIMIT);

    Ok(serde_json::json!({
        "schema_version": PHASE1_PROMOTION_HISTORY_SCHEMA,
        "generated_at": Utc::now(),
        "limit": PHASE1_PROMOTION_HISTORY_LIMIT,
        "counts": {
            "checklists": checklist_entries.len(),
            "signed_decisions": decision_entries.len(),
            "promotion_input_verifications": inputs_verification_entries.len(),
            "three_os_smokes": smoke_entries.len(),
        },
        "latest": {
            "checklist_sha256": checklist_entries.first().map(|entry| entry.sha256.as_str()),
            "decision_sha256": decision_entries.first().map(|entry| entry.sha256.as_str()),
            "promotion_inputs_verification_sha256": inputs_verification_entries.first().map(|entry| entry.sha256.as_str()),
            "three_os_smoke_sha256": smoke_entries.first().map(|entry| entry.sha256.as_str()),
        },
        "history": {
            "checklists": checklists,
            "signed_decisions": decisions,
            "promotion_input_verifications": inputs_verifications,
            "three_os_smokes": three_os_smokes,
        },
        "timeline": timeline,
        "links": {
            "dashboard": "/api/v1/phase1/promotion/dashboard",
            "dashboard_json": "/api/v1/phase1/promotion/dashboard.json",
            "gap_report_json": "/api/v1/phase1/promotion/gap-report.json",
            "portable_manifest_json": "/api/v1/phase1/promotion/portable-manifest.json",
            "latest_three_os_smoke": "/api/v1/phase1/promotion/three-os-smoke/latest",
            "latest_checklist": "/api/v1/phase1/promotion/checklist/latest",
            "latest_promotion_inputs_verification": "/api/v1/phase1/promotion/inputs-verification/latest",
            "latest_decision": "/api/v1/phase1/promotion/decision/latest",
        },
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
        }
    }))
}

fn phase1_promotion_timeline(
    checklists: &[serde_json::Value],
    decisions: &[serde_json::Value],
    inputs_verifications: &[serde_json::Value],
    three_os_smokes: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut timeline = Vec::new();
    timeline.extend(checklists.iter().map(|artifact| {
        serde_json::json!({
            "artifact_kind": "phase1_promotion_checklist",
            "schema_version": PHASE1_PROMOTION_CHECKLIST_SCHEMA,
            "sha256": json_str(artifact, "sha256").unwrap_or("unknown"),
            "status": json_str(artifact, "status").unwrap_or("unknown"),
            "phase1_state": json_str(artifact, "phase1_state").unwrap_or("unknown"),
            "ingested_at": artifact.get("ingested_at").cloned().unwrap_or(serde_json::Value::Null),
            "raw_url": json_str(artifact, "raw_url").unwrap_or("missing"),
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
        })
    }));
    timeline.extend(decisions.iter().map(|artifact| {
        let signature_verified = artifact
            .get("signature")
            .and_then(|signature| signature.get("signature_verified"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        serde_json::json!({
            "artifact_kind": "signed_phase1_promotion_decision",
            "schema_version": PHASE1_PROMOTION_DECISION_SCHEMA,
            "sha256": json_str(artifact, "sha256").unwrap_or("unknown"),
            "status": json_str(artifact, "status").unwrap_or("unknown"),
            "decision": json_str(artifact, "decision").unwrap_or("unknown"),
            "phase1_state": json_str(artifact, "phase1_state").unwrap_or("unknown"),
            "checklist_sha256": json_str(artifact, "checklist_sha256").unwrap_or("unknown"),
            "signature_verified": signature_verified,
            "ingested_at": artifact.get("ingested_at").cloned().unwrap_or(serde_json::Value::Null),
            "raw_url": json_str(artifact, "raw_url").unwrap_or("missing"),
            "signature_url": json_str(artifact, "signature_url").unwrap_or("missing"),
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
        })
    }));
    timeline.extend(inputs_verifications.iter().map(|artifact| {
        serde_json::json!({
            "artifact_kind": "phase1_promotion_inputs_verification",
            "schema_version": PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA,
            "sha256": json_str(artifact, "sha256").unwrap_or("unknown"),
            "status": json_str(artifact, "status").unwrap_or("unknown"),
            "mode": json_str(artifact, "mode").unwrap_or("unknown"),
            "failure_count": artifact.get("failure_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
            "ingested_at": artifact.get("ingested_at").cloned().unwrap_or(serde_json::Value::Null),
            "raw_url": json_str(artifact, "raw_url").unwrap_or("missing"),
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "control_plane_approves_release": false,
        })
    }));
    timeline.extend(three_os_smokes.iter().map(|artifact| {
        serde_json::json!({
            "artifact_kind": "three_os_release_smoke",
            "schema_version": THREE_OS_RELEASE_SMOKE_SCHEMA,
            "sha256": json_str(artifact, "sha256").unwrap_or("unknown"),
            "status": json_str(artifact, "status").unwrap_or("unknown"),
            "state": json_str(artifact, "state").unwrap_or("unknown"),
            "release_candidate_version": json_str(artifact, "release_candidate_version").unwrap_or("unknown"),
            "ingested_at": artifact.get("ingested_at").cloned().unwrap_or(serde_json::Value::Null),
            "raw_url": json_str(artifact, "raw_url").unwrap_or("missing"),
            "targets": artifact.get("targets").cloned().unwrap_or_else(|| serde_json::json!({})),
            "control_plane_role": "read-only-observer",
            "mutates_ao_artifacts": false,
        })
    }));
    timeline
}

struct Phase1GapInputs<'a> {
    state: &'a str,
    next_action: &'a str,
    readiness_status: &'a serde_json::Value,
    acceptance_status: &'a serde_json::Value,
    checklist_summary: &'a serde_json::Value,
    decision_summary: &'a serde_json::Value,
    release_gate_status: &'a serde_json::Value,
    three_os_smoke_status: &'a serde_json::Value,
}

fn phase1_gap_report(input: Phase1GapInputs<'_>) -> serde_json::Value {
    let mut gaps = Vec::new();

    match input.state {
        "release_gate_ready" => {
            gaps.push(phase1_gap(
                "release_gate",
                "blocking",
                "factory-v3 guarded release-gate evidence",
                json_str(input.release_gate_status, "next_action")
                    .unwrap_or("run factory-v3 release gate"),
            ));
            if json_str(input.three_os_smoke_status, "status") != Some("passed") {
                gaps.push(phase1_gap(
                    "three_os_smoke",
                    "blocking",
                    "macOS, Ubuntu, and Windows smoke evidence",
                    json_str(input.three_os_smoke_status, "next_action")
                        .unwrap_or("attach three-OS smoke summary"),
                ));
            }
        }
        "release_candidate_observed" => {
            gaps.push(phase1_gap(
                "signed_promotion_decision",
                "blocking",
                "signed Phase 1 promotion decision linked to the accepted checklist",
                json_str(input.decision_summary, "next_action")
                    .unwrap_or("publish a signed release-line decision"),
            ));
        }
        "promotion_decision_observed" => {}
        _ => {
            if json_str(input.readiness_status, "status") == Some("missing") {
                gaps.push(phase1_gap(
                    "provider_readiness",
                    "blocking",
                    "latest provider readiness evidence",
                    json_str(input.readiness_status, "next_action")
                        .unwrap_or("publish provider readiness evidence"),
                ));
            }
            if json_str(input.acceptance_status, "state") != Some("live_acceptance_complete") {
                gaps.push(phase1_gap(
                    "live_provider_acceptance",
                    "blocking",
                    "live Codex and Claude provider acceptance artifacts",
                    json_str(input.acceptance_status, "next_action")
                        .unwrap_or("publish live provider acceptance evidence"),
                ));
            }
            if json_str(input.checklist_summary, "status") == Some("missing") {
                gaps.push(phase1_gap(
                    "phase1_promotion_checklist",
                    "blocking",
                    "factory-v3 Phase 1 promotion checklist artifact",
                    json_str(input.checklist_summary, "next_action")
                        .unwrap_or("publish the Phase 1 promotion checklist"),
                ));
            }
        }
    }

    let blocking_count = gaps
        .iter()
        .filter(|gap| json_str(gap, "severity") == Some("blocking"))
        .count();
    let open_gap_ids: Vec<&str> = gaps.iter().filter_map(|gap| json_str(gap, "id")).collect();
    let operator_action_queue: Vec<_> = gaps
        .iter()
        .enumerate()
        .map(|(index, gap)| {
            let id = json_str(gap, "id").unwrap_or("unknown");
            let dependencies = phase1_gap_dependencies(id);
            let blocked_by_open_gaps: Vec<&str> = dependencies
                .iter()
                .copied()
                .filter(|dependency| open_gap_ids.contains(dependency))
                .collect();
            serde_json::json!({
                "id": id,
                "severity": json_str(gap, "severity").unwrap_or("blocking"),
                "owner": "factory-v3 evaluator-closer",
                "control_plane_action": "observe_only",
                "action_order": index + 1,
                "depends_on": dependencies,
                "ready_to_start": blocked_by_open_gaps.is_empty(),
                "blocked_by_open_gaps": blocked_by_open_gaps,
                "next_action": json_str(gap, "next_action").unwrap_or("review phase readiness gap"),
                "evidence_needed": json_str(gap, "evidence_needed").unwrap_or("governed release evidence"),
            })
        })
        .collect();
    let ready_to_start_count = operator_action_queue
        .iter()
        .filter(|action| {
            action
                .get("ready_to_start")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let mut critical_path = operator_action_queue.clone();
    critical_path.sort_by_key(|action| {
        (
            !action
                .get("ready_to_start")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            std::cmp::Reverse(
                action
                    .get("depends_on")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
            ),
            action
                .get("action_order")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX),
        )
    });

    serde_json::json!({
        "schema_version": "ao2.cp-phase1-gap-report.v1",
        "state": input.state,
        "total_open_gaps": gaps.len(),
        "summary": {
            "blocking": blocking_count,
            "ready_to_start_actions": ready_to_start_count,
            "read_only_observer": true,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
        },
        "blocking_gaps": gaps,
        "operator_action_queue": operator_action_queue,
        "critical_path": critical_path,
        "next_recommended_action": input.next_action,
        "trust_boundary": {
            "role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary"
        }
    })
}

fn phase1_gap(
    id: &str,
    severity: &str,
    evidence_needed: &str,
    next_action: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "severity": severity,
        "evidence_needed": evidence_needed,
        "next_action": next_action,
    })
}

fn phase1_gap_dependencies(id: &str) -> Vec<&'static str> {
    match id {
        "provider_readiness" => Vec::new(),
        "live_provider_acceptance" => vec!["provider_readiness"],
        "three_os_smoke" => vec!["provider_readiness", "live_provider_acceptance"],
        "release_gate" => vec![
            "provider_readiness",
            "live_provider_acceptance",
            "three_os_smoke",
        ],
        "phase1_promotion_checklist" => vec![
            "provider_readiness",
            "live_provider_acceptance",
            "release_gate",
            "three_os_smoke",
        ],
        "signed_promotion_decision" => vec!["phase1_promotion_checklist"],
        _ => Vec::new(),
    }
}

async fn latest_checklist_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = phase1_promotion_checklist_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_phase1_promotion_checklist_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn latest_decision_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = phase1_promotion_decision_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_phase1_promotion_decision_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn latest_inputs_verification_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = phase1_promotion_inputs_verification_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_phase1_promotion_inputs_verification_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn latest_three_os_smoke_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = three_os_smoke_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_three_os_smoke_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn phase1_promotion_checklist_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PHASE1_PROMOTION_CHECKLIST_SCHEMA);
    Ok(entries)
}

async fn phase1_promotion_decision_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PHASE1_PROMOTION_DECISION_SCHEMA);
    Ok(entries)
}

async fn phase1_promotion_inputs_verification_entries(
    state: &AppState,
) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA);
    Ok(entries)
}

async fn three_os_smoke_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == THREE_OS_RELEASE_SMOKE_SCHEMA);
    Ok(entries)
}

async fn read_phase1_promotion_checklist_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionChecklist, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn read_phase1_promotion_decision_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionDecision, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn read_phase1_promotion_inputs_verification_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionInputsVerification, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn read_three_os_smoke_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ThreeOsReleaseSmoke, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn get_phase1_three_os_smoke_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ThreeOsReleaseSmoke, sha)
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

async fn get_phase1_promotion_checklist_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionChecklist, sha)
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

async fn get_phase1_promotion_inputs_verification_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionInputsVerification, sha)
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

async fn get_phase1_promotion_decision_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionDecision, sha)
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

fn checklist_artifact_summary(
    entry: &IndexEntry,
    checklist: &serde_json::Value,
) -> serde_json::Value {
    let sha = &entry.sha256;
    serde_json::json!({
        "status": json_str(checklist, "status").unwrap_or("unknown"),
        "phase1_state": json_str(checklist, "phase1_state").unwrap_or("unknown"),
        "next_action": json_str(checklist, "next_action").unwrap_or("unknown"),
        "sha256": sha,
        "ingested_at": entry.ingested_at,
        "raw_url": format!("/api/v1/phase1/promotion/checklist/{sha}"),
    })
}

fn inputs_verification_artifact_summary(
    entry: &IndexEntry,
    report: &serde_json::Value,
) -> serde_json::Value {
    let sha = &entry.sha256;
    let trust_boundary = report
        .get("trust_boundary")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::json!({
        "status": json_str(report, "status").unwrap_or("unknown"),
        "mode": json_str(report, "mode").unwrap_or("unknown"),
        "failure_count": report.get("failure_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
        "sha256": sha,
        "ingested_at": entry.ingested_at,
        "raw_url": format!("/api/v1/phase1/promotion/inputs-verification/{sha}"),
        "control_plane_role": json_str(&trust_boundary, "control_plane_role").unwrap_or("unknown"),
        "mutates_ao_artifacts": trust_boundary
            .get("mutates_ao_artifacts")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "release_acceptance_owner": json_str(&trust_boundary, "release_acceptance_owner").unwrap_or("unknown"),
        "control_plane_approves_release": trust_boundary
            .get("control_plane_approves_release")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
    })
}

async fn decision_artifact_summary(
    state: &AppState,
    entry: &IndexEntry,
    decision: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    let sha = &entry.sha256;
    let signature = read_decision_signature_sidecar(state, sha).await.ok();
    let sig = signature
        .as_ref()
        .and_then(|sidecar| sidecar.get("signature"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"signature_verified": false}));
    let artifacts = decision.get("artifacts");
    let governed_run_evidence_count = artifacts
        .and_then(|a| a.get("governed_run_evidence"))
        .and_then(serde_json::Value::as_array)
        .map(|paths| paths.iter().filter(|v| v.is_string()).count() as u64)
        .unwrap_or(0);
    let replacement_smoke_gate_present = artifacts
        .and_then(|a| a.get("replacement_smoke_gate"))
        .map(|v| v.is_string() && !v.as_str().unwrap_or("").is_empty())
        .unwrap_or(false);
    let decision_mode = if governed_run_evidence_count > 0 {
        "governed_run_primary"
    } else if replacement_smoke_gate_present {
        "replacement_smoke"
    } else {
        "unknown"
    };
    Ok(serde_json::json!({
        "status": json_str(decision, "status").unwrap_or("unknown"),
        "decision": json_str(decision, "decision").unwrap_or("unknown"),
        "phase1_state": json_str(decision, "phase1_state").unwrap_or("unknown"),
        "checklist_sha256": json_str(decision, "checklist_sha256").unwrap_or("unknown"),
        "operator": json_str(decision, "operator").unwrap_or("unknown"),
        "rationale": json_str(decision, "rationale").unwrap_or("unknown"),
        "decision_mode": decision_mode,
        "governed_run_evidence_count": governed_run_evidence_count,
        "replacement_smoke_gate_present": replacement_smoke_gate_present,
        "sha256": sha,
        "ingested_at": entry.ingested_at,
        "raw_url": format!("/api/v1/phase1/promotion/decision/{sha}"),
        "signature_url": format!("/api/v1/phase1/promotion/decision/{sha}/signature"),
        "signature": {
            "present": signature.is_some(),
            "signature_verified": sig
                .get("signature_verified")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            "signer_id": json_str(&sig, "signer_id").unwrap_or("unsigned"),
            "signature_sha256": json_str(&sig, "signature_sha256").unwrap_or("not provided"),
            "public_key_sha256": json_str(&sig, "public_key_sha256").unwrap_or("not provided"),
            // Trust-anchor classification recorded by annotate_trust_policy:
            // a verified signature is only release-authoritative when its key
            // is a configured trust anchor. Surfaced here so the dashboard and
            // operator panel can withhold authority from an unpinned signer.
            "verification_scope": json_str(&sig, "verification_scope").unwrap_or("unsigned"),
            "trust_anchor": json_str(&sig, "trust_anchor").unwrap_or("unsigned"),
            "trust_policy": sig
                .get("trust_policy")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        }
    }))
}

fn three_os_smoke_artifact_summary(
    entry: &IndexEntry,
    smoke: &serde_json::Value,
) -> serde_json::Value {
    let sha = &entry.sha256;
    let status = json_str(smoke, "status").unwrap_or("unknown");
    let source_dirty = smoke
        .get("source_dirty")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let all_targets_passed = ["macos", "ubuntu", "windows"].iter().all(|target| {
        smoke
            .get("targets")
            .and_then(|targets| targets.get(*target))
            .and_then(|target| json_str(target, "status"))
            == Some("passed")
    });
    let clean_pass = status == "passed" && !source_dirty && all_targets_passed;
    serde_json::json!({
        "status": if clean_pass { "passed" } else { "failed" },
        "state": if clean_pass { "three_os_release_smoke_passed" } else { "three_os_release_smoke_needs_attention" },
        "version": json_str(smoke, "version").unwrap_or("unknown"),
        "release_candidate_version": json_str(smoke, "release_candidate_version").unwrap_or("unknown"),
        "source_commit": json_str(smoke, "source_commit").unwrap_or("unknown"),
        "source_dirty": source_dirty,
        "sha256": sha,
        "ingested_at": entry.ingested_at,
        "raw_url": format!("/api/v1/phase1/promotion/three-os-smoke/{sha}"),
        "targets": smoke.get("targets").cloned().unwrap_or_else(|| serde_json::json!({})),
        "remote_command_files": smoke
            .get("remote_command_files")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "rerun_commands": smoke
            .get("rerun_commands")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "report": json_str(smoke, "report").unwrap_or("missing"),
        "root": json_str(smoke, "root").unwrap_or("missing"),
        "next_action": if clean_pass {
            "three-OS release smoke is present; run the guarded release gate"
        } else {
            "rerun three-OS release smoke from a clean source commit until macOS, Ubuntu, and Windows pass"
        }
    })
}

fn validate_phase1_promotion_checklist(checklist: &serde_json::Value) -> Result<(), AppError> {
    let schema = checklist
        .get("schema")
        .or_else(|| checklist.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PHASE1_PROMOTION_CHECKLIST_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {PHASE1_PROMOTION_CHECKLIST_SCHEMA}, got {schema}"
        )));
    }
    for key in ["status", "phase1_state"] {
        if checklist
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "Phase 1 promotion checklist missing {key}"
            )));
        }
    }
    let checks = checklist
        .get("checklist")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::SchemaInvalid("Phase 1 checklist missing checks".into()))?;
    for key in [
        "provider_readiness",
        "live_provider_acceptance",
        "release_gate",
        "three_os_smoke",
    ] {
        if !checks.contains_key(key) {
            return Err(AppError::SchemaInvalid(format!(
                "Phase 1 checklist missing {key}"
            )));
        }
    }
    Ok(())
}

fn validate_phase1_promotion_inputs_verification(
    report: &serde_json::Value,
) -> Result<(), AppError> {
    let schema = report
        .get("schema")
        .or_else(|| report.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {PHASE1_PROMOTION_INPUTS_VERIFICATION_SCHEMA}, got {schema}"
        )));
    }
    let status = report
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if !matches!(status, "accepted" | "rejected") {
        return Err(AppError::SchemaInvalid(
            "Phase 1 promotion inputs verification status must be accepted or rejected".into(),
        ));
    }
    if report
        .get("failure_count")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return Err(AppError::SchemaInvalid(
            "Phase 1 promotion inputs verification missing failure_count".into(),
        ));
    }
    let trust_boundary = report
        .get("trust_boundary")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::SchemaInvalid(
                "Phase 1 promotion inputs verification missing trust_boundary".into(),
            )
        })?;
    for (field, expected) in [
        ("control_plane_role", "read_only_observer"),
        ("release_acceptance_owner", "factory-v3 evaluator-closer"),
    ] {
        let actual = trust_boundary
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if actual != expected {
            return Err(AppError::SchemaInvalid(format!(
                "Phase 1 promotion inputs verification trust_boundary.{field} must be {expected}"
            )));
        }
    }
    for (field, expected) in [
        ("mutates_ao_artifacts", false),
        ("control_plane_approves_release", false),
    ] {
        let actual = trust_boundary
            .get(field)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if actual != expected {
            return Err(AppError::SchemaInvalid(format!(
                "Phase 1 promotion inputs verification trust_boundary.{field} must be {expected}"
            )));
        }
    }
    Ok(())
}

fn validate_three_os_release_smoke(smoke: &serde_json::Value) -> Result<(), AppError> {
    let schema = smoke
        .get("schema")
        .or_else(|| smoke.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != THREE_OS_RELEASE_SMOKE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {THREE_OS_RELEASE_SMOKE_SCHEMA}, got {schema}"
        )));
    }
    for key in [
        "status",
        "source_commit",
        "version",
        "release_candidate_version",
    ] {
        if smoke
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "three-OS release smoke missing {key}"
            )));
        }
    }
    if smoke
        .get("source_dirty")
        .and_then(serde_json::Value::as_bool)
        .is_none()
    {
        return Err(AppError::SchemaInvalid(
            "three-OS release smoke missing source_dirty".into(),
        ));
    }

    // Lane KK: enforce source_commit is a 40-char lowercase hex git
    // sha1. The aggregator (scripts/smoke-three-os-release.sh, line
    // ~73) sets `source_commit="$(git rev-parse HEAD)"` which ALWAYS
    // emits a 40-char hex SHA. A tampered ingestion could swap that
    // for a placeholder ("unknown", "tampered", "fake", "TODO") and
    // pass the legacy non-empty-string check. The format check rejects
    // any value that is not a valid git sha1, closing the obvious-
    // placeholder tamper class. (Schema bump would let us validate
    // per-target source_commit equality next; for now the orchestrator
    // builds all three targets from the same source.tgz so per-target
    // equality is true by construction.)
    let source_commit = json_str(smoke, "source_commit").unwrap_or("");
    let is_git_sha40 = source_commit.len() == 40
        && source_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_git_sha40 {
        return Err(AppError::SchemaInvalid(format!(
            "three-OS release smoke source_commit must be a 40-char lowercase \
             hex git sha1; got {source_commit:?}"
        )));
    }
    let targets = smoke
        .get("targets")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::SchemaInvalid("three-OS release smoke missing targets".into()))?;
    for target in ["macos", "ubuntu", "windows"] {
        let status = targets
            .get(target)
            .and_then(|value| json_str(value, "status"))
            .ok_or_else(|| {
                AppError::SchemaInvalid(format!(
                    "three-OS release smoke missing {target} target status"
                ))
            })?;
        if !["passed", "failed", "skipped"].contains(&status) {
            return Err(AppError::SchemaInvalid(format!(
                "three-OS release smoke has invalid {target} status {status}"
            )));
        }
    }

    // Lane DD: server-side recomputation of the top-level smoke.status
    // from per-target evidence. The aggregator
    // (scripts/smoke-three-os-release.sh, line ~164) emits "passed" iff
    // every per-target status is "passed", else "failed". A tampered
    // ingestion could set top-level status="passed" while a per-target
    // status is "failed" or "skipped" — hiding the failure from any
    // downstream consumer that trusts the top-level field. Reject any
    // ingestion where the posted top-level field disagrees with the
    // server-side recomputation. Closes the
    // server-trusted-input vs. recomputable-from-evidence gap (parallel
    // to Lane W's defense for candidate_correlation_parity).
    //
    // Lane KK: tighten the recomputation to ALSO require
    // source_dirty=false for "passed", matching the downstream
    // `three_os_smoke_clean_status` derivation in release_publication.rs.
    // Without this, a tampered ingestion could post status="passed" with
    // source_dirty=true and all targets passed — accepted by the legacy
    // Lane DD gate but downgraded to "failed" by the downstream
    // derivation, leaving inconsistent verdicts visible to operators.
    let posted_status = json_str(smoke, "status").unwrap_or("");
    let all_passed = ["macos", "ubuntu", "windows"].iter().all(|target| {
        targets
            .get(*target)
            .and_then(|value| json_str(value, "status"))
            == Some("passed")
    });
    let source_dirty = smoke
        .get("source_dirty")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let recomputed_status = if all_passed && !source_dirty {
        "passed"
    } else {
        "failed"
    };
    if posted_status != recomputed_status {
        return Err(AppError::SchemaInvalid(format!(
            "three-OS release smoke top-level status disagrees with \
             server-side recomputation from per-target evidence: \
             posted={posted_status}, recomputed={recomputed_status} \
             (all_targets_passed={all_passed}, source_dirty={source_dirty})"
        )));
    }

    // Lane W: server-side recomputation of candidate_correlation_parity
    // from per-target evidence. Today the field is computed by the
    // aggregator (scripts/smoke-three-os-release.sh's compute_parity()).
    // A tampered ingestion could set candidate_correlation_parity=matched
    // while per-target candidate_correlation_status values disagree.
    // Reject any ingestion where the posted top-level field disagrees
    // with the server-side recomputation — closing the
    // server-trusted-input vs. recomputable-from-evidence gap.
    //
    // Recomputation algorithm matches the aggregator: collect statuses
    // of targets whose status == "passed", default unrecognized values
    // to "unknown", return "unknown" if no targets passed, return the
    // common value if all observed statuses agree, else "drift".
    if let Some(posted_parity) = smoke
        .get("candidate_correlation_parity")
        .and_then(serde_json::Value::as_str)
    {
        let mut observed: Vec<&str> = Vec::new();
        for target in ["macos", "ubuntu", "windows"] {
            let target_value = targets.get(target);
            let target_status = target_value
                .and_then(|value| json_str(value, "status"))
                .unwrap_or("unknown");
            if target_status != "passed" {
                continue;
            }
            let correlation_status = target_value
                .and_then(|value| json_str(value, "candidate_correlation_status"))
                .unwrap_or("unknown");
            observed.push(correlation_status);
        }
        let recomputed: &str = if observed.is_empty() {
            "unknown"
        } else {
            let reference = observed[0];
            if observed.iter().all(|value| *value == reference) {
                reference
            } else {
                "drift"
            }
        };
        if posted_parity != recomputed {
            return Err(AppError::SchemaInvalid(format!(
                "three-OS release smoke candidate_correlation_parity \
                 disagrees with server-side recomputation from per-target \
                 evidence: posted={posted_parity}, recomputed={recomputed}"
            )));
        }
    }

    // Lane PP-server: enforce orchestrator HEAD consistency across the
    // per-target source_commit_at_target values. The orchestrator
    // packages source.tgz once and ships it to every target; each per-
    // target smoke reads the embedded `.source-commit` record and emits
    // the value as `source_commit_at_target`. The aggregator then
    // surfaces both the per-target values (under
    // `source_commit_per_target`) and a recomputed drift verdict
    // (`source_commit_per_target_drift` boolean). A tampered ingestion
    // could post a clean-looking top-level `source_commit` while one or
    // more per-target values disagree (HEAD drift between packaging
    // and execution, or a forged target run from a different
    // source.tgz). Reject any ingestion where:
    //   1. The posted `source_commit_per_target_drift` boolean disagrees
    //      with the server-side recomputation (top-level source_commit
    //      vs. every per-target source_commit_at_target for passed
    //      targets).
    //   2. The recomputed drift is true (i.e. some per-target value
    //      differs from top-level source_commit).
    //
    // The field is OPTIONAL today — bundles ingested from clients
    // that predate Lane OO will still pass the legacy gates without
    // this check. New bundles (post Lane OO aggregator commit
    // fa7940b) always include it; the absence below acts as a
    // legacy-acceptance hatch, not a stealth bypass.
    if let Some(per_target) = smoke
        .get("source_commit_per_target")
        .and_then(serde_json::Value::as_object)
    {
        let mut recomputed_drift = false;
        for target in ["macos", "ubuntu", "windows"] {
            let target_status = targets
                .get(target)
                .and_then(|value| json_str(value, "status"))
                .unwrap_or("unknown");
            if target_status != "passed" {
                continue;
            }
            let per_target_value = per_target
                .get(target)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            if per_target_value != source_commit {
                recomputed_drift = true;
                break;
            }
        }
        // The posted drift verdict (when present) MUST agree with the
        // recomputed value. The boolean field is the operator-visible
        // signal; the string status mirror (`_drift_status`) carries
        // the same value with an additional "unknown" possibility for
        // the zero-target case (skipped via the iteration above).
        if let Some(posted_drift) = smoke
            .get("source_commit_per_target_drift")
            .and_then(serde_json::Value::as_bool)
        {
            if posted_drift != recomputed_drift {
                return Err(AppError::SchemaInvalid(format!(
                    "three-OS release smoke source_commit_per_target_drift \
                     disagrees with server-side recomputation: posted={posted_drift}, \
                     recomputed={recomputed_drift} (top-level source_commit={source_commit:?})"
                )));
            }
        }
        // A true drift verdict is rejected with a Lane OO-class
        // diagnostic that names the dissenting target so an operator
        // can triage immediately. The first dissenting target is
        // surfaced; subsequent ones would require re-running the
        // smoke after the orchestrator fix anyway.
        if recomputed_drift {
            let mut dissenters: Vec<String> = Vec::new();
            for target in ["macos", "ubuntu", "windows"] {
                let target_status = targets
                    .get(target)
                    .and_then(|value| json_str(value, "status"))
                    .unwrap_or("unknown");
                if target_status != "passed" {
                    continue;
                }
                let per_target_value = per_target
                    .get(target)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                if per_target_value != source_commit {
                    dissenters.push(format!("{target}={per_target_value}"));
                }
            }
            return Err(AppError::SchemaInvalid(format!(
                "three-OS release smoke source_commit_per_target drift: \
                 top-level source_commit={source_commit} disagrees with per-target \
                 source_commit_at_target ({}); orchestrator HEAD drifted between \
                 packaging and execution",
                dissenters.join(", ")
            )));
        }
    }

    Ok(())
}

fn validate_phase1_promotion_decision(decision: &serde_json::Value) -> Result<(), AppError> {
    let schema = decision
        .get("schema")
        .or_else(|| decision.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PHASE1_PROMOTION_DECISION_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {PHASE1_PROMOTION_DECISION_SCHEMA}, got {schema}"
        )));
    }
    for key in [
        "status",
        "decision",
        "phase1_state",
        "checklist_sha256",
        "operator",
        "rationale",
    ] {
        if decision
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "Phase 1 promotion decision missing {key}"
            )));
        }
    }
    if required_json_str(decision, "decision")? != "promote_phase1_candidate" {
        return Err(AppError::SchemaInvalid(
            "Phase 1 promotion decision must be promote_phase1_candidate".into(),
        ));
    }
    validate_sha(required_json_str(decision, "checklist_sha256")?)?;
    Ok(())
}

fn verify_signed_phase1_promotion_decision(
    decision_raw: &str,
    signature: &serde_json::Value,
) -> Result<(), AppError> {
    let schema = signature
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported Phase 1 promotion decision signature algorithm: {algorithm}"
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
    verify_rsa_sha256_signature(decision_raw.as_bytes(), &signature_bytes, public_key_pem)
}

async fn read_decision_signature_sidecar(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    validate_sha(sha)?;
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::Phase1PromotionDecisionSignature, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    let sidecar: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    let sidecar_sha = sidecar
        .get("phase1_promotion_decision_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if sidecar_sha != sha {
        return Err(AppError::SchemaInvalid(format!(
            "Phase 1 promotion decision signature sidecar sha mismatch: expected {sha}, got {sidecar_sha}"
        )));
    }
    let schema = sidecar
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {PHASE1_PROMOTION_DECISION_SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    Ok(sidecar)
}

fn required_json_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, AppError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::SchemaInvalid(format!("missing {field}")))
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
            AppError::SchemaInvalid(format!("signed Phase 1 promotion decision missing {field}"))
        })
}

fn decode_decision_b64(encoded: &str) -> Result<Vec<u8>, AppError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| AppError::SchemaInvalid(format!("decision_b64 is not valid base64: {e}")))
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

fn validate_sha(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}

async fn latest_provider_readiness(
    state: &AppState,
) -> Result<Option<serde_json::Value>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == PROVIDER_READINESS_SCHEMA);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ProviderReadiness, &entry.sha256)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| AppError::Internal(e.to_string()))
}

async fn latest_acceptance_by_provider(
    state: &AppState,
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema.contains("acceptance"));
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let mut latest = serde_json::Map::new();
    for entry in entries {
        let provider = entry.provider.clone().unwrap_or_default();
        if latest.contains_key(&provider) {
            continue;
        }
        let bundle = read_acceptance_value(state, &entry).await?;
        latest.insert(provider, acceptance_entry_summary(entry, &bundle));
    }
    Ok(latest)
}

async fn read_acceptance_value(
    state: &AppState,
    entry: &IndexEntry,
) -> Result<serde_json::Value, AppError> {
    let kind = match entry.provider.as_deref() {
        Some("codex") => BundleKind::AcceptanceCodex,
        Some("claude") => BundleKind::AcceptanceClaude,
        Some("antigravity") => BundleKind::AcceptanceAntigravity,
        _ => return Ok(serde_json::Value::Null),
    };
    let bytes = state
        .storage
        .bundles
        .read(kind, &entry.sha256)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

fn provider_readiness_check(
    readiness: &serde_json::Value,
    acceptance_complete: bool,
) -> serde_json::Value {
    let artifact_status = json_str(readiness, "status").unwrap_or("unknown");
    let codex_gate = readiness_status(readiness, "codex_gate");
    let codex_pilot = readiness_status(readiness, "codex_pilot");
    let phase1_state = if artifact_status != "passed" {
        "failed"
    } else if codex_gate == "ready" && codex_pilot == "ready" {
        "ready"
    } else {
        "blocked"
    };
    let superseded = acceptance_complete && phase1_state != "ready";
    serde_json::json!({
        "status": if superseded { "superseded_by_live_acceptance" } else { "observed" },
        "artifact_status": artifact_status,
        "phase1_state": phase1_state,
        "codex_gate": codex_gate,
        "codex_pilot": codex_pilot,
        "superseded_by": if superseded { Some("live_provider_acceptance") } else { None },
        "next_action": if phase1_state == "ready" {
            "review live provider acceptance evidence"
        } else if superseded {
            "continue with live acceptance proof; keep direct provider execution guarded"
        } else {
            "keep provider execution guarded; use live acceptance evidence for promotion proof"
        }
    })
}

fn live_provider_acceptance_check(
    latest_codex: &serde_json::Value,
    latest_claude: &serde_json::Value,
    latest_antigravity: &serde_json::Value,
) -> serde_json::Value {
    let codex_ready = live_acceptance_ready(latest_codex);
    let claude_ready = live_acceptance_ready(latest_claude);
    let antigravity_ready = live_acceptance_ready(latest_antigravity);
    let state = if codex_ready && claude_ready && antigravity_ready {
        "live_acceptance_complete"
    } else {
        "blocked"
    };
    serde_json::json!({
        "status": if state == "live_acceptance_complete" { "passed" } else { "missing" },
        "state": state,
        "codex": provider_acceptance_state(latest_codex),
        "claude": provider_acceptance_state(latest_claude),
        "antigravity": provider_acceptance_state(latest_antigravity),
        "source_class": if state == "live_acceptance_complete" { "live" } else { "mixed" },
        "next_action": if state == "live_acceptance_complete" {
            "review signed evidence and run the guarded release gate before Phase 1 promotion"
        } else {
            "publish passing live Codex, Claude, and Antigravity provider-pilot acceptance evidence"
        }
    })
}

fn acceptance_entry_summary(entry: IndexEntry, bundle: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "sha256": entry.sha256,
        "provider": entry.provider.unwrap_or_default(),
        "status": entry.status.unwrap_or_default(),
        "source_class": acceptance_source_class(bundle),
        "score": acceptance_score(bundle),
        "minimum_score": bundle
            .get("smoke")
            .and_then(|smoke| smoke.get("minimum_score"))
            .and_then(serde_json::Value::as_u64),
        "run_id": json_str(bundle, "run_id").unwrap_or("unknown"),
    })
}

fn readiness_status(readiness: &serde_json::Value, key: &str) -> String {
    readiness
        .get(key)
        .and_then(|value| value.get("verdict").or_else(|| value.get("status")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string()
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

fn html_object_rows(
    value: Option<&serde_json::Value>,
    empty_message: &str,
    redact_sensitive_values: bool,
) -> String {
    let Some(entries) = value.and_then(serde_json::Value::as_object) else {
        return format!(
            "<tr><td colspan=\"2\">{}</td></tr>",
            escape_html(empty_message)
        );
    };
    if entries.is_empty() {
        return format!(
            "<tr><td colspan=\"2\">{}</td></tr>",
            escape_html(empty_message)
        );
    }
    entries
        .iter()
        .map(|(key, value)| {
            let raw_value = value
                .as_str()
                .map(ToString::to_string)
                .unwrap_or_else(|| value.to_string());
            let display_value = if redact_sensitive_values {
                redact_sensitive_text(&raw_value)
            } else {
                raw_value
            };
            format!(
                "<tr><td>{}</td><td><code>{}</code></td></tr>",
                escape_html(key),
                escape_html(&display_value)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn redact_sensitive_text(value: &str) -> String {
    value
        .split_whitespace()
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            if lower.starts_with("ao2_cp_api_token=")
                || lower.starts_with("api_token=")
                || lower.starts_with("token=")
            {
                part.split_once('=')
                    .map(|(key, _)| format!("{key}=<redacted>"))
                    .unwrap_or_else(|| "<redacted-token>".to_string())
            } else if lower == "bearer" || lower.starts_with("bearer=") {
                "<redacted-auth-scheme>".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
