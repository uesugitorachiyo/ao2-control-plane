use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::IngestReceipt;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, RetentionPolicy};
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

mod evaluator_decision;
mod release_surfaces;
mod support_bundle;
mod view;

use evaluator_decision::{
    get_release_evaluator_decision_by_sha_cached, get_release_evaluator_decision_signature_by_sha,
    latest_release_evaluator_decision_entry_value, release_evaluator_decision_dashboard_value,
    validate_release_evaluator_decision, verify_release_evaluator_decision_signature,
};
use release_surfaces::{
    hosted_release_smoke_value, install_verification_readiness_observed,
    install_verification_trust_value, provider_acceptance_readiness, release_assembly_value,
    release_readiness_gate, release_readiness_gate_with_detail,
};
use support_bundle::{
    normalize_release_support_storage_surface, release_support_bundle_checksums_text,
    release_support_bundle_filename, release_support_bundle_manifest_value,
    release_support_bundle_verification_value, release_support_verifier_handoff_value,
    support_bundle_surface_sha256, SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS,
};
use view::{
    escape_html, json_scalar, json_str, json_str_obj, render_release_support_bundle_manifest,
    render_release_support_bundle_verification, render_release_support_verifier_handoff,
};

const RELEASE_PUBLICATION_SCHEMA: &str = "ao2.release-publication-summary.v1";
const RELEASE_PUBLICATION_DASHBOARD_SCHEMA: &str = "ao2.cp-release-publication-dashboard.v1";
const RELEASE_COCKPIT_SCHEMA: &str = "ao2.cp-release-cockpit.v1";
const RELEASE_CANDIDATE_HANDOFF_SCHEMA: &str = "ao2.cp-release-candidate-handoff.v1";
const RELEASE_READINESS_SCHEMA: &str = "ao2.cp-release-readiness.v1";
const RELEASE_SUPPORT_BUNDLE_SCHEMA: &str = "ao2.cp-release-support-bundle.v1";
const RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA: &str = "ao2.cp-release-support-bundle-manifest.v1";
const RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA: &str =
    "ao2.cp-release-support-bundle-verification.v1";
const RELEASE_SUPPORT_VERIFIER_HANDOFF_SCHEMA: &str = "ao2.cp-release-support-verifier-handoff.v1";
const RELEASE_ASSEMBLY_SCHEMA: &str = "ao2.cp-release-assembly.v1";
const RELEASE_EVALUATOR_DECISION_SCHEMA: &str = "factory-v3/ao2-release-evaluator-decision/v1";
const RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA: &str =
    "ao2.cp-release-evaluator-decision-dashboard.v1";
const RELEASE_EVALUATOR_DECISION_SIGNED_UPLOAD_SCHEMA: &str =
    "ao2.cp-release-evaluator-decision-signed-upload.v1";
const RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA: &str =
    "ao2.cp-release-evaluator-decision-signature.v1";
const PROVIDER_REGISTRY_SCHEMA: &str = "ao2.provider-plugin-registry.v1";
const PROVIDER_READINESS_SCHEMA: &str = "factory-v3/hermes-provider-phase1-readiness/v1";
const CODEX_ACCEPTANCE_SCHEMA: &str = "ao2.codex-provider-pilot-acceptance.v1";
const CLAUDE_ACCEPTANCE_SCHEMA: &str = "ao2.claude-provider-pilot-acceptance.v1";
const ANTIGRAVITY_ACCEPTANCE_SCHEMA: &str = "ao2.antigravity-provider-pilot-acceptance.v1";
const PHASE1_PROMOTION_CHECKLIST_SCHEMA: &str = "factory-v3/ao2-phase1-promotion-checklist/v1";
const PHASE1_PROMOTION_DECISION_SCHEMA: &str = "factory-v3/ao2-phase1-promotion-decision/v1";
const THREE_OS_RELEASE_SMOKE_SCHEMA: &str = "ao2-control-plane.three-os-release-smoke.v1";

#[derive(Debug, Deserialize)]
pub struct ReleaseSupportBundleQuery {
    #[serde(default = "default_keep_latest")]
    keep_latest: usize,
}

#[derive(Debug, Deserialize)]
struct SignedReleaseEvaluatorDecisionUpload {
    schema_version: String,
    decision: serde_json::Value,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ReleaseEvaluatorDecisionSignatureSidecar {
    schema_version: String,
    release_evaluator_decision_sha256: String,
    signature: serde_json::Value,
}

fn default_keep_latest() -> usize {
    25
}

fn retention_policy(keep_latest: usize) -> Result<RetentionPolicy, AppError> {
    if keep_latest == 0 {
        return Err(AppError::BadRequest(
            "keep_latest must be greater than zero".to_string(),
        ));
    }
    Ok(RetentionPolicy { keep_latest })
}

pub async fn post_release_publication(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let publication: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_release_publication(&publication)?;
    let sha = sha256_of_canonical(&publication).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::ReleasePublication, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ReleasePublication, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: RELEASE_PUBLICATION_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: publication
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
        RELEASE_PUBLICATION_SCHEMA.to_string(),
    )))
}

pub async fn latest_release_publication(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_release_publication_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_release_publication_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_release_publication(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_release_publication_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/release/publication/:sha`.
pub async fn head_release_publication(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ReleasePublication, &sha)
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

pub async fn release_publication_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(release_publication_dashboard_value(&state).await?))
}

pub async fn release_publication_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let dashboard = release_publication_dashboard_value(&state).await?;
    let latest = dashboard
        .get("latest")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let verification = dashboard
        .get("verification")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let repositories = latest
        .get("repositories")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let verification_row = |key: &str, label: &str| {
        let value = verification
            .get(key)
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(&value)
        )
    };
    let repository_rows = if repositories.is_empty() {
        "<tr><td colspan=\"3\">missing</td></tr>".to_string()
    } else {
        repositories
            .iter()
            .map(|(repo, value)| {
                let head = value
                    .get("head")
                    .map(json_scalar)
                    .unwrap_or_else(|| "missing".to_string());
                let tag_target = value
                    .get("tag_target")
                    .map(json_scalar)
                    .unwrap_or_else(|| "missing".to_string());
                format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
                    escape_html(repo),
                    escape_html(&head),
                    escape_html(&tag_target)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
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
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Publication</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:84rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Publication</h1><p>Read-only observer view for AO2 published release evidence. This control plane displays signed evidence and release health only; it does not approve releases or mutate AO artifacts.</p><dl><dt>State</dt><dd>{state}</dd><dt>Version</dt><dd>{version}</dd><dt>Tag</dt><dd>{tag}</dd><dt>Status</dt><dd class=\"ok\">{status}</dd><dt>SHA256</dt><dd><code>{sha}</code></dd><dt>Archive targets</dt><dd>{archive_targets}</dd></dl><section><h2>Repository Heads</h2><table><thead><tr><th>Repository</th><th>Head</th><th>Tag target</th></tr></thead><tbody>{repository_rows}</tbody></table></section><section><h2>Verification</h2><table><thead><tr><th>Check</th><th>Status</th></tr></thead><tbody>{verification_rows}</tbody></table></section>{correlation_section}<p><a href=\"/api/v1/release/publication/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/release/publication/latest\">Latest Release Publication</a> · <a href=\"/api/v1/release/cockpit\">Release Cockpit</a> · <a href=\"/api/v1/phase1/promotion/dashboard\">Phase 1 Promotion</a> · <a href=\"/api/v1/storage/dashboard\">Storage</a></p></main></body></html>",
        state = escape_html(json_str(&dashboard, "state").unwrap_or("unknown")),
        version = escape_html(json_str_obj(&latest, "version").unwrap_or("unknown")),
        tag = escape_html(json_str_obj(&latest, "release_tag").unwrap_or("unknown")),
        status = escape_html(json_str_obj(&latest, "status").unwrap_or("missing")),
        sha = escape_html(json_str_obj(&latest, "sha256").unwrap_or("missing")),
        archive_targets = dashboard
            .get("archive_targets")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        repository_rows = repository_rows,
        verification_rows = [
            verification_row("release_ship", "release ship"),
            verification_row("release_download_verify", "download verify"),
            verification_row("release_doctor_status", "release doctor"),
            verification_row("provenance_verified", "provenance verified"),
            verification_row("provenance_tag_matches", "provenance tag matches"),
            verification_row("rollback_status", "rollback"),
            verification_row("three_os_smoke", "three-OS smoke"),
            verification_row("native_windows_smoke", "native Windows smoke"),
        ]
        .join(""),
        correlation_section = correlation_section,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_cockpit_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(release_cockpit_value(&state).await?))
}

pub async fn release_candidate_handoff_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(release_candidate_handoff_value(&state).await?))
}

pub async fn release_readiness_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(release_readiness_value(&state).await?))
}

pub async fn release_support_bundle_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(
        release_support_bundle_value(&state, q.keep_latest).await?,
    ))
}

pub async fn release_support_bundle_manifest_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    Ok(Json(release_support_bundle_manifest_value(
        &bundle,
        q.keep_latest,
    )?))
}

pub async fn release_support_bundle_manifest(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Response, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    let manifest = release_support_bundle_manifest_value(&bundle, q.keep_latest)?;
    let html = render_release_support_bundle_manifest(&manifest);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_support_bundle_download(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Response, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    let bundle_sha256 = support_bundle_surface_sha256(&bundle)?;
    let filename = release_support_bundle_filename(&bundle);
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

pub async fn release_support_bundle_checksums(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Response, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    let body = release_support_bundle_checksums_text(&bundle)?;

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

pub async fn release_support_bundle_verification_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    Ok(Json(release_support_bundle_verification_value(&bundle)?))
}

pub async fn release_support_verifier_handoff_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    Ok(Json(release_support_verifier_handoff_value(
        &bundle,
        q.keep_latest,
    )?))
}

pub async fn release_support_verifier_handoff(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Response, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    let handoff = release_support_verifier_handoff_value(&bundle, q.keep_latest)?;
    let html = render_release_support_verifier_handoff(&handoff);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_support_bundle_verification(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReleaseSupportBundleQuery>,
) -> Result<Response, AppError> {
    let bundle = release_support_bundle_value(&state, q.keep_latest).await?;
    let verification = release_support_bundle_verification_value(&bundle)?;
    let html = render_release_support_bundle_verification(&verification, q.keep_latest);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn post_release_evaluator_decision(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let raw =
        std::str::from_utf8(&body).map_err(|_| AppError::BadRequest("body is not utf-8".into()))?;
    let decision: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_release_evaluator_decision(&decision)?;
    let sha = sha256_of_canonical(&decision).map_err(|e| AppError::Internal(e.to_string()))?;

    if !state
        .storage
        .bundles
        .exists(BundleKind::ReleaseEvaluatorDecision, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::ReleaseEvaluatorDecision, &sha, raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: RELEASE_EVALUATOR_DECISION_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status: decision
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
        RELEASE_EVALUATOR_DECISION_SCHEMA.to_string(),
    )))
}

pub async fn post_signed_release_evaluator_decision(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedReleaseEvaluatorDecisionUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != RELEASE_EVALUATOR_DECISION_SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {RELEASE_EVALUATOR_DECISION_SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    validate_release_evaluator_decision(&upload.decision)?;
    let decision_raw = serde_json::to_string_pretty(&upload.decision)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let sha =
        sha256_of_canonical(&upload.decision).map_err(|e| AppError::Internal(e.to_string()))?;
    let mut signature = upload.signature;
    let annotation = verify_release_evaluator_decision_signature(
        &decision_raw,
        &signature,
        &state.release_evaluator_decision_trusted_key_sha256s,
    )?;
    // Merge the trust annotation (signature_verified + trust_anchor /
    // trust_policy.release_authoritative) into the stored signature so
    // downstream surfaces can distinguish a pinned-key authoritative
    // decision from a merely cryptographically-valid one.
    let signature_obj = signature.as_object_mut().ok_or_else(|| {
        AppError::SchemaInvalid(
            "release evaluator decision signature must be an object".to_string(),
        )
    })?;
    if let Some(annotation_obj) = annotation.as_object() {
        for (key, value) in annotation_obj {
            signature_obj.insert(key.clone(), value.clone());
        }
    }

    if !state
        .storage
        .bundles
        .exists(BundleKind::ReleaseEvaluatorDecision, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(
                BundleKind::ReleaseEvaluatorDecision,
                &sha,
                decision_raw.as_bytes(),
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = ReleaseEvaluatorDecisionSignatureSidecar {
        schema_version: RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA.to_string(),
        release_evaluator_decision_sha256: sha.clone(),
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
        .exists(BundleKind::ReleaseEvaluatorDecisionSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::ReleaseEvaluatorDecisionSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "release evaluator decision signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(
                BundleKind::ReleaseEvaluatorDecisionSignature,
                &sha,
                &sidecar_raw,
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: RELEASE_EVALUATOR_DECISION_SCHEMA.to_string(),
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
        RELEASE_EVALUATOR_DECISION_SCHEMA.to_string(),
    )))
}

pub async fn get_release_evaluator_decision_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    get_release_evaluator_decision_signature_by_sha(&state, &sha).await
}

pub async fn latest_release_evaluator_decision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some((entry, _)) = latest_release_evaluator_decision_entry_value(&state).await? else {
        return Err(AppError::NotFound);
    };
    get_release_evaluator_decision_by_sha_cached(&state, &entry.sha256, &headers).await
}

pub async fn get_release_evaluator_decision(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    get_release_evaluator_decision_by_sha_cached(&state, &sha, &headers).await
}

/// HEAD-equivalent for `/api/v1/release/evaluator-decision/:sha`.
pub async fn head_release_evaluator_decision(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::ReleaseEvaluatorDecision, &sha)
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

pub async fn release_evaluator_decision_dashboard_json(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(
        release_evaluator_decision_dashboard_value(&state).await?,
    ))
}

pub async fn release_evaluator_decision_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let dashboard = release_evaluator_decision_dashboard_value(&state).await?;
    let latest = dashboard
        .get("latest")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let blockers = dashboard
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let blocker_items = if blockers.is_empty() {
        "<li>none</li>".to_string()
    } else {
        blockers
            .iter()
            .map(|blocker| format!("<li>{}</li>", escape_html(&json_scalar(blocker))))
            .collect::<Vec<_>>()
            .join("")
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Evaluator Decision</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:86rem}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Evaluator Decision</h1><p>Read-only observer view for the Factory v3 evaluator-closer release-line decision. The control plane stores and displays this artifact but does not approve releases or mutate AO artifacts.</p><dl><dt>State</dt><dd class=\"{state_class}\">{state}</dd><dt>Version</dt><dd>{version}</dd><dt>Tag</dt><dd>{tag}</dd><dt>Decision</dt><dd><code>{decision}</code></dd><dt>Status</dt><dd>{status}</dd><dt>SHA256</dt><dd><code>{sha}</code></dd><dt>Owner</dt><dd>factory-v3 evaluator-closer</dd></dl><section><h2>Blockers</h2><ul>{blocker_items}</ul></section><p><a href=\"/api/v1/release/evaluator-decision/dashboard.json\">Dashboard JSON</a> · <a href=\"/api/v1/release/evaluator-decision/latest\">Latest Decision</a> · <a href=\"/api/v1/release/cockpit\">Release Cockpit</a> · <a href=\"/api/v1/release/readiness\">Release Readiness</a></p></main></body></html>",
        state_class = if json_str(&dashboard, "state") == Some("accepted") {
            "ok"
        } else {
            "warn"
        },
        state = escape_html(json_str(&dashboard, "state").unwrap_or("missing")),
        version = escape_html(
            latest
                .get("release")
                .and_then(|release| json_str(release, "version"))
                .unwrap_or("unknown")
        ),
        tag = escape_html(
            latest
                .get("release")
                .and_then(|release| json_str(release, "release_tag"))
                .unwrap_or("unknown")
        ),
        decision = escape_html(json_str(&latest, "decision").unwrap_or("missing")),
        status = escape_html(json_str(&latest, "status").unwrap_or("missing")),
        sha = escape_html(json_str(&latest, "sha256").unwrap_or("missing")),
        blocker_items = blocker_items,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_readiness(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let readiness = release_readiness_value(&state).await?;
    let release = readiness
        .get("release")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let links = readiness
        .get("links")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let gates = readiness
        .get("gate_results")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let blockers = readiness
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let smoke_details = readiness
        .get("three_os_smoke_details")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let install_verification = readiness
        .get("install_verification")
        .cloned()
        .unwrap_or_else(|| install_verification_trust_value(None));
    let gate_rows = gates
        .iter()
        .map(|gate| {
            let status = json_str(gate, "status").unwrap_or("missing");
            let class = if status == "passed" { "ok" } else { "warn" };
            format!(
                "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(json_str(gate, "label").unwrap_or("unknown")),
                class,
                escape_html(status),
                escape_html(json_str(gate, "observed").unwrap_or("missing")),
                escape_html(json_str(gate, "expected").unwrap_or("missing")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let blocker_items = if blockers.is_empty() {
        "<li>none</li>".to_string()
    } else {
        blockers
            .iter()
            .map(|blocker| format!("<li>{}</li>", escape_html(&json_scalar(blocker))))
            .collect::<Vec<_>>()
            .join("")
    };
    let smoke_target_rows = three_os_smoke_detail_rows(&smoke_details);
    let install_verification_status =
        json_str(&install_verification, "offline_verification_status").unwrap_or("missing");
    let install_verification_section = format!(
        "<section><h2>Install Verification Trust</h2><dl><dt>Schema</dt><dd><code>{schema}</code></dd><dt>Status</dt><dd>{status}</dd><dt>Offline verification</dt><dd>{offline_status}</dd><dt>Artifact</dt><dd><code>{path}</code></dd><dt>SHA-256</dt><dd><code>{sha}</code></dd><dt>Trust boundary</dt><dd>read-only observer display; does not approve releases or mutate AO artifacts</dd></dl></section>",
        schema = escape_html(json_str(&install_verification, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&install_verification, "status").unwrap_or("missing")),
        offline_status = if install_verification_status == "verified" {
            "offline verified".to_string()
        } else {
            escape_html(install_verification_status)
        },
        path = escape_html(json_str(&install_verification, "path").unwrap_or("missing")),
        sha = escape_html(json_str(&install_verification, "sha256").unwrap_or("missing")),
    );
    // Lane JJ: render the per-surface content-hash parity table on the
    // readiness HTML so operators landing on /api/v1/release/readiness
    // triage drift visually instead of cross-referencing JSON.
    let surface_parity_detail = readiness
        .get("surface_content_hash_parity_detail")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let surface_parity_section = render_surface_content_hash_parity_section(&surface_parity_detail);
    // Lane QQ: mirror the rejected-smoke audit count onto the
    // readiness HTML so operators landing on /api/v1/release/readiness
    // see tampering-attempt volume without re-navigating to cockpit.
    let rejected_smoke_summary =
        crate::handlers::phase1_promotion::rejected_smoke_audit_summary(&state).await;
    let rejected_smoke_section = render_rejected_smoke_audit_section(&rejected_smoke_summary);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Readiness</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:92rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Readiness</h1><p>Read-only release readiness summary for Hermes and factory-v3 evaluator-closer review. This control plane does not approve releases, start providers, or mutate AO artifacts.</p><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Version</dt><dd>{version}</dd><dt>Tag</dt><dd>{tag}</dd><dt>Owner</dt><dd>factory-v3 evaluator-closer</dd></dl><section><h2>Gate Results</h2><table><thead><tr><th>Gate</th><th>Status</th><th>Observed</th><th>Expected</th></tr></thead><tbody>{gate_rows}</tbody></table></section><section><h2>Three-OS Smoke Details</h2><table><thead><tr><th>Target</th><th>Status</th><th>Duration seconds</th><th>Artifact</th></tr></thead><tbody>{smoke_target_rows}</tbody></table></section>{install_verification_section}{surface_parity_section}{rejected_smoke_section}<section><h2>Blockers</h2><ul>{blocker_items}</ul></section><p><a href=\"{readiness_json}\">Readiness JSON</a> · <a href=\"{handoff}\">Release Candidate Handoff</a> · <a href=\"{cockpit}\">Release Cockpit</a> · <a href=\"{acceptance}\">Provider Acceptance</a></p></main></body></html>",
        status_class = if json_str(&readiness, "status") == Some("ready") {
            "ok"
        } else {
            "warn"
        },
        status = escape_html(json_str(&readiness, "status").unwrap_or("unknown")),
        version = escape_html(json_str(&release, "version").unwrap_or("unknown")),
        tag = escape_html(json_str(&release, "release_tag").unwrap_or("unknown")),
        gate_rows = gate_rows,
        smoke_target_rows = smoke_target_rows,
        install_verification_section = install_verification_section,
        surface_parity_section = surface_parity_section,
        rejected_smoke_section = rejected_smoke_section,
        blocker_items = blocker_items,
        readiness_json = escape_html(json_str(&links, "release_readiness_json").unwrap_or("/api/v1/release/readiness.json")),
        handoff = escape_html(json_str(&links, "release_candidate_handoff").unwrap_or("/api/v1/release/handoff")),
        cockpit = escape_html(json_str(&links, "cockpit").unwrap_or("/api/v1/release/cockpit")),
        acceptance = escape_html(json_str(&links, "provider_acceptance_dashboard_json").unwrap_or("/api/v1/acceptance/dashboard.json")),
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_candidate_handoff(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let handoff = release_candidate_handoff_value(&state).await?;
    let release = handoff
        .get("release")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let gates = handoff
        .get("gates")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let acceptance = handoff
        .get("acceptance")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let artifacts = handoff
        .get("artifacts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let links = handoff
        .get("links")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let operator_handoff = handoff
        .get("operator_handoff")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let gate_row = |key: &str, label: &str| {
        let value = gates
            .get(key)
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(&value)
        )
    };
    let acceptance_row = |key: &str, label: &str| {
        let provider = acceptance
            .get(key)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let status = json_str(&provider, "status").unwrap_or("missing");
        let source = json_str(&provider, "source_class").unwrap_or("missing");
        let run_id = json_str(&provider, "run_id").unwrap_or("missing");
        let score = provider
            .get("score")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        let raw_url = json_str(&provider, "raw_url").unwrap_or("");
        let raw_link = if raw_url.is_empty() {
            "missing".to_string()
        } else {
            format!("<a href=\"{}\">raw</a>", escape_html(raw_url))
        };
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(status),
            escape_html(source),
            escape_html(run_id),
            escape_html(&score),
            raw_link
        )
    };
    let artifact_row = |key: &str, label: &str| {
        let artifact = artifacts
            .get(key)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let sha = json_str(&artifact, "sha256").unwrap_or("missing");
        let raw_url = json_str(&artifact, "raw_url").unwrap_or("missing");
        let raw_link = if raw_url == "missing" {
            "missing".to_string()
        } else {
            format!("<a href=\"{}\">raw</a>", escape_html(raw_url))
        };
        let signature = json_str(&artifact, "signature_url")
            .filter(|value| *value != "missing")
            .map(|value| format!(" · <a href=\"{}\">signature</a>", escape_html(value)))
            .unwrap_or_default();
        format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}{}</td></tr>",
            escape_html(label),
            escape_html(sha),
            raw_link,
            signature
        )
    };
    let next_actions = handoff
        .get("next_actions")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            let mut html = String::from("<ul>");
            for item in items {
                html.push_str(&format!("<li>{}</li>", escape_html(&json_scalar(item))));
            }
            html.push_str("</ul>");
            html
        })
        .unwrap_or_else(|| "<p>missing</p>".to_string());
    // Lane JJ: render the per-surface content-hash parity table on the
    // handoff HTML so operators landing on /api/v1/release/handoff see
    // per-surface drift without cross-referencing the readiness page.
    let surface_parity_detail = handoff
        .get("surface_content_hash_parity_detail")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let surface_parity_section = render_surface_content_hash_parity_section(&surface_parity_detail);
    // Lane QQ: mirror the rejected-smoke audit count onto the handoff
    // HTML so operators landing on /api/v1/release/handoff see
    // tampering-attempt volume without re-navigating to cockpit.
    let rejected_smoke_summary =
        crate::handlers::phase1_promotion::rejected_smoke_audit_summary(&state).await;
    let rejected_smoke_section = render_rejected_smoke_audit_section(&rejected_smoke_summary);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Candidate Handoff</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:92rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Candidate Handoff</h1><p>Read-only operator handoff for Phase 1 release-candidate review. This page displays signed evidence and checklist posture only; it does not approve releases, start providers, or mutate AO artifacts.</p><dl><dt>Status</dt><dd class=\"ok\">{status}</dd><dt>Kind</dt><dd>{kind}</dd><dt>Version</dt><dd>{version}</dd><dt>Tag</dt><dd>{tag}</dd><dt>Release SHA256</dt><dd><code>{sha}</code></dd><dt>Release owner</dt><dd>{owner}</dd><dt>Frontend</dt><dd>{frontend}</dd><dt>Trusted execution</dt><dd>{trusted_execution}</dd></dl><section><h2>Release Checklist</h2><table><thead><tr><th>Gate</th><th>Status</th></tr></thead><tbody>{gate_rows}</tbody></table></section>{surface_parity_section}{rejected_smoke_section}<section><h2>Provider Acceptance</h2><table><thead><tr><th>Provider</th><th>Status</th><th>Source</th><th>Run</th><th>Score</th><th>Evidence</th></tr></thead><tbody>{acceptance_rows}</tbody></table></section><section><h2>Evidence Artifacts</h2><table><thead><tr><th>Artifact</th><th>SHA256</th><th>Links</th></tr></thead><tbody>{artifact_rows}</tbody></table></section><section><h2>Next Actions</h2>{next_actions}</section><p><a href=\"{handoff_json}\">Handoff JSON</a> · <a href=\"{cockpit}\">Release Cockpit</a> · <a href=\"{cockpit_json}\">Cockpit JSON</a> · <a href=\"{phase1_panel}\">Phase 1 Operator Panel JSON</a> · <a href=\"{acceptance_dashboard}\">Provider Acceptance JSON</a></p></main></body></html>",
        status = escape_html(json_str(&handoff, "status").unwrap_or("unknown")),
        kind = escape_html(json_str(&handoff, "handoff_kind").unwrap_or("unknown")),
        version = escape_html(json_str(&release, "version").unwrap_or("unknown")),
        tag = escape_html(json_str(&release, "release_tag").unwrap_or("unknown")),
        sha = escape_html(json_str(&release, "sha256").unwrap_or("missing")),
        owner = escape_html(
            json_str(&operator_handoff, "release_acceptance_owner").unwrap_or("unknown")
        ),
        frontend = escape_html(json_str(&operator_handoff, "front_end").unwrap_or("unknown")),
        trusted_execution = escape_html(
            json_str(&operator_handoff, "trusted_execution").unwrap_or("unknown")
        ),
        gate_rows = [
            gate_row("release_cockpit", "Release Cockpit"),
            gate_row("phase1_promotion", "Phase 1 Promotion"),
            gate_row("decision_signature", "Decision Signature"),
            gate_row("provider_acceptance", "Provider Acceptance"),
            gate_row("release_evaluator_decision", "Release Evaluator Decision"),
            gate_row("candidate_correlation", "Candidate Correlation"),
            gate_row("surface_content_hash_parity", "Surface Content-Hash Parity"),
        ]
        .join(""),
        surface_parity_section = surface_parity_section,
        rejected_smoke_section = rejected_smoke_section,
        acceptance_rows = [
            acceptance_row("codex", "Codex"),
            acceptance_row("claude", "Claude"),
        ]
        .join(""),
        artifact_rows = [
            artifact_row("release_publication", "Release Publication"),
            artifact_row("phase1_checklist", "Phase 1 Checklist"),
            artifact_row("phase1_decision", "Phase 1 Decision"),
            artifact_row("three_os_smoke", "Three-OS Smoke"),
        ]
        .join(""),
        next_actions = next_actions,
        handoff_json = escape_html(
            json_str(&links, "release_candidate_handoff_json").unwrap_or("/api/v1/release/handoff.json")
        ),
        cockpit = escape_html(json_str(&links, "cockpit").unwrap_or("/api/v1/release/cockpit")),
        cockpit_json = escape_html(
            json_str(&links, "cockpit_json").unwrap_or("/api/v1/release/cockpit.json")
        ),
        phase1_panel = escape_html(
            json_str(&links, "phase1_operator_panel_json")
                .unwrap_or("/api/v1/phase1/promotion/operator-panel.json")
        ),
        acceptance_dashboard = escape_html(
            json_str(&links, "provider_acceptance_dashboard_json")
                .unwrap_or("/api/v1/acceptance/dashboard.json")
        ),
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn release_cockpit(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let cockpit = release_cockpit_value(&state).await?;
    let surfaces = cockpit
        .get("surfaces")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let provider_acceptance = surfaces
        .get("provider_acceptance")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let surface_row = |key: &str, label: &str| {
        let value = surfaces
            .get(key)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"status": "missing"}));
        let state = value
            .get("state")
            .or_else(|| value.get("status"))
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        let sha = value
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing");
        format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            escape_html(label),
            escape_html(&state),
            escape_html(sha)
        )
    };
    let acceptance_row = |key: &str, label: &str| {
        let entry = provider_acceptance
            .get(key)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let status = json_str(&entry, "status").unwrap_or("missing");
        let source_class = json_str(&entry, "source_class").unwrap_or("missing");
        let run_id = json_str(&entry, "run_id").unwrap_or("missing");
        let score = entry
            .get("score")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        let raw_url = json_str(&entry, "raw_url").unwrap_or("");
        let evidence_link = if raw_url.is_empty() {
            "missing".to_string()
        } else {
            format!("<a href=\"{}\">raw</a>", escape_html(raw_url))
        };
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(status),
            escape_html(source_class),
            escape_html(run_id),
            escape_html(&score),
            evidence_link
        )
    };
    let handoff_link = cockpit
        .get("links")
        .and_then(|links| json_str(links, "release_candidate_handoff"))
        .unwrap_or("/api/v1/release/handoff");
    let correlation = cockpit
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
    let parity = cockpit
        .get("candidate_correlation_parity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    let parity_class = if parity == "matched" { "ok" } else { "warn" };
    let surface_parity = cockpit
        .get("surface_content_hash_parity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    let surface_parity_class = if surface_parity == "matched" {
        "ok"
    } else {
        "warn"
    };
    let surface_parity_detail = cockpit
        .get("surface_content_hash_parity_detail")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let correlation_section = format!(
        "<section><h2>Candidate Correlation</h2><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Three-OS smoke parity</dt><dd class=\"{parity_class}\">{parity}</dd><dt>Surface content-hash parity</dt><dd class=\"{surface_parity_class}\">{surface_parity}</dd><dt>Release version</dt><dd><code>{release_version}</code></dd><dt>Release tag</dt><dd><code>{release_tag}</code></dd><dt>Three-OS smoke version</dt><dd><code>{three_os_version}</code></dd><dt>Evaluator version</dt><dd><code>{evaluator_version}</code></dd><dt>Codex acceptance version</dt><dd><code>{codex_version}</code></dd><dt>Claude acceptance version</dt><dd><code>{claude_version}</code></dd></dl><h3>Blockers</h3><ul>{blockers}</ul></section>",
        status_class = correlation_status_class,
        status = escape_html(correlation_status),
        parity_class = parity_class,
        parity = escape_html(parity),
        surface_parity_class = surface_parity_class,
        surface_parity = escape_html(surface_parity),
        release_version = escape_html(json_str(&correlation, "release_version").unwrap_or("unknown")),
        release_tag = escape_html(json_str(&correlation, "release_tag").unwrap_or("unknown")),
        three_os_version = escape_html(json_str(&correlation, "three_os_version").unwrap_or("unknown")),
        evaluator_version = escape_html(json_str(&correlation, "release_evaluator_version").unwrap_or("unknown")),
        codex_version = escape_html(json_str(&correlation, "codex_acceptance_version").unwrap_or("unknown")),
        claude_version = escape_html(json_str(&correlation, "claude_acceptance_version").unwrap_or("unknown")),
        blockers = correlation_blocker_items,
    );
    let surface_parity_section = render_surface_content_hash_parity_section(&surface_parity_detail);
    let provider_registry_metadata_section =
        render_provider_registry_metadata_section(surfaces.get("provider_registry"));
    // Lane MM: surface the Lane LL rejected-smoke audit count on the
    // cockpit so operators see tampering-attempt volume at-a-glance
    // without grepping the jsonl file by hand. Zero count is the
    // common case (rendered ok); any non-zero count is rendered warn.
    let rejected_smoke_summary =
        crate::handlers::phase1_promotion::rejected_smoke_audit_summary(&state).await;
    let rejected_smoke_section = render_rejected_smoke_audit_section(&rejected_smoke_summary);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Cockpit</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:88rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Cockpit</h1><p>Read-only operator cockpit for release, Phase 1, provider, and evidence observer surfaces. It does not approve releases, start providers, or mutate AO artifacts.</p><dl><dt>Status</dt><dd class=\"ok\">{status}</dd><dt>Next action</dt><dd>{next_action}</dd></dl><section><h2>Release Surfaces</h2><table><thead><tr><th>Surface</th><th>State</th><th>SHA256</th></tr></thead><tbody>{rows}</tbody></table></section>{provider_registry_metadata_section}{correlation_section}{surface_parity_section}{rejected_smoke_section}<section><h2>Provider Acceptance Details</h2><table><thead><tr><th>Provider</th><th>Status</th><th>Source</th><th>Run</th><th>Score</th><th>Evidence</th></tr></thead><tbody>{acceptance_rows}</tbody></table></section><p><a href=\"{handoff}\">Release Candidate Handoff</a> · <a href=\"/api/v1/release/cockpit.json\">Cockpit JSON</a> · <a href=\"/api/v1/release/publication/dashboard\">Release Publication</a> · <a href=\"/api/v1/phase1/promotion/operator-panel\">Phase 1 Operator Panel</a> · <a href=\"/api/v1/provider/registry/dashboard\">Provider Registry</a> · <a href=\"/api/v1/provider/readiness/dashboard\">Provider Readiness</a> · <a href=\"/api/v1/acceptance/dashboard\">Provider Acceptance</a> · <a href=\"/api/v1/storage/dashboard\">Storage</a></p></main></body></html>",
        status = escape_html(json_str(&cockpit, "status").unwrap_or("unknown")),
        next_action = escape_html(json_str(&cockpit, "next_action").unwrap_or("observe release cockpit")),
        rows = [
            surface_row("release_publication", "Release Publication"),
            surface_row("phase1_promotion", "Phase 1 Promotion"),
            surface_row("provider_registry", "Provider Registry"),
            surface_row("provider_readiness", "Provider Readiness"),
            surface_row("provider_acceptance", "Provider Acceptance"),
            surface_row("release_evaluator_decision", "Release Evaluator Decision"),
        ]
        .join(""),
        provider_registry_metadata_section = provider_registry_metadata_section,
        correlation_section = correlation_section,
        surface_parity_section = surface_parity_section,
        rejected_smoke_section = rejected_smoke_section,
        acceptance_rows = [
            acceptance_row("latest_codex", "Codex"),
            acceptance_row("latest_claude", "Claude"),
        ]
        .join(""),
        handoff = escape_html(handoff_link),
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

fn provider_registry_metadata_sources(surface: &serde_json::Value) -> serde_json::Value {
    let providers = surface
        .get("value")
        .and_then(|value| value.get("providers"))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|provider| {
                    let name = json_str(provider, "provider").unwrap_or("unknown");
                    let adapter_crate = provider
                        .get("crate")
                        .or_else(|| provider.get("adapter_crate"))
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| match name {
                            "codex" => "ao2-adapter-codex".to_string(),
                            "claude" => "ao2-adapter-claude".to_string(),
                            "scripted" => "ao2-adapters".to_string(),
                            _ => "built-in".to_string(),
                        });
                    let metadata_source = json_str(provider, "metadata_source")
                        .map(ToString::to_string)
                        .unwrap_or_else(|| adapter_crate.clone());
                    let doctor_metadata_source = provider
                        .get("doctor")
                        .and_then(|doctor| json_str(doctor, "metadata_source"))
                        .map(ToString::to_string)
                        .unwrap_or_else(|| metadata_source.clone());
                    serde_json::json!({
                        "provider": name,
                        "metadata_source": metadata_source,
                        "adapter_crate": adapter_crate,
                        "adapter_kind": json_str(provider, "adapter_kind").unwrap_or("unknown"),
                        "doctor_metadata_source": doctor_metadata_source,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::Value::Array(providers)
}

fn render_provider_registry_metadata_section(
    provider_registry: Option<&serde_json::Value>,
) -> String {
    let rows = provider_registry
        .and_then(|registry| registry.get("providers"))
        .and_then(serde_json::Value::as_array)
        .map(|providers| {
            providers
                .iter()
                .map(|provider| {
                    format!(
                        "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                        escape_html(json_str(provider, "provider").unwrap_or("unknown")),
                        escape_html(json_str(provider, "metadata_source").unwrap_or("unknown")),
                        escape_html(json_str(provider, "doctor_metadata_source").unwrap_or("unknown")),
                        escape_html(json_str(provider, "adapter_kind").unwrap_or("unknown")),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            "<tr><td colspan=\"4\">No provider registry metadata observed.</td></tr>".to_string()
        });
    format!(
        "<section><h2>Provider Registry Metadata</h2><table><thead><tr><th>Provider</th><th>Metadata Source</th><th>Doctor Metadata Source</th><th>Adapter Kind</th></tr></thead><tbody>{rows}</tbody></table></section>"
    )
}

pub(super) async fn release_publication_dashboard_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let publication_artifact = latest_release_publication_entry_value(state).await?;
    let Some((entry, publication)) = publication_artifact else {
        return Ok(serde_json::json!({
            "schema_version": RELEASE_PUBLICATION_DASHBOARD_SCHEMA,
            "state": "release_publication_missing",
            "next_action": "publish AO2 release-publication summary evidence from the governed release workflow",
            "latest": null,
            "verification": {},
            "archive_targets": 0,
            "candidate_correlation": candidate_correlation_value(
                &serde_json::json!({}),
                &serde_json::json!({}),
                &serde_json::json!({}),
                &serde_json::json!({}),
                &serde_json::json!({}),
            ),
            "trust_boundary": trust_boundary(),
            "links": release_publication_links(),
        }));
    };
    let verification = publication
        .get("verification")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let status = json_str(&publication, "status").unwrap_or("unknown");
    let provenance_verified = verification
        .get("provenance_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let provenance_tag_matches = verification
        .get("provenance_tag_matches")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let release_ship_passed = json_str(&verification, "release_ship") == Some("passed");
    let rollback_verified = json_str(&verification, "rollback_status") == Some("verified");
    let state_value = if status == "published_verified"
        && provenance_verified
        && provenance_tag_matches
        && release_ship_passed
        && rollback_verified
    {
        "release_published_verified"
    } else {
        "release_publication_needs_attention"
    };
    let archive_targets = publication
        .get("archives")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    let release_surface = serde_json::json!({
        "version": json_str(&publication, "version").unwrap_or("unknown"),
        "release_tag": json_str(&publication, "release_tag").unwrap_or("unknown"),
    });
    let three_os_smoke = latest_json_surface(
        state,
        THREE_OS_RELEASE_SMOKE_SCHEMA,
        BundleKind::ThreeOsReleaseSmoke,
    )
    .await?;
    let phase1_surface = serde_json::json!({
        "three_os_smoke": compact_surface(&three_os_smoke),
    });
    let release_evaluator_decision = latest_json_surface(
        state,
        RELEASE_EVALUATOR_DECISION_SCHEMA,
        BundleKind::ReleaseEvaluatorDecision,
    )
    .await?;
    let evaluator_surface = serde_json::json!({
        "version": release_evaluator_decision
            .get("value")
            .and_then(|value| value.get("release"))
            .and_then(|release| json_str(release, "version"))
            .unwrap_or("unknown"),
        "release_tag": release_evaluator_decision
            .get("value")
            .and_then(|value| value.get("release"))
            .and_then(|release| json_str(release, "release_tag"))
            .unwrap_or("unknown"),
    });
    let acceptance_summary = acceptance_surface(state).await?;
    let codex_acceptance = acceptance_summary
        .get("latest_codex")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let claude_acceptance = acceptance_summary
        .get("latest_claude")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let candidate_correlation = candidate_correlation_value(
        &release_surface,
        &phase1_surface,
        &evaluator_surface,
        &codex_acceptance,
        &claude_acceptance,
    );

    Ok(serde_json::json!({
        "schema_version": RELEASE_PUBLICATION_DASHBOARD_SCHEMA,
        "state": state_value,
        "next_action": if state_value == "release_published_verified" {
            "observe release health and proceed to fresh-install smoke on each platform"
        } else {
            "rerun release ship or publish complete release verification evidence"
        },
        "latest": {
            "version": json_str(&publication, "version").unwrap_or("unknown"),
            "release_tag": json_str(&publication, "release_tag").unwrap_or("unknown"),
            "status": status,
            "release_url": json_str(&publication, "release_url").unwrap_or("unknown"),
            "repositories": publication
                .get("repositories")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            "sha256": entry.sha256,
            "ingested_at": entry.ingested_at,
            "raw_url": format!("/api/v1/release/publication/{}", entry.sha256),
        },
        "verification": verification,
        "archives": publication.get("archives").cloned().unwrap_or_else(|| serde_json::json!([])),
        "archive_targets": archive_targets,
        "artifacts": publication.get("artifacts").cloned().unwrap_or_else(|| serde_json::json!({})),
        "candidate_correlation": candidate_correlation,
        "trust_boundary": trust_boundary(),
        "links": release_publication_links(),
    }))
}

async fn release_cockpit_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let release_publication = release_publication_dashboard_value(state).await?;
    let provider_registry = latest_json_surface(
        state,
        PROVIDER_REGISTRY_SCHEMA,
        BundleKind::ProviderRegistry,
    )
    .await?;
    let provider_readiness = latest_json_surface(
        state,
        PROVIDER_READINESS_SCHEMA,
        BundleKind::ProviderReadiness,
    )
    .await?;
    let phase1_checklist = latest_json_surface(
        state,
        PHASE1_PROMOTION_CHECKLIST_SCHEMA,
        BundleKind::Phase1PromotionChecklist,
    )
    .await?;
    let phase1_decision = latest_json_surface(
        state,
        PHASE1_PROMOTION_DECISION_SCHEMA,
        BundleKind::Phase1PromotionDecision,
    )
    .await?;
    let three_os_smoke = latest_json_surface(
        state,
        THREE_OS_RELEASE_SMOKE_SCHEMA,
        BundleKind::ThreeOsReleaseSmoke,
    )
    .await?;
    let release_evaluator_decision = latest_json_surface(
        state,
        RELEASE_EVALUATOR_DECISION_SCHEMA,
        BundleKind::ReleaseEvaluatorDecision,
    )
    .await?;
    let acceptance_summary = acceptance_surface(state).await?;

    let provider_registry_status = if provider_registry.get("value").is_some() {
        "observed"
    } else {
        "missing"
    };
    let provider_readiness_status = provider_readiness
        .get("value")
        .and_then(|value| json_str(value, "status"))
        .unwrap_or("missing");
    let release_state = json_str(&release_publication, "state").unwrap_or("missing");
    let status = if release_state == "release_published_verified"
        && provider_registry_status == "observed"
        && provider_readiness_status == "passed"
    {
        "ready"
    } else {
        "needs_attention"
    };

    let mut cockpit = serde_json::json!({
        "schema_version": RELEASE_COCKPIT_SCHEMA,
        "status": status,
        "next_action": if status == "ready" {
            "continue cross-OS release observation and close remaining Phase 1 promotion evidence gaps"
        } else {
            "publish missing release, provider registry, and provider readiness evidence"
        },
        "surfaces": {
            "release_publication": {
                "state": release_state,
                "sha256": release_publication
                    .get("latest")
                    .and_then(|latest| json_str(latest, "sha256"))
                    .unwrap_or("missing"),
                "version": release_publication
                    .get("latest")
                    .and_then(|latest| json_str(latest, "version"))
                    .unwrap_or("unknown"),
                "release_tag": release_publication
                    .get("latest")
                    .and_then(|latest| json_str(latest, "release_tag"))
                    .unwrap_or("unknown"),
                "repositories": release_publication
                    .get("latest")
                    .and_then(|latest| latest.get("repositories"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                "dashboard_state": release_state,
            },
            "phase1_promotion": {
                "status": phase1_status(&phase1_checklist, &phase1_decision, &three_os_smoke),
                "checklist": compact_surface(&phase1_checklist),
                "decision": compact_surface(&phase1_decision),
                "decision_signature_present": phase1_decision_signature_present(state, &phase1_decision).await,
                "three_os_smoke": compact_surface(&three_os_smoke),
                "three_os_smoke_details": three_os_smoke_details(&three_os_smoke),
            },
            "provider_registry": {
                "status": provider_registry_status,
                "sha256": json_str(&provider_registry, "sha256").unwrap_or("missing"),
                "phase": provider_registry
                    .get("value")
                    .and_then(|value| json_str(value, "phase"))
                    .unwrap_or("unknown"),
                "provider_count": provider_registry
                    .get("value")
                    .and_then(|value| value.get("providers"))
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0),
                "providers": provider_registry_metadata_sources(&provider_registry),
                "signature_present": provider_registry_signature_present(state, &provider_registry).await,
            },
            "provider_readiness": {
                "status": provider_readiness_status,
                "sha256": json_str(&provider_readiness, "sha256").unwrap_or("missing"),
                "codex_gate": provider_readiness
                    .get("value")
                    .and_then(|value| value.get("codex_gate"))
                    .and_then(|gate| json_str(gate, "verdict"))
                    .unwrap_or("missing"),
                "codex_pilot": provider_readiness
                    .get("value")
                    .and_then(|value| value.get("codex_pilot"))
                    .and_then(|pilot| json_str(pilot, "status"))
                    .unwrap_or("missing"),
            },
            "provider_acceptance": acceptance_summary,
            "release_evaluator_decision": {
                "status": json_str(&release_evaluator_decision, "status").unwrap_or("missing"),
                "sha256": json_str(&release_evaluator_decision, "sha256").unwrap_or("missing"),
                "decision": release_evaluator_decision
                    .get("value")
                    .and_then(|value| json_str(value, "decision"))
                    .unwrap_or("missing"),
                "version": release_evaluator_decision
                    .get("value")
                    .and_then(|value| value.get("release"))
                    .and_then(|release| json_str(release, "version"))
                    .unwrap_or("unknown"),
                "release_tag": release_evaluator_decision
                    .get("value")
                    .and_then(|value| value.get("release"))
                    .and_then(|release| json_str(release, "release_tag"))
                    .unwrap_or("unknown"),
                "raw_url": raw_url(
                    "/api/v1/release/evaluator-decision",
                    json_str(&release_evaluator_decision, "sha256").unwrap_or("missing"),
                ),
            },
        },
        "trust_boundary": trust_boundary(),
        "links": release_cockpit_links(),
    });

    let surfaces_clone = cockpit
        .get("surfaces")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let release_surface = surfaces_clone
        .get("release_publication")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let phase1_surface = surfaces_clone
        .get("phase1_promotion")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let evaluator_surface = surfaces_clone
        .get("release_evaluator_decision")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let provider_acceptance_surface = surfaces_clone
        .get("provider_acceptance")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let codex_acceptance = provider_acceptance_surface
        .get("latest_codex")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let claude_acceptance = provider_acceptance_surface
        .get("latest_claude")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    cockpit["candidate_correlation"] = candidate_correlation_value(
        &release_surface,
        &phase1_surface,
        &evaluator_surface,
        &codex_acceptance,
        &claude_acceptance,
    );
    cockpit["candidate_correlation_parity"] = phase1_surface
        .get("three_os_smoke_details")
        .and_then(|details| details.get("candidate_correlation_parity"))
        .cloned()
        .unwrap_or_else(|| serde_json::Value::String("missing".to_string()));
    // Lane CC: mirror the per-surface byte-identity verdict onto the
    // cockpit so operators reading the cockpit (the primary triage
    // surface) see drift on any of the 6 Lane Z/BB invariants
    // without paging to the readiness panel.
    cockpit["surface_content_hash_parity"] = phase1_surface
        .get("three_os_smoke_details")
        .and_then(|details| details.get("surface_content_hash_parity"))
        .cloned()
        .unwrap_or_else(|| serde_json::Value::String("missing".to_string()));
    cockpit["surface_content_hash_parity_detail"] = phase1_surface
        .get("three_os_smoke_details")
        .and_then(|details| details.get("surface_content_hash_parity_detail"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    // Lane XX: mirror the audit-log rotation budget that Lane VV
    // added to the HTML onto the cockpit JSON so external monitors
    // (e.g., a Prometheus exporter) can alert on
    // audit_log_size_bytes / audit_log_cap_bytes > 0.75 without
    // parsing HTML. The summary shape is exactly what the HTML
    // renderer consumes: count + latest_timestamp_utc +
    // latest_rejection_reason + audit_log_size_bytes +
    // audit_log_cap_bytes. The handoff + readiness JSON inherit
    // this field automatically through their existing cockpit
    // pass-through.
    cockpit["rejected_smoke_audit"] =
        crate::handlers::phase1_promotion::rejected_smoke_audit_summary(state).await;
    Ok(cockpit)
}

async fn release_candidate_handoff_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let cockpit = release_cockpit_value(state).await?;
    let surfaces = cockpit
        .get("surfaces")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let release = surfaces
        .get("release_publication")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let phase1 = surfaces
        .get("phase1_promotion")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let provider_acceptance = surfaces
        .get("provider_acceptance")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let codex = provider_acceptance
        .get("latest_codex")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let claude = provider_acceptance
        .get("latest_claude")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let release_evaluator_decision = surfaces
        .get("release_evaluator_decision")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let live_acceptance_complete =
        provider_acceptance_is_live_passed(&codex) && provider_acceptance_is_live_passed(&claude);
    let cockpit_status = json_str(&cockpit, "status").unwrap_or("unknown");
    let phase1_status = json_str(&phase1, "status").unwrap_or("missing");
    let release_evaluator_status =
        release_evaluator_decision_gate_status(&release_evaluator_decision);
    let candidate_correlation = candidate_correlation_value(
        &release,
        &phase1,
        &release_evaluator_decision,
        &codex,
        &claude,
    );
    let candidate_correlation_status =
        json_str(&candidate_correlation, "status").unwrap_or("mismatched");
    let decision_signature_present = phase1
        .get("decision_signature_present")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let surface_content_hash_parity = phase1
        .get("three_os_smoke_details")
        .and_then(|details| details.get("surface_content_hash_parity"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    let status = if cockpit_status == "ready"
        && phase1_status == "observed"
        && decision_signature_present
        && live_acceptance_complete
        && release_evaluator_status == "accepted"
        && candidate_correlation_status == "matched"
        && surface_content_hash_parity == "matched"
    {
        "ready"
    } else {
        "attention"
    };
    let release_sha = json_str(&release, "sha256").unwrap_or("missing");
    let checklist_sha = phase1
        .get("checklist")
        .and_then(|surface| json_str(surface, "sha256"))
        .unwrap_or("missing");
    let decision_sha = phase1
        .get("decision")
        .and_then(|surface| json_str(surface, "sha256"))
        .unwrap_or("missing");
    let three_os_sha = phase1
        .get("three_os_smoke")
        .and_then(|surface| json_str(surface, "sha256"))
        .unwrap_or("missing");
    let three_os_status = phase1
        .get("three_os_smoke")
        .and_then(|surface| json_str(surface, "status"))
        .unwrap_or(if three_os_sha == "missing" {
            "missing"
        } else {
            "failed"
        });

    Ok(serde_json::json!({
        "schema_version": RELEASE_CANDIDATE_HANDOFF_SCHEMA,
        "status": status,
        "handoff_kind": "phase1_release_candidate",
        "release": {
            "version": json_str(&release, "version").unwrap_or("unknown"),
            "release_tag": json_str(&release, "release_tag").unwrap_or("unknown"),
            "sha256": release_sha,
            "repositories": release
                .get("repositories")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            "raw_url": raw_url("/api/v1/release/publication", release_sha),
        },
        "gates": {
            "release_cockpit": cockpit_status,
            "phase1_promotion": phase1_status,
            "decision_signature": if decision_signature_present { "present" } else { "missing" },
            "provider_acceptance": if live_acceptance_complete { "live_complete" } else { "attention" },
            "release_evaluator_decision": release_evaluator_status,
            "candidate_correlation": candidate_correlation_status,
            "surface_content_hash_parity": surface_content_hash_parity,
            "three_os_smoke": three_os_status,
        },
        "candidate_correlation": candidate_correlation,
        "candidate_correlation_parity": phase1
            .get("three_os_smoke_details")
            .and_then(|details| details.get("candidate_correlation_parity"))
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("missing".to_string())),
        "surface_content_hash_parity": phase1
            .get("three_os_smoke_details")
            .and_then(|details| details.get("surface_content_hash_parity"))
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("missing".to_string())),
        "surface_content_hash_parity_detail": phase1
            .get("three_os_smoke_details")
            .and_then(|details| details.get("surface_content_hash_parity_detail"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "three_os_smoke_details": phase1
            .get("three_os_smoke_details")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        // Lane XX: pass the cockpit's rejected-smoke audit summary
        // through to the handoff JSON so a monitor polling
        // /api/v1/release/handoff.json sees the rotation budget
        // (audit_log_size_bytes / audit_log_cap_bytes) alongside the
        // gate verdicts it already consumes. Field name matches the
        // cockpit JSON exactly for cross-surface consistency.
        "rejected_smoke_audit": cockpit
            .get("rejected_smoke_audit")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "acceptance": {
            "codex": compact_acceptance_for_handoff(&codex),
            "claude": compact_acceptance_for_handoff(&claude),
        },
        "artifacts": {
            "release_publication": {
                "sha256": release_sha,
                "raw_url": raw_url("/api/v1/release/publication", release_sha),
            },
            "phase1_checklist": {
                "sha256": checklist_sha,
                "raw_url": raw_url("/api/v1/phase1/promotion/checklist", checklist_sha),
            },
            "phase1_decision": {
                "sha256": decision_sha,
                "raw_url": raw_url("/api/v1/phase1/promotion/decision", decision_sha),
                "signature_url": if decision_sha == "missing" {
                    "missing".to_string()
                } else {
                    format!("/api/v1/phase1/promotion/decision/{decision_sha}/signature")
                },
            },
            "three_os_smoke": {
                "sha256": three_os_sha,
                "raw_url": raw_url("/api/v1/phase1/promotion/three-os-smoke", three_os_sha),
            },
        },
        "links": {
            "release_candidate_handoff": "/api/v1/release/handoff",
            "release_candidate_handoff_json": "/api/v1/release/handoff.json",
            "release_readiness": "/api/v1/release/readiness",
            "release_readiness_json": "/api/v1/release/readiness.json",
            "cockpit": "/api/v1/release/cockpit",
            "cockpit_json": "/api/v1/release/cockpit.json",
            "phase1_operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
            "phase1_history_json": "/api/v1/phase1/promotion/history.json",
            "provider_acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
        },
        "operator_handoff": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "front_end": "Hermes front end / queue / memory surface",
            "trusted_execution": "ao2 signed evidence boundary",
        },
        "next_actions": if status == "ready" {
            serde_json::json!([
                "factory-v3 evaluator-closer should review the signed handoff bundle before any release-line decision",
                "Hermes may display this read-only handoff but must not approve, start providers, or mutate AO artifacts"
            ])
        } else {
            serde_json::json!([
                "close missing release cockpit, signed Phase 1 decision, live provider acceptance, release evaluator decision, candidate correlation, or three-OS smoke evidence before release-line handoff"
            ])
        },
        "source": {
            "cockpit_schema_version": RELEASE_COCKPIT_SCHEMA,
            "cockpit_status": cockpit_status,
        },
        "trust_boundary": trust_boundary(),
    }))
}

async fn release_readiness_value(state: &AppState) -> Result<serde_json::Value, AppError> {
    let handoff = release_candidate_handoff_value(state).await?;
    let release_publication = release_publication_dashboard_value(state).await?;
    let gates = handoff
        .get("gates")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let artifacts = handoff
        .get("artifacts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let acceptance = handoff
        .get("acceptance")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let operator_handoff = handoff
        .get("operator_handoff")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let codex = acceptance
        .get("codex")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let claude = acceptance
        .get("claude")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let three_os_sha = artifacts
        .get("three_os_smoke")
        .and_then(|artifact| json_str(artifact, "sha256"))
        .unwrap_or("missing");
    let candidate_correlation = handoff
        .get("candidate_correlation")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let candidate_correlation_parity = json_str(&handoff, "candidate_correlation_parity")
        .unwrap_or("missing")
        .to_string();
    // Lane CC: aggregate per-surface byte-identity verdict for the
    // readiness gate. The handoff lifts both the aggregate verdict
    // (string) and the per-surface detail (dict) from the ingested
    // three-OS smoke; the readiness gate reads the aggregate as
    // observed, and the response payload exposes the detail dict so
    // operators see which surface drifted without re-running the
    // aggregator.
    let surface_content_hash_parity = json_str(&handoff, "surface_content_hash_parity")
        .unwrap_or("missing")
        .to_string();
    let surface_content_hash_parity_detail = handoff
        .get("surface_content_hash_parity_detail")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let control_plane_role = json_str(&operator_handoff, "control_plane_role").unwrap_or("missing");
    let mutates_ao_artifacts = operator_handoff
        .get("mutates_ao_artifacts")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let owner = json_str(&operator_handoff, "release_acceptance_owner").unwrap_or("missing");
    let install_verification = install_verification_trust_value(
        release_publication
            .get("artifacts")
            .and_then(|artifacts| artifacts.get("install_verification")),
    );
    let install_verification_observed =
        install_verification_readiness_observed(&install_verification);

    let gate_results = vec![
        release_readiness_gate(
            "release_cockpit",
            "Release Cockpit",
            json_str(&gates, "release_cockpit").unwrap_or("missing"),
            "ready",
        ),
        release_readiness_gate(
            "phase1_promotion",
            "Phase 1 Promotion",
            json_str(&gates, "phase1_promotion").unwrap_or("missing"),
            "observed",
        ),
        release_readiness_gate(
            "decision_signature",
            "Decision Signature",
            json_str(&gates, "decision_signature").unwrap_or("missing"),
            "present",
        ),
        release_readiness_gate(
            "provider_acceptance",
            "Provider Acceptance",
            json_str(&gates, "provider_acceptance").unwrap_or("missing"),
            "live_complete",
        ),
        release_readiness_gate(
            "release_evaluator_decision",
            "Release Evaluator Decision",
            json_str(&gates, "release_evaluator_decision").unwrap_or("missing"),
            "accepted",
        ),
        release_readiness_gate_with_detail(
            "candidate_correlation",
            "Candidate Correlation",
            json_str(&candidate_correlation, "status").unwrap_or("missing"),
            "matched",
            Some(&candidate_correlation),
        ),
        release_readiness_gate(
            "candidate_correlation_parity",
            "Candidate Correlation Parity (Three-OS Smoke)",
            &candidate_correlation_parity,
            "matched",
        ),
        release_readiness_gate_with_detail(
            "surface_content_hash_parity",
            "Surface Content-Hash Parity (Three-OS Smoke)",
            &surface_content_hash_parity,
            "matched",
            Some(&surface_content_hash_parity_detail),
        ),
        release_readiness_gate(
            "codex_acceptance",
            "Codex Acceptance",
            provider_acceptance_readiness(&codex),
            "passed/live",
        ),
        release_readiness_gate(
            "claude_acceptance",
            "Claude Acceptance",
            provider_acceptance_readiness(&claude),
            "passed/live",
        ),
        release_readiness_gate(
            "three_os_smoke",
            "Three-OS Smoke Evidence",
            json_str(&gates, "three_os_smoke").unwrap_or(if three_os_sha == "missing" {
                "missing"
            } else {
                "failed"
            }),
            "passed",
        ),
        release_readiness_gate_with_detail(
            "install_verification",
            "Install Verification Evidence",
            &install_verification_observed,
            "verified/offline_verified/read_only",
            Some(&install_verification),
        ),
        release_readiness_gate(
            "trust_boundary",
            "Trust Boundary",
            if control_plane_role == "read_only_observer"
                && !mutates_ao_artifacts
                && owner == "factory-v3 evaluator-closer"
            {
                "read_only_evaluator_owned"
            } else {
                "attention"
            },
            "read_only_evaluator_owned",
        ),
    ];
    let blockers = gate_results
        .iter()
        .filter(|gate| json_str(gate, "status") != Some("passed"))
        .map(|gate| {
            format!(
                "{}: expected {}, observed {}",
                json_str(gate, "id").unwrap_or("unknown"),
                json_str(gate, "expected").unwrap_or("missing"),
                json_str(gate, "observed").unwrap_or("missing")
            )
        })
        .collect::<Vec<_>>();
    let status = if json_str(&handoff, "status") == Some("ready") && blockers.is_empty() {
        "ready"
    } else {
        "attention"
    };

    Ok(serde_json::json!({
        "schema_version": RELEASE_READINESS_SCHEMA,
        "status": status,
        "release": handoff.get("release").cloned().unwrap_or_else(|| serde_json::json!({})),
        "gate_results": gate_results,
        "blockers": blockers,
        "candidate_correlation": candidate_correlation,
        "candidate_correlation_parity": handoff
            .get("candidate_correlation_parity")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("missing".to_string())),
        "surface_content_hash_parity": handoff
            .get("surface_content_hash_parity")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("missing".to_string())),
        "surface_content_hash_parity_detail": handoff
            .get("surface_content_hash_parity_detail")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "three_os_smoke_details": handoff
            .get("three_os_smoke_details")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "install_verification": install_verification,
        // Lane XX: surface the rotation budget on the readiness
        // JSON too — readiness is the operator's final pre-decision
        // page, and an external monitor consuming readiness JSON
        // should not need a second poll against cockpit JSON to see
        // audit-log capacity headroom.
        "rejected_smoke_audit": handoff
            .get("rejected_smoke_audit")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        "operator_decision": {
            "factory_v3_evaluator_closer_required": true,
            "control_plane_approves_release": false,
            "next_action": if status == "ready" {
                "factory-v3 evaluator-closer may review this readiness summary and handoff before release-line decision"
            } else {
                "resolve readiness blockers before factory-v3 evaluator-closer release-line review"
            },
        },
        "links": {
            "release_readiness": "/api/v1/release/readiness",
            "release_readiness_json": "/api/v1/release/readiness.json",
            "release_candidate_handoff": "/api/v1/release/handoff",
            "release_candidate_handoff_json": "/api/v1/release/handoff.json",
            "cockpit": "/api/v1/release/cockpit",
            "cockpit_json": "/api/v1/release/cockpit.json",
            "phase1_operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
            "provider_acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
        },
        "source": {
            "handoff_schema_version": RELEASE_CANDIDATE_HANDOFF_SCHEMA,
            "handoff_status": json_str(&handoff, "status").unwrap_or("missing"),
        },
        "trust_boundary": trust_boundary(),
    }))
}

async fn release_support_bundle_value(
    state: &AppState,
    keep_latest: usize,
) -> Result<serde_json::Value, AppError> {
    let readiness = release_readiness_value(state).await?;
    let handoff = release_candidate_handoff_value(state).await?;
    let cockpit = release_cockpit_value(state).await?;
    let evaluator_decision = release_evaluator_decision_dashboard_value(state).await?;
    let ci_evidence_index = crate::handlers::ci_evidence::ci_evidence_index_value();
    let storage_support = state
        .storage
        .support_bundle(retention_policy(keep_latest)?)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut storage_support =
        serde_json::to_value(storage_support).map_err(|e| AppError::Internal(e.to_string()))?;
    let release = readiness
        .get("release")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    normalize_release_support_storage_surface(
        &mut storage_support,
        json_str(&release, "ingested_at").unwrap_or("unknown"),
    );
    let release_assembly = release_assembly_value(&readiness, &handoff);
    let release_assembly_sha = support_bundle_surface_sha256(&release_assembly)?;
    let readiness_sha = support_bundle_surface_sha256(&readiness)?;
    let install_verification = readiness
        .get("install_verification")
        .cloned()
        .unwrap_or_else(|| install_verification_trust_value(None));
    let install_verification_sha = support_bundle_surface_sha256(&install_verification)?;
    let hosted_release_smoke = hosted_release_smoke_value(&install_verification);
    let hosted_release_smoke_sha = support_bundle_surface_sha256(&hosted_release_smoke)?;
    let handoff_sha = support_bundle_surface_sha256(&handoff)?;
    let cockpit_sha = support_bundle_surface_sha256(&cockpit)?;
    let evaluator_decision_sha = support_bundle_surface_sha256(&evaluator_decision)?;
    let ci_evidence_index_sha = support_bundle_surface_sha256(&ci_evidence_index)?;
    let storage_support_sha = support_bundle_surface_sha256(&storage_support)?;

    Ok(serde_json::json!({
        "schema_version": RELEASE_SUPPORT_BUNDLE_SCHEMA,
        "bundle_kind": "portable_release_operator_handoff",
        "generated_at": json_str(&release, "ingested_at").unwrap_or("unknown"),
        "release": release,
        "release_assembly": release_assembly,
        "readiness": readiness,
        "install_verification": install_verification,
        "handoff": handoff,
        "cockpit": cockpit,
        "evaluator_decision": evaluator_decision,
        "ci_evidence_index": ci_evidence_index,
        "storage_support": storage_support,
        "hosted_release_smoke": hosted_release_smoke,
        "portable_bundle_manifest": {
            "schema_version": RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA,
            "format": "single authenticated JSON document",
            "intended_use": "offline operator review and factory-v3 evaluator-closer handoff without mutating AO2 artifacts",
            "included_surfaces": [
                {
                    "id": "release_assembly",
                    "schema_version": RELEASE_ASSEMBLY_SCHEMA,
                    "path": "$.release_assembly",
                    "sha256": release_assembly_sha
                },
                {
                    "id": "release_readiness",
                    "schema_version": RELEASE_READINESS_SCHEMA,
                    "path": "$.readiness",
                    "endpoint": "/api/v1/release/readiness.json",
                    "sha256": readiness_sha
                },
                {
                    "id": "release_candidate_handoff",
                    "schema_version": RELEASE_CANDIDATE_HANDOFF_SCHEMA,
                    "path": "$.handoff",
                    "endpoint": "/api/v1/release/handoff.json",
                    "sha256": handoff_sha
                },
                {
                    "id": "release_cockpit",
                    "schema_version": RELEASE_COCKPIT_SCHEMA,
                    "path": "$.cockpit",
                    "endpoint": "/api/v1/release/cockpit.json",
                    "sha256": cockpit_sha
                },
                {
                    "id": "release_evaluator_decision",
                    "schema_version": RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA,
                    "path": "$.evaluator_decision",
                    "endpoint": "/api/v1/release/evaluator-decision/dashboard.json",
                    "sha256": evaluator_decision_sha
                },
                {
                    "id": "install_verification",
                    "schema_version": "ao2.install-verification-evidence.v1",
                    "path": "$.install_verification",
                    "sha256": install_verification_sha
                },
                {
                    "id": "hosted_release_smoke",
                    "schema_version": "ao2.release-archive-hosted-smoke.v1",
                    "path": "$.hosted_release_smoke",
                    "sha256": hosted_release_smoke_sha
                },
                {
                    "id": "ci_evidence_index",
                    "schema_version": "ao2.cp-ci-evidence-index.v1",
                    "path": "$.ci_evidence_index",
                    "endpoint": "/api/v1/ci/evidence-index.json",
                    "sha256": ci_evidence_index_sha
                },
                {
                    "id": "storage_support_bundle",
                    "schema_version": "ao2.cp-support-bundle.v1",
                    "path": "$.storage_support",
                    "endpoint": format!("/api/v1/storage/support-bundle.json?keep_latest={keep_latest}"),
                    "sha256": storage_support_sha
                }
            ],
            "integrity": {
                "algorithm": "sha256-ao2-cp-canonical-json-v1",
                "scope": "embedded_support_bundle_surfaces",
                "surface_sha256": {
                    "release_assembly": release_assembly_sha,
                    "release_readiness": readiness_sha,
                    "release_candidate_handoff": handoff_sha,
                    "release_cockpit": cockpit_sha,
                    "release_evaluator_decision": evaluator_decision_sha,
                    "install_verification": install_verification_sha,
                    "hosted_release_smoke": hosted_release_smoke_sha,
                    "ci_evidence_index": ci_evidence_index_sha,
                    "storage_support_bundle": storage_support_sha
                },
                "verification_plan": {
                    "surface_count": SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len(),
                    "expected_fail_closed": true,
                    "trust_boundary": "offline digest verification only; no AO2 artifact mutation and no release approval",
                    "cross_platform_commands": {
                        "macos_ubuntu": "python3 verify_release_support_bundle.py --checksums SHA256SUMS release-support-bundle.json",
                        "windows_powershell": "pwsh -File Verify-ReleaseSupportBundle.ps1 -Checksums SHA256SUMS -Path release-support-bundle.json"
                    },
                    "required_checks": [
                        "recompute each embedded support-bundle surface sha256 with canonical JSON",
                        "compare every recomputed digest to portable_bundle_manifest.integrity.surface_sha256",
                        "fail closed if any included surface path, schema_version, or sha256 is missing",
                        "confirm install verification is a standalone offline-verifiable surface before release review",
                        "confirm hosted release smoke passed and references install verification before release review",
                        "confirm CI evidence index remains a read-only observer surface before offline release review",
                        "confirm factory-v3 evaluator decision remains an observed dashboard surface and not a control-plane approval",
                        "confirm trust_boundary.role remains read_only_observer before evaluator-closer review"
                    ]
                }
            },
            "credential_handling": "bearer tokens are required only in HTTP headers and are never embedded in this bundle",
            "cross_platform_review": {
                "macos_ubuntu": "python3 -m json.tool release-support-bundle.json >/dev/null",
                "windows": "python -m json.tool release-support-bundle.json > $null"
            }
        },
        "operator_handoff": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "control_plane_approves_release": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "offline_review_commands": [
                "python3 -m json.tool release-support-bundle.json >/dev/null",
                "python -m json.tool release-support-bundle.json > $null",
                "sha256sum -c SHA256SUMS",
                "python3 verify_release_support_bundle.py --checksums SHA256SUMS release-support-bundle.json",
                "Get-FileHash -Algorithm SHA256 release-support-bundle.json",
                "pwsh -File Verify-ReleaseSupportBundle.ps1 -Checksums SHA256SUMS -Path release-support-bundle.json",
                "jq '.readiness.status, .handoff.status, .trust_boundary.role' release-support-bundle.json"
            ],
            "credential_handoff": {
                "source": "local_oauth_cli",
                "environment_variable": "AO2_CP_AUTH_VALUE",
                "value_contract": "HTTP Authorization header value only; never a URL query parameter, markdown literal, or committed artifact",
                "allowed_transport": "HTTP Authorization header only",
                "forbidden_locations": ["urls", "logs", "reports", "markdown", "committed artifacts"],
                "cross_platform_capture": {
                    "posix_shell": "set +x; AO2_CP_AUTH_VALUE=\"$(local-oauth-cli prints authorization-value)\"; export AO2_CP_AUTH_VALUE",
                    "powershell": "Set-PSDebug -Off; $env:AO2_CP_AUTH_VALUE = (& local-oauth-cli prints authorization-value)"
                },
                "clear_after_fetch": ["unset AO2_CP_AUTH_VALUE", "Remove-Item Env:AO2_CP_AUTH_VALUE"],
                "operator_note": "The control plane documents the handoff contract only; the local OAuth/session CLI obtains credentials outside generated evidence."
            },
            "next_action": "factory-v3 evaluator-closer reviews this portable observer bundle alongside AO2 signed evidence before any release-line acceptance decision"
        },
        "links": {
            "release_support_bundle_json": format!("/api/v1/release/support-bundle.json?keep_latest={keep_latest}"),
            "release_support_bundle_verification_json": format!("/api/v1/release/support-bundle/verify.json?keep_latest={keep_latest}"),
            "release_support_verifier_handoff_json": format!("/api/v1/release/support-bundle/handoff.json?keep_latest={keep_latest}"),
            "release_support_verifier_handoff": format!("/api/v1/release/support-bundle/handoff?keep_latest={keep_latest}"),
            "release_support_bundle_checksums": format!("/api/v1/release/support-bundle/SHA256SUMS?keep_latest={keep_latest}"),
            "release_readiness_json": "/api/v1/release/readiness.json",
            "release_candidate_handoff_json": "/api/v1/release/handoff.json",
            "release_cockpit_json": "/api/v1/release/cockpit.json",
            "ci_evidence_index_json": "/api/v1/ci/evidence-index.json",
            "storage_support_bundle_json": format!("/api/v1/storage/support-bundle.json?keep_latest={keep_latest}"),
            "phase1_gap_report_json": "/api/v1/phase1/promotion/gap-report.json",
            "evaluator_decision_dashboard_json": "/api/v1/release/evaluator-decision/dashboard.json"
        },
        "trust_boundary": trust_boundary(),
    }))
}

async fn latest_release_publication_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = release_publication_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_release_publication_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn release_publication_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == RELEASE_PUBLICATION_SCHEMA);
    Ok(entries)
}

async fn latest_json_surface(
    state: &AppState,
    schema: &str,
    kind: BundleKind,
) -> Result<serde_json::Value, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == schema);
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(serde_json::json!({
            "status": "missing",
            "schema": schema,
        }));
    };
    let bytes = state
        .storage
        .bundles
        .read(kind, &entry.sha256)
        .await
        .map_err(|_| AppError::NotFound)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(serde_json::json!({
        "status": entry.status.unwrap_or_else(|| "observed".to_string()),
        "schema": schema,
        "sha256": entry.sha256,
        "ingested_at": entry.ingested_at,
        "value": value,
    }))
}

fn compact_surface(surface: &serde_json::Value) -> serde_json::Value {
    let mut compact = serde_json::json!({
        "status": compact_surface_status(surface),
        "sha256": json_str(surface, "sha256").unwrap_or("missing"),
    });
    if let Some(value) = surface.get("value") {
        for key in ["version", "release_candidate_version", "source_commit"] {
            if let Some(raw) = json_str(value, key) {
                compact[key] = serde_json::json!(raw);
            }
        }
    }
    compact
}

fn compact_surface_status(surface: &serde_json::Value) -> String {
    let Some(value) = surface.get("value") else {
        return json_str(surface, "status").unwrap_or("missing").to_string();
    };
    if value.get("targets").is_some() && value.get("source_dirty").is_some() {
        return three_os_smoke_clean_status(value).to_string();
    }
    json_str(surface, "status").unwrap_or("missing").to_string()
}

fn three_os_smoke_clean_status(smoke: &serde_json::Value) -> &'static str {
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
    if status == "passed" && !source_dirty && all_targets_passed {
        "passed"
    } else {
        "failed"
    }
}

const EXPECTED_SURFACE_CONTENT_HASH_PARITY_KEYS: [&str; 6] = [
    "release_cockpit",
    "release_handoff",
    "release_readiness",
    "release_publication_dashboard",
    "release_assembly",
    "release_assembly_blockers",
];

// Lane CC: derive an aggregate verdict from the per-surface
// content-hash parity dict written by Lane Z + Lane BB
// (`surface_content_hash_parity` on the three-OS smoke artifact). The
// aggregate is "drift" if ANY expected per-surface verdict is "drift",
// "matched" only if ALL six expected surfaces are present and "matched",
// and "unknown" if an expected surface is missing, malformed, or unknown
// and none reported "drift". Unexpected extra keys are ignored so future
// observer-only surfaces do not change the release gate contract.
fn aggregate_surface_content_hash_parity(detail: &serde_json::Value) -> String {
    let Some(map) = detail.as_object() else {
        return "missing".to_string();
    };
    if map.is_empty() {
        return "missing".to_string();
    }

    let mut observed_unknown = false;
    for key in EXPECTED_SURFACE_CONTENT_HASH_PARITY_KEYS {
        match map.get(key).and_then(serde_json::Value::as_str) {
            Some("drift") => return "drift".to_string(),
            Some("matched") => {}
            Some("unknown") | Some(_) | None => observed_unknown = true,
        }
    }

    if observed_unknown {
        "unknown".to_string()
    } else {
        "matched".to_string()
    }
}

// Lane GG: render the per-surface content-hash parity dict as a small
// HTML table on the cockpit so operators triage drift visually instead
// of by reading JSON. Rows = the six expected operator-triage surfaces
// (cockpit, handoff, readiness, publication_dashboard, assembly,
// assembly_blockers); the verdict cell is colored "ok" on matched and
// "warn" on every other state (drift, unknown, missing). Returns an
// empty string when the detail dict is absent so legacy callers that
// have no surface-parity evidence yet render an unchanged cockpit.
fn render_surface_content_hash_parity_section(detail: &serde_json::Value) -> String {
    let detail_map = detail.as_object();
    if detail_map.map(|m| m.is_empty()).unwrap_or(true) {
        return String::new();
    }
    let surface_labels = [
        ("release_cockpit", "Release Cockpit"),
        ("release_handoff", "Release Candidate Handoff"),
        ("release_readiness", "Release Readiness"),
        (
            "release_publication_dashboard",
            "Release Publication Dashboard",
        ),
        ("release_assembly", "Release Assembly"),
        ("release_assembly_blockers", "Release Assembly Blockers"),
    ];
    let rows: String = surface_labels
        .iter()
        .map(|(key, label)| {
            let verdict = detail_map
                .and_then(|m| m.get(*key))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("missing");
            let class = if verdict == "matched" { "ok" } else { "warn" };
            format!(
                "<tr><td>{label}</td><td class=\"{class}\">{verdict}</td></tr>",
                label = escape_html(label),
                class = class,
                verdict = escape_html(verdict),
            )
        })
        .collect();
    format!(
        "<section><h2>Per-Surface Content-Hash Parity</h2><p>Each row is one of the six release-publication-shaped surfaces audited cross-OS by the aggregator. A non-<code>matched</code> verdict on any surface hard-blocks the release readiness gate.</p><table><thead><tr><th>Surface</th><th>Verdict</th></tr></thead><tbody>{rows}</tbody></table></section>",
    )
}

// Lane MM: render the rejected-smoke audit summary as a small cockpit
// section so operators see tampering-attempt volume at a glance.
//
// The Lane LL audit log is at <storage-root>/rejected-three-os-smoke.jsonl
// and grows by one record on every 422'd three-OS smoke ingestion. The
// 422 response body alone is invisible once the client disconnects, so
// the cockpit row is the operator's persistent forensic view.
//
// The section ALWAYS renders (zero is a positive operator signal: the
// audit trail is reachable and no tampering has been observed). Count
// is colored `ok` when zero, `warn` when non-zero. The latest record's
// timestamp + rejection reason render only when count >= 1; long
// reasons are already pre-truncated to 240 chars by the reader.
fn render_rejected_smoke_audit_section(summary: &serde_json::Value) -> String {
    let count = summary
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let class = if count == 0 { "ok" } else { "warn" };
    let latest_timestamp = summary
        .get("latest_timestamp_utc")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let latest_reason = summary
        .get("latest_rejection_reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let latest_row = if count >= 1 && !latest_timestamp.is_empty() {
        format!(
            "<dt>Latest timestamp</dt><dd><code>{ts}</code></dd><dt>Latest rejection reason</dt><dd><code>{reason}</code></dd>",
            ts = escape_html(latest_timestamp),
            reason = escape_html(latest_reason),
        )
    } else {
        String::new()
    };
    // Lane VV: surface the audit-log size against its rotation cap so
    // operators can answer "is rotation imminent?" and "did the log
    // just rotate?" without shelling into the storage root. Lane UU
    // rotates newest-records-kept when size exceeds the cap, but
    // emits no persistent rotation counter — instead the raw
    // (size, cap) pair lets operators infer both states:
    //  - size near cap (>=75%) → "rotation imminent" → warn
    //  - size dropped after a known burst → "rotation just happened"
    // A fresh control plane renders 0 / 1048576 bytes so the row is
    // always present, giving operators positive evidence the section
    // is wired up before any rejection lands.
    let size_bytes = summary
        .get("audit_log_size_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cap_bytes = summary
        .get("audit_log_cap_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let size_class = if cap_bytes > 0 && size_bytes.saturating_mul(4) >= cap_bytes.saturating_mul(3)
    {
        "warn"
    } else {
        "ok"
    };
    let size_row = format!(
        "<dt>Audit log size</dt><dd class=\"{size_class}\"><code>{size_bytes}</code> / <code>{cap_bytes}</code> bytes (Lane UU rotation cap)</dd>",
    );
    // Lane EEE: surface a brief on-call triage pointer right next to the
    // audit-log row so an operator paged at 3 AM on a tampering-burst
    // alert (Lane XX-doc rule 2) lands on the correct runbook section
    // without needing to know the section number in advance. The
    // load-bearing framing — "tampering event, not audit-log corruption"
    // — is documented in runbook 9.9 (Lane DDD); the pointer keeps the
    // cockpit row navigable without duplicating the prose.
    let triage_row =
        "<dt>On-call triage</dt><dd>See release-smoke runbook section 9.9 for tampering-burst triage (a burst is a tampering event, not audit-log corruption).</dd>";
    format!(
        "<section><h2>Rejected Smoke Ingestions</h2><p>Append-only forensic record (Lane LL) of three-OS release smoke POSTs that were rejected at ingestion (422 SchemaInvalid). A non-zero count surfaces tampering attempts that the response body alone does not preserve; the log lives at <code>&lt;storage-root&gt;/rejected-three-os-smoke.jsonl</code>.</p><dl><dt>Total rejected</dt><dd class=\"{class}\">{count}</dd>{latest_row}{size_row}{triage_row}</dl></section>",
    )
}

fn three_os_smoke_details(surface: &serde_json::Value) -> serde_json::Value {
    let smoke = surface.get("value").unwrap_or(surface);
    let targets = ["macos", "ubuntu", "windows"]
        .iter()
        .map(|target| {
            let value = smoke
                .get("targets")
                .and_then(|targets| targets.get(*target))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({ "status": "missing" }));
            ((*target).to_string(), value)
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let candidate_correlation_parity = smoke
        .get("candidate_correlation_parity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing")
        .to_string();
    // Lane CC: lift the per-surface byte-identity verdict dict from the
    // ingested smoke (written by the aggregator in Lanes V/Z/BB) onto
    // the compact details surface so cockpit/handoff/readiness can read
    // it without re-parsing the raw smoke artifact.
    let surface_content_hash_parity_detail = smoke
        .get("surface_content_hash_parity")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let surface_content_hash_parity =
        aggregate_surface_content_hash_parity(&surface_content_hash_parity_detail);
    serde_json::json!({
        "overall_status": three_os_smoke_clean_status(smoke),
        "source_dirty": smoke
            .get("source_dirty")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "targets": targets,
        "candidate_correlation_parity": candidate_correlation_parity,
        "surface_content_hash_parity": surface_content_hash_parity,
        "surface_content_hash_parity_detail": surface_content_hash_parity_detail,
    })
}

fn three_os_smoke_detail_rows(details: &serde_json::Value) -> String {
    let Some(targets) = details.get("targets") else {
        return "<tr><td colspan=\"4\">No three-OS smoke details observed</td></tr>".to_string();
    };
    [
        ("macos", "macOS"),
        ("ubuntu", "Ubuntu"),
        ("windows", "Windows"),
    ]
    .iter()
    .map(|(key, label)| {
        let target = targets
            .get(*key)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let duration = target
            .get("duration_seconds")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string());
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(label),
            escape_html(json_str(&target, "status").unwrap_or("missing")),
            escape_html(&duration),
            escape_html(json_str(&target, "artifact_url").unwrap_or("missing")),
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn release_evaluator_decision_gate_status(surface: &serde_json::Value) -> &'static str {
    if json_str(surface, "status") == Some("missing")
        || json_str(surface, "sha256") == Some("missing")
    {
        return "missing";
    }
    let decision = surface
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            surface
                .get("value")
                .and_then(|value| json_str(value, "decision"))
        });
    if json_str(surface, "status") == Some("accepted")
        && decision == Some("accept_phase1_release_candidate")
    {
        "accepted"
    } else if decision == Some("reject_phase1_release_candidate") {
        "rejected"
    } else {
        "attention"
    }
}

fn candidate_correlation_value(
    release: &serde_json::Value,
    phase1: &serde_json::Value,
    evaluator: &serde_json::Value,
    codex: &serde_json::Value,
    claude: &serde_json::Value,
) -> serde_json::Value {
    let release_version = json_str(release, "version").unwrap_or("unknown");
    let release_tag = json_str(release, "release_tag").unwrap_or("unknown");
    let three_os_version = phase1
        .get("three_os_smoke")
        .and_then(|surface| {
            json_str(surface, "release_candidate_version").or_else(|| json_str(surface, "version"))
        })
        .unwrap_or("unknown");
    let evaluator_version = json_str(evaluator, "version").unwrap_or("unknown");
    let evaluator_tag = json_str(evaluator, "release_tag").unwrap_or("unknown");
    let codex_version = json_str(codex, "release_candidate_version").unwrap_or("unknown");
    let claude_version = json_str(claude, "release_candidate_version").unwrap_or("unknown");

    let mut blockers = Vec::new();
    if release_version == "unknown" {
        blockers.push("release_version is unknown".to_string());
    }
    if release_tag == "unknown" {
        blockers.push("release_tag is unknown".to_string());
    }
    if three_os_version != release_version {
        blockers.push(format!(
            "three_os_release_candidate_version {three_os_version} does not match release_version {release_version}"
        ));
    }
    if evaluator_version != release_version {
        blockers.push(format!(
            "release_evaluator_version {evaluator_version} does not match release_version {release_version}"
        ));
    }
    if evaluator_tag != release_tag {
        blockers.push(format!(
            "release_evaluator_tag {evaluator_tag} does not match release_tag {release_tag}"
        ));
    }
    if codex_version != release_version {
        blockers.push(format!(
            "codex_acceptance_version {codex_version} does not match release_version {release_version}"
        ));
    }
    if claude_version != release_version {
        blockers.push(format!(
            "claude_acceptance_version {claude_version} does not match release_version {release_version}"
        ));
    }

    serde_json::json!({
        "status": if blockers.is_empty() { "matched" } else { "mismatched" },
        "release_version": release_version,
        "release_tag": release_tag,
        "three_os_version": three_os_version,
        "release_evaluator_version": evaluator_version,
        "release_evaluator_tag": evaluator_tag,
        "codex_acceptance_version": codex_version,
        "claude_acceptance_version": claude_version,
        "blockers": blockers,
    })
}

fn phase1_status(
    checklist: &serde_json::Value,
    decision: &serde_json::Value,
    smoke: &serde_json::Value,
) -> &'static str {
    if checklist.get("value").is_some()
        && decision.get("value").is_some()
        && smoke
            .get("value")
            .map(|value| three_os_smoke_clean_status(value) == "passed")
            .unwrap_or(false)
    {
        "observed"
    } else {
        "incomplete"
    }
}

async fn provider_registry_signature_present(
    state: &AppState,
    surface: &serde_json::Value,
) -> bool {
    let Some(sha) = json_str(surface, "sha256") else {
        return false;
    };
    state
        .storage
        .bundles
        .exists(BundleKind::ProviderRegistrySignature, sha)
        .await
}

async fn phase1_decision_signature_present(state: &AppState, surface: &serde_json::Value) -> bool {
    let Some(sha) = json_str(surface, "sha256") else {
        return false;
    };
    state
        .storage
        .bundles
        .exists(BundleKind::Phase1PromotionDecisionSignature, sha)
        .await
}

async fn acceptance_surface(state: &AppState) -> Result<serde_json::Value, AppError> {
    let entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut latest_codex = None::<IndexEntry>;
    let mut latest_claude = None::<IndexEntry>;
    let mut latest_antigravity = None::<IndexEntry>;
    let mut total = 0usize;
    for entry in &entries {
        if entry.schema != CODEX_ACCEPTANCE_SCHEMA
            && entry.schema != CLAUDE_ACCEPTANCE_SCHEMA
            && entry.schema != ANTIGRAVITY_ACCEPTANCE_SCHEMA
        {
            continue;
        }
        total += 1;
        match entry.provider.as_deref() {
            Some("codex")
                if latest_codex
                    .as_ref()
                    .map(|latest| entry.ingested_at > latest.ingested_at)
                    .unwrap_or(true) =>
            {
                latest_codex = Some(entry.clone());
            }
            Some("claude")
                if latest_claude
                    .as_ref()
                    .map(|latest| entry.ingested_at > latest.ingested_at)
                    .unwrap_or(true) =>
            {
                latest_claude = Some(entry.clone());
            }
            Some("antigravity")
                if latest_antigravity
                    .as_ref()
                    .map(|latest| entry.ingested_at > latest.ingested_at)
                    .unwrap_or(true) =>
            {
                latest_antigravity = Some(entry.clone());
            }
            _ => {}
        }
    }
    let latest_codex = match latest_codex.as_ref() {
        Some(entry) => acceptance_entry_summary(state, entry).await?,
        None => serde_json::Value::Null,
    };
    let latest_claude = match latest_claude.as_ref() {
        Some(entry) => acceptance_entry_summary(state, entry).await?,
        None => serde_json::Value::Null,
    };
    let latest_antigravity = match latest_antigravity.as_ref() {
        Some(entry) => acceptance_entry_summary(state, entry).await?,
        None => serde_json::Value::Null,
    };
    Ok(serde_json::json!({
        "status": if total > 0 { "observed" } else { "missing" },
        "total_count": total,
        "latest_codex": latest_codex,
        "latest_claude": latest_claude,
        "latest_antigravity": latest_antigravity,
        "latest_by_provider": {
            "codex": latest_codex,
            "claude": latest_claude,
            "antigravity": latest_antigravity,
        },
        "links": {
            "dashboard": "/api/v1/acceptance/dashboard",
            "dashboard_json": "/api/v1/acceptance/dashboard.json",
        },
    }))
}

async fn acceptance_entry_summary(
    state: &AppState,
    entry: &IndexEntry,
) -> Result<serde_json::Value, AppError> {
    let bundle = read_acceptance_value(state, entry).await?;
    Ok(serde_json::json!({
        "sha256": entry.sha256,
        "status": entry.status.as_deref().unwrap_or("observed"),
        "ingested_at": entry.ingested_at,
        "provider": entry.provider.as_deref().unwrap_or("unknown"),
        "schema_version": entry.schema,
        "source_class": acceptance_source_class(&bundle),
        "run_id": json_str(&bundle, "run_id").unwrap_or("unknown"),
        "score": acceptance_score(&bundle),
        "minimum_score": bundle
            .get("smoke")
            .and_then(|smoke| smoke.get("minimum_score"))
            .and_then(serde_json::Value::as_u64),
        "release_candidate_version": acceptance_release_candidate_version(&bundle),
        "evidence_pack": json_str(&bundle, "evidence_pack").unwrap_or(""),
        "raw_url": format!("/api/v1/acceptance/{}", entry.sha256),
    }))
}

async fn read_acceptance_value(
    state: &AppState,
    entry: &IndexEntry,
) -> Result<serde_json::Value, AppError> {
    let kind = match entry.schema.as_str() {
        CODEX_ACCEPTANCE_SCHEMA => BundleKind::AcceptanceCodex,
        CLAUDE_ACCEPTANCE_SCHEMA => BundleKind::AcceptanceClaude,
        ANTIGRAVITY_ACCEPTANCE_SCHEMA => BundleKind::AcceptanceAntigravity,
        _ => return Err(AppError::NotFound),
    };
    let bytes = state
        .storage
        .bundles
        .read(kind, &entry.sha256)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
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

fn acceptance_release_candidate_version(bundle: &serde_json::Value) -> String {
    for key in ["release_candidate_version", "candidate_version", "version"] {
        if let Some(version) = json_str(bundle, key) {
            return normalize_release_version(version);
        }
    }
    for key in ["root", "target", "evidence_pack"] {
        if let Some(version) = json_str(bundle, key).and_then(provider_acceptance_version_from_path)
        {
            return version;
        }
    }
    "unknown".to_string()
}

fn provider_acceptance_version_from_path(value: &str) -> Option<String> {
    let normalized = value.replace('\\', "/");
    let marker = "/target/provider-pilot-acceptance/";
    let offset = normalized.find(marker)? + marker.len();
    let candidate = normalized[offset..].split('/').next()?.trim();
    if candidate.is_empty() || candidate.starts_with('<') {
        return None;
    }
    Some(normalize_release_version(candidate))
}

fn normalize_release_version(version: &str) -> String {
    version.trim().trim_start_matches('v').to_string()
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

async fn read_release_publication_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ReleasePublication, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

async fn get_release_publication_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ReleasePublication, sha)
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

fn validate_release_publication(publication: &serde_json::Value) -> Result<(), AppError> {
    let schema = publication
        .get("schema")
        .or_else(|| publication.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != RELEASE_PUBLICATION_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {RELEASE_PUBLICATION_SCHEMA}, got {schema}"
        )));
    }
    for key in ["version", "release_tag", "status", "release_url"] {
        if publication
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "release publication missing {key}"
            )));
        }
    }
    let verification = publication
        .get("verification")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::SchemaInvalid("release publication missing verification".into())
        })?;
    for key in [
        "release_ship",
        "release_download_verify",
        "release_doctor_status",
        "rollback_status",
        "three_os_smoke",
    ] {
        if verification
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "release publication verification missing {key}"
            )));
        }
    }
    for key in ["provenance_verified", "provenance_tag_matches"] {
        if verification
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "release publication verification missing {key}"
            )));
        }
    }
    let archives = publication
        .get("archives")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AppError::SchemaInvalid("release publication missing archives".into()))?;
    if archives.is_empty() {
        return Err(AppError::SchemaInvalid(
            "release publication archives must not be empty".into(),
        ));
    }
    for archive in archives {
        for key in ["target", "path", "sha256"] {
            if archive
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .is_none()
            {
                return Err(AppError::SchemaInvalid(format!(
                    "release publication archive missing {key}"
                )));
            }
        }
    }
    Ok(())
}

fn trust_boundary() -> serde_json::Value {
    serde_json::json!({
        "frontend": "Hermes front end / queue / memory surface",
        "governed_backend": "AO2 governed evaluator-closer",
        "trusted_execution": "ao2 signed evidence boundary",
        "role": "read_only_observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "release_acceptance_owner": "factory-v3 evaluator-closer",
    })
}

fn release_publication_links() -> serde_json::Value {
    serde_json::json!({
        "dashboard": "/api/v1/release/publication/dashboard",
        "dashboard_json": "/api/v1/release/publication/dashboard.json",
        "latest_release_publication": "/api/v1/release/publication/latest",
        "phase1_promotion_dashboard": "/api/v1/phase1/promotion/dashboard",
        "storage_dashboard": "/api/v1/storage/dashboard",
    })
}

fn release_cockpit_links() -> serde_json::Value {
    serde_json::json!({
        "cockpit": "/api/v1/release/cockpit",
        "cockpit_json": "/api/v1/release/cockpit.json",
        "release_candidate_handoff": "/api/v1/release/handoff",
        "release_candidate_handoff_json": "/api/v1/release/handoff.json",
        "release_publication_dashboard": "/api/v1/release/publication/dashboard",
        "release_publication_dashboard_json": "/api/v1/release/publication/dashboard.json",
        "release_evaluator_decision_dashboard": "/api/v1/release/evaluator-decision/dashboard",
        "release_evaluator_decision_dashboard_json": "/api/v1/release/evaluator-decision/dashboard.json",
        "phase1_operator_panel": "/api/v1/phase1/promotion/operator-panel",
        "phase1_operator_panel_json": "/api/v1/phase1/promotion/operator-panel.json",
        "phase1_dashboard_json": "/api/v1/phase1/promotion/dashboard.json",
        "provider_registry_dashboard": "/api/v1/provider/registry/dashboard",
        "provider_registry_dashboard_json": "/api/v1/provider/registry/dashboard.json",
        "provider_readiness_dashboard": "/api/v1/provider/readiness/dashboard",
        "provider_readiness_dashboard_json": "/api/v1/provider/readiness/dashboard.json",
        "acceptance_dashboard": "/api/v1/acceptance/dashboard",
        "acceptance_dashboard_json": "/api/v1/acceptance/dashboard.json",
        "storage_dashboard": "/api/v1/storage/dashboard",
        "storage_support_bundle_json": "/api/v1/storage/support-bundle.json",
    })
}

fn provider_acceptance_is_live_passed(entry: &serde_json::Value) -> bool {
    json_str(entry, "status") == Some("passed") && json_str(entry, "source_class") == Some("live")
}

fn compact_acceptance_for_handoff(entry: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "provider": json_str(entry, "provider").unwrap_or("unknown"),
        "status": json_str(entry, "status").unwrap_or("missing"),
        "source_class": json_str(entry, "source_class").unwrap_or("missing"),
        "release_candidate_version": json_str(entry, "release_candidate_version").unwrap_or("unknown"),
        "run_id": json_str(entry, "run_id").unwrap_or("missing"),
        "score": entry.get("score").cloned().unwrap_or(serde_json::Value::Null),
        "sha256": json_str(entry, "sha256").unwrap_or("missing"),
        "raw_url": json_str(entry, "raw_url").unwrap_or(""),
    })
}

fn raw_url(base: &str, sha: &str) -> String {
    if sha == "missing" {
        "missing".to_string()
    } else {
        format!("{base}/{sha}")
    }
}

fn validate_sha(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::evaluator_decision::{
        decode_release_evaluator_signature_hex, verify_release_evaluator_rsa_sha256_signature,
    };
    use super::support_bundle::{support_bundle_surface_by_id, support_bundle_surface_path_by_id};
    use super::*;

    fn minimal_surface(schema: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": schema,
            "status": "ready",
        })
    }

    fn test_support_bundle() -> serde_json::Value {
        let mut bundle = serde_json::json!({
            "schema_version": RELEASE_SUPPORT_BUNDLE_SCHEMA,
            "generated_at": "2026-01-01T00:00:00Z",
            "release_assembly": minimal_surface(RELEASE_ASSEMBLY_SCHEMA),
            "readiness": minimal_surface(RELEASE_READINESS_SCHEMA),
            "handoff": minimal_surface(RELEASE_CANDIDATE_HANDOFF_SCHEMA),
            "cockpit": minimal_surface(RELEASE_COCKPIT_SCHEMA),
            "evaluator_decision": minimal_surface(RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA),
            "install_verification": {
                "schema_version": "ao2.install-verification-evidence.v1",
                "status": "verified",
                "offline_verification_status": "verified",
                "path": "target/release-archive-hosted-smoke/install-verification.json",
                "sha256": "abc123",
                "provider_api_keys_required": false,
                "control_plane_approves_release": false,
                "mutates_ao_artifacts": false,
            },
            "hosted_release_smoke": {
                "schema_version": "ao2.release-archive-hosted-smoke.v1",
                "status": "passed",
                "target": "release-archive-hosted-smoke",
                "install_verification_schema": "ao2.install-verification-evidence.v1",
                "install_verification_evidence": "target/release-archive-hosted-smoke/install-verification.json",
                "provider_api_keys_required": false,
                "control_plane_approves_release": false,
                "mutates_ao_artifacts": false,
                "release_acceptance_owner": "factory-v3 evaluator-closer",
            },
            "ci_evidence_index": minimal_surface("ao2.cp-ci-evidence-index.v1"),
            "storage_support": minimal_surface("ao2.cp-support-bundle.v1"),
            "trust_boundary": trust_boundary(),
        });
        let included = SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS
            .iter()
            .map(|id| {
                let surface = support_bundle_surface_by_id(&bundle, id).unwrap();
                serde_json::json!({
                    "id": id,
                    "schema_version": surface.get("schema_version").unwrap().as_str().unwrap(),
                    "path": support_bundle_surface_path_by_id(id).unwrap(),
                    "sha256": support_bundle_surface_sha256(surface).unwrap(),
                })
            })
            .collect::<Vec<_>>();
        let mut surface_sha256 = serde_json::Map::new();
        for id in SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS {
            surface_sha256.insert(
                id.to_string(),
                serde_json::Value::String(
                    support_bundle_surface_sha256(
                        support_bundle_surface_by_id(&bundle, id).unwrap(),
                    )
                    .unwrap(),
                ),
            );
        }
        bundle["portable_bundle_manifest"] = serde_json::json!({
            "schema_version": RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA,
            "included_surfaces": included,
            "integrity": {
                "surface_sha256": surface_sha256,
                "verification_plan": {
                    "surface_count": SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len(),
                }
            }
        });
        bundle
    }

    // --- signature verify-path panic-safety regression tests ---
    //
    // The release-evaluator decision verify path consumes attacker-influenced
    // input (the `signature_hex` and `public_key_pem` fields of an ingested
    // artifact). These tests pin the invariant that every malformed shape is
    // surfaced as an `AppError`, never a panic, so a crafted artifact cannot
    // take the read-only observer down. They also round-trip a real RSA-SHA256
    // signature to prove the happy path still verifies.

    fn rsa_keypair_pem_and_signer() -> (String, rsa::pkcs1v15::SigningKey<sha2::Sha256>) {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};
        use rsa::RsaPrivateKey;
        let mut rng = rsa::rand_core::OsRng;
        let signing_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public_key_pem = signing_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode test public key");
        (
            public_key_pem,
            rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(signing_key),
        )
    }

    #[test]
    fn decode_signature_hex_rejects_malformed_input_without_panicking() {
        // Odd length.
        assert!(decode_release_evaluator_signature_hex("abc").is_err());
        // Non-hex characters at even length.
        assert!(decode_release_evaluator_signature_hex("zz").is_err());
        // Empty string decodes to empty bytes (no panic, no error).
        assert_eq!(
            decode_release_evaluator_signature_hex("").expect("empty is valid"),
            Vec::<u8>::new()
        );
        // Well-formed hex round-trips.
        assert_eq!(
            decode_release_evaluator_signature_hex("00ff10").expect("valid hex"),
            vec![0x00, 0xff, 0x10]
        );
    }

    #[test]
    fn verify_signature_round_trips_for_a_valid_signature() {
        use signature::{SignatureEncoding, Signer};
        let (public_key_pem, signer) = rsa_keypair_pem_and_signer();
        let message = b"release evaluator decision canonical bytes";
        let signature = signer.sign(message).to_vec();
        assert!(verify_release_evaluator_rsa_sha256_signature(
            message,
            &signature,
            &public_key_pem,
        )
        .is_ok());
    }

    #[test]
    fn verify_signature_rejects_tampered_message_and_garbage_without_panicking() {
        use signature::{SignatureEncoding, Signer};
        let (public_key_pem, signer) = rsa_keypair_pem_and_signer();
        let signature = signer.sign(b"original message").to_vec();

        // A valid signature over different bytes must fail to verify, not panic.
        assert!(verify_release_evaluator_rsa_sha256_signature(
            b"tampered message",
            &signature,
            &public_key_pem,
        )
        .is_err());

        // Garbage signature bytes (wrong length for the modulus) must error.
        assert!(verify_release_evaluator_rsa_sha256_signature(
            b"original message",
            &[0u8; 7],
            &public_key_pem,
        )
        .is_err());

        // Empty signature bytes must error rather than panic.
        assert!(verify_release_evaluator_rsa_sha256_signature(
            b"original message",
            &[],
            &public_key_pem,
        )
        .is_err());
    }

    #[test]
    fn verify_signature_rejects_invalid_public_key_pem_without_panicking() {
        // Not a PEM at all.
        assert!(verify_release_evaluator_rsa_sha256_signature(
            b"message",
            &[0u8; 256],
            "not a pem",
        )
        .is_err());
        // Empty PEM.
        assert!(
            verify_release_evaluator_rsa_sha256_signature(b"message", &[0u8; 256], "").is_err()
        );
        // PEM-shaped but bogus body.
        let bogus = "-----BEGIN PUBLIC KEY-----\nnotbase64!!!\n-----END PUBLIC KEY-----\n";
        assert!(
            verify_release_evaluator_rsa_sha256_signature(b"message", &[0u8; 256], bogus).is_err()
        );
    }

    #[test]
    fn release_readiness_and_assembly_explain_candidate_correlation_blockers() {
        let readiness = serde_json::json!({
            "schema_version": RELEASE_READINESS_SCHEMA,
            "status": "attention",
        });
        let handoff = serde_json::json!({
            "schema_version": RELEASE_CANDIDATE_HANDOFF_SCHEMA,
            "status": "attention",
            "release": {
                "version": "v0.4.80",
                "release_tag": "v0.4.80",
            },
            "candidate_correlation": {
                "status": "mismatched",
                "release_version": "v0.4.80",
                "three_os_version": "v0.4.79",
                "blockers": [
                    "three_os_release_candidate_version v0.4.79 does not match release_version v0.4.80"
                ],
            },
        });

        let gate = release_readiness_gate_with_detail(
            "candidate_correlation",
            "Candidate Correlation",
            "mismatched",
            "matched",
            handoff.get("candidate_correlation"),
        );
        assert_eq!(gate["status"], "blocked");
        assert_eq!(
            gate["detail"]["blockers"][0],
            "three_os_release_candidate_version v0.4.79 does not match release_version v0.4.80"
        );
        assert_eq!(
            gate["next_action"],
            "republish same-candidate release, evaluator, provider acceptance, and three-OS evidence before factory-v3 evaluator-closer review"
        );

        let assembly = release_assembly_value(&readiness, &handoff);
        assert_eq!(assembly["status"], "attention");
        let assembly_blockers = assembly["assembly_blockers"].as_array().unwrap();
        assert!(assembly_blockers.iter().any(|blocker| blocker
            == "candidate_correlation: three_os_release_candidate_version v0.4.79 does not match release_version v0.4.80"));
        assert_eq!(
            assembly["next_action"],
            "republish same-candidate release, evaluator, provider acceptance, and three-OS evidence before factory-v3 evaluator-closer review"
        );
    }

    #[test]
    fn support_bundle_verification_requires_exact_surface_set() {
        let bundle = test_support_bundle();
        let verification = release_support_bundle_verification_value(&bundle).unwrap();
        assert_eq!(verification["status"], "passed");
        assert_eq!(
            verification["surface_count"],
            SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len()
        );

        let mut missing = bundle.clone();
        missing["portable_bundle_manifest"]["included_surfaces"]
            .as_array_mut()
            .unwrap()
            .retain(|surface| surface["id"] != "release_evaluator_decision");
        let verification = release_support_bundle_verification_value(&missing).unwrap();
        assert_eq!(verification["status"], "failed");
        assert!(verification["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| {
                blocker
                    .as_str()
                    .unwrap()
                    .contains("release_evaluator_decision: missing required support-bundle surface")
            }));

        let mut unknown = bundle.clone();
        unknown["portable_bundle_manifest"]["included_surfaces"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "unexpected_surface",
                "schema_version": "unexpected.v1",
                "path": "$.unexpected",
                "sha256": "missing",
            }));
        let verification = release_support_bundle_verification_value(&unknown).unwrap();
        assert_eq!(verification["status"], "failed");
        assert!(verification["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| {
                blocker
                    .as_str()
                    .unwrap()
                    .contains("unexpected_surface: unknown support-bundle surface id")
            }));

        let mut duplicate = bundle.clone();
        let first = duplicate["portable_bundle_manifest"]["included_surfaces"][0].clone();
        duplicate["portable_bundle_manifest"]["included_surfaces"]
            .as_array_mut()
            .unwrap()
            .push(first);
        let verification = release_support_bundle_verification_value(&duplicate).unwrap();
        assert_eq!(verification["status"], "failed");
        assert!(verification["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| {
                blocker
                    .as_str()
                    .unwrap()
                    .contains("ci_evidence_index: duplicate support-bundle surface id")
            }));
    }

    #[test]
    fn support_bundle_verification_requires_declared_surface_count() {
        let mut bundle = test_support_bundle();
        bundle["portable_bundle_manifest"]["integrity"]["verification_plan"]["surface_count"] =
            serde_json::json!(5);
        let verification = release_support_bundle_verification_value(&bundle).unwrap();
        assert_eq!(verification["status"], "failed");
        assert!(verification["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| {
                blocker.as_str().unwrap().contains(&format!(
                    "verification_plan.surface_count: expected {}, found 5",
                    SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len()
                ))
            }));
    }
}
