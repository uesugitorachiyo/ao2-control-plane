use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_schema::responses::{BundleListEntry, BundleListResponse, IngestReceipt};
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;
use crate::signing::{annotate_trust_policy, sha256_hex, verify_rsa_sha256_signature};

const EVIDENCE_PACK_SCHEMA: &str = "ao2.evidence-pack.v1";
const SIGNED_UPLOAD_SCHEMA: &str = "ao2.cp-evidence-pack-signed-upload.v1";
const SIGNATURE_SCHEMA: &str = "ao2.cp-evidence-pack-signature.v1";
const EVIDENCE_PACK_LIST_SCHEMA: &str = "ao2.cp-evidence-pack-list.v1";
const EVIDENCE_PACK_DETAIL_SCHEMA: &str = "ao2.cp-evidence-pack-detail.v1";
const EVIDENCE_PACK_DASHBOARD_SCHEMA: &str = "ao2.cp-evidence-pack-dashboard.v1";

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

#[derive(Debug, Default, Deserialize)]
pub struct EvidencePackDashboardQuery {
    #[serde(default)]
    gate: Option<String>,
    #[serde(default)]
    view: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    signer_id: Option<String>,
    #[serde(default)]
    since: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    until: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EvidencePackDetailQuery {
    #[serde(default)]
    workbench_url: Option<String>,
    #[serde(default)]
    release_gate_artifact: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignedEvidencePackUpload {
    schema_version: String,
    evidence_pack: serde_json::Value,
    /// Base64 of the producer's exact signed bytes. When present the signature is
    /// verified over these bytes verbatim; when absent (legacy producers) the server
    /// falls back to re-serializing `evidence_pack`, which can fail-close on lossy
    /// round-trips.
    #[serde(default)]
    evidence_pack_b64: Option<String>,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SignatureSidecar {
    schema_version: String,
    evidence_pack_sha256: String,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct EvidencePackDashboardResponse {
    schema_version: String,
    view: String,
    view_label: String,
    gate: String,
    filters: EvidencePackDashboardFilters,
    presets: Vec<EvidencePackDashboardPreset>,
    summary: EvidencePackDashboardSummary,
    entry_count: usize,
    entries: Vec<EvidencePackDashboardEntry>,
}

#[derive(Debug, Serialize)]
pub struct EvidencePackDashboardSummary {
    total_entries: usize,
    gate_attention_count: usize,
    run_health_attention_count: usize,
    repair_source_count: usize,
    signature_unverified_count: usize,
    verdict_counts: BTreeMap<String, usize>,
    read_only_observer: bool,
}

#[derive(Debug, Serialize)]
pub struct EvidencePackDashboardPreset {
    id: String,
    label: String,
    dashboard_url: String,
    dashboard_json_url: String,
    bookmark_url: String,
    download_filename: String,
}

#[derive(Debug, Serialize)]
pub struct EvidencePackDashboardFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct EvidencePackDashboardEntry {
    sha256: String,
    run_id: String,
    verdict: String,
    signer_id: String,
    signature_verified: bool,
    signature_label: String,
    gate_attention: bool,
    gate_label: String,
    run_health: serde_json::Value,
    repair_source: serde_json::Value,
    size_bytes: u64,
    ingested_at: chrono::DateTime<Utc>,
    detail_url: String,
    signature_url: String,
}

pub async fn post_signed_evidence_pack(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<IngestReceipt>, AppError> {
    if body.len() > state.max_body_bytes {
        return Err(AppError::BodyTooLarge);
    }
    let upload: SignedEvidencePackUpload =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version != SIGNED_UPLOAD_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNED_UPLOAD_SCHEMA}, got {}",
            upload.schema_version
        )));
    }
    // Recover the exact bytes the producer signed. With `evidence_pack_b64` we verify
    // over those bytes verbatim, so a lossy serde_json round-trip (whitespace reflow,
    // float re-formatting) can no longer fail-close an untampered upload. Legacy
    // producers omit it; fall back to re-serializing `evidence_pack` (byte-identical
    // to prior behavior).
    let signed_bytes = match &upload.evidence_pack_b64 {
        Some(encoded) => decode_evidence_pack_b64(encoded)?,
        None => serde_json::to_string_pretty(&upload.evidence_pack)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .into_bytes(),
    };
    let mut signature = upload.signature;
    // Verify before parsing or trusting any structure derived from the bytes.
    verify_signed_evidence_pack(&signed_bytes, &signature)?;
    let evidence_raw = std::str::from_utf8(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(format!("signed evidence pack is not utf-8: {e}")))?;
    let evidence_pack: serde_json::Value = serde_json::from_slice(&signed_bytes)
        .map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = evidence_pack
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != EVIDENCE_PACK_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {EVIDENCE_PACK_SCHEMA}, got {schema}"
        )));
    }
    let sha = sha256_of_canonical(&evidence_pack).map_err(|e| AppError::Internal(e.to_string()))?;
    annotate_trust_policy(&mut signature, &state.signed_artifact_trusted_key_sha256s);

    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePack, &sha)
        .await
    {
        state
            .storage
            .bundles
            .write(BundleKind::EvidencePack, &sha, evidence_raw.as_bytes())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let sidecar = SignatureSidecar {
        schema_version: SIGNATURE_SCHEMA.to_string(),
        evidence_pack_sha256: sha.clone(),
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
        .exists(BundleKind::EvidencePackSignature, &sha)
        .await
    {
        let existing = state
            .storage
            .bundles
            .read(BundleKind::EvidencePackSignature, &sha)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if existing != sidecar_raw {
            return Err(AppError::SchemaInvalid(
                "evidence pack signature sidecar already exists for this sha with different provenance"
                    .to_string(),
            ));
        }
    } else {
        state
            .storage
            .bundles
            .write(BundleKind::EvidencePackSignature, &sha, &sidecar_raw)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let status = evidence_pack
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let entry = IndexEntry {
        ingested_at: Utc::now(),
        schema: EVIDENCE_PACK_SCHEMA.to_string(),
        provider: None,
        sha256: sha.clone(),
        status,
        size_bytes: evidence_raw.len() as u64,
    };
    state
        .storage
        .index
        .append_if_absent(entry)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(IngestReceipt::new(
        sha,
        EVIDENCE_PACK_SCHEMA.to_string(),
    )))
}

fn verify_signed_evidence_pack(
    signed_bytes: &[u8],
    signature: &serde_json::Value,
) -> Result<(), AppError> {
    let schema = signature
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported evidence pack signature algorithm: {algorithm}"
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

    verify_rsa_sha256_signature(signed_bytes, &signature_bytes, public_key_pem)
}

fn required_signature_string<'a>(
    signature: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AppError> {
    signature
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::SchemaInvalid(format!("signed evidence pack missing {field}")))
}

fn decode_evidence_pack_b64(encoded: &str) -> Result<Vec<u8>, AppError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| AppError::SchemaInvalid(format!("evidence_pack_b64 is not valid base64: {e}")))
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

pub async fn list_evidence_packs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BundleListResponse>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == EVIDENCE_PACK_SCHEMA);
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
        schema_version: EVIDENCE_PACK_LIST_SCHEMA.to_string(),
        total_count,
        limit,
        offset: q.offset,
        entries,
    }))
}

pub async fn evidence_pack_dashboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EvidencePackDashboardQuery>,
) -> Result<Response, AppError> {
    let dashboard = evidence_pack_dashboard_response(&state, &query).await?;
    let mut rows = String::new();
    for entry in &dashboard.entries {
        let repair_source = json_str(&entry.repair_source, "source_run_id").unwrap_or("none");
        rows.push_str(&format!(
            "<tr><td><a href=\"/api/v1/evidence-pack/{sha}/detail\"><code>{short_sha}</code></a></td><td>{run_id}</td><td>{verdict}</td><td>{signer_id}</td><td>{verification_label}</td><td>{gate_label}</td><td>{run_health}</td><td>{repair_source}</td><td>{size}</td><td>{ingested}</td><td><a href=\"/api/v1/evidence-pack/{sha}/signature\">signature</a></td></tr>",
            sha = escape_html(&entry.sha256),
            short_sha = escape_html(&entry.sha256[..12]),
            run_id = escape_html(&entry.run_id),
            verdict = escape_html(&entry.verdict),
            signer_id = escape_html(&entry.signer_id),
            verification_label = escape_html(&entry.signature_label),
            gate_label = escape_html(&entry.gate_label),
            run_health = escape_html(json_str(&entry.run_health, "repair_status").unwrap_or("unknown")),
            repair_source = escape_html(repair_source),
            size = entry.size_bytes,
            ingested = escape_html(&entry.ingested_at.to_rfc3339())
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"11\">No signed AO2 evidence packs match this filter.</td></tr>",
        );
    }
    let all_selected = if dashboard.gate == "all" {
        " selected"
    } else {
        ""
    };
    let attention_selected = if dashboard.gate == "attention" || dashboard.view == "gate_attention"
    {
        " selected"
    } else {
        ""
    };
    let run_id_value = query.run_id.as_deref().unwrap_or_default();
    let signer_id_value = query.signer_id.as_deref().unwrap_or_default();
    let since_value = query
        .since
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    let until_value = query
        .until
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    let view_label = dashboard.view_label;
    let preset_links = dashboard
        .presets
        .iter()
        .map(|preset| {
            format!(
                "<a href=\"{}\">{}</a><a href=\"{}\" download=\"{}\">JSON</a>",
                escape_html(&preset.dashboard_url),
                escape_html(&preset.label),
                escape_html(&preset.dashboard_json_url),
                escape_html(&preset.download_filename)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let preset_bookmarks = dashboard
        .presets
        .iter()
        .map(|preset| {
            format!(
                "{} HTML: {}\n{} JSON: {}",
                preset.label, preset.bookmark_url, preset.label, preset.dashboard_json_url
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let verdict_counts = if dashboard.summary.verdict_counts.is_empty() {
        "none".to_string()
    } else {
        dashboard
            .summary
            .verdict_counts
            .iter()
            .map(|(verdict, count)| format!("{}: {}", escape_html(verdict), count))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Signed Evidence Packs</title><style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace}}form,.saved-views{{margin:1rem 0;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}}.saved-views a{{border:1px solid #ddd;border-radius:6px;padding:.35rem .55rem;text-decoration:none}}input{{min-width:14rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;border:1px solid #ddd;border-radius:6px;padding:.75rem}}</style></head><body><main><h1>AO2 Signed Evidence Packs</h1><p>Read-only observer dashboard. Verification here never approves, mutates, or closes AO2 runs.</p><nav class=\"saved-views\" aria-label=\"Saved Views\"><strong>Saved Views</strong>{preset_links}</nav><details><summary>Preset Bookmarks</summary><pre>{preset_bookmarks}</pre></details><p>Current view: <strong>{view_label}</strong></p><form method=\"get\"><label for=\"gate\">Gate Filter</label><select id=\"gate\" name=\"gate\"><option value=\"all\"{all_selected}>All signed packs</option><option value=\"attention\"{attention_selected}>Needs obligation-gate attention</option></select><label for=\"run_id\">Run ID</label><input id=\"run_id\" name=\"run_id\" value=\"{run_id_value}\"><label for=\"signer_id\">Signer</label><input id=\"signer_id\" name=\"signer_id\" value=\"{signer_id_value}\"><label for=\"since\">Since</label><input id=\"since\" name=\"since\" value=\"{since_value}\" placeholder=\"2026-05-21T00:00:00Z\"><label for=\"until\">Until</label><input id=\"until\" name=\"until\" value=\"{until_value}\" placeholder=\"2026-05-22T00:00:00Z\"><button type=\"submit\">Apply</button><a href=\"/api/v1/evidence-pack/dashboard\">Clear</a></form><section aria-label=\"Summary\"><h2>Summary</h2><dl><dt>Total entries</dt><dd>{summary_total}</dd><dt>Gate attention</dt><dd>{summary_gate_attention}</dd><dt>Run health attention</dt><dd>{summary_run_health_attention}</dd><dt>Repair-source runs</dt><dd>{summary_repair_source}</dd><dt>Unverified signatures</dt><dd>{summary_signature_unverified}</dd><dt>Verdict counts</dt><dd>{verdict_counts}</dd></dl></section><table><thead><tr><th>SHA256</th><th>Run</th><th>Verdict</th><th>Signer</th><th>Signature</th><th>Gate</th><th>Run Health</th><th>Repair Source</th><th>Bytes</th><th>Ingested</th><th>Sidecar</th></tr></thead><tbody>{rows}</tbody></table></main></body></html>",
        preset_links = preset_links,
        preset_bookmarks = escape_html(&preset_bookmarks),
        run_id_value = escape_html(run_id_value),
        signer_id_value = escape_html(signer_id_value),
        since_value = escape_html(&since_value),
        until_value = escape_html(&until_value),
        summary_total = dashboard.summary.total_entries,
        summary_gate_attention = dashboard.summary.gate_attention_count,
        summary_run_health_attention = dashboard.summary.run_health_attention_count,
        summary_repair_source = dashboard.summary.repair_source_count,
        summary_signature_unverified = dashboard.summary.signature_unverified_count,
        verdict_counts = verdict_counts
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn evidence_pack_dashboard_json(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EvidencePackDashboardQuery>,
) -> Result<Json<EvidencePackDashboardResponse>, AppError> {
    Ok(Json(
        evidence_pack_dashboard_response(&state, &query).await?,
    ))
}

async fn evidence_pack_dashboard_response(
    state: &AppState,
    query: &EvidencePackDashboardQuery,
) -> Result<EvidencePackDashboardResponse, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == EVIDENCE_PACK_SCHEMA);
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));

    let view = query.view.as_deref().unwrap_or("all").to_string();
    let gate = query.gate.as_deref().unwrap_or("all").to_string();
    let attention_only = gate == "attention" || view == "gate_attention";
    let view_label = match view.as_str() {
        "gate_attention" => "Gate Attention",
        "signature_unverified" => "Unverified Signatures",
        "verdict_failed" => "Failed Verdicts",
        _ if attention_only => "Gate Attention",
        _ => "All Signed Packs",
    }
    .to_string();
    let mut entries = Vec::new();

    for entry in all {
        if query.since.is_some_and(|since| entry.ingested_at < since) {
            continue;
        }
        if query.until.is_some_and(|until| entry.ingested_at > until) {
            continue;
        }
        let evidence = read_json_bundle(state, BundleKind::EvidencePack, &entry.sha256).await?;
        let actual =
            sha256_of_canonical(&evidence).map_err(|e| AppError::Internal(e.to_string()))?;
        if actual != entry.sha256 {
            return Err(AppError::BundleTampered {
                expected: entry.sha256,
                actual,
            });
        }
        let signature = read_signature_sidecar(state, &entry.sha256).await.ok();
        let run_id = json_str(&evidence, "run_id")
            .unwrap_or("unknown")
            .to_string();
        let verdict = entry
            .status
            .as_deref()
            .unwrap_or_else(|| json_str(&evidence, "verdict").unwrap_or("unknown"))
            .to_string();
        let signer_id = signature
            .as_ref()
            .and_then(|sidecar| sidecar.get("signature"))
            .and_then(|sig| json_str(sig, "signer_id"))
            .unwrap_or("unknown")
            .to_string();
        if query
            .run_id
            .as_deref()
            .is_some_and(|filter| filter != run_id)
        {
            continue;
        }
        if query
            .signer_id
            .as_deref()
            .is_some_and(|filter| filter != signer_id)
        {
            continue;
        }
        let signature_verified = signature
            .as_ref()
            .and_then(|sidecar| sidecar.get("signature"))
            .and_then(|sig| sig.get("signature_verified"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let obligation_gates = obligation_gate_summary_value(&evidence);
        let gate_attention = obligation_gates_need_attention(&obligation_gates);
        let run_health = run_health_summary_value(&evidence);
        let repair_source = repair_source_summary_value(&evidence);
        let include_row = match view.as_str() {
            "signature_unverified" => !signature_verified,
            "verdict_failed" => verdict != "accepted",
            "gate_attention" => gate_attention,
            _ => !attention_only || gate_attention,
        };
        if !include_row {
            continue;
        }
        let signature_label = if signature_verified {
            "Verified"
        } else {
            "Unverified"
        }
        .to_string();
        let gate_label = if gate_attention {
            "Gate Attention"
        } else if obligation_gates
            .get("present")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            "Gate Clear"
        } else {
            "No Gate"
        }
        .to_string();
        entries.push(EvidencePackDashboardEntry {
            detail_url: format!("/api/v1/evidence-pack/{}/detail", entry.sha256),
            signature_url: format!("/api/v1/evidence-pack/{}/signature", entry.sha256),
            sha256: entry.sha256,
            run_id,
            verdict,
            signer_id,
            signature_verified,
            signature_label,
            gate_attention,
            gate_label,
            run_health,
            repair_source,
            size_bytes: entry.size_bytes,
            ingested_at: entry.ingested_at,
        });
    }

    let summary = evidence_pack_dashboard_summary(&entries);

    Ok(EvidencePackDashboardResponse {
        schema_version: EVIDENCE_PACK_DASHBOARD_SCHEMA.to_string(),
        view,
        view_label,
        gate,
        filters: EvidencePackDashboardFilters {
            run_id: query.run_id.clone(),
            signer_id: query.signer_id.clone(),
            since: query.since,
            until: query.until,
        },
        presets: evidence_pack_dashboard_presets(),
        summary,
        entry_count: entries.len(),
        entries,
    })
}

fn evidence_pack_dashboard_summary(
    entries: &[EvidencePackDashboardEntry],
) -> EvidencePackDashboardSummary {
    let mut verdict_counts = BTreeMap::new();
    let mut gate_attention_count = 0;
    let mut run_health_attention_count = 0;
    let mut repair_source_count = 0;
    let mut signature_unverified_count = 0;

    for entry in entries {
        *verdict_counts.entry(entry.verdict.clone()).or_insert(0) += 1;
        if entry.gate_attention {
            gate_attention_count += 1;
        }
        if entry
            .run_health
            .get("attention_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            run_health_attention_count += 1;
        }
        if entry
            .repair_source
            .get("present")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            repair_source_count += 1;
        }
        if !entry.signature_verified {
            signature_unverified_count += 1;
        }
    }

    EvidencePackDashboardSummary {
        total_entries: entries.len(),
        gate_attention_count,
        run_health_attention_count,
        repair_source_count,
        signature_unverified_count,
        verdict_counts,
        read_only_observer: true,
    }
}

fn evidence_pack_dashboard_presets() -> Vec<EvidencePackDashboardPreset> {
    [
        (
            "all_signed_packs",
            "All Signed Packs",
            "/api/v1/evidence-pack/dashboard",
            "/api/v1/evidence-pack/dashboard.json",
        ),
        (
            "gate_attention",
            "Gate Attention",
            "/api/v1/evidence-pack/dashboard?view=gate_attention",
            "/api/v1/evidence-pack/dashboard.json?view=gate_attention",
        ),
        (
            "signature_unverified",
            "Unverified Signatures",
            "/api/v1/evidence-pack/dashboard?view=signature_unverified",
            "/api/v1/evidence-pack/dashboard.json?view=signature_unverified",
        ),
        (
            "failed_verdicts",
            "Failed Verdicts",
            "/api/v1/evidence-pack/dashboard?view=verdict_failed",
            "/api/v1/evidence-pack/dashboard.json?view=verdict_failed",
        ),
    ]
    .into_iter()
    .map(
        |(id, label, dashboard_url, dashboard_json_url)| EvidencePackDashboardPreset {
            id: id.to_string(),
            label: label.to_string(),
            dashboard_url: dashboard_url.to_string(),
            dashboard_json_url: dashboard_json_url.to_string(),
            bookmark_url: dashboard_url.to_string(),
            download_filename: format!("{id}-dashboard.json"),
        },
    )
    .collect()
}

async fn read_json_bundle(
    state: &AppState,
    kind: BundleKind,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(kind, sha)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(serde_json::Value::as_str)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn obligation_gate_summary_value(evidence: &serde_json::Value) -> serde_json::Value {
    let mut gates = Vec::new();
    collect_obligation_gates(evidence, &mut gates);
    let summaries = gates
        .into_iter()
        .map(|gate| {
            serde_json::json!({
                "schema_version": "ao2.cp-obligation-gate-summary.v1",
                "stage": json_str(&gate, "stage").unwrap_or("unknown"),
                "status": json_str(&gate, "status").unwrap_or("unknown"),
                "verdict": json_str(&gate, "verdict").unwrap_or("unknown"),
                "summary": gate.get("summary").cloned().unwrap_or_else(|| serde_json::json!({})),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": "ao2.cp-obligation-gates.v1",
        "present": !summaries.is_empty(),
        "count": summaries.len(),
        "gates": summaries,
    })
}

fn obligation_gates_need_attention(summary: &serde_json::Value) -> bool {
    summary
        .get("gates")
        .and_then(serde_json::Value::as_array)
        .map(|gates| {
            gates.iter().any(|gate| {
                let counts = gate.get("summary").unwrap_or(&serde_json::Value::Null);
                json_str(gate, "status") != Some("passed")
                    || json_str(gate, "verdict") != Some("accepted")
                    || counts
                        .get("fail")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
                    || counts
                        .get("unverified")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
            })
        })
        .unwrap_or(false)
}

fn run_health_summary_value(evidence: &serde_json::Value) -> serde_json::Value {
    let Some(health) = evidence.get("run_health") else {
        return serde_json::json!({
            "schema_version": "ao2.cp-run-health-summary.v1",
            "present": false,
            "repair_status": "unknown",
            "attention_required": false,
            "next_action": "No AO2 run_health block was embedded in this evidence pack."
        });
    };
    serde_json::json!({
        "schema_version": "ao2.cp-run-health-summary.v1",
        "present": true,
        "repair_status": json_str(health, "repair_status").unwrap_or("unknown"),
        "attention_required": health
            .get("attention_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "next_action": json_str(health, "next_action").unwrap_or(""),
        "repair_attempt_count": health
            .get("repair_attempt_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "failed_repair_attempts": health
            .get("failed_repair_attempts")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "accepted_repair_attempts": health
            .get("accepted_repair_attempts")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    })
}

fn repair_source_summary_value(evidence: &serde_json::Value) -> serde_json::Value {
    let Some(source) = evidence
        .get("repair_source")
        .filter(|value| value.is_object())
    else {
        return serde_json::json!({
            "schema_version": "ao2.cp-repair-source-summary.v1",
            "present": false,
            "source_run_id": null,
            "source_verdict": null,
            "next_action": "No AO2 repair_source block was embedded in this evidence pack."
        });
    };
    serde_json::json!({
        "schema_version": "ao2.cp-repair-source-summary.v1",
        "present": true,
        "source_run_id": json_str(source, "source_run_id").unwrap_or("unknown"),
        "source_verdict": json_str(source, "source_verdict").unwrap_or("unknown"),
        "source_schema_version": json_str(source, "schema_version").unwrap_or("unknown"),
        "evidence_pack_path": json_str(source, "evidence_pack_path").unwrap_or(""),
        "unresolved_concern_count": source
            .get("unresolved_concerns")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        "evidence_ref_count": source
            .get("evidence_refs")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        "has_latest_verifier_output": source
            .get("latest_verifier_output")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "latest_verifier_output_digest": json_str(source, "latest_verifier_output_digest").unwrap_or(""),
    })
}

fn collect_obligation_gates(value: &serde_json::Value, gates: &mut Vec<serde_json::Value>) {
    if let Some(gate) = obligation_gate_from_value(value) {
        gates.push(gate);
        return;
    }
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_obligation_gates(item, gates);
            }
        }
        serde_json::Value::Object(object) => {
            for item in object.values() {
                collect_obligation_gates(item, gates);
            }
        }
        _ => {}
    }
}

fn obligation_gate_from_value(value: &serde_json::Value) -> Option<serde_json::Value> {
    if json_str(value, "schema_version") == Some("ao2.obligation-gate.v1") {
        return Some(value.clone());
    }
    if let Some(gate) = value.get("gate") {
        if json_str(gate, "schema_version") == Some("ao2.obligation-gate.v1") {
            return Some(gate.clone());
        }
    }
    if json_str(value, "export_kind") == Some("obligation-gate") {
        if let Some(gate) = value.pointer("/export/gate") {
            if json_str(gate, "schema_version") == Some("ao2.obligation-gate.v1") {
                return Some(gate.clone());
            }
        }
    }
    None
}

fn render_obligation_gates_html(summary: &serde_json::Value) -> String {
    let gates = summary
        .get("gates")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if gates.is_empty() {
        return "<section><h2>Obligation Gates</h2><p class=\"muted\">No obligation gate artifacts were found in this signed evidence pack.</p></section>".to_string();
    }
    let rows = gates
        .iter()
        .map(|gate| {
            let counts = gate.get("summary").unwrap_or(&serde_json::Value::Null);
            format!(
                "<tr><td>{stage}</td><td>{status}</td><td>{verdict}</td><td>pass={pass} fail={fail} unverified={unverified} waived={waived}</td></tr>",
                stage = escape_html(json_str(gate, "stage").unwrap_or("unknown")),
                status = escape_html(json_str(gate, "status").unwrap_or("unknown")),
                verdict = escape_html(json_str(gate, "verdict").unwrap_or("unknown")),
                pass = counts.get("pass").and_then(serde_json::Value::as_u64).unwrap_or(0),
                fail = counts.get("fail").and_then(serde_json::Value::as_u64).unwrap_or(0),
                unverified = counts
                    .get("unverified")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                waived = counts
                    .get("waived")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            )
        })
        .collect::<String>();
    format!(
        "<section><h2>Obligation Gates</h2><table><thead><tr><th>Stage</th><th>Status</th><th>Verdict</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table></section>"
    )
}

fn render_run_health_html(evidence: &serde_json::Value) -> String {
    let health = run_health_summary_value(evidence);
    if !health
        .get("present")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return "<section><h2>Run Health</h2><p class=\"muted\">No AO2 run_health block was embedded in this evidence pack.</p></section>".to_string();
    }
    let attention = health
        .get("attention_required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let attention_label = if attention { "yes" } else { "no" };
    format!(
        "<section><h2>Run Health</h2><dl><dt>Repair status</dt><dd>{repair_status}</dd><dt>Attention required</dt><dd>{attention_label}</dd><dt>Repair attempts</dt><dd>{attempts}</dd><dt>Accepted repairs</dt><dd>{accepted}</dd><dt>Failed repairs</dt><dd>{failed}</dd><dt>Next action</dt><dd>{next_action}</dd></dl></section>",
        repair_status = escape_html(json_str(&health, "repair_status").unwrap_or("unknown")),
        attention_label = attention_label,
        attempts = health
            .get("repair_attempt_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        accepted = health
            .get("accepted_repair_attempts")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        failed = health
            .get("failed_repair_attempts")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        next_action = escape_html(json_str(&health, "next_action").unwrap_or(""))
    )
}

fn render_repair_source_html(evidence: &serde_json::Value) -> String {
    let source = repair_source_summary_value(evidence);
    if !source
        .get("present")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return "<section><h2>Repair Source</h2><p class=\"muted\">No AO2 repair_source block was embedded in this evidence pack.</p></section>".to_string();
    }
    let verifier_output = if source
        .get("has_latest_verifier_output")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        "captured"
    } else {
        "not captured"
    };
    format!(
        "<section><h2>Repair Source</h2><dl><dt>Source run</dt><dd>{source_run}</dd><dt>Source verdict</dt><dd>{source_verdict}</dd><dt>Unresolved concerns</dt><dd>{concerns}</dd><dt>Evidence refs</dt><dd>{refs}</dd><dt>Verifier output</dt><dd>{verifier_output}</dd><dt>Verifier output digest</dt><dd><code>{digest}</code></dd><dt>Evidence pack path</dt><dd><code>{path}</code></dd></dl></section>",
        source_run = escape_html(json_str(&source, "source_run_id").unwrap_or("unknown")),
        source_verdict = escape_html(json_str(&source, "source_verdict").unwrap_or("unknown")),
        concerns = source
            .get("unresolved_concern_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        refs = source
            .get("evidence_ref_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        verifier_output = verifier_output,
        digest = escape_html(json_str(&source, "latest_verifier_output_digest").unwrap_or("")),
        path = escape_html(json_str(&source, "evidence_pack_path").unwrap_or(""))
    )
}

fn render_workbench_release_gate_link(
    workbench_url: Option<&str>,
    release_gate_artifact: Option<&str>,
) -> String {
    let Some(workbench_url) = workbench_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return String::new();
    };
    let Some(release_gate_artifact) = release_gate_artifact
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return String::new();
    };
    let href = append_query_param(
        workbench_url,
        "release_gate_artifact",
        release_gate_artifact,
    );
    format!(
        "<section><h2>AO2 Workbench</h2><p><a href=\"{href}\">Open Release Gate Artifact in AO2 Workbench</a></p></section>",
        href = escape_html(&href)
    )
}

fn append_query_param(base: &str, key: &str, value: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!(
        "{base}{separator}{key}={value}",
        key = percent_encode_component(key),
        value = percent_encode_component(value)
    )
}

fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub async fn evidence_pack_detail(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    Query(query): Query<EvidencePackDetailQuery>,
) -> Result<Response, AppError> {
    validate_sha256(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePack, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let evidence = read_json_bundle(&state, BundleKind::EvidencePack, &sha).await?;
    let actual = sha256_of_canonical(&evidence).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha,
            actual,
        });
    }
    let signature = read_signature_sidecar(&state, &sha).await?;
    let sig = signature
        .get("signature")
        .unwrap_or(&serde_json::Value::Null);
    let run_id = json_str(&evidence, "run_id").unwrap_or("unknown");
    let verdict = json_str(&evidence, "verdict").unwrap_or("unknown");
    let signer_id = json_str(sig, "signer_id").unwrap_or("unknown");
    let public_key_sha256 = json_str(sig, "public_key_sha256").unwrap_or("not provided");
    let signature_sha256 = json_str(sig, "signature_sha256").unwrap_or("not provided");
    let verified = sig
        .get("signature_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let verification_label = if verified { "Verified" } else { "Unverified" };
    let obligation_gates = obligation_gate_summary_value(&evidence);
    let obligation_gates_html = render_obligation_gates_html(&obligation_gates);
    let run_health_html = render_run_health_html(&evidence);
    let repair_source_html = render_repair_source_html(&evidence);
    let workbench_link_html = render_workbench_release_gate_link(
        query.workbench_url.as_deref(),
        query.release_gate_artifact.as_deref(),
    );
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Evidence Pack Detail</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:72rem}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.5rem 1rem}}dt{{font-weight:700}}table{{border-collapse:collapse;width:100%;margin-top:.5rem}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}.verified{{color:#096b36;font-weight:700}}.muted{{color:#555}}</style></head><body><main><p><a href=\"/api/v1/evidence-pack/dashboard\">← Dashboard</a></p><h1>AO2 Evidence Pack Detail</h1><p class=\"muted\">Read-only observer detail. This page verifies stored evidence and never approves, mutates, or closes AO2 runs.</p><dl><dt>SHA256</dt><dd><code>{sha}</code></dd><dt>Run</dt><dd>{run_id}</dd><dt>Verdict</dt><dd>{verdict}</dd><dt>Signer</dt><dd>{signer_id}</dd><dt>Signature</dt><dd><span class=\"verified\">{verification_label}</span></dd><dt>Public key SHA256</dt><dd><code>{public_key_sha256}</code></dd><dt>Signature SHA256</dt><dd><code>{signature_sha256}</code></dd><dt>Raw pack</dt><dd><a href=\"/api/v1/evidence-pack/{sha}\">JSON</a></dd><dt>Sidecar</dt><dd><a href=\"/api/v1/evidence-pack/{sha}/signature\">signature JSON</a></dd></dl>{workbench_link_html}{run_health_html}{repair_source_html}{obligation_gates_html}</main></body></html>",
        sha = escape_html(&sha),
        run_id = escape_html(run_id),
        verdict = escape_html(verdict),
        signer_id = escape_html(signer_id),
        verification_label = verification_label,
        public_key_sha256 = escape_html(public_key_sha256),
        signature_sha256 = escape_html(signature_sha256),
        workbench_link_html = workbench_link_html,
        run_health_html = run_health_html,
        repair_source_html = repair_source_html,
        obligation_gates_html = obligation_gates_html,
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

pub async fn evidence_pack_detail_json(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (evidence, signature) = read_verified_evidence_and_signature(&state, &sha).await?;
    Ok(Json(evidence_pack_detail_value(&sha, evidence, signature)))
}

pub async fn latest_evidence_pack_detail_for_run(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut all = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    all.retain(|e| e.schema == EVIDENCE_PACK_SCHEMA);
    all.sort_by_key(|b| std::cmp::Reverse(b.ingested_at));

    for entry in all {
        let (evidence, signature) =
            read_verified_evidence_and_signature(&state, &entry.sha256).await?;
        if json_str(&evidence, "run_id") == Some(run_id.as_str()) {
            return Ok(Json(evidence_pack_detail_value(
                &entry.sha256,
                evidence,
                signature,
            )));
        }
    }
    Err(AppError::NotFound)
}

fn evidence_pack_detail_value(
    sha: &str,
    evidence: serde_json::Value,
    signature: serde_json::Value,
) -> serde_json::Value {
    let sig = signature
        .get("signature")
        .unwrap_or(&serde_json::Value::Null);
    let run_id = json_str(&evidence, "run_id").unwrap_or("unknown");
    let verdict = json_str(&evidence, "verdict").unwrap_or("unknown");
    let signer_id = json_str(sig, "signer_id").unwrap_or("unknown");
    let public_key_sha256 = json_str(sig, "public_key_sha256").unwrap_or("not provided");
    let signature_sha256 = json_str(sig, "signature_sha256").unwrap_or("not provided");
    let verified = sig
        .get("signature_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let obligation_gates = obligation_gate_summary_value(&evidence);
    let run_health = run_health_summary_value(&evidence);
    let repair_source = repair_source_summary_value(&evidence);
    serde_json::json!({
        "schema_version": EVIDENCE_PACK_DETAIL_SCHEMA,
        "sha256": sha,
        "run_id": run_id,
        "verdict": verdict,
        "signature": {
            "signer_id": signer_id,
            "verified": verified,
            "public_key_sha256": public_key_sha256,
            "signature_sha256": signature_sha256,
        },
        "links": {
            "raw_pack": format!("/api/v1/evidence-pack/{sha}"),
            "signature": format!("/api/v1/evidence-pack/{sha}/signature"),
            "html_detail": format!("/api/v1/evidence-pack/{sha}/detail"),
        },
        "trust_boundary": {
            "role": "read_only_observer_for_signed_evidence",
            "can_approve_runs": false,
            "can_mutate_ao2_evidence": false,
        },
        "obligation_gates": obligation_gates,
        "run_health": run_health,
        "repair_source": repair_source,
        "evidence_pack": evidence,
    })
}

async fn read_verified_evidence_and_signature(
    state: &AppState,
    sha: &str,
) -> Result<(serde_json::Value, serde_json::Value), AppError> {
    validate_sha256(sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePack, sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let evidence = read_json_bundle(state, BundleKind::EvidencePack, sha).await?;
    let actual = sha256_of_canonical(&evidence).map_err(|e| AppError::Internal(e.to_string()))?;
    if actual != sha {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual,
        });
    }
    let signature = read_signature_sidecar(state, sha).await?;
    Ok((evidence, signature))
}

async fn read_signature_sidecar(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let sidecar = read_json_bundle(state, BundleKind::EvidencePackSignature, sha).await?;
    let sidecar_sha = sidecar
        .get("evidence_pack_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if sidecar_sha != sha {
        return Err(AppError::SchemaInvalid(format!(
            "evidence pack signature sidecar sha mismatch: expected {sha}, got {sidecar_sha}"
        )));
    }
    let schema = sidecar
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    Ok(sidecar)
}

pub async fn get_evidence_pack_signature(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, AppError> {
    validate_sha256(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePackSignature, &sha)
        .await
    {
        return Err(AppError::NotFound);
    }
    let sidecar = read_signature_sidecar(&state, &sha).await?;
    let bytes =
        serde_json::to_vec_pretty(&sidecar).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

pub async fn get_evidence_pack(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePack, &sha)
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
        .read(BundleKind::EvidencePack, &sha)
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

/// HEAD-equivalent: ETag + Cache-Control with `If-None-Match` → 304
/// short-circuit. Existence checked so HEAD reflects what GET would do.
pub async fn head_evidence_pack(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(&sha)?;
    if !state
        .storage
        .bundles
        .exists(BundleKind::EvidencePack, &sha)
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

fn validate_sha256(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}
