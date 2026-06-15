use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;

use crate::error::AppError;

const STABLE_PROMOTION_EVIDENCE_SUMMARY_ENV: &str =
    "AO2_CP_STABLE_PROMOTION_EVIDENCE_INDEX_SUMMARY";
const OBSERVER_SCHEMA: &str = "ao2.cp-stable-promotion-evidence-readback.v1";
const STABLE_PROMOTION_EVIDENCE_SCHEMA: &str = "ao2.stable-promotion-evidence-index.v1";

pub async fn stable_promotion_evidence_readback_json() -> Result<Json<serde_json::Value>, AppError>
{
    Ok(Json(stable_promotion_evidence_readback_value().await?))
}

pub async fn stable_promotion_evidence_readback() -> Result<Response, AppError> {
    let observer = stable_promotion_evidence_readback_value().await?;
    let evidence = observer
        .get("stable_promotion_evidence")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let evidence_map = evidence
        .get("evidence")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let rows = if evidence_map.is_empty() {
        "<tr><td colspan=\"4\">No stable-promotion evidence families listed.</td></tr>".to_string()
    } else {
        let mut entries = evidence_map.iter().collect::<Vec<_>>();
        entries.sort_by_key(|(name, _)| *name);
        entries
            .into_iter()
            .map(|(name, item)| {
                let schema = json_str(item, "schema_version").unwrap_or("missing");
                let status = json_str(item, "status").unwrap_or("missing");
                let ready = item
                    .get("ready")
                    .map(json_scalar)
                    .unwrap_or_else(|| "missing".to_string());
                let details = evidence_detail_summary(item);
                format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}: <code>{}</code></td></tr>",
                    escape_html(name),
                    escape_html(schema),
                    escape_html(status),
                    escape_html(&ready),
                    escape_html(&details)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let blockers = evidence
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let blocker_summary = if blockers.is_empty() {
        "none".to_string()
    } else {
        blockers
            .iter()
            .map(json_scalar)
            .collect::<Vec<_>>()
            .join("; ")
    };
    let trust = evidence
        .get("trust_boundary")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AO2 Stable Promotion Evidence</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #172026; background: #f7f8f5; }}
    main {{ max-width: 1120px; margin: 0 auto; }}
    h1 {{ margin-bottom: .25rem; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .75rem; margin: 1.25rem 0; }}
    .meta div {{ border: 1px solid #cad2c8; background: #fff; padding: .75rem; }}
    .label {{ color: #58635d; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cad2c8; }}
    th, td {{ padding: .65rem .75rem; border-bottom: 1px solid #dde3dc; text-align: left; vertical-align: top; }}
    th {{ background: #edf1ea; color: #27332d; }}
    code {{ overflow-wrap: anywhere; }}
  </style>
</head>
<body>
<main>
  <h1>AO2 Stable Promotion Evidence</h1>
  <p>Authenticated read-only observer surface for AO2 stable-promotion evidence. The control plane does not approve releases, publish tags, deploy, or mutate AO2 artifacts.</p>
  <section class="meta">
    <div><div class="label">Observer schema</div><code>{observer_schema}</code></div>
    <div><div class="label">Producer schema</div><code>{producer_schema}</code></div>
    <div><div class="label">Status</div>{status}</div>
    <div><div class="label">Ready</div>{ready}</div>
    <div><div class="label">Role</div>{role}</div>
    <div><div class="label">Blockers</div>{blockers}</div>
    <div><div class="label">Release mutation</div>mutates_releases={mutates_releases}</div>
    <div><div class="label">Release approval</div>control_plane_approves_release={approves_release}</div>
  </section>
  <section>
    <h2>Evidence Families</h2>
    <table>
      <thead><tr><th>Evidence</th><th>Schema</th><th>Status</th><th>Ready and details</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"#,
        observer_schema = escape_html(json_str(&observer, "schema_version").unwrap_or("missing")),
        producer_schema = escape_html(json_str(&evidence, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&evidence, "status").unwrap_or("missing")),
        ready = evidence
            .get("stable_promotion_evidence_index_ready")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string()),
        role = escape_html(json_str(&observer, "control_plane_role").unwrap_or("missing")),
        blockers = escape_html(&blocker_summary),
        mutates_releases = trust
            .get("mutates_releases")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string()),
        approves_release = trust
            .get("control_plane_approves_release")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string()),
        rows = rows
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

async fn stable_promotion_evidence_readback_value() -> Result<serde_json::Value, AppError> {
    let path = configured_summary_path()?;
    let raw = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let mut stable_promotion_evidence: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = stable_promotion_evidence
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema != STABLE_PROMOTION_EVIDENCE_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }
    redact_local_paths(&mut stable_promotion_evidence);

    Ok(json!({
        "schema_version": OBSERVER_SCHEMA,
        "generated_at": Utc::now().to_rfc3339(),
        "status": "observed",
        "control_plane_role": "read-only-observer",
        "mutates_ao_artifacts": false,
        "mutates_observer_storage": false,
        "control_plane_approves_release": false,
        "auth": {
            "required": true,
            "scheme": "bearer",
            "credential_material_included": false,
            "credential_material_in_urls": false
        },
        "source": {
            "configured_env": STABLE_PROMOTION_EVIDENCE_SUMMARY_ENV,
            "configured_path_present": true,
            "path_redacted": true
        },
        "stable_promotion_evidence": stable_promotion_evidence
    }))
}

fn configured_summary_path() -> Result<PathBuf, AppError> {
    let path = std::env::var_os(STABLE_PROMOTION_EVIDENCE_SUMMARY_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(AppError::NotFound)?;
    Ok(path)
}

fn redact_local_paths(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                redact_local_paths(item);
            }
        }
        serde_json::Value::Object(fields) => {
            for value in fields.values_mut() {
                redact_local_paths(value);
            }
        }
        serde_json::Value::String(text) if looks_like_local_path(text) => {
            *text = "[redacted-local-path]".to_string();
        }
        _ => {}
    }
}

fn looks_like_local_path(value: &str) -> bool {
    value.starts_with('/')
        || value.contains("/private/")
        || value.contains("/Users/")
        || value.contains("\\Users\\")
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        _ => value.to_string(),
    }
}

fn evidence_detail_summary(evidence: &serde_json::Value) -> String {
    [
        "archive_parity_status",
        "post_release_evidence_ready",
        "stable_release_evidence_ready",
        "violations",
    ]
    .iter()
    .filter_map(|key| {
        evidence
            .get(key)
            .map(|value| format!("{key}={}", json_scalar(value)))
    })
    .collect::<Vec<_>>()
    .join("; ")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
