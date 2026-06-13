use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;

use crate::error::AppError;

const OPERATOR_RELEASE_EVIDENCE_SUMMARY_ENV: &str = "AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY";
const OBSERVER_SCHEMA: &str = "ao2.cp-operator-release-evidence-readback.v1";
const OPERATOR_RELEASE_EVIDENCE_SCHEMA: &str = "ao2.operator-release-evidence-bundle.v1";

pub async fn operator_release_evidence_readback_json() -> Result<Json<serde_json::Value>, AppError>
{
    Ok(Json(operator_release_evidence_readback_value().await?))
}

pub async fn operator_release_evidence_readback() -> Result<Response, AppError> {
    let observer = operator_release_evidence_readback_value().await?;
    let evidence = observer
        .get("operator_release_evidence")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let checks = evidence
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows = if checks.is_empty() {
        "<tr><td colspan=\"6\">No operator release evidence checks listed.</td></tr>".to_string()
    } else {
        checks
            .iter()
            .map(|check| {
                let component = json_str(check, "component").unwrap_or("missing");
                let platform = json_str(check, "platform").unwrap_or("missing");
                let artifact = json_str(check, "artifact").unwrap_or("missing");
                let kind = json_str(check, "kind").unwrap_or("missing");
                let status = json_str(check, "status").unwrap_or("missing");
                let detail = check_detail_summary(check);
                format!(
                    "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                    escape_html(component),
                    escape_html(platform),
                    escape_html(artifact),
                    escape_html(kind),
                    escape_html(status),
                    escape_html(&detail)
                )
            })
            .collect::<Vec<_>>()
            .join("")
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
  <title>AO2 Operator Release Evidence</title>
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
  <h1>AO2 Operator Release Evidence</h1>
  <p>Authenticated read-only observer surface for AO2 operator release evidence bundles. The control plane does not approve releases, publish tags, deploy, or mutate AO2 artifacts.</p>
  <section class="meta">
    <div><div class="label">Observer schema</div><code>{observer_schema}</code></div>
    <div><div class="label">Evidence schema</div><code>{evidence_schema}</code></div>
    <div><div class="label">Status</div>{status}</div>
    <div><div class="label">Ready</div>{ready}</div>
    <div><div class="label">Role</div>{role}</div>
    <div><div class="label">Release mutation</div>{mutates_releases}</div>
  </section>
  <section>
    <h2>Checks</h2>
    <table>
      <thead><tr><th>Component</th><th>Platform</th><th>Artifact</th><th>Kind</th><th>Status</th><th>Details</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"#,
        observer_schema = escape_html(json_str(&observer, "schema_version").unwrap_or("missing")),
        evidence_schema = escape_html(json_str(&evidence, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&evidence, "status").unwrap_or("missing")),
        ready = evidence
            .get("operator_release_evidence_ready")
            .map(json_scalar)
            .unwrap_or_else(|| "missing".to_string()),
        role = escape_html(json_str(&observer, "control_plane_role").unwrap_or("missing")),
        mutates_releases = trust
            .get("mutates_releases")
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

async fn operator_release_evidence_readback_value() -> Result<serde_json::Value, AppError> {
    let path = configured_summary_path()?;
    let raw = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let mut evidence: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = evidence
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema != OPERATOR_RELEASE_EVIDENCE_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }
    redact_local_paths(&mut evidence);

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
            "configured_env": OPERATOR_RELEASE_EVIDENCE_SUMMARY_ENV,
            "configured_path_present": true,
            "path_redacted": true
        },
        "operator_release_evidence": evidence
    }))
}

fn configured_summary_path() -> Result<PathBuf, AppError> {
    let path = std::env::var_os(OPERATOR_RELEASE_EVIDENCE_SUMMARY_ENV)
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

fn check_detail_summary(check: &serde_json::Value) -> String {
    [
        "schema_version",
        "task_board_readback_schema",
        "task_board_dashboard_schema",
        "summary_status",
        "archive_parity_status",
        "signature_verified",
        "checksum_verified",
        "auth_value_stored",
        "credential_material_in_urls",
        "credential_material_included",
        "mutates_github_releases",
        "mutates_releases",
        "stores_credentials",
        "control_plane_approves_release",
    ]
    .iter()
    .filter_map(|key| {
        check
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
