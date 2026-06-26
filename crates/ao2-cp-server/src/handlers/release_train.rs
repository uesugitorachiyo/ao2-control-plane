use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;

use crate::error::AppError;

const RELEASE_TRAIN_SUMMARY_ENV: &str = "AO2_CP_RELEASE_TRAIN_SUMMARY";
const OBSERVER_SCHEMA: &str = "ao2.cp-release-train-readback.v1";
const RELEASE_TRAIN_SCHEMA: &str = "ao2.public-release-train-drill.v1";

pub async fn release_train_readback_json() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(release_train_readback_value().await?))
}

pub async fn release_train_readback() -> Result<Response, AppError> {
    let observer = release_train_readback_value().await?;
    let release_train = observer
        .get("release_train")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let contract = release_train
        .get("release_readiness_artifact_consumer_contract")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let publish_guards = release_train
        .get("publish_guards")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let checks = release_train
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows = if checks.is_empty() {
        "<tr><td colspan=\"3\">No release-train checks listed.</td></tr>".to_string()
    } else {
        checks
            .iter()
            .map(|check| {
                let name = json_str(check, "name").unwrap_or("missing");
                let status = json_str(check, "status").unwrap_or("missing");
                let exit_code = check
                    .get("exit_code")
                    .map(json_scalar)
                    .unwrap_or_else(|| "missing".to_string());
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    escape_html(name),
                    escape_html(status),
                    escape_html(&exit_code)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AO2 Release Train Readback</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #172026; background: #f7f8f5; }}
    main {{ max-width: 1040px; margin: 0 auto; }}
    h1 {{ margin-bottom: .25rem; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: .75rem; margin: 1.25rem 0; }}
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
  <h1>AO2 Release Train Readback</h1>
  <p>Authenticated read-only observer surface for AO2 public release-train drill evidence. The control plane does not approve releases, publish tags, deploy, or mutate AO2 artifacts.</p>
  <section class="meta">
    <div><div class="label">Observer schema</div><code>{observer_schema}</code></div>
    <div><div class="label">Release-train schema</div><code>{release_train_schema}</code></div>
    <div><div class="label">Status</div>{status}</div>
    <div><div class="label">Role</div>{role}</div>
    <div><div class="label">Required check</div><code>{required_check}</code></div>
    <div><div class="label">Publish guard</div>{publish_guard}</div>
  </section>
  <section>
    <h2>Release Readiness Artifact Consumer Contract</h2>
    <p>Status: <strong>{contract_status}</strong>. Detail: {contract_detail}</p>
    <p>AO2 release-readiness consumer dashboard: <code>{consumer_dashboard}</code></p>
    <p>Dashboard schema: <code>{consumer_dashboard_schema}</code></p>
  </section>
  <section>
    <h2>Checks</h2>
    <table>
      <thead><tr><th>Name</th><th>Status</th><th>Exit code</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"#,
        observer_schema = escape_html(json_str(&observer, "schema_version").unwrap_or("missing")),
        release_train_schema =
            escape_html(json_str(&release_train, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&release_train, "status").unwrap_or("missing")),
        role = escape_html(json_str(&observer, "control_plane_role").unwrap_or("missing")),
        required_check = escape_html(json_str(&contract, "required_check").unwrap_or("missing")),
        publish_guard =
            escape_html(json_str(&publish_guards, "tag_push_publish_deploy").unwrap_or("missing")),
        contract_status = escape_html(json_str(&contract, "status").unwrap_or("missing")),
        contract_detail = escape_html(json_str(&contract, "check_detail").unwrap_or("missing")),
        consumer_dashboard =
            escape_html(json_str(&contract, "dashboard_artifact").unwrap_or("missing")),
        consumer_dashboard_schema =
            escape_html(json_str(&contract, "dashboard_schema_version").unwrap_or("missing")),
        rows = rows
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

async fn release_train_readback_value() -> Result<serde_json::Value, AppError> {
    let path = configured_summary_path()?;
    let raw = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let mut release_train: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = release_train
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema != RELEASE_TRAIN_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }
    redact_local_paths(&mut release_train);

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
            "configured_env": RELEASE_TRAIN_SUMMARY_ENV,
            "configured_path_present": true,
            "path_redacted": true
        },
        "release_train": release_train
    }))
}

fn configured_summary_path() -> Result<PathBuf, AppError> {
    let path = std::env::var_os(RELEASE_TRAIN_SUMMARY_ENV)
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

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
