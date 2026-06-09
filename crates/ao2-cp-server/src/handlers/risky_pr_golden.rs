use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;

use crate::error::AppError;

const RISKY_PR_GOLDEN_MANIFEST_ENV: &str = "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST";
const OBSERVER_SCHEMA: &str = "ao2.cp-risky-pr-golden-artifact-manifest-observer.v1";
const MANIFEST_SCHEMA: &str = "ao2.risky-pr-golden-artifact-manifest.v1";

pub async fn risky_pr_golden_artifact_manifest_json() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(risky_pr_golden_artifact_manifest_value().await?))
}

pub async fn risky_pr_golden_artifact_manifest() -> Result<Response, AppError> {
    let observer = risky_pr_golden_artifact_manifest_value().await?;
    let manifest = observer
        .get("manifest")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows = if artifacts.is_empty() {
        "<tr><td colspan=\"4\">No artifacts indexed.</td></tr>".to_string()
    } else {
        artifacts
            .iter()
            .map(|artifact| {
                let path = json_str(artifact, "relative_path").unwrap_or("missing");
                let schema = json_str(artifact, "schema_version").unwrap_or("n/a");
                let sha = json_str(artifact, "sha256").unwrap_or("missing");
                let size = artifact
                    .get("size_bytes")
                    .map(json_scalar)
                    .unwrap_or_else(|| "missing".to_string());
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                    escape_html(path),
                    escape_html(schema),
                    escape_html(sha),
                    escape_html(&size)
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
  <title>AO2 Risky PR Golden Artifact Manifest</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #172026; background: #f7f8f5; }}
    main {{ max-width: 1040px; margin: 0 auto; }}
    h1 {{ margin-bottom: .25rem; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .75rem; margin: 1.25rem 0; }}
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
  <h1>Risky PR Golden Artifact Manifest</h1>
  <p>Authenticated read-only observer surface for AO2 CI release-support evidence. The control plane does not approve releases or mutate AO2 artifacts.</p>
  <section class="meta">
    <div><div class="label">Observer schema</div><code>{observer_schema}</code></div>
    <div><div class="label">Manifest schema</div><code>{manifest_schema}</code></div>
    <div><div class="label">Status</div>{status}</div>
    <div><div class="label">Role</div>{role}</div>
    <div><div class="label">Run</div><code>{run_id}</code></div>
    <div><div class="label">Artifacts</div>{artifact_count}</div>
  </section>
  <table>
    <thead><tr><th>Path</th><th>Schema</th><th>SHA-256</th><th>Bytes</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</main>
</body>
</html>"#,
        observer_schema = escape_html(json_str(&observer, "schema_version").unwrap_or("missing")),
        manifest_schema = escape_html(json_str(&manifest, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&observer, "status").unwrap_or("missing")),
        role = escape_html(json_str(&observer, "control_plane_role").unwrap_or("missing")),
        run_id = escape_html(json_str(&manifest, "run_id").unwrap_or("missing")),
        artifact_count = escape_html(&json_scalar(
            manifest
                .get("artifact_count")
                .unwrap_or(&serde_json::Value::Null)
        )),
        rows = rows
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

async fn risky_pr_golden_artifact_manifest_value() -> Result<serde_json::Value, AppError> {
    let path = configured_manifest_path()?;
    let raw = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let manifest: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AppError::SchemaInvalid(e.to_string()))?;
    let schema = manifest
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema != MANIFEST_SCHEMA {
        return Err(AppError::SchemaUnknown(schema.to_string()));
    }

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
            "configured_env": RISKY_PR_GOLDEN_MANIFEST_ENV,
            "configured_path_present": true,
            "path_redacted": true
        },
        "manifest": manifest
    }))
}

fn configured_manifest_path() -> Result<PathBuf, AppError> {
    let path = std::env::var_os(RISKY_PR_GOLDEN_MANIFEST_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(AppError::NotFound)?;
    Ok(path)
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
