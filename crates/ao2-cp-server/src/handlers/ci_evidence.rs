use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

const CI_EVIDENCE_INDEX_SCHEMA: &str = "ao2.cp-ci-evidence-index.v1";

pub async fn ci_evidence_index_json() -> Json<serde_json::Value> {
    Json(ci_evidence_index_value())
}

pub async fn ci_evidence_index() -> Response {
    let index = ci_evidence_index_value();
    let families = index["evidence_families"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let rows = families
        .iter()
        .map(|family| {
            let name = evidence_display_name(json_str(family, "id").unwrap_or("unknown-evidence"));
            let artifact = json_str(family, "artifact_name_pattern").unwrap_or("missing");
            let schema_versions = family
                .get("schema_versions")
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "missing".to_string());
            let purpose = evidence_purpose(json_str(family, "id").unwrap_or("unknown-evidence"));
            format!(
                "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(name),
                escape_html(artifact),
                escape_html(&schema_versions),
                escape_html(purpose)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AO2 CI Evidence Index</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #172026; background: #f7f8f5; }}
    main {{ max-width: 1120px; margin: 0 auto; }}
    h1 {{ margin-bottom: .25rem; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .75rem; margin: 1.25rem 0; }}
    .meta div {{ border: 1px solid #cad2c8; background: #fff; padding: .75rem; }}
    .label {{ color: #58635d; font-size: .78rem; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cad2c8; }}
    th, td {{ padding: .65rem .75rem; border-bottom: 1px solid #dde3dc; text-align: left; vertical-align: top; }}
    th {{ background: #edf1ea; color: #27332d; }}
    code {{ overflow-wrap: anywhere; }}
  </style>
</head>
<body>
<main>
  <h1>AO2 CI Evidence Index</h1>
  <p>Authenticated read-only operator index for production-readiness CI evidence. The control plane does not approve releases or mutate AO2 artifacts.</p>
  <section class="meta">
    <div><div class="label">Schema</div><code>{schema}</code></div>
    <div><div class="label">Status</div>{status}</div>
    <div><div class="label">Role</div>{role}</div>
    <div><div class="label">Families</div>{count}</div>
  </section>
  <table>
    <thead><tr><th>Evidence</th><th>CI artifact</th><th>Schema versions</th><th>Purpose</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</main>
</body>
</html>"#,
        schema = escape_html(json_str(&index, "schema_version").unwrap_or("missing")),
        status = escape_html(json_str(&index, "status").unwrap_or("missing")),
        role = escape_html(json_str(&index, "control_plane_role").unwrap_or("missing")),
        count = families.len(),
        rows = rows
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

pub(crate) fn ci_evidence_index_value() -> serde_json::Value {
    json!({
        "schema_version": CI_EVIDENCE_INDEX_SCHEMA,
        "status": "indexed",
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
        "endpoints": {
            "html": "/api/v1/ci/evidence-index",
            "json": "/api/v1/ci/evidence-index.json"
        },
        "evidence_families": [
            {
                "id": "risky-pr-golden-bridge-smoke",
                "artifact_name_pattern": "ao2-control-plane-risky-pr-golden-bridge-<target>",
                "schema_versions": [
                    "ao2.cp-risky-pr-golden-bridge-smoke.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "risky-pr-golden-bridge-smoke (<target>)"
                    ],
                    &[
                        "ao2-control-plane-risky-pr-golden-bridge-ubuntu-x86_64"
                    ],
                    "summary.json carries schema/status and artifact digests"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            },
            {
                "id": "release-train-bridge-smoke",
                "artifact_name_pattern": "ao2-control-plane-release-train-bridge-<target>",
                "schema_versions": [
                    "ao2.cp-release-train-bridge-smoke.v1",
                    "ao2.cp-release-train-readback.v1",
                    "ao2.public-release-train-drill.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "release-train-bridge-smoke (<target>)"
                    ],
                    &[
                        "ao2-control-plane-release-train-bridge-ubuntu-x86_64"
                    ],
                    "summary.json carries schema/status and release-train readback captures"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            },
            {
                "id": "ingest-smoke",
                "artifact_name_pattern": "ao2-control-plane-ingest-smoke-<target>",
                "schema_versions": [
                    "ao2.cp-ingest-smoke.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "ingest-smoke (<target>)"
                    ],
                    &[
                        "ao2-control-plane-ingest-smoke-ubuntu-x86_64"
                    ],
                    "summary.json carries schema/status and artifact digests"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            },
            {
                "id": "release-archive-smoke",
                "artifact_name_pattern": "ao2-control-plane-smoke-<target>",
                "schema_versions": [
                    "ao2.cp-release-archive-smoke.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "release-archive-smoke (<target>)"
                    ],
                    &[
                        "ao2-control-plane-smoke-ubuntu-x86_64"
                    ],
                    "summary.json carries schema/status and artifact digests"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            },
            {
                "id": "backup-restore-drill",
                "artifact_name_pattern": "ao2-control-plane-dr-restore",
                "schema_versions": [
                    "ao2.cp-dr-restore-drill.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "backup-restore-drill (<target>)"
                    ],
                    &[
                        "ao2-control-plane-dr-restore"
                    ],
                    "summary.json carries schema/status and artifact digests"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            },
            {
                "id": "stable-promotion-evidence-readback",
                "artifact_name_pattern": "ao2-control-plane-ao2-stable-promotion-evidence-index-readback",
                "schema_versions": [
                    "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1",
                    "ao2.cp-stable-promotion-evidence-readback.v1",
                    "ao2.stable-promotion-evidence-index.v1"
                ],
                "operator_action": "download-ci-artifact",
                "ci_artifact_provenance": github_actions_provenance(
                    &[
                        "AO2 stable promotion evidence index readback"
                    ],
                    &[
                        "ao2-control-plane-ao2-stable-promotion-evidence-index-readback"
                    ],
                    "summary.json carries schema/status plus stable promotion evidence readiness"
                ),
                "trust_boundary": {
                    "read_only": true,
                    "approves_release": false,
                    "mutates_ao_artifacts": false
                }
            }
        ]
    })
}

fn github_actions_provenance(
    job_names: &[&str],
    artifact_names: &[&str],
    digest_reference: &str,
) -> serde_json::Value {
    json!({
        "provider": "github-actions",
        "workflow_file": ".github/workflows/ci.yml",
        "workflow_name": "CI",
        "run_id_source": "github_actions_run_id",
        "run_url_template": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/<run_id>",
        "artifact_download_url_template": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/<run_id>/artifacts",
        "job_names": job_names,
        "artifact_names": artifact_names,
        "digest_reference": digest_reference,
        "token_free": true
    })
}

fn evidence_display_name(id: &str) -> &'static str {
    match id {
        "risky-pr-golden-bridge-smoke" => "Risky PR golden bridge smoke",
        "release-train-bridge-smoke" => "Release train bridge smoke",
        "ingest-smoke" => "Ingest smoke",
        "release-archive-smoke" => "Release archive smoke",
        "backup-restore-drill" => "Backup/restore drill",
        "stable-promotion-evidence-readback" => "Stable promotion evidence readback",
        _ => "Unknown evidence",
    }
}

fn evidence_purpose(id: &str) -> &'static str {
    match id {
        "risky-pr-golden-bridge-smoke" => {
            "AO2 risky PR golden artifact manifests can be observed without release approval."
        }
        "release-train-bridge-smoke" => {
            "AO2 public release-train summaries can be observed without release approval."
        }
        "ingest-smoke" => "Signed AO2 evidence can be ingested on supported operating systems.",
        "release-archive-smoke" => {
            "Packaged release archives install and run on supported operating systems."
        }
        "backup-restore-drill" => "Storage backup and restore behavior is exercised.",
        "stable-promotion-evidence-readback" => {
            "AO2 stable-promotion evidence can be observed without release approval."
        }
        _ => "missing",
    }
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
