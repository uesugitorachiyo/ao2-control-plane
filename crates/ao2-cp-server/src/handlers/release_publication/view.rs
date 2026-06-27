pub(super) fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn json_str_obj<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn json_scalar(value: &serde_json::Value) -> String {
    if let Some(s) = value.as_str() {
        s.to_string()
    } else if let Some(b) = value.as_bool() {
        b.to_string()
    } else if let Some(n) = value.as_i64() {
        n.to_string()
    } else {
        value.to_string()
    }
}

pub(super) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn render_release_support_bundle_manifest(manifest: &serde_json::Value) -> String {
    let surface_rows = manifest
        .get("surface_checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|surface| {
            let status = json_str(surface, "status").unwrap_or("failed");
            let class = if status == "passed" { "ok" } else { "bad" };
            format!(
                "<tr><td><code>{id}</code></td><td><code>{path}</code></td><td><code>{sha}</code></td><td class=\"{class}\">{status}</td></tr>",
                id = escape_html(json_str(surface, "id").unwrap_or("missing")),
                path = escape_html(json_str(surface, "path").unwrap_or("missing")),
                sha = escape_html(json_str(surface, "sha256").unwrap_or("missing")),
                class = class,
                status = escape_html(status),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let links = manifest
        .get("links")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let operator = manifest
        .get("operator_handoff")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Support Bundle Manifest</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:100rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.bad{{color:#b42318;font-weight:700}}</style></head><body><main><h1>AO2 Release Support Bundle Manifest</h1><p>Read-only portable handoff manifest for scheduler/operator indexing. It exposes filenames, digests, surfaces, and offline verification commands without bearer tokens and without mutating AO2 artifacts.</p><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Filename</dt><dd><code>{filename}</code></dd><dt>Bundle SHA-256</dt><dd><code>{bundle_sha}</code></dd><dt>Release</dt><dd>{release_tag}</dd><dt>Included surfaces</dt><dd>{surface_count}</dd><dt>Control-plane role</dt><dd>{role}</dd><dt>Release acceptance owner</dt><dd>{owner}</dd></dl><section><h2>Surface Manifest</h2><table><thead><tr><th>Surface</th><th>Path</th><th>SHA-256</th><th>Status</th></tr></thead><tbody>{surface_rows}</tbody></table></section><section><h2>Offline verification commands</h2><p>Populate <code>AO2_CP_AUTH_VALUE</code> from the local OAuth CLI before fetching (the value for the HTTP Authorization header, not a full header line). Transport credential values by HTTP Authorization header only. Keep credential values out of URLs, logs, reports, markdown, and committed artifacts; disable shell tracing around fetches and clear the variable after use. The local OAuth/session CLI obtains credentials outside generated evidence.</p><h3>POSIX shell fetch</h3><pre><code>printf 'header = \"Authorization: %s\"\nurl = \"%s\"\noutput = \"%s\"\n' \"$AO2_CP_AUTH_VALUE\" '{download_url}' '{filename}' | curl -fsS --config -
printf 'header = \"Authorization: %s\"\nurl = \"%s\"\noutput = \"%s\"\n' \"$AO2_CP_AUTH_VALUE\" '{checksums_url}' 'SHA256SUMS' | curl -fsS --config -
unset AO2_CP_AUTH_VALUE
sha256sum -c SHA256SUMS
python3 verify_release_support_bundle.py --checksums SHA256SUMS {filename}</code></pre><h3>PowerShell fetch</h3><pre><code>$Headers = @{{ Authorization = $env:AO2_CP_AUTH_VALUE }}
Invoke-WebRequest -Headers $Headers -Uri '{download_url}' -OutFile '{filename}'
Invoke-WebRequest -Headers $Headers -Uri '{checksums_url}' -OutFile 'SHA256SUMS'
Remove-Item Env:AO2_CP_AUTH_VALUE
Get-FileHash -Algorithm SHA256 {filename}
pwsh -File Verify-ReleaseSupportBundle.ps1 -Checksums SHA256SUMS -Path {filename}</code></pre></section><p><a href=\"{download_url}\">Download JSON</a> · <a href=\"{checksums_url}\">SHA256SUMS</a> · <a href=\"{manifest_json}\">Manifest JSON</a> · <a href=\"{verify_html}\">Verification HTML</a> · <a href=\"{verify_json}\">Verification JSON</a></p></main></body></html>",
        status_class = if json_str(manifest, "status") == Some("passed") {
            "ok"
        } else {
            "bad"
        },
        status = escape_html(json_str(manifest, "status").unwrap_or("unknown")),
        filename = escape_html(
            json_str(manifest, "filename").unwrap_or("release-support-bundle.json")
        ),
        bundle_sha = escape_html(json_str(manifest, "bundle_sha256").unwrap_or("missing")),
        release_tag = escape_html(
            manifest
                .get("release")
                .and_then(|release| json_str(release, "release_tag"))
                .unwrap_or("unknown"),
        ),
        surface_count = manifest
            .get("portable_bundle_manifest")
            .and_then(|portable| portable.get("included_surface_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        role = escape_html(json_str(&operator, "control_plane_role").unwrap_or("unknown")),
        owner = escape_html(json_str(&operator, "release_acceptance_owner").unwrap_or("unknown")),
        surface_rows = surface_rows,
        download_url = escape_html(
            json_str(&links, "release_support_bundle_download").unwrap_or("#")
        ),
        checksums_url = escape_html(
            json_str(&links, "release_support_bundle_checksums").unwrap_or("#")
        ),
        manifest_json = escape_html(
            json_str(&links, "release_support_bundle_manifest_json").unwrap_or("#")
        ),
        verify_html = escape_html(
            json_str(&links, "release_support_bundle_verify_html").unwrap_or("#")
        ),
        verify_json = escape_html(
            json_str(&links, "release_support_bundle_verify_json").unwrap_or("#")
        ),
    )
}

pub(super) fn render_release_support_verifier_handoff(handoff: &serde_json::Value) -> String {
    let checks = handoff
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let check_rows = checks
        .iter()
        .map(|check| {
            let status = json_str(check, "status").unwrap_or("failed");
            let class = if status == "passed" { "ok" } else { "bad" };
            format!(
                "<tr><td><code>{id}</code></td><td><code>{digest}</code></td><td class=\"{class}\">{status}</td></tr>",
                id = escape_html(json_str(check, "id").unwrap_or("missing")),
                digest = escape_html(json_str(check, "recomputed_sha256").unwrap_or("missing")),
                class = class,
                status = escape_html(status),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let links = handoff
        .get("links")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let status = json_str(handoff, "status").unwrap_or("failed");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Support Verifier Handoff</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:96rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.bad{{color:#b42318;font-weight:700}}</style></head><body><main><h1>AO2 Release Support Verifier Handoff</h1><p>Read-only observer handoff for factory-v3 evaluator-closer review. It summarizes support-bundle verifier output and preserves the boundary: no release approval and no AO2 artifact mutation.</p><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Bundle SHA-256</dt><dd><code>{bundle_sha}</code></dd><dt>Release</dt><dd>{release_tag}</dd><dt>Release acceptance owner</dt><dd>{owner}</dd><dt>Control-plane approves release</dt><dd>{approves}</dd><dt>Mutates AO artifacts</dt><dd>{mutates}</dd></dl><section><h2>Verifier checks</h2><table><thead><tr><th>Surface</th><th>Recomputed SHA-256</th><th>Status</th></tr></thead><tbody>{check_rows}</tbody></table></section><p><a href=\"{handoff_json}\">Handoff JSON</a> · <a href=\"{verify_json}\">Verifier JSON</a> · <a href=\"{manifest}\">Manifest</a> · <a href=\"{bundle}\">Support Bundle</a></p></main></body></html>",
        status_class = if status == "passed" { "ok" } else { "bad" },
        status = escape_html(status),
        bundle_sha = escape_html(json_str(handoff, "bundle_sha256").unwrap_or("missing")),
        release_tag = escape_html(
            handoff
                .get("release")
                .and_then(|release| json_str(release, "release_tag"))
                .unwrap_or("unknown"),
        ),
        owner = escape_html(json_str(handoff, "release_acceptance_owner").unwrap_or("unknown")),
        approves = escape_html(
            &handoff
                .get("control_plane_approves_release")
                .map(json_scalar)
                .unwrap_or_else(|| "missing".to_string())
        ),
        mutates = escape_html(
            &handoff
                .get("mutates_ao_artifacts")
                .map(json_scalar)
                .unwrap_or_else(|| "missing".to_string())
        ),
        check_rows = check_rows,
        handoff_json = escape_html(
            json_str(&links, "release_support_verifier_handoff_json").unwrap_or("#")
        ),
        verify_json = escape_html(
            json_str(&links, "release_support_bundle_verify_json").unwrap_or("#")
        ),
        manifest = escape_html(json_str(&links, "release_support_bundle_manifest").unwrap_or("#")),
        bundle = escape_html(json_str(&links, "release_support_bundle_json").unwrap_or("#")),
    )
}

pub(super) fn render_release_support_bundle_verification(
    verification: &serde_json::Value,
    keep_latest: usize,
) -> String {
    let checks = verification
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let blockers = verification
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let check_rows = checks
        .iter()
        .map(|check| {
            let status = json_str(check, "status").unwrap_or("missing");
            let class = if status == "passed" { "ok" } else { "bad" };
            format!(
                "<tr><td><code>{id}</code></td><td>{path}</td><td>{declared}</td><td>{embedded}</td><td><code>{digest}</code></td><td class=\"{class}\">{status}</td></tr>",
                id = escape_html(json_str(check, "id").unwrap_or("missing")),
                path = escape_html(json_str(check, "path").unwrap_or("missing")),
                declared = escape_html(
                    json_str(check, "declared_schema_version").unwrap_or("missing")
                ),
                embedded = escape_html(
                    json_str(check, "embedded_schema_version").unwrap_or("missing")
                ),
                digest = escape_html(json_str(check, "recomputed_sha256").unwrap_or("missing")),
                class = class,
                status = escape_html(status),
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
    let status = json_str(verification, "status").unwrap_or("unknown");
    let trust = verification
        .get("trust_boundary_check")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AO2 Release Support Bundle Verification</title><style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:100rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}.ok{{color:#096b36;font-weight:700}}.bad{{color:#b42318;font-weight:700}}.warn{{color:#9a5b00;font-weight:700}}</style></head><body><main><h1>AO2 Release Support Bundle Verification</h1><p>Authenticated read-only observer page for portable release support bundle digest checks. It recomputes embedded support-bundle surface digests and never approves a release or mutates AO2 artifacts.</p><dl><dt>Status</dt><dd class=\"{status_class}\">{status}</dd><dt>Bundle SHA-256</dt><dd><code>{bundle_sha}</code></dd><dt>Algorithm</dt><dd>{algorithm}</dd><dt>Control-plane role</dt><dd>{role}</dd><dt>Mutates AO artifacts</dt><dd>{mutates}</dd><dt>Release acceptance owner</dt><dd>factory-v3 evaluator-closer</dd></dl><section><h2>Surface Checks</h2><table><thead><tr><th>Surface</th><th>Path</th><th>Declared schema</th><th>Embedded schema</th><th>Recomputed SHA-256</th><th>Status</th></tr></thead><tbody>{check_rows}</tbody></table></section><section><h2>Blockers</h2><ul>{blocker_items}</ul></section><p><a href=\"/api/v1/release/support-bundle/verify.json?keep_latest={keep_latest}\">Verification JSON</a> · <a href=\"/api/v1/release/support-bundle.json?keep_latest={keep_latest}\">Release Support Bundle JSON</a> · <a href=\"/api/v1/release/readiness\">Release Readiness</a> · <a href=\"/api/v1/release/handoff\">Release Handoff</a></p></main></body></html>",
        status_class = if status == "passed" { "ok" } else { "bad" },
        status = escape_html(status),
        bundle_sha = escape_html(json_str(verification, "bundle_sha256").unwrap_or("missing")),
        algorithm = escape_html(json_str(verification, "algorithm").unwrap_or("missing")),
        role = escape_html(json_str(&trust, "role").unwrap_or("missing")),
        mutates = escape_html(
            &trust
                .get("mutates_ao_artifacts")
                .map(json_scalar)
                .unwrap_or_else(|| "missing".to_string())
        ),
        check_rows = check_rows,
        blocker_items = blocker_items,
        keep_latest = keep_latest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_scalar_formats_simple_values_for_html_tables() {
        assert_eq!(json_scalar(&serde_json::json!("ready")), "ready");
        assert_eq!(json_scalar(&serde_json::json!(false)), "false");
        assert_eq!(json_scalar(&serde_json::json!(42)), "42");
        assert_eq!(
            json_scalar(&serde_json::json!({"status": "ready"})),
            "{\"status\":\"ready\"}"
        );
    }

    #[test]
    fn escape_html_escapes_text_inserted_into_dashboard_markup() {
        assert_eq!(
            escape_html("<tag attr=\"one\">Tom & 'AO2'</tag>"),
            "&lt;tag attr=&quot;one&quot;&gt;Tom &amp; &#39;AO2&#39;&lt;/tag&gt;"
        );
    }

    #[test]
    fn json_str_helpers_return_only_string_fields() {
        let value = serde_json::json!({
            "status": "passed",
            "count": 3,
        });
        assert_eq!(json_str(&value, "status"), Some("passed"));
        assert_eq!(json_str(&value, "count"), None);

        let object = value.as_object().expect("test value is object");
        assert_eq!(json_str_obj(object, "status"), Some("passed"));
        assert_eq!(json_str_obj(object, "count"), None);
    }

    #[test]
    fn support_bundle_verification_renderer_escapes_dynamic_values() {
        let verification = serde_json::json!({
            "status": "failed",
            "bundle_sha256": "<bundle>",
            "algorithm": "sha256",
            "checks": [{
                "id": "release_readiness",
                "path": "$.readiness",
                "declared_schema_version": "<declared>",
                "embedded_schema_version": "embedded",
                "recomputed_sha256": "abc123",
                "status": "failed",
            }],
            "blockers": ["<script>alert('x')</script>"],
            "trust_boundary_check": {
                "role": "read_only_observer",
                "mutates_ao_artifacts": false,
            },
        });

        let html = render_release_support_bundle_verification(&verification, 25);

        assert!(html.contains("&lt;bundle&gt;"));
        assert!(html.contains("&lt;declared&gt;"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn support_bundle_handoff_renderer_preserves_observer_boundary() {
        let handoff = serde_json::json!({
            "status": "passed",
            "bundle_sha256": "abc123",
            "release": {
                "release_tag": "v1.2.3",
            },
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "control_plane_approves_release": false,
            "mutates_ao_artifacts": false,
            "checks": [],
            "links": {},
        });

        let html = render_release_support_verifier_handoff(&handoff);

        assert!(html.contains("no release approval"));
        assert!(html.contains("no AO2 artifact mutation"));
        assert!(html.contains("<dd>false</dd>"));
    }
}
