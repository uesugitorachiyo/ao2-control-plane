use ao2_cp_schema::canonical::sha256_of_canonical;
use serde::Serialize;

use crate::error::AppError;

use super::{
    view::json_str, RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA,
    RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA, RELEASE_SUPPORT_VERIFIER_HANDOFF_SCHEMA,
};

pub(super) fn normalize_release_support_storage_surface(
    storage_support: &mut serde_json::Value,
    stable_generated_at: &str,
) {
    if let Some(storage_support_object) = storage_support.as_object_mut() {
        storage_support_object.insert(
            "generated_at".to_string(),
            serde_json::Value::String(stable_generated_at.to_string()),
        );
    }
    normalize_release_support_storage_volatile_fields(storage_support);
}

fn normalize_release_support_storage_volatile_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if object.contains_key("age_seconds") {
                object.insert(
                    "age_seconds".to_string(),
                    serde_json::Value::Number(0.into()),
                );
            }
            for child in object.values_mut() {
                normalize_release_support_storage_volatile_fields(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                normalize_release_support_storage_volatile_fields(item);
            }
        }
        _ => {}
    }
}

pub(super) fn release_support_bundle_filename(bundle: &serde_json::Value) -> String {
    let version = bundle
        .get("release")
        .and_then(|release| json_str(release, "version"))
        .unwrap_or("unknown");
    let sanitized_version = version
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("ao2-release-support-bundle-{sanitized_version}.json")
}

pub(super) const SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS: [&str; 9] = [
    "ci_evidence_index",
    "hosted_release_smoke",
    "install_verification",
    "release_assembly",
    "release_readiness",
    "release_candidate_handoff",
    "release_cockpit",
    "release_evaluator_decision",
    "storage_support_bundle",
];

pub(super) fn release_support_bundle_manifest_value(
    bundle: &serde_json::Value,
    keep_latest: usize,
) -> Result<serde_json::Value, AppError> {
    let verification = release_support_bundle_verification_value(bundle)?;
    let bundle_sha256 = json_str(&verification, "bundle_sha256").unwrap_or("missing");
    let release = bundle
        .get("release")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let manifest = bundle
        .get("portable_bundle_manifest")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let surfaces = manifest
        .get("included_surfaces")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let manifest_schema_status =
        if json_str(&manifest, "schema_version") == Some(RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA) {
            "passed"
        } else {
            "failed"
        };
    let checks = verification
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(serde_json::json!({
        "schema_version": RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA,
        "status": json_str(&verification, "status").unwrap_or("failed"),
        "bundle_kind": json_str(bundle, "bundle_kind").unwrap_or("unknown"),
        "bundle_sha256": bundle_sha256,
        "filename": release_support_bundle_filename(bundle),
        "keep_latest": keep_latest,
        "release": {
            "version": json_str(&release, "version").unwrap_or("unknown"),
            "release_tag": json_str(&release, "release_tag").unwrap_or("unknown"),
            "status": json_str(&release, "status").unwrap_or("unknown"),
        },
        "verification": {
            "schema_version": RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA,
            "status": json_str(&verification, "status").unwrap_or("failed"),
            "surface_count": verification
                .get("surface_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            "blocker_count": verification
                .get("blockers")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            "trust_boundary_status": verification
                .get("trust_boundary_check")
                .and_then(|trust| json_str(trust, "status"))
                .unwrap_or("failed"),
        },
        "portable_bundle_manifest": {
            "schema_version": manifest
                .get("schema_version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("missing"),
            "schema_status": manifest_schema_status,
            "included_surface_count": surfaces.len(),
            "integrity_algorithm": manifest
                .get("integrity")
                .and_then(|integrity| json_str(integrity, "algorithm"))
                .unwrap_or("missing"),
            "integrity_scope": manifest
                .get("integrity")
                .and_then(|integrity| json_str(integrity, "scope"))
                .unwrap_or("missing"),
        },
        "surface_checks": checks
            .iter()
            .map(|check| serde_json::json!({
                "id": json_str(check, "id").unwrap_or("missing"),
                "path": json_str(check, "path").unwrap_or("missing"),
                "sha256": json_str(check, "recomputed_sha256").unwrap_or("missing"),
                "status": json_str(check, "status").unwrap_or("failed"),
            }))
            .collect::<Vec<_>>(),
        "verifier_output_schema_sample": {
            "schema_version": "ao2.cp-release-support-bundle-verifier-output-sample.v1",
            "purpose": "Stable, token-free example of the offline verifier JSON shape for Hermes/factory-v3 ingestion tests; values are illustrative except for contract constants.",
            "status": "passed",
            "checksum_verified": true,
            "bundle_sha256": "<64 lowercase sha256 hex from ao2.cp-release-support-bundle.v1 canonical JSON>",
            "surface_count": checks.len(),
            "failures": [],
            "control_plane_role": "read_only_observer",
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "mutates_ao_artifacts": false,
            "control_plane_approves_release": false,
            "expected_fields": [
                "status",
                "checksum_verified",
                "bundle_sha256",
                "surface_count",
                "failures",
                "control_plane_role",
                "release_acceptance_owner",
            ],
            "token_hygiene": {
                "contains_bearer_token": false,
                "allowed_transport": "HTTP Authorization header only during fetch; verifier output must not contain credentials",
                "forbidden_locations": ["urls", "logs", "reports", "markdown", "committed artifacts"],
            },
            "platform_commands": {
                "macos_ubuntu": format!("python3 verify_release_support_bundle.py --json --checksums SHA256SUMS {}", release_support_bundle_filename(bundle)),
                "windows_powershell": format!("pwsh -File Verify-ReleaseSupportBundle.ps1 -Json -Checksums SHA256SUMS -Path {}", release_support_bundle_filename(bundle)),
            },
        },
        "links": {
            "release_support_bundle_json": format!("/api/v1/release/support-bundle.json?keep_latest={keep_latest}"),
            "release_support_bundle_manifest": format!("/api/v1/release/support-bundle/manifest?keep_latest={keep_latest}"),
            "release_support_bundle_manifest_json": format!("/api/v1/release/support-bundle/manifest.json?keep_latest={keep_latest}"),
            "release_support_bundle_download": format!("/api/v1/release/support-bundle/download?keep_latest={keep_latest}"),
            "release_support_bundle_checksums": format!("/api/v1/release/support-bundle/SHA256SUMS?keep_latest={keep_latest}"),
            "release_support_bundle_verify_json": format!("/api/v1/release/support-bundle/verify.json?keep_latest={keep_latest}"),
            "release_support_bundle_verify_html": format!("/api/v1/release/support-bundle/verify?keep_latest={keep_latest}"),
            "release_support_verifier_handoff_json": format!("/api/v1/release/support-bundle/handoff.json?keep_latest={keep_latest}"),
            "release_support_verifier_handoff_html": format!("/api/v1/release/support-bundle/handoff?keep_latest={keep_latest}"),
        },
        "operator_handoff": {
            "control_plane_role": "read_only_observer",
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "safe_for_scheduler_indexing": true,
            "contains_bearer_token": false,
            "mutates_ao_artifacts": false,
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
                "clear_after_fetch": ["unset AO2_CP_AUTH_VALUE", "Remove-Item Env:AO2_CP_AUTH_VALUE"]
            }
        },
    }))
}

pub(super) fn release_support_verifier_handoff_value(
    bundle: &serde_json::Value,
    keep_latest: usize,
) -> Result<serde_json::Value, AppError> {
    let verification = release_support_bundle_verification_value(bundle)?;
    let release = bundle
        .get("release")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let bundle_sha256 = json_str(&verification, "bundle_sha256").unwrap_or("missing");
    let checks = verification
        .get("checks")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let blockers = verification
        .get("blockers")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let verification_status = json_str(&verification, "status").unwrap_or("failed");
    let trust_boundary_status = verification
        .get("trust_boundary_check")
        .and_then(|trust| json_str(trust, "status"))
        .unwrap_or("failed");

    Ok(serde_json::json!({
        "schema_version": RELEASE_SUPPORT_VERIFIER_HANDOFF_SCHEMA,
        "status": if verification_status == "passed" && trust_boundary_status == "passed" {
            "passed"
        } else {
            "attention"
        },
        "generated_from": RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA,
        "keep_latest": keep_latest,
        "release": {
            "version": json_str(&release, "version").unwrap_or("unknown"),
            "release_tag": json_str(&release, "release_tag").unwrap_or("unknown"),
            "status": json_str(&release, "status").unwrap_or("unknown"),
        },
        "bundle_sha256": bundle_sha256,
        "verification": {
            "schema_version": RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA,
            "status": verification_status,
            "trust_boundary_status": trust_boundary_status,
            "surface_count": verification
                .get("surface_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            "blocker_count": blockers.as_array().map(Vec::len).unwrap_or(0),
        },
        "checks": checks,
        "blockers": blockers,
        "release_acceptance_owner": "factory-v3 evaluator-closer",
        "control_plane_role": "read_only_observer",
        "mutates_ao_artifacts": false,
        "control_plane_approves_release": false,
        "safe_for_scheduler_indexing": true,
        "contains_bearer_token": false,
        "handoff_summary": {
            "purpose": "Hermes/factory-v3 operator handoff for AO2 Control Plane verifier output",
            "trust_boundary": "observer verifier summary only; factory-v3 evaluator-closer remains release acceptance owner",
            "next_action": if verification_status == "passed" && trust_boundary_status == "passed" {
                "factory-v3 evaluator-closer may review this verifier handoff alongside AO2 signed evidence"
            } else {
                "resolve support-bundle verifier blockers before evaluator-closer review"
            },
        },
        "links": {
            "release_support_verifier_handoff_json": format!("/api/v1/release/support-bundle/handoff.json?keep_latest={keep_latest}"),
            "release_support_verifier_handoff_html": format!("/api/v1/release/support-bundle/handoff?keep_latest={keep_latest}"),
            "release_support_bundle_verify_json": format!("/api/v1/release/support-bundle/verify.json?keep_latest={keep_latest}"),
            "release_support_bundle_manifest": format!("/api/v1/release/support-bundle/manifest?keep_latest={keep_latest}"),
            "release_support_bundle_json": format!("/api/v1/release/support-bundle.json?keep_latest={keep_latest}"),
        },
    }))
}

pub(super) fn release_support_bundle_checksums_text(
    bundle: &serde_json::Value,
) -> Result<String, AppError> {
    let verification = release_support_bundle_verification_value(bundle)?;
    let filename = release_support_bundle_filename(bundle);
    let bundle_sha256 = json_str(&verification, "bundle_sha256").unwrap_or("missing");

    let mut lines = vec![
        "# ao2-control-plane release support bundle SHA256SUMS".to_string(),
        "# schema: ao2.cp-release-support-bundle-checksums.v1".to_string(),
        "# algorithm: sha256-ao2-cp-canonical-json-v1".to_string(),
        "# control-plane-role: read-only-observer".to_string(),
        "# mutates-ao-artifacts: false".to_string(),
        "# release-acceptance-owner: factory-v3 evaluator-closer".to_string(),
        format!("{bundle_sha256}  {filename}"),
    ];

    for check in verification
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = json_str(check, "id").unwrap_or("missing");
        let digest = json_str(check, "recomputed_sha256").unwrap_or("missing");
        lines.push(format!("{digest}  surfaces/{id}.json"));
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
}

pub(super) fn release_support_bundle_verification_value(
    bundle: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    let bundle_sha256 = support_bundle_surface_sha256(bundle)?;
    let surfaces = bundle
        .get("portable_bundle_manifest")
        .and_then(|manifest| manifest.get("included_surfaces"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let expected_sha256s = bundle
        .get("portable_bundle_manifest")
        .and_then(|manifest| manifest.get("integrity"))
        .and_then(|integrity| integrity.get("surface_sha256"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let mut checks = Vec::new();
    let mut blockers = Vec::new();
    if bundle
        .get("portable_bundle_manifest")
        .and_then(|manifest| json_str(manifest, "schema_version"))
        != Some(RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA)
    {
        blockers.push(format!(
            "portable_bundle_manifest.schema_version: expected {RELEASE_SUPPORT_BUNDLE_MANIFEST_SCHEMA}"
        ));
    }
    let required_ids = SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut seen_ids = std::collections::BTreeSet::new();
    for surface in surfaces {
        let id = json_str(&surface, "id").unwrap_or("missing");
        let path = json_str(&surface, "path").unwrap_or("missing");
        let expected_path = support_bundle_surface_path_by_id(id).unwrap_or("missing");
        let declared_schema = json_str(&surface, "schema_version").unwrap_or("missing");
        let manifest_sha = json_str(&surface, "sha256").unwrap_or("missing");
        let integrity_sha = json_str(&expected_sha256s, id).unwrap_or("missing");
        if !required_ids.contains(id) {
            blockers.push(format!("{id}: unknown support-bundle surface id"));
        }
        if !seen_ids.insert(id.to_string()) {
            blockers.push(format!("{id}: duplicate support-bundle surface id"));
        }
        let embedded = support_bundle_surface_by_id(bundle, id);
        let embedded_schema = embedded
            .and_then(|value| json_str(value, "schema_version"))
            .unwrap_or("missing");
        let recomputed_sha = match embedded {
            Some(value) => support_bundle_surface_sha256(value)?,
            None => "missing".to_string(),
        };
        let status = if embedded.is_some()
            && manifest_sha != "missing"
            && path != "missing"
            && path == expected_path
            && integrity_sha != "missing"
            && manifest_sha == integrity_sha
            && manifest_sha == recomputed_sha
            && declared_schema == embedded_schema
        {
            "passed"
        } else {
            blockers.push(format!(
                "{id}: expected manifest/integrity/recomputed digests and schemas to match for {path}"
            ));
            "failed"
        };
        if id == "hosted_release_smoke" {
            if let Some(embedded) = embedded {
                blockers.extend(hosted_release_smoke_blockers(embedded));
            }
        }
        checks.push(serde_json::json!({
            "id": id,
            "path": path,
            "expected_path": expected_path,
            "declared_schema_version": declared_schema,
            "embedded_schema_version": embedded_schema,
            "manifest_sha256": manifest_sha,
            "integrity_sha256": integrity_sha,
            "recomputed_sha256": recomputed_sha,
            "status": status,
        }));
    }

    if checks.len() != SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len() {
        blockers.push(format!(
            "portable_bundle_manifest: expected {} included surfaces, found {}",
            SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len(),
            checks.len()
        ));
    }
    for required_id in SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS {
        if !seen_ids.contains(required_id) {
            blockers.push(format!(
                "{required_id}: missing required support-bundle surface"
            ));
        }
        if json_str(&expected_sha256s, required_id).is_none() {
            blockers.push(format!(
                "{required_id}: missing required integrity.surface_sha256 entry"
            ));
        }
    }
    if let Some(surface_count) = bundle
        .get("portable_bundle_manifest")
        .and_then(|manifest| manifest.get("integrity"))
        .and_then(|integrity| integrity.get("verification_plan"))
        .and_then(|plan| plan.get("surface_count"))
        .and_then(serde_json::Value::as_u64)
    {
        if surface_count != SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len() as u64 {
            blockers.push(format!(
                "verification_plan.surface_count: expected {}, found {surface_count}",
                SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS.len()
            ));
        }
    } else {
        blockers.push("verification_plan.surface_count: missing".to_string());
    }

    let trust_boundary = bundle
        .get("trust_boundary")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let trust_boundary_status = if json_str(&trust_boundary, "role") == Some("read_only_observer")
        && trust_boundary
            .get("mutates_ao_artifacts")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    {
        "passed"
    } else {
        blockers.push(
            "trust_boundary: expected read_only_observer and mutates_ao_artifacts=false"
                .to_string(),
        );
        "failed"
    };

    Ok(serde_json::json!({
        "schema_version": RELEASE_SUPPORT_BUNDLE_VERIFICATION_SCHEMA,
        "status": if blockers.is_empty() { "passed" } else { "failed" },
        "bundle_sha256": bundle_sha256,
        "algorithm": "sha256-ao2-cp-canonical-json-v1",
        "surface_count": checks.len(),
        "checks": checks,
        "blockers": blockers,
        "trust_boundary_check": {
            "status": trust_boundary_status,
            "role": json_str(&trust_boundary, "role").unwrap_or("missing"),
            "mutates_ao_artifacts": trust_boundary
                .get("mutates_ao_artifacts")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true),
            "control_plane_approves_release": false,
        },
        "operator_handoff": {
            "control_plane_role": "read_only_observer",
            "release_acceptance_owner": "factory-v3 evaluator-closer",
            "verification_scope": "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval",
        },
    }))
}

pub(super) fn support_bundle_surface_by_id<'a>(
    bundle: &'a serde_json::Value,
    id: &str,
) -> Option<&'a serde_json::Value> {
    match id {
        "release_assembly" => bundle.get("release_assembly"),
        "release_readiness" => bundle.get("readiness"),
        "release_candidate_handoff" => bundle.get("handoff"),
        "release_cockpit" => bundle.get("cockpit"),
        "release_evaluator_decision" => bundle.get("evaluator_decision"),
        "hosted_release_smoke" => bundle.get("hosted_release_smoke"),
        "install_verification" => bundle.get("install_verification"),
        "ci_evidence_index" => bundle.get("ci_evidence_index"),
        "storage_support_bundle" => bundle.get("storage_support"),
        _ => None,
    }
}

pub(super) fn support_bundle_surface_path_by_id(id: &str) -> Option<&'static str> {
    match id {
        "release_assembly" => Some("$.release_assembly"),
        "release_readiness" => Some("$.readiness"),
        "release_candidate_handoff" => Some("$.handoff"),
        "release_cockpit" => Some("$.cockpit"),
        "release_evaluator_decision" => Some("$.evaluator_decision"),
        "hosted_release_smoke" => Some("$.hosted_release_smoke"),
        "install_verification" => Some("$.install_verification"),
        "ci_evidence_index" => Some("$.ci_evidence_index"),
        "storage_support_bundle" => Some("$.storage_support"),
        _ => None,
    }
}

fn hosted_release_smoke_blockers(surface: &serde_json::Value) -> Vec<String> {
    let mut blockers = Vec::new();
    if json_str(surface, "schema_version") != Some("ao2.release-archive-hosted-smoke.v1") {
        blockers.push(
            "hosted_release_smoke.schema_version: expected ao2.release-archive-hosted-smoke.v1"
                .to_string(),
        );
    }
    if json_str(surface, "status") != Some("passed") {
        blockers.push("hosted_release_smoke.status: expected passed".to_string());
    }
    if json_str(surface, "install_verification_schema")
        != Some("ao2.install-verification-evidence.v1")
    {
        blockers.push(
            "hosted_release_smoke.install_verification_schema: expected ao2.install-verification-evidence.v1"
                .to_string(),
        );
    }
    if json_str(surface, "install_verification_evidence")
        .filter(|value| !value.is_empty())
        .is_none()
    {
        blockers.push(
            "hosted_release_smoke.install_verification_evidence: expected non-empty string"
                .to_string(),
        );
    }
    for field_name in [
        "provider_api_keys_required",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
    ] {
        if surface.get(field_name).and_then(serde_json::Value::as_bool) != Some(false) {
            blockers.push(format!("hosted_release_smoke.{field_name}: expected false"));
        }
    }
    if json_str(surface, "release_acceptance_owner") != Some("factory-v3 evaluator-closer") {
        blockers.push(
            "hosted_release_smoke.release_acceptance_owner: expected factory-v3 evaluator-closer"
                .to_string(),
        );
    }
    blockers
}

pub(super) fn support_bundle_surface_sha256<T: Serialize>(surface: &T) -> Result<String, AppError> {
    let value = serde_json::to_value(surface).map_err(|e| AppError::Internal(e.to_string()))?;
    sha256_of_canonical(&value).map_err(|e| AppError::Internal(e.to_string()))
}
