use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry};
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::error::AppError;
use crate::handlers::caching;
use crate::server::AppState;
use crate::signing::{sha256_hex, verify_rsa_sha256_signature};

use super::{
    trust_boundary, validate_sha, view::json_str, RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA,
    RELEASE_EVALUATOR_DECISION_SCHEMA, RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA,
};

pub(super) fn validate_release_evaluator_decision(
    decision: &serde_json::Value,
) -> Result<(), AppError> {
    let schema = decision
        .get("schema")
        .or_else(|| decision.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != RELEASE_EVALUATOR_DECISION_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema {RELEASE_EVALUATOR_DECISION_SCHEMA}, got {schema}"
        )));
    }
    for key in ["status", "decision", "next_action"] {
        if decision
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "release evaluator decision missing {key}"
            )));
        }
    }
    let release = decision
        .get("release")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::SchemaInvalid("release evaluator decision missing release".into())
        })?;
    for key in ["version", "release_tag", "sha256"] {
        if release
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err(AppError::SchemaInvalid(format!(
                "release evaluator decision release missing {key}"
            )));
        }
    }
    let blockers = decision
        .get("blockers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            AppError::SchemaInvalid("release evaluator decision missing blockers array".into())
        })?;
    let checks = decision
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            AppError::SchemaInvalid("release evaluator decision missing checks array".into())
        })?;
    if checks.is_empty() {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision checks must not be empty".into(),
        ));
    }
    let trust_boundary = decision
        .get("trust_boundary")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::SchemaInvalid("release evaluator decision missing trust_boundary".into())
        })?;
    if trust_boundary
        .get("control_plane_role")
        .and_then(serde_json::Value::as_str)
        != Some("read_only_observer")
    {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision trust_boundary.control_plane_role must be read_only_observer"
                .into(),
        ));
    }
    if trust_boundary
        .get("mutates_ao_artifacts")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision must not let the control plane mutate AO artifacts".into(),
        ));
    }
    if trust_boundary
        .get("control_plane_approves_release")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision must keep release approval outside the control plane"
                .into(),
        ));
    }
    if trust_boundary
        .get("release_acceptance_owner")
        .and_then(serde_json::Value::as_str)
        != Some("factory-v3 evaluator-closer")
    {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision owner must be factory-v3 evaluator-closer".into(),
        ));
    }
    if json_str(decision, "status") == Some("accepted") && !blockers.is_empty() {
        return Err(AppError::SchemaInvalid(
            "accepted release evaluator decision must not contain blockers".into(),
        ));
    }
    Ok(())
}

pub(super) async fn latest_release_evaluator_decision_entry_value(
    state: &AppState,
) -> Result<Option<(IndexEntry, serde_json::Value)>, AppError> {
    let mut entries = release_evaluator_decision_entries(state).await?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let value = read_release_evaluator_decision_value(state, &entry.sha256).await?;
    Ok(Some((entry, value)))
}

async fn release_evaluator_decision_entries(state: &AppState) -> Result<Vec<IndexEntry>, AppError> {
    let mut entries = state
        .storage
        .index
        .read_all()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    entries.retain(|entry| entry.schema == RELEASE_EVALUATOR_DECISION_SCHEMA);
    Ok(entries)
}

async fn read_release_evaluator_decision_value(
    state: &AppState,
    sha: &str,
) -> Result<serde_json::Value, AppError> {
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ReleaseEvaluatorDecision, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))
}

pub(super) async fn get_release_evaluator_decision_by_sha_cached(
    state: &AppState,
    sha: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    caching::validate_sha(sha)?;
    let etag = caching::format_etag(sha);
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ReleaseEvaluatorDecision, sha)
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

pub(super) async fn get_release_evaluator_decision_signature_by_sha(
    state: &AppState,
    sha: &str,
) -> Result<Response, AppError> {
    validate_sha(sha)?;
    let bytes = state
        .storage
        .bundles
        .read(BundleKind::ReleaseEvaluatorDecisionSignature, sha)
        .await
        .map_err(|_| AppError::NotFound)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some(RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA)
    {
        return Err(AppError::SchemaInvalid(
            "release evaluator decision signature sidecar schema mismatch".into(),
        ));
    }
    if value
        .get("release_evaluator_decision_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(sha)
    {
        return Err(AppError::BundleTampered {
            expected: sha.to_string(),
            actual: value
                .get("release_evaluator_decision_sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("missing")
                .to_string(),
        });
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

pub(super) async fn release_evaluator_decision_signature_value(
    state: &AppState,
    sha: &str,
) -> Result<Option<serde_json::Value>, AppError> {
    validate_sha(sha)?;
    let bytes = match state
        .storage
        .bundles
        .read(BundleKind::ReleaseEvaluatorDecisionSignature, sha)
        .await
    {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Some(value))
}

pub(super) async fn release_evaluator_decision_dashboard_value(
    state: &AppState,
) -> Result<serde_json::Value, AppError> {
    let Some((entry, decision)) = latest_release_evaluator_decision_entry_value(state).await?
    else {
        return Ok(serde_json::json!({
            "schema_version": RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA,
            "state": "missing",
            "next_action": "publish the Factory v3 evaluator-closer release decision artifact",
            "latest": null,
            "blockers": [],
            "trust_boundary": trust_boundary(),
            "links": release_evaluator_decision_links(),
        }));
    };
    let decision_value = json_str(&decision, "decision").unwrap_or("missing");
    let status = json_str(&decision, "status").unwrap_or("missing");
    let blockers = decision
        .get("blockers")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let state_value = if status == "accepted" && decision_value == "accept_phase1_release_candidate"
    {
        "accepted"
    } else if status == "rejected" || decision_value == "reject_phase1_release_candidate" {
        "rejected"
    } else {
        "attention"
    };
    let signature = release_evaluator_decision_signature_value(state, &entry.sha256).await?;
    let signature_verified = signature
        .as_ref()
        .and_then(|value| value.get("signature"))
        .and_then(|value| value.get("signature_verified"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // Whether the decision was signed by a pinned trust-anchor key.
    // Defaults to false: a cryptographically-valid signature from an
    // unpinned key is observer-only metadata, not an authoritative
    // release acceptance.
    let release_authoritative = signature
        .as_ref()
        .and_then(|value| value.get("signature"))
        .and_then(|value| value.get("trust_policy"))
        .and_then(|value| value.get("release_authoritative"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(serde_json::json!({
        "schema_version": RELEASE_EVALUATOR_DECISION_DASHBOARD_SCHEMA,
        "state": state_value,
        "next_action": if state_value == "accepted" {
            "observe final release publication and install/download health"
        } else {
            "resolve evaluator decision blockers before release-line handoff"
        },
        "latest": {
            "sha256": entry.sha256,
            "ingested_at": entry.ingested_at,
            "status": status,
            "decision": decision_value,
            "release": decision.get("release").cloned().unwrap_or_else(|| serde_json::json!({})),
            "raw_url": format!("/api/v1/release/evaluator-decision/{}", entry.sha256),
            "signature_url": format!("/api/v1/release/evaluator-decision/{}/signature", entry.sha256),
            "signature_verified": signature_verified,
            "release_authoritative": release_authoritative,
        },
        "blockers": blockers,
        "evidence": decision.get("evidence").cloned().unwrap_or_else(|| serde_json::json!({})),
        "trust_boundary": trust_boundary(),
        "links": release_evaluator_decision_links(),
    }))
}

fn release_evaluator_decision_links() -> serde_json::Value {
    serde_json::json!({
        "dashboard": "/api/v1/release/evaluator-decision/dashboard",
        "dashboard_json": "/api/v1/release/evaluator-decision/dashboard.json",
        "latest_release_evaluator_decision": "/api/v1/release/evaluator-decision/latest",
        "release_cockpit": "/api/v1/release/cockpit",
        "release_readiness": "/api/v1/release/readiness",
    })
}

/// Cryptographically verify the evaluator-decision signature, then
/// classify the signing key against the configured trust anchor.
///
/// Returns a JSON object of trust-annotation fields to merge into the
/// stored signature. Mirrors `verified_provider_readiness_signature`:
/// a valid signature whose `public_key_sha256` is NOT in
/// `trusted_key_sha256s` is recorded as `cryptographic-only` with
/// `release_authoritative: false`. The control plane is a read-only
/// observer — it records the decision either way, but only a
/// pinned-key decision is marked release-authoritative. Without this,
/// any holder of the API token could mint a self-signed "decision" that
/// downstream surfaces could not distinguish from the real
/// evaluator-closer's.
pub(super) fn verify_release_evaluator_decision_signature(
    decision_raw: &str,
    signature: &serde_json::Value,
    trusted_key_sha256s: &[String],
) -> Result<serde_json::Value, AppError> {
    let schema = signature
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA {
        return Err(AppError::SchemaUnknown(format!(
            "expected schema_version {RELEASE_EVALUATOR_DECISION_SIGNATURE_SCHEMA}, got {schema}"
        )));
    }
    let algorithm = signature
        .get("signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if algorithm != "RSA/SHA-256" {
        return Err(AppError::SchemaInvalid(format!(
            "unsupported release evaluator decision signature algorithm: {algorithm}"
        )));
    }
    let signature_hex = required_release_evaluator_signature_string(signature, "signature_hex")?;
    let public_key_pem = required_release_evaluator_signature_string(signature, "public_key_pem")?;
    let signature_bytes = decode_release_evaluator_signature_hex(signature_hex)?;

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

    verify_release_evaluator_rsa_sha256_signature(
        decision_raw.as_bytes(),
        &signature_bytes,
        public_key_pem,
    )?;

    // Signature is cryptographically valid. Now classify the signing key
    // against the configured trust anchor. A key not in the pinned set
    // is observer-only metadata, never release-authoritative.
    let public_key_sha256 = sha256_hex(public_key_pem.as_bytes());
    let trusted_key_match = trusted_key_sha256s
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(&public_key_sha256));
    let (verification_scope, trust_anchor, policy, matched_public_key_sha256) = if trusted_key_match
    {
        (
            "cryptographic-and-pinned-key",
            "configured-release-evaluator-decision-public-key-sha256",
            "pinned-public-key-sha256",
            public_key_sha256.as_str(),
        )
    } else {
        (
            "cryptographic-only",
            "upload-public-key-not-authority",
            "observer-only-upload-key",
            "",
        )
    };

    Ok(serde_json::json!({
        "signature_verified": true,
        "public_key_sha256": public_key_sha256,
        "verification_scope": verification_scope,
        "trust_anchor": trust_anchor,
        "trust_policy": {
            "policy": policy,
            "trusted_key_match": trusted_key_match,
            "release_authoritative": trusted_key_match,
            "matched_public_key_sha256": matched_public_key_sha256
        }
    }))
}

fn required_release_evaluator_signature_string<'a>(
    signature: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AppError> {
    signature
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::SchemaInvalid(format!("signed release evaluator decision missing {field}"))
        })
}

pub(super) fn decode_release_evaluator_signature_hex(value: &str) -> Result<Vec<u8>, AppError> {
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

/// Thin wrapper over [`crate::signing::verify_rsa_sha256_signature`] that
/// preserves this handler's domain-specific name. The shared helper carries the
/// audited verification logic; this name keeps call sites (and the
/// release-publication regression tests) self-documenting about what is being
/// verified.
pub(super) fn verify_release_evaluator_rsa_sha256_signature(
    decision_bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<(), AppError> {
    verify_rsa_sha256_signature(decision_bytes, signature_bytes, public_key_pem)
}
