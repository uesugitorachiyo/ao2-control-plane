//! Contract test for the `AppError` → HTTP response mapping.
//!
//! `AppError::into_response` is the single place every API error funnels
//! through, and its output is a public contract: clients branch on the HTTP
//! status and on the stable snake_case `code` string, and every error body is
//! expected to carry the `ao2.control-plane-error.v1` envelope (schema_version,
//! code, message, request_id, optional details). None of that was pinned by a
//! test — a reordered match arm or a renamed `ErrorCode` would silently break
//! every consumer while every existing handler test stayed green.
//!
//! This drives all nine variants through `into_response` and asserts the full
//! envelope, including the two variants that attach structured `details`
//! (`SchemaUnknown`, `BundleTampered`) and the deliberate sanitization of the
//! `BundleTampered` message (hashes live in `details`, not the human message).

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::collections::BTreeSet;

use ao2_cp_server::error::AppError;

const ERROR_SCHEMA_VERSION: &str = "ao2.control-plane-error.v1";

/// Render an `AppError` exactly as the server would and return the status plus
/// the parsed JSON envelope.
async fn render(err: AppError) -> (StatusCode, serde_json::Value) {
    let response = err.into_response();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error body must be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("error body must be valid JSON");
    (status, json)
}

/// Every rendered error must carry the stable envelope: the fixed
/// schema_version and a non-empty request_id for log correlation.
fn assert_envelope(json: &serde_json::Value) {
    assert_eq!(
        json["schema_version"], ERROR_SCHEMA_VERSION,
        "every error must carry the versioned envelope"
    );
    let request_id = json["request_id"]
        .as_str()
        .expect("request_id must be a string");
    assert!(
        !request_id.is_empty(),
        "request_id must be present for log correlation"
    );
}

#[tokio::test]
async fn unauthorized_maps_to_401() {
    let (status, json) = render(AppError::Unauthorized).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "unauthorized");
    assert_envelope(&json);
    // No structured details on this variant; the field is omitted when null.
    assert!(json.get("details").is_none());
}

#[tokio::test]
async fn bad_request_maps_to_400_and_echoes_reason() {
    let (status, json) = render(AppError::BadRequest("missing field x".into())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "bad_request");
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("missing field x"));
    assert_envelope(&json);
}

#[tokio::test]
async fn schema_unknown_maps_to_422_with_schema_version_detail() {
    let (status, json) = render(AppError::SchemaUnknown("ao2.bogus.v9".into())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["code"], "schema_unknown");
    // The offending schema version is surfaced in structured details so a
    // client can react without parsing the human message.
    assert_eq!(json["details"]["schema_version"], "ao2.bogus.v9");
    assert_envelope(&json);
}

#[tokio::test]
async fn schema_invalid_maps_to_422() {
    let (status, json) = render(AppError::SchemaInvalid(
        "signature verification failed".into(),
    ))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["code"], "schema_invalid");
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("signature verification failed"));
    assert_envelope(&json);
}

#[tokio::test]
async fn body_too_large_maps_to_413() {
    let (status, json) = render(AppError::BodyTooLarge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json["code"], "body_too_large");
    assert_envelope(&json);
}

#[tokio::test]
async fn not_found_maps_to_404() {
    let (status, json) = render(AppError::NotFound).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["code"], "not_found");
    assert_envelope(&json);
}

#[tokio::test]
async fn storage_full_maps_to_507() {
    let (status, json) = render(AppError::StorageFull).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(json["code"], "storage_full");
    assert_envelope(&json);
}

#[tokio::test]
async fn forbidden_maps_to_403_with_operator_remediation_message() {
    // `Forbidden` is the gate response for an operation the server policy
    // disables by default (e.g. remote destructive storage prune). The message
    // is operator-authored remediation text (no internal detail), so it is
    // surfaced to the caller to explain how to enable the action.
    let (status, json) = render(AppError::Forbidden(
        "destructive prune (execute=true) is disabled on this server".into(),
    ))
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["code"], "forbidden");
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("execute=true) is disabled"));
    assert_envelope(&json);
}

#[tokio::test]
async fn bundle_tampered_maps_to_500_with_sanitized_message_and_detail_hashes() {
    let (status, json) = render(AppError::BundleTampered {
        expected: "aaaa".into(),
        actual: "bbbb".into(),
    })
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "bundle_tampered");
    // The human message is deliberately generic; the expected/actual digests
    // are carried in details, not interpolated into the message.
    assert_eq!(json["message"], "bundle digest mismatch");
    assert_eq!(json["details"]["expected"], "aaaa");
    assert_eq!(json["details"]["actual"], "bbbb");
    assert_envelope(&json);
}

#[tokio::test]
async fn internal_maps_to_500() {
    let (status, json) = render(AppError::Internal("disk io failed".into())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "internal");
    assert_envelope(&json);
}

#[tokio::test]
async fn every_variant_has_a_distinct_code_and_request_ids_are_fresh() {
    // One representative per variant — the full set the contract must cover.
    let variants = vec![
        AppError::Unauthorized,
        AppError::Forbidden("x".into()),
        AppError::BadRequest("x".into()),
        AppError::SchemaUnknown("x".into()),
        AppError::SchemaInvalid("x".into()),
        AppError::BodyTooLarge,
        AppError::NotFound,
        AppError::StorageFull,
        AppError::BundleTampered {
            expected: "x".into(),
            actual: "y".into(),
        },
        AppError::Internal("x".into()),
    ];

    let mut codes = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    for variant in variants {
        let (_status, json) = render(variant).await;
        codes.insert(json["code"].as_str().unwrap().to_string());
        request_ids.insert(json["request_id"].as_str().unwrap().to_string());
    }

    // All ten codes are distinct: no two variants collide on the client-facing
    // discriminator.
    assert_eq!(
        codes.len(),
        10,
        "expected 10 distinct error codes, got {codes:?}"
    );
    // Each response is stamped with its own freshly generated request_id.
    assert_eq!(
        request_ids.len(),
        10,
        "each error response must carry a unique request_id"
    );
}
