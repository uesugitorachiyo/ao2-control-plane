//! Contract coverage for `AppError::into_response`.
//!
//! This is the single chokepoint that turns every server-side error into an
//! HTTP status + a `ControlPlaneError` JSON envelope. The envelope *struct*
//! is unit-tested in the schema crate, but the *mapping* — which variant
//! becomes which status, which `ErrorCode`, what message, and what `details`
//! — was never pinned. Two properties matter beyond "it returns an error":
//!
//!   1. Status codes are part of the API contract (clients branch on 404 vs
//!      422 vs 507). A silent reshuffle would break callers without a
//!      compile error.
//!   2. `BundleTampered` is the one variant whose human-readable message is
//!      deliberately redacted to a generic string — the expected/actual
//!      digests are confined to `details`, never interpolated into `message`.
//!      That's an information-shape decision worth a regression guard.
//!
//! `into_response` consumes `self` and is synchronous, but reading the body
//! out of an axum `Response` is async, hence `#[tokio::test]`.

use ao2_cp_server::error::AppError;
use axum::response::IntoResponse;
use serde_json::Value;

/// Render an `AppError` and pull back `(status, parsed JSON body)`.
async fn render(err: AppError) -> (u16, Value) {
    let resp = err.into_response();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body must be readable");
    let json: Value = serde_json::from_slice(&bytes).expect("body must be valid JSON");
    (status, json)
}

#[tokio::test]
async fn each_variant_maps_to_its_contracted_status_code_message_and_error_code() {
    // (constructed error, expected status, expected `code`, expected `message`)
    let cases = vec![
        (AppError::Unauthorized, 401, "unauthorized", "unauthorized"),
        (
            AppError::Forbidden("prune is disabled".into()),
            403,
            "forbidden",
            "forbidden: prune is disabled",
        ),
        (
            AppError::BadRequest("missing provider".into()),
            400,
            "bad_request",
            "bad request: missing provider",
        ),
        (
            AppError::SchemaUnknown("ao2.bogus.v9".into()),
            422,
            "schema_unknown",
            "unknown schema: ao2.bogus.v9",
        ),
        (
            AppError::SchemaInvalid("field x".into()),
            422,
            "schema_invalid",
            "schema invalid: field x",
        ),
        (
            AppError::BodyTooLarge,
            413,
            "body_too_large",
            "body too large",
        ),
        (AppError::NotFound, 404, "not_found", "not found"),
        (AppError::StorageFull, 507, "storage_full", "storage full"),
        (
            AppError::Internal("db unavailable".into()),
            500,
            "internal",
            // Deliberately generic: the wrapped detail ("db unavailable") is
            // redacted from the client and logged server-side instead. See
            // internal_error_never_leaks_its_detail_into_the_response.
            "internal server error",
        ),
    ];

    for (err, want_status, want_code, want_message) in cases {
        let (status, body) = render(err).await;
        assert_eq!(status, want_status, "status for code {want_code}");
        assert_eq!(body["code"], want_code, "error code");
        assert_eq!(body["message"], want_message, "message for {want_code}");
        // Every envelope is self-describing and request-correlated.
        assert_eq!(body["schema_version"], "ao2.control-plane-error.v1");
        assert!(
            body["request_id"].as_str().is_some_and(|s| !s.is_empty()),
            "request_id must be a non-empty string for {want_code}"
        );
    }
}

#[tokio::test]
async fn null_detail_variants_omit_the_details_field_entirely() {
    // `details` is `skip_serializing_if = is_null`, so error bodies that carry
    // no structured detail must not even emit the key — clients can rely on its
    // presence meaning "there is structured detail here".
    for err in [
        AppError::Unauthorized,
        AppError::NotFound,
        AppError::BodyTooLarge,
    ] {
        let (_, body) = render(err).await;
        assert!(
            body.get("details").is_none(),
            "details key must be absent when there is no structured detail"
        );
    }
}

#[tokio::test]
async fn bundle_tampered_redacts_digests_from_message_but_preserves_them_in_details() {
    // The security-relevant invariant: the human-readable message is a fixed
    // generic string, and the only place the (attacker-influenceable) digest
    // values appear is the structured `details` object. If a refactor ever
    // routed `self.to_string()` into `message`, the raw "expected X, got Y"
    // hashes would leak into the human message — this guards against that.
    let expected = "a".repeat(64);
    let actual = "b".repeat(64);
    let (status, body) = render(AppError::BundleTampered {
        expected: expected.clone(),
        actual: actual.clone(),
    })
    .await;

    assert_eq!(status, 500);
    assert_eq!(body["code"], "bundle_tampered");
    assert_eq!(
        body["message"], "bundle digest mismatch",
        "message must be the generic redacted form"
    );
    let message = body["message"].as_str().unwrap();
    assert!(
        !message.contains(&expected) && !message.contains(&actual),
        "neither digest may appear in the human-readable message"
    );
    // The digests are still available for diagnostics — in details only.
    assert_eq!(body["details"]["expected"], expected);
    assert_eq!(body["details"]["actual"], actual);
}

#[tokio::test]
async fn internal_error_never_leaks_its_detail_into_the_response() {
    // `AppError::Internal` wraps raw lower-level error text — serde messages, IO
    // errors, absolute file paths — captured at dozens of `.map_err(|e|
    // AppError::Internal(e.to_string()))` call sites. That detail must never
    // reach the client: the human message is a fixed generic string, and the
    // wrapped detail must appear *nowhere* in the rendered body (message,
    // details, or any field). The real detail is emitted to the server log
    // (correlated by request_id) instead — see error.rs.
    let secret_detail = "open /etc/ao2/secret.key: no such file or directory";
    let (status, body) = render(AppError::Internal(secret_detail.into())).await;

    assert_eq!(status, 500);
    assert_eq!(body["code"], "internal");
    assert_eq!(
        body["message"], "internal server error",
        "message must be the generic redacted form, not the wrapped detail"
    );
    // Belt-and-suspenders: scan the whole serialized envelope for any fragment
    // of the leaked path, so a future refactor that routes the detail into
    // `details` (or anywhere else) is also caught.
    let serialized = body.to_string();
    assert!(
        !serialized.contains("/etc/ao2") && !serialized.contains("secret.key"),
        "internal detail must not appear anywhere in the response body: {serialized}"
    );
}

#[tokio::test]
async fn schema_unknown_reports_the_offending_version_in_details() {
    let (status, body) = render(AppError::SchemaUnknown("ao2.acceptance.v999".into())).await;
    assert_eq!(status, 422);
    assert_eq!(body["details"]["schema_version"], "ao2.acceptance.v999");
}

#[tokio::test]
async fn body_round_trips_as_the_canonical_control_plane_error_struct() {
    // `ControlPlaneError` uses `deny_unknown_fields`; deserializing the live
    // response into it proves the wire body conforms exactly to the published
    // schema (no stray fields, all required fields present).
    let resp = AppError::SchemaInvalid("provider must be a string".into()).into_response();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: ao2_cp_schema::error::ControlPlaneError =
        serde_json::from_slice(&bytes).expect("body must satisfy the ControlPlaneError schema");
    assert_eq!(parsed.code, ao2_cp_schema::error::ErrorCode::SchemaInvalid);
    assert!(!parsed.request_id.is_empty());
}
