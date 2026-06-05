use ao2_cp_schema::error::{ControlPlaneError, ErrorCode};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unknown schema: {0}")]
    SchemaUnknown(String),
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    #[error("body too large")]
    BodyTooLarge,
    #[error("not found")]
    NotFound,
    #[error("storage full")]
    StorageFull,
    #[error("bundle tampered: expected {expected}, got {actual}")]
    BundleTampered { expected: String, actual: String },
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // `Internal` wraps raw lower-level error text (serde messages, IO
        // errors, absolute file paths) captured at the many
        // `.map_err(|e| AppError::Internal(e.to_string()))` call sites. We must
        // never surface that to the client, so its client-facing `message` is a
        // fixed generic string. The real detail is captured here and logged
        // server-side below, correlated by the envelope's `request_id`, so an
        // operator can still diagnose the failure from the logs.
        let mut internal_detail: Option<&str> = None;
        let (status, code, message, details) = match &self {
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                // The message is operator-authored remediation text (no internal
                // detail), so it is safe to surface to the caller.
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::BadRequest(_) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::BadRequest,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::SchemaUnknown(s) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::SchemaUnknown,
                self.to_string(),
                serde_json::json!({"schema_version": s}),
            ),
            AppError::SchemaInvalid(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::SchemaInvalid,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::BodyTooLarge,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::StorageFull => (
                StatusCode::INSUFFICIENT_STORAGE,
                ErrorCode::StorageFull,
                self.to_string(),
                serde_json::Value::Null,
            ),
            AppError::BundleTampered { expected, actual } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::BundleTampered,
                "bundle digest mismatch".to_string(),
                serde_json::json!({"expected": expected, "actual": actual}),
            ),
            AppError::Internal(detail) => {
                internal_detail = Some(detail.as_str());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::Internal,
                    "internal server error".to_string(),
                    serde_json::Value::Null,
                )
            }
        };

        let body = ControlPlaneError::new(code, message).with_details(details);
        if let Some(detail) = internal_detail {
            // Emit the redacted-from-client detail to the server log, keyed by
            // the same request_id that the client receives, so the generic 500
            // can be tied back to its root cause during diagnosis.
            tracing::error!(
                request_id = %body.request_id,
                detail = %detail,
                "internal server error"
            );
        }
        (status, Json(body)).into_response()
    }
}
