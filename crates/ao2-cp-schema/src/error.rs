use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SCHEMA_VERSION: &str = "ao2.control-plane-error.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Forbidden,
    BadRequest,
    SchemaUnknown,
    SchemaInvalid,
    BodyTooLarge,
    NotFound,
    StorageFull,
    BundleTampered,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneError {
    pub schema_version: String,
    pub code: ErrorCode,
    pub message: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl ControlPlaneError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            code,
            message: message.into(),
            request_id: Uuid::new_v4().to_string(),
            details: serde_json::Value::Null,
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}
