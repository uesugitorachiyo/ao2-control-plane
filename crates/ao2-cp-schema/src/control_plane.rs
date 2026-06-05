use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA: &str = "ao2.control-plane-fleet-bundle.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneBundle {
    pub schema_version: String,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum ControlPlaneBundleParseError {
    #[error("json parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("expected schema_version {expected}, got {actual}")]
    WrongSchema { expected: String, actual: String },
}

pub fn parse_control_plane_bundle(
    raw: &str,
) -> Result<ControlPlaneBundle, ControlPlaneBundleParseError> {
    let bundle: ControlPlaneBundle = serde_json::from_str(raw)?;
    if bundle.schema_version != SCHEMA {
        return Err(ControlPlaneBundleParseError::WrongSchema {
            expected: SCHEMA.to_string(),
            actual: bundle.schema_version.clone(),
        });
    }
    Ok(bundle)
}

pub fn is_control_plane_bundle_schema(schema_version: &str) -> bool {
    schema_version == SCHEMA
}
