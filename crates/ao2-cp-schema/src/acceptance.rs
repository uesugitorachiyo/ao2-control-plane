use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_CODEX: &str = "ao2.codex-provider-pilot-acceptance.v1";
const SCHEMA_CLAUDE: &str = "ao2.claude-provider-pilot-acceptance.v1";
const SCHEMA_ANTIGRAVITY: &str = "ao2.antigravity-provider-pilot-acceptance.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcceptanceProvider {
    Codex,
    Claude,
    Antigravity,
}

impl AcceptanceProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            AcceptanceProvider::Codex => "codex",
            AcceptanceProvider::Claude => "claude",
            AcceptanceProvider::Antigravity => "antigravity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceBundle {
    pub schema_version: String,
    pub status: String,
    pub provider: AcceptanceProvider,
    pub run_id: String,
    pub root: String,
    pub target: String,
    pub provider_prompt_file: String,
    pub evidence_pack: String,
    pub cockpit: String,
    pub artifacts: serde_json::Value,
    pub smoke: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum AcceptanceParseError {
    #[error("json parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown schema_version: {0}")]
    UnknownSchema(String),
    #[error("provider {provider} does not match schema {schema}")]
    ProviderMismatch { provider: String, schema: String },
}

pub fn parse_acceptance(raw: &str) -> Result<AcceptanceBundle, AcceptanceParseError> {
    let bundle: AcceptanceBundle = serde_json::from_str(raw)?;
    let expected_provider = match bundle.schema_version.as_str() {
        SCHEMA_CODEX => AcceptanceProvider::Codex,
        SCHEMA_CLAUDE => AcceptanceProvider::Claude,
        SCHEMA_ANTIGRAVITY => AcceptanceProvider::Antigravity,
        other => return Err(AcceptanceParseError::UnknownSchema(other.to_string())),
    };
    if bundle.provider != expected_provider {
        return Err(AcceptanceParseError::ProviderMismatch {
            provider: bundle.provider.as_str().to_string(),
            schema: bundle.schema_version.clone(),
        });
    }
    Ok(bundle)
}

pub fn is_acceptance_schema(schema_version: &str) -> bool {
    schema_version == SCHEMA_CODEX
        || schema_version == SCHEMA_CLAUDE
        || schema_version == SCHEMA_ANTIGRAVITY
}
