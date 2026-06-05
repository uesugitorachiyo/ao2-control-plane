use clap::Parser;
use std::path::PathBuf;
use thiserror::Error;

/// Minimum accepted API-token length (chars). A shorter token is
/// brute-forceable under the reverse-proxy / remote exposure SECURITY.md
/// contemplates, so it is rejected at startup rather than silently accepted.
const MIN_API_TOKEN_LEN: usize = 32;

#[derive(Debug, Parser)]
#[command(name = "ao2-cp-server", version)]
struct RawArgs {
    #[arg(long, env = "AO2_CP_BIND", default_value = "127.0.0.1:8744")]
    bind: String,

    #[arg(long, env = "AO2_CP_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,

    #[arg(long, env = "AO2_CP_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "AO2_CP_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "AO2_CP_MAX_BODY_BYTES", default_value = "10485760")]
    max_body_bytes: usize,

    /// Comma-separated provider-readiness public-key SHA-256 digests that may be treated as release-authoritative observer metadata.
    #[arg(
        long,
        env = "AO2_CP_PROVIDER_READINESS_TRUSTED_KEY_SHA256S",
        value_delimiter = ','
    )]
    provider_readiness_trusted_key_sha256s: Vec<String>,

    /// Comma-separated release-evaluator-decision signing public-key SHA-256 digests that may be treated as release-authoritative. A decision signed by a key NOT in this list is recorded as cryptographically-verified-only (`release_authoritative: false`) — it is never treated as an authoritative acceptance. Empty/unset = no signer is pinned, so every recorded decision is observer-only metadata.
    #[arg(
        long,
        env = "AO2_CP_RELEASE_EVALUATOR_DECISION_TRUSTED_KEY_SHA256S",
        value_delimiter = ','
    )]
    release_evaluator_decision_trusted_key_sha256s: Vec<String>,

    /// Comma-separated public-key SHA-256 digests trusted to sign AO2 evidence-ingest artifacts (phase-1 promotion decisions, provider registry, evidence packs, memory exports). A signature from a key NOT in this list still verifies cryptographically, but is recorded as observer-only (`release_authoritative: false`) and can never drive a release-authoritative display. Empty/unset = no signer pinned, so every such artifact is observer-only metadata.
    #[arg(
        long,
        env = "AO2_CP_SIGNED_ARTIFACT_TRUSTED_KEY_SHA256S",
        value_delimiter = ','
    )]
    signed_artifact_trusted_key_sha256s: Vec<String>,

    /// Maximum entries retained by the `/api/v1/audit-log` ring buffer.
    /// Each entry is roughly 200 bytes; 1024 ≈ 200 KiB resident.
    #[arg(long, env = "AO2_CP_AUDIT_LOG_CAPACITY", default_value = "1024")]
    audit_log_capacity: usize,

    /// Optional file path to which every audit-log entry is appended as
    /// newline-delimited JSON. Survives process restart (unlike the
    /// in-memory ring buffer). Empty / unset = disabled.
    #[arg(long, env = "AO2_CP_AUDIT_LOG_FILE")]
    audit_log_file: Option<PathBuf>,

    /// Size-based rotation threshold (bytes) for the audit-log NDJSON
    /// file. When the live file grows past this value, it is renamed
    /// to `<path>.1` (replacing any prior sidecar) and a fresh file is
    /// opened. Unset = no rotation (operator owns retention). Only
    /// meaningful in combination with `--audit-log-file`.
    #[arg(long, env = "AO2_CP_AUDIT_LOG_MAX_BYTES")]
    audit_log_max_bytes: Option<u64>,

    /// Run forbidden-env preflight. Enabled by default in main(); the flag exists so tests can opt in.
    #[arg(long, hide = true)]
    check_env: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub data_dir: PathBuf,
    pub api_token: String,
    pub log_level: String,
    pub max_body_bytes: usize,
    pub provider_readiness_trusted_key_sha256s: Vec<String>,
    pub release_evaluator_decision_trusted_key_sha256s: Vec<String>,
    pub signed_artifact_trusted_key_sha256s: Vec<String>,
    pub audit_log_capacity: usize,
    pub audit_log_file: Option<PathBuf>,
    pub audit_log_max_bytes: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required --api-token / AO2_CP_API_TOKEN")]
    MissingApiToken,
    #[error(
        "--api-token / AO2_CP_API_TOKEN is empty; an empty token would disable authentication"
    )]
    EmptyApiToken,
    #[error(
        "--api-token / AO2_CP_API_TOKEN is {0} chars; the minimum is 32 to resist brute force"
    )]
    WeakApiToken(usize),
    #[error("forbidden env var present: {0}")]
    ForbiddenEnv(String),
    #[error("clap parse: {0}")]
    Clap(#[from] clap::Error),
}

impl Config {
    pub fn parse_from<I, T>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let env: Vec<(String, String)> = std::env::vars().collect();
        Self::parse_with_env(args, env)
    }

    pub fn parse_with_env<I, T>(args: I, env: Vec<(String, String)>) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let raw = RawArgs::try_parse_from(args)?;
        let api_token = raw.api_token.ok_or(ConfigError::MissingApiToken)?;
        // An empty or whitespace-only token is `Some("")`, which slips past the
        // missing-token check above and would unauthenticate the whole API
        // surface; a too-short token is brute-forceable. Reject both at startup.
        if api_token.trim().is_empty() {
            return Err(ConfigError::EmptyApiToken);
        }
        if api_token.len() < MIN_API_TOKEN_LEN {
            return Err(ConfigError::WeakApiToken(api_token.len()));
        }

        if raw.check_env {
            for (k, _) in &env {
                if k == "OPENAI_API_KEY" || k == "ANTHROPIC_API_KEY" {
                    return Err(ConfigError::ForbiddenEnv(k.clone()));
                }
            }
        }

        Ok(Config {
            bind: raw.bind,
            data_dir: raw.data_dir,
            api_token,
            log_level: raw.log_level,
            max_body_bytes: raw.max_body_bytes,
            provider_readiness_trusted_key_sha256s: sanitize_sha256_list(
                raw.provider_readiness_trusted_key_sha256s,
            ),
            release_evaluator_decision_trusted_key_sha256s: sanitize_sha256_list(
                raw.release_evaluator_decision_trusted_key_sha256s,
            ),
            signed_artifact_trusted_key_sha256s: sanitize_sha256_list(
                raw.signed_artifact_trusted_key_sha256s,
            ),
            audit_log_capacity: raw.audit_log_capacity,
            audit_log_file: raw
                .audit_log_file
                .filter(|path| !path.as_os_str().is_empty()),
            audit_log_max_bytes: raw.audit_log_max_bytes,
        })
    }

    /// Convenience for main(): real env, full preflight including forbidden-env check.
    pub fn from_real_env() -> Result<Self, ConfigError> {
        let env: Vec<(String, String)> = std::env::vars().collect();
        let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        args.push("--check-env".into());
        Self::parse_with_env(args, env)
    }
}

fn sanitize_sha256_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .collect()
}
