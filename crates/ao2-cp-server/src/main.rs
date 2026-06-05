use ao2_cp_server::audit_log::AuditLog;
use ao2_cp_server::config::{Config, ConfigError};
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::{build_router, AppState};
use ao2_cp_storage::Storage;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = match Config::from_real_env() {
        Ok(c) => c,
        Err(ConfigError::Clap(e))
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            e.print()?;
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(78);
        }
    };

    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::new(&cfg.log_level))
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), bind = %cfg.bind, data_dir = %cfg.data_dir.display(), "starting ao2-cp-server");

    let storage = Storage::open(cfg.data_dir.clone()).await?;

    let audit_log = match cfg.audit_log_file.as_deref() {
        Some(path) => {
            let log = match cfg.audit_log_max_bytes {
                Some(max) => {
                    let log = AuditLog::with_persistence_rotated(cfg.audit_log_capacity, path, max)
                        .map_err(|e| anyhow::anyhow!("audit_log_file {}: {e}", path.display()))?;
                    tracing::info!(
                        audit_log_file = %path.display(),
                        audit_log_max_bytes = max,
                        "audit-log persistence enabled with size-based rotation"
                    );
                    log
                }
                None => {
                    let log = AuditLog::with_persistence(cfg.audit_log_capacity, path)
                        .map_err(|e| anyhow::anyhow!("audit_log_file {}: {e}", path.display()))?;
                    tracing::info!(audit_log_file = %path.display(), "audit-log persistence enabled");
                    log
                }
            };
            log
        }
        None => AuditLog::new(cfg.audit_log_capacity),
    };

    let state = Arc::new(AppState {
        storage,
        api_token: cfg.api_token.clone(),
        max_body_bytes: cfg.max_body_bytes,
        provider_readiness_trusted_key_sha256s: cfg.provider_readiness_trusted_key_sha256s.clone(),
        release_evaluator_decision_trusted_key_sha256s: cfg
            .release_evaluator_decision_trusted_key_sha256s
            .clone(),
        signed_artifact_trusted_key_sha256s: cfg.signed_artifact_trusted_key_sha256s.clone(),
        metrics: Arc::new(Metrics::new()),
        audit_log: Arc::new(audit_log),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!(bind = %cfg.bind, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl_c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT received"),
        _ = terminate => tracing::info!("SIGTERM received"),
    }
}
