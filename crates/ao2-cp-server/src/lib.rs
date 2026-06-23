//! ao2-cp-server: HTTP API surface for ao2-control-plane.
//!
//! ao2-control-plane is the **read-only observer** for AO2 evidence. Local
//! AO2 CLIs post signed acceptance bundles, control-plane bundles, memory
//! exports, evidence packs, provider readiness, release publication,
//! evaluator decisions, and Phase 1 promotion artifacts. The server
//! verifies cryptographic signatures where supplied, stores content by
//! canonical SHA-256, and renders authenticated dashboards plus
//! token-free portable handoff bundles.
//!
//! # Trust boundary
//! - The control plane **never** mutates AO2 artifacts or approves runs.
//! - Release acceptance lives with AO2's governed evaluator-closer, not here.
//! - Bearer tokens are accepted only via the `Authorization` header and
//!   never appear in URLs, logs, or response bodies.
//! - The preflight refuses to start if `OPENAI_API_KEY` or
//!   `ANTHROPIC_API_KEY` is present in the process environment.
//!
//! # Modules
//! - [`audit_log`] — bounded ring buffer of recent requests for the
//!   `/api/v1/audit-log` operator endpoint
//! - [`auth`] — bearer-token middleware and forbidden-env preflight
//! - [`config`] — clap-derived configuration with env + flag binding
//! - [`error`] — typed error responses with stable JSON shape
//! - [`handlers`] — per-route handler families (acceptance, memory,
//!   evidence pack, provider readiness, release publication, storage,
//!   Phase 1 promotion, release support bundle, etc.)
//! - [`route_catalog`] — canonical machine-readable route index for
//!   Hermes/front-end discovery
//! - [`server`] — Axum router assembly and shared [`server::AppState`]
pub mod audit_log;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod route_catalog;
pub mod server;
pub mod signing;
