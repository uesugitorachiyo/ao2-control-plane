use ao2_cp_storage::Storage;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Upper bound on how long any non-streaming request may run before the server
/// returns `408 Request Timeout`. Generous enough for signature verification
/// plus storage writes on large bundles, while bounding a hung or pathological
/// handler from holding a connection open indefinitely. The audit-log SSE
/// stream is deliberately exempt (see `build_router`).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of concurrent in-flight non-streaming requests. Past this the
/// layer applies backpressure (it does not reject); a waiter that then exceeds
/// `REQUEST_TIMEOUT` receives a 408. This caps unbounded memory/CPU fan-out
/// from a request flood without affecting the long-lived SSE stream.
const MAX_INFLIGHT_REQUESTS: usize = 512;

use crate::audit_log::{now_unix_micros, AuditEntry, AuditLog};
use crate::auth::require_token;
use crate::handlers;
use crate::metrics::{AuditLogSamples, Metrics};

pub struct AppState {
    pub storage: Storage,
    pub api_token: String,
    pub max_body_bytes: usize,
    pub provider_readiness_trusted_key_sha256s: Vec<String>,
    pub release_evaluator_decision_trusted_key_sha256s: Vec<String>,
    pub signed_artifact_trusted_key_sha256s: Vec<String>,
    pub metrics: Arc<Metrics>,
    pub audit_log: Arc<AuditLog>,
}

async fn record_metrics(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let auth_attempted = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .is_some();
    let start = Instant::now();
    let _guard = state.metrics.track_in_flight();
    let response = next.run(req).await;
    let duration = start.elapsed();
    let status = response.status().as_u16();

    state.metrics.record_request(&method, status, duration);

    // Structured access log. NOTE: the Authorization header value is
    // intentionally never referenced — only its presence (`auth_attempted`)
    // and the outcome (`status` ≠ 401 on `/api/v1/*` ⇒ `authenticated`).
    // The JSON-format tracing subscriber in `main.rs` renders this as a
    // single JSON line per request to stderr.
    let authenticated = auth_attempted && status != 401 && path.starts_with("/api/v1/");
    let duration_micros = duration.as_micros() as u64;
    tracing::info!(
        target: "ao2_cp_server::access",
        method = %method,
        path = %path,
        status = status,
        duration_micros = duration_micros,
        auth_attempted = auth_attempted,
        authenticated = authenticated,
        "request"
    );

    state.audit_log.append(AuditEntry {
        timestamp_unix_micros: now_unix_micros(),
        method,
        path,
        status,
        duration_micros,
        auth_attempted,
        authenticated,
    });

    response
}

/// Attach defensive security headers to every response. The control plane
/// serves HTML dashboards as well as JSON/text, so a baseline set of headers
/// reduces the blast radius of any reflected content:
/// - `X-Content-Type-Options: nosniff` stops MIME sniffing.
/// - `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` block clickjacking.
/// - `Referrer-Policy: no-referrer` keeps internal URLs out of referer headers.
/// - CSP locks resource loading to same-origin. The dashboards use inline
///   `<style>` blocks and one inline `EventSource` script, so `style-src`/
///   `script-src` allow `'unsafe-inline'`; everything else is `'self'`/`'none'`,
///   which still forbids external script/object/frame loads.
async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; \
             style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline'; \
             connect-src 'self'; \
             img-src 'self' data:; \
             base-uri 'none'; \
             form-action 'self'; \
             frame-ancestors 'none'",
        ),
    );
    response
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let entries = state
        .storage
        .index
        .read_all()
        .await
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    let oldest_resident_age_seconds = state
        .audit_log
        .oldest_resident_unix_micros()
        .map(|ts| {
            let now = now_unix_micros();
            // Saturating subtraction: a future-dated timestamp (e.g. a
            // clock-skewed remote pushed an entry from "the future")
            // yields 0 rather than a wrapping u64.
            now.saturating_sub(ts) as f64 / 1_000_000.0
        })
        .unwrap_or(0.0);
    let audit_log = AuditLogSamples {
        appended: state.audit_log.total_appended_since_boot(),
        rotated: state.audit_log.rotation_count(),
        persistence_errors: state.audit_log.total_persistence_errors_since_boot(),
        dropped: state.audit_log.total_dropped_since_boot(),
        file_bytes: state.audit_log.persistence_file_bytes(),
        oldest_resident_age_seconds,
    };
    let body = state.metrics.render(entries, audit_log);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let body_limit = state.max_body_bytes;

    let api_v1 = Router::new()
        .route(
            "/acceptance",
            post(handlers::acceptance::post_acceptance).get(handlers::acceptance::list_acceptance),
        )
        .route(
            "/acceptance/dashboard",
            get(handlers::acceptance::acceptance_dashboard),
        )
        .route(
            "/acceptance/dashboard.json",
            get(handlers::acceptance::acceptance_dashboard_json),
        )
        .route(
            "/acceptance/:sha",
            get(handlers::acceptance::get_acceptance).head(handlers::acceptance::head_acceptance),
        )
        .route(
            "/control-plane/bundle",
            post(handlers::control_plane::post_bundle).get(handlers::control_plane::list_bundles),
        )
        .route(
            "/control-plane/bundle/:sha",
            get(handlers::control_plane::get_bundle).head(handlers::control_plane::head_bundle),
        )
        .route(
            "/control-plane/routes.json",
            get(handlers::control_plane::route_index),
        )
        .route(
            "/ci/evidence-index",
            get(handlers::ci_evidence::ci_evidence_index),
        )
        .route(
            "/ci/evidence-index.json",
            get(handlers::ci_evidence::ci_evidence_index_json),
        )
        .route(
            "/ai/task-board",
            post(handlers::ai_task_board::post_ai_task_board),
        )
        .route(
            "/ai/task-board/latest",
            get(handlers::ai_task_board::latest_ai_task_board),
        )
        .route(
            "/ai/task-board/dashboard.json",
            get(handlers::ai_task_board::ai_task_board_dashboard_json),
        )
        .route(
            "/ai/task-board/:sha",
            get(handlers::ai_task_board::get_ai_task_board)
                .head(handlers::ai_task_board::head_ai_task_board),
        )
        .route(
            "/evidence-pack",
            get(handlers::evidence_pack::list_evidence_packs),
        )
        .route(
            "/evidence-pack/signed",
            post(handlers::evidence_pack::post_signed_evidence_pack),
        )
        .route(
            "/evidence-pack/dashboard",
            get(handlers::evidence_pack::evidence_pack_dashboard),
        )
        .route(
            "/evidence-pack/dashboard.json",
            get(handlers::evidence_pack::evidence_pack_dashboard_json),
        )
        .route(
            "/evidence-pack/run/:run_id/latest",
            get(handlers::evidence_pack::latest_evidence_pack_detail_for_run),
        )
        .route(
            "/evidence-pack/:sha/detail",
            get(handlers::evidence_pack::evidence_pack_detail),
        )
        .route(
            "/evidence-pack/:sha/detail.json",
            get(handlers::evidence_pack::evidence_pack_detail_json),
        )
        .route(
            "/evidence-pack/:sha/signature",
            get(handlers::evidence_pack::get_evidence_pack_signature),
        )
        .route(
            "/evidence-pack/:sha",
            get(handlers::evidence_pack::get_evidence_pack)
                .head(handlers::evidence_pack::head_evidence_pack),
        )
        .route(
            "/operator-packet",
            get(handlers::operator_packet::list_operator_packets),
        )
        .route(
            "/operator-packet/signed",
            post(handlers::operator_packet::post_signed_operator_packet),
        )
        .route(
            "/operator-packet/dashboard",
            get(handlers::operator_packet::operator_packet_dashboard),
        )
        .route(
            "/operator-packet/dashboard.json",
            get(handlers::operator_packet::operator_packet_dashboard_json),
        )
        .route(
            "/operator-packet/run/:run_id/latest",
            get(handlers::operator_packet::latest_operator_packet_detail_for_run),
        )
        .route(
            "/operator-packet/:sha/detail",
            get(handlers::operator_packet::operator_packet_detail),
        )
        .route(
            "/operator-packet/:sha/detail.json",
            get(handlers::operator_packet::operator_packet_detail_json),
        )
        .route(
            "/operator-packet/:sha/signature",
            get(handlers::operator_packet::get_operator_packet_signature),
        )
        .route(
            "/operator-packet/:sha",
            get(handlers::operator_packet::get_operator_packet)
                .head(handlers::operator_packet::head_operator_packet),
        )
        .route(
            "/hermes/watchdog/panel",
            post(handlers::hermes_watchdog::post_watchdog_panel)
                .get(handlers::hermes_watchdog::watchdog_panel),
        )
        .route(
            "/hermes/watchdog/panel/latest.json",
            get(handlers::hermes_watchdog::latest_watchdog_panel_json),
        )
        .route(
            "/hermes/watchdog/history.json",
            get(handlers::hermes_watchdog::watchdog_history_json),
        )
        .route(
            "/memory/export",
            post(handlers::memory::post_memory_export).get(handlers::memory::list_memory_exports),
        )
        .route(
            "/memory/export/signed",
            post(handlers::memory::post_signed_memory_export),
        )
        .route(
            "/memory/export/dashboard",
            get(handlers::memory::memory_export_dashboard),
        )
        .route(
            "/memory/export/:sha/signature",
            get(handlers::memory::get_memory_export_signature),
        )
        .route(
            "/memory/export/:sha",
            get(handlers::memory::get_memory_export).head(handlers::memory::head_memory_export),
        )
        .route(
            "/phase1/promotion/dashboard",
            get(handlers::phase1_promotion::phase1_promotion_dashboard),
        )
        .route(
            "/phase1/promotion/dashboard.json",
            get(handlers::phase1_promotion::phase1_promotion_dashboard_json),
        )
        .route(
            "/phase1/promotion/operator-panel",
            get(handlers::phase1_promotion::phase1_operator_panel),
        )
        .route(
            "/phase1/promotion/operator-panel.json",
            get(handlers::phase1_promotion::phase1_operator_panel_json),
        )
        .route(
            "/phase1/promotion/operator-support-bundle.json",
            get(handlers::phase1_promotion::phase1_operator_support_bundle_json),
        )
        .route(
            "/phase1/promotion/operator-support-bundle/download",
            get(handlers::phase1_promotion::phase1_operator_support_bundle_download),
        )
        .route(
            "/phase1/promotion/operator-support-bundle/SHA256SUMS",
            get(handlers::phase1_promotion::phase1_operator_support_bundle_checksums),
        )
        .route(
            "/phase1/promotion/operator-support-bundle/verify",
            post(handlers::phase1_promotion::phase1_operator_support_bundle_verify),
        )
        .route(
            "/phase1/promotion/operator-support-bundle/verify.json",
            post(handlers::phase1_promotion::phase1_operator_support_bundle_verify_json),
        )
        .route(
            "/phase1/promotion/gap-report.json",
            get(handlers::phase1_promotion::phase1_gap_report_json),
        )
        .route(
            "/phase1/promotion/portable-manifest",
            get(handlers::phase1_promotion::phase1_portable_manifest),
        )
        .route(
            "/phase1/promotion/portable-manifest.json",
            get(handlers::phase1_promotion::phase1_portable_manifest_json),
        )
        .route(
            "/phase1/promotion/portable-manifest/download",
            get(handlers::phase1_promotion::phase1_portable_manifest_download),
        )
        .route(
            "/phase1/promotion/portable-manifest/SHA256SUMS",
            get(handlers::phase1_promotion::phase1_portable_manifest_checksums),
        )
        .route(
            "/phase1/promotion/portable-manifest/verify",
            post(handlers::phase1_promotion::phase1_portable_manifest_verify),
        )
        .route(
            "/phase1/promotion/portable-manifest/verify.json",
            post(handlers::phase1_promotion::phase1_portable_manifest_verify_json),
        )
        .route(
            "/phase1/promotion/gap-report/download",
            get(handlers::phase1_promotion::phase1_gap_report_download),
        )
        .route(
            "/phase1/promotion/gap-report/SHA256SUMS",
            get(handlers::phase1_promotion::phase1_gap_report_checksums),
        )
        .route(
            "/phase1/promotion/history.json",
            get(handlers::phase1_promotion::phase1_promotion_history_json),
        )
        .route(
            "/phase1/promotion/three-os-smoke",
            post(handlers::phase1_promotion::post_phase1_three_os_smoke),
        )
        .route(
            "/phase1/promotion/three-os-smoke/latest",
            get(handlers::phase1_promotion::latest_phase1_three_os_smoke),
        )
        .route(
            "/phase1/promotion/three-os-smoke/:sha",
            get(handlers::phase1_promotion::get_phase1_three_os_smoke)
                .head(handlers::phase1_promotion::head_phase1_three_os_smoke),
        )
        .route(
            "/phase1/promotion/checklist",
            post(handlers::phase1_promotion::post_phase1_promotion_checklist),
        )
        .route(
            "/phase1/promotion/checklist/latest",
            get(handlers::phase1_promotion::latest_phase1_promotion_checklist),
        )
        .route(
            "/phase1/promotion/checklist/:sha",
            get(handlers::phase1_promotion::get_phase1_promotion_checklist)
                .head(handlers::phase1_promotion::head_phase1_promotion_checklist),
        )
        .route(
            "/phase1/promotion/inputs-verification",
            post(handlers::phase1_promotion::post_phase1_promotion_inputs_verification),
        )
        .route(
            "/phase1/promotion/inputs-verification/latest",
            get(handlers::phase1_promotion::latest_phase1_promotion_inputs_verification),
        )
        .route(
            "/phase1/promotion/inputs-verification/:sha",
            get(handlers::phase1_promotion::get_phase1_promotion_inputs_verification)
                .head(handlers::phase1_promotion::head_phase1_promotion_inputs_verification),
        )
        .route(
            "/phase1/promotion/decision/signed",
            post(handlers::phase1_promotion::post_signed_phase1_promotion_decision),
        )
        .route(
            "/phase1/promotion/decision/latest",
            get(handlers::phase1_promotion::latest_phase1_promotion_decision),
        )
        .route(
            "/phase1/promotion/decision/:sha",
            get(handlers::phase1_promotion::get_phase1_promotion_decision)
                .head(handlers::phase1_promotion::head_phase1_promotion_decision),
        )
        .route(
            "/phase1/promotion/decision/:sha/signature",
            get(handlers::phase1_promotion::get_phase1_promotion_decision_signature),
        )
        .route(
            "/provider/registry",
            post(handlers::provider_registry::post_provider_registry)
                .get(handlers::provider_registry::list_provider_registries),
        )
        .route(
            "/provider/registry/signed",
            post(handlers::provider_registry::post_signed_provider_registry),
        )
        .route(
            "/provider/registry/latest",
            get(handlers::provider_registry::latest_provider_registry)
                .head(handlers::provider_registry::head_latest_provider_registry),
        )
        .route(
            "/provider/registry/dashboard",
            get(handlers::provider_registry::provider_registry_dashboard),
        )
        .route(
            "/provider/registry/dashboard.json",
            get(handlers::provider_registry::provider_registry_dashboard_json),
        )
        .route(
            "/provider/registry/:sha/detail",
            get(handlers::provider_registry::provider_registry_detail),
        )
        .route(
            "/provider/registry/:sha/detail.json",
            get(handlers::provider_registry::provider_registry_detail_json),
        )
        .route(
            "/provider/registry/:sha/signature",
            get(handlers::provider_registry::get_provider_registry_signature),
        )
        .route(
            "/provider/registry/:sha",
            get(handlers::provider_registry::get_provider_registry)
                .head(handlers::provider_registry::head_provider_registry),
        )
        .route(
            "/provider/readiness",
            post(handlers::provider_readiness::post_provider_readiness)
                .get(handlers::provider_readiness::list_provider_readiness),
        )
        .route(
            "/provider/readiness/signed",
            post(handlers::provider_readiness::post_signed_provider_readiness),
        )
        .route(
            "/provider/readiness/latest",
            get(handlers::provider_readiness::latest_provider_readiness),
        )
        .route(
            "/provider/readiness/dashboard",
            get(handlers::provider_readiness::provider_readiness_dashboard),
        )
        .route(
            "/provider/readiness/dashboard.json",
            get(handlers::provider_readiness::provider_readiness_dashboard_json),
        )
        .route(
            "/provider/readiness/support-bundle.json",
            get(handlers::provider_readiness::provider_readiness_support_bundle_json),
        )
        .route(
            "/provider/readiness/support-bundle/download",
            get(handlers::provider_readiness::provider_readiness_support_bundle_download),
        )
        .route(
            "/provider/readiness/support-bundle/SHA256SUMS",
            get(handlers::provider_readiness::provider_readiness_support_bundle_checksums),
        )
        .route(
            "/provider/readiness/:sha/detail",
            get(handlers::provider_readiness::provider_readiness_detail),
        )
        .route(
            "/provider/readiness/:sha/detail.json",
            get(handlers::provider_readiness::provider_readiness_detail_json),
        )
        .route(
            "/provider/readiness/:sha/signature",
            get(handlers::provider_readiness::get_provider_readiness_signature),
        )
        .route(
            "/provider/readiness/:sha",
            get(handlers::provider_readiness::get_provider_readiness)
                .head(handlers::provider_readiness::head_provider_readiness),
        )
        .route(
            "/risky-pr/golden/artifact-manifest",
            get(handlers::risky_pr_golden::risky_pr_golden_artifact_manifest),
        )
        .route(
            "/risky-pr/golden/artifact-manifest.json",
            get(handlers::risky_pr_golden::risky_pr_golden_artifact_manifest_json),
        )
        .route(
            "/release/publication",
            post(handlers::release_publication::post_release_publication),
        )
        .route(
            "/release/cockpit",
            get(handlers::release_publication::release_cockpit),
        )
        .route(
            "/release/cockpit.json",
            get(handlers::release_publication::release_cockpit_json),
        )
        .route(
            "/release/handoff",
            get(handlers::release_publication::release_candidate_handoff),
        )
        .route(
            "/release/handoff.json",
            get(handlers::release_publication::release_candidate_handoff_json),
        )
        .route(
            "/release/train",
            get(handlers::release_train::release_train_readback),
        )
        .route(
            "/release/train.json",
            get(handlers::release_train::release_train_readback_json),
        )
        .route(
            "/release/operator-evidence",
            get(handlers::operator_release_evidence::operator_release_evidence_readback),
        )
        .route(
            "/release/operator-evidence.json",
            get(handlers::operator_release_evidence::operator_release_evidence_readback_json),
        )
        .route(
            "/release/stable-promotion-evidence",
            get(handlers::stable_promotion_evidence::stable_promotion_evidence_readback),
        )
        .route(
            "/release/stable-promotion-evidence.json",
            get(handlers::stable_promotion_evidence::stable_promotion_evidence_readback_json),
        )
        .route(
            "/release/readiness",
            get(handlers::release_publication::release_readiness),
        )
        .route(
            "/release/readiness.json",
            get(handlers::release_publication::release_readiness_json),
        )
        .route(
            "/release/support-bundle.json",
            get(handlers::release_publication::release_support_bundle_json),
        )
        .route(
            "/release/support-bundle/manifest",
            get(handlers::release_publication::release_support_bundle_manifest),
        )
        .route(
            "/release/support-bundle/manifest.json",
            get(handlers::release_publication::release_support_bundle_manifest_json),
        )
        .route(
            "/release/support-bundle/download",
            get(handlers::release_publication::release_support_bundle_download),
        )
        .route(
            "/release/support-bundle/SHA256SUMS",
            get(handlers::release_publication::release_support_bundle_checksums),
        )
        .route(
            "/release/support-bundle/verify",
            get(handlers::release_publication::release_support_bundle_verification),
        )
        .route(
            "/release/support-bundle/verify.json",
            get(handlers::release_publication::release_support_bundle_verification_json),
        )
        .route(
            "/release/support-bundle/handoff",
            get(handlers::release_publication::release_support_verifier_handoff),
        )
        .route(
            "/release/support-bundle/handoff.json",
            get(handlers::release_publication::release_support_verifier_handoff_json),
        )
        .route(
            "/release/evaluator-decision",
            post(handlers::release_publication::post_release_evaluator_decision),
        )
        .route(
            "/release/evaluator-decision/signed",
            post(handlers::release_publication::post_signed_release_evaluator_decision),
        )
        .route(
            "/release/evaluator-decision/latest",
            get(handlers::release_publication::latest_release_evaluator_decision),
        )
        .route(
            "/release/evaluator-decision/dashboard",
            get(handlers::release_publication::release_evaluator_decision_dashboard),
        )
        .route(
            "/release/evaluator-decision/dashboard.json",
            get(handlers::release_publication::release_evaluator_decision_dashboard_json),
        )
        .route(
            "/release/evaluator-decision/:sha/signature",
            get(handlers::release_publication::get_release_evaluator_decision_signature),
        )
        .route(
            "/release/evaluator-decision/:sha",
            get(handlers::release_publication::get_release_evaluator_decision)
                .head(handlers::release_publication::head_release_evaluator_decision),
        )
        .route(
            "/release/publication/latest",
            get(handlers::release_publication::latest_release_publication),
        )
        .route(
            "/release/publication/dashboard",
            get(handlers::release_publication::release_publication_dashboard),
        )
        .route(
            "/release/publication/dashboard.json",
            get(handlers::release_publication::release_publication_dashboard_json),
        )
        .route(
            "/release/publication/:sha",
            get(handlers::release_publication::get_release_publication)
                .head(handlers::release_publication::head_release_publication),
        )
        .route("/storage/report", get(handlers::storage::storage_report))
        .route(
            "/storage/dashboard",
            get(handlers::storage::storage_dashboard),
        )
        .route(
            "/storage/dashboard.json",
            get(handlers::storage::storage_dashboard_json),
        )
        .route(
            "/storage/support-bundle.json",
            get(handlers::storage::storage_support_bundle),
        )
        .route(
            "/storage/support-bundle/download",
            get(handlers::storage::storage_support_bundle_download),
        )
        .route(
            "/storage/support-bundle/contract.json",
            get(handlers::storage::storage_support_bundle_contract),
        )
        .route(
            "/storage/support-bundle/SHA256SUMS",
            get(handlers::storage::storage_support_bundle_checksums),
        )
        .route("/storage/prune", post(handlers::storage::storage_prune))
        .route("/metrics", get(metrics_handler))
        .route("/status", get(handlers::health::status))
        .route("/healthz/extended", get(handlers::health::healthz_extended))
        .route("/audit-log", get(handlers::audit_log::get_audit_log))
        .route(
            "/audit-log/dashboard",
            get(handlers::audit_log::audit_log_dashboard),
        )
        .route(
            "/audit-log/dashboard.json",
            get(handlers::audit_log::audit_log_dashboard_json),
        )
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(GlobalConcurrencyLimitLayer::new(MAX_INFLIGHT_REQUESTS))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());

    // The audit-log SSE stream is a long-lived response. A request timeout
    // would sever it mid-stream, and a global in-flight cap would let idle
    // dashboard viewers hold slots and starve ingest. It gets the same bearer
    // auth but is exempt from the timeout and concurrency layers.
    let api_v1_stream = Router::new()
        .route(
            "/audit-log/stream",
            get(handlers::audit_log::audit_log_stream),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());

    Router::new()
        .route("/", get(handlers::landing::landing_page))
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz))
        .nest("/api/v1", api_v1.merge(api_v1_stream))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            record_metrics,
        ))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}
