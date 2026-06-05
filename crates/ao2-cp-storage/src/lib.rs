//! ao2-cp-storage: content-addressed flat-file bundle storage with JSONL index.
//!
//! Bundles are stored under the data directory keyed by SHA-256 over AO2
//! canonical JSON v1 (`ao2-canonical-v1`). The companion [`index::IndexStore`] is an
//! append-only NDJSON ledger keyed by canonical digest plus bundle kind.
//! Content-addressed storage means tampering is detectable on every GET
//! (the server recomputes the digest before returning a body).
//!
//! No transactional state lives in process — the data dir is the entire
//! state of the control plane. Backup with `tar -czf` (Linux/macOS) or
//! `Compress-Archive` (Windows). Bundle files are immutable.
//!
//! # Modules
//! - [`bundle`] — content-addressed file write/read primitives
//! - [`index`] — append-only JSONL ledger with read scans
//!
//! [`bundle::BundleStore`] and [`index::IndexStore`] are bundled together
//! in [`Storage`] for the server's [`AppState`](../ao2_cp_server/server/struct.AppState.html).

pub mod bundle;
pub mod index;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;

pub use bundle::{BundleKind, BundleStore, BundleStoreError};
pub use index::{IndexEntry, IndexStore, IndexStoreError};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("bundle error: {0}")]
    Bundle(#[from] BundleStoreError),
    #[error("index error: {0}")]
    Index(#[from] IndexStoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Storage {
    pub bundles: BundleStore,
    pub index: IndexStore,
}

const SUPPORT_BUNDLE_MAX_INDEX_ENTRIES: usize = 50;
const RETENTION_REPORT_MAX_PRUNE_CANDIDATES: usize = 100;
const PHASE1_RELEASE_FRESHNESS_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub keep_latest: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionReport {
    pub schema_version: String,
    pub keep_latest: usize,
    pub total_index_entries: usize,
    pub total_bundle_files: usize,
    pub total_size_bytes: u64,
    pub reclaimable_bytes: u64,
    pub total_prune_candidates: usize,
    pub prune_candidates_limit: usize,
    pub prune_candidates_truncated: bool,
    pub kinds: Vec<RetentionKindReport>,
    pub prune_candidates: Vec<RetentionCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionKindReport {
    pub kind: String,
    pub indexed_entries: usize,
    pub bundle_files: usize,
    pub size_bytes: u64,
    pub prune_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionCandidate {
    pub kind: String,
    pub sha256: String,
    pub schema: String,
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub size_bytes: u64,
    pub related_bundle_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPruneResult {
    pub schema_version: String,
    pub dry_run: bool,
    pub keep_latest: usize,
    pub pruned: Vec<RetentionCandidate>,
    pub retained_index_entries: usize,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    pub schema_version: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub trust_boundary: SupportBundleTrustBoundary,
    pub operator_handoff: SupportBundleOperatorHandoff,
    pub phase1_release_readiness: SupportBundlePhase1Readiness,
    pub retention_report: RetentionReport,
    pub latest_index_entries: Vec<IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundlePhase1Readiness {
    pub schema_version: String,
    pub trust_boundary: SupportBundlePhase1TrustBoundary,
    pub operator_links: BTreeMap<String, String>,
    pub observed_artifacts: BTreeMap<String, Option<SupportBundleArtifactSummary>>,
    pub readiness_status: String,
    pub release_decision_allowed: bool,
    pub total_open_gaps: usize,
    pub gap_summary: SupportBundleGapSummary,
    pub critical_path: Vec<SupportBundleCriticalPathStep>,
    pub blocking_gaps: Vec<SupportBundleGap>,
    pub next_recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleGapSummary {
    pub schema_version: String,
    pub total_blocking: usize,
    pub missing_artifact_count: usize,
    pub stale_artifact_count: usize,
    pub failed_status_count: usize,
    pub missing_signature_count: usize,
    pub unverified_signature_count: usize,
    pub untrusted_signature_count: usize,
    pub trust_boundary: SupportBundlePhase1TrustBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleCriticalPathStep {
    pub operator_step: usize,
    pub id: String,
    pub severity: String,
    pub gap_kind: String,
    pub evidence_needed: String,
    pub next_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleArtifactSummary {
    pub sha256: String,
    pub schema: String,
    pub status: Option<String>,
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub age_seconds: i64,
    pub stale_after_seconds: Option<i64>,
    pub is_stale: bool,
    pub raw_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SupportBundleSignatureSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleSignatureSummary {
    pub schema_version: String,
    pub raw_url: String,
    pub signature_algorithm: Option<String>,
    pub signature_verified: Option<bool>,
    pub signer_id: Option<String>,
    pub public_key_sha256: Option<String>,
    pub trust_anchor: Option<String>,
    pub verification_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_policy: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleGap {
    pub id: String,
    pub severity: String,
    pub gap_kind: String,
    pub evidence_needed: String,
    pub next_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundlePhase1TrustBoundary {
    pub role: String,
    pub mutates_ao_artifacts: bool,
    pub release_acceptance_owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleOperatorHandoff {
    pub control_plane_role: String,
    pub mutates_ao_artifacts: bool,
    pub relative_endpoints: BTreeMap<String, String>,
    pub cross_os_smoke_commands: BTreeMap<String, String>,
    pub recommended_follow_up: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleTrustBoundary {
    pub frontend: String,
    pub governed_backend: String,
    pub trusted_execution: String,
    pub role: String,
    pub mutates_ao_artifacts: bool,
}

fn support_bundle_operator_handoff(keep_latest: usize) -> SupportBundleOperatorHandoff {
    let mut relative_endpoints = BTreeMap::new();
    relative_endpoints.insert(
        "storage_dashboard".to_string(),
        format!("/api/v1/storage/dashboard?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "storage_dashboard_json".to_string(),
        format!("/api/v1/storage/dashboard.json?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "support_bundle_json".to_string(),
        format!("/api/v1/storage/support-bundle.json?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "support_bundle_download".to_string(),
        format!("/api/v1/storage/support-bundle/download?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "support_bundle_checksums".to_string(),
        format!("/api/v1/storage/support-bundle/SHA256SUMS?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "retention_report_json".to_string(),
        format!("/api/v1/storage/report?keep_latest={keep_latest}"),
    );
    relative_endpoints.insert(
        "signed_evidence_dashboard".to_string(),
        "/api/v1/evidence-pack/dashboard".to_string(),
    );
    relative_endpoints.insert(
        "provider_registry_dashboard".to_string(),
        "/api/v1/provider/registry/dashboard".to_string(),
    );
    relative_endpoints.insert(
        "provider_registry_dashboard_json".to_string(),
        "/api/v1/provider/registry/dashboard.json".to_string(),
    );
    relative_endpoints.insert(
        "phase1_promotion_dashboard".to_string(),
        "/api/v1/phase1/promotion/dashboard".to_string(),
    );
    relative_endpoints.insert(
        "phase1_promotion_dashboard_json".to_string(),
        "/api/v1/phase1/promotion/dashboard.json".to_string(),
    );
    relative_endpoints.insert(
        "phase1_operator_panel".to_string(),
        "/api/v1/phase1/promotion/operator-panel".to_string(),
    );
    relative_endpoints.insert(
        "phase1_operator_panel_json".to_string(),
        "/api/v1/phase1/promotion/operator-panel.json".to_string(),
    );
    relative_endpoints.insert(
        "phase1_operator_support_bundle_json".to_string(),
        "/api/v1/phase1/promotion/operator-support-bundle.json".to_string(),
    );
    relative_endpoints.insert(
        "phase1_operator_support_bundle_download".to_string(),
        "/api/v1/phase1/promotion/operator-support-bundle/download".to_string(),
    );
    relative_endpoints.insert(
        "phase1_operator_support_bundle_checksums".to_string(),
        "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS".to_string(),
    );
    relative_endpoints.insert(
        "phase1_promotion_history_json".to_string(),
        "/api/v1/phase1/promotion/history.json".to_string(),
    );
    relative_endpoints.insert(
        "phase1_promotion_gap_report_json".to_string(),
        "/api/v1/phase1/promotion/gap-report.json".to_string(),
    );
    relative_endpoints.insert(
        "release_publication_dashboard".to_string(),
        "/api/v1/release/publication/dashboard".to_string(),
    );
    relative_endpoints.insert(
        "release_publication_dashboard_json".to_string(),
        "/api/v1/release/publication/dashboard.json".to_string(),
    );
    relative_endpoints.insert(
        "release_cockpit".to_string(),
        "/api/v1/release/cockpit".to_string(),
    );
    relative_endpoints.insert(
        "release_cockpit_json".to_string(),
        "/api/v1/release/cockpit.json".to_string(),
    );
    relative_endpoints.insert(
        "release_handoff".to_string(),
        "/api/v1/release/handoff".to_string(),
    );
    relative_endpoints.insert(
        "release_handoff_json".to_string(),
        "/api/v1/release/handoff.json".to_string(),
    );
    relative_endpoints.insert(
        "release_readiness".to_string(),
        "/api/v1/release/readiness".to_string(),
    );
    relative_endpoints.insert(
        "release_readiness_json".to_string(),
        "/api/v1/release/readiness.json".to_string(),
    );
    relative_endpoints.insert(
        "release_evaluator_decision_dashboard".to_string(),
        "/api/v1/release/evaluator-decision/dashboard".to_string(),
    );
    relative_endpoints.insert(
        "release_evaluator_decision_dashboard_json".to_string(),
        "/api/v1/release/evaluator-decision/dashboard.json".to_string(),
    );

    let mut cross_os_smoke_commands = BTreeMap::new();
    cross_os_smoke_commands.insert(
        "macos_zsh".to_string(),
        "cargo fmt --all -- --check && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings".to_string(),
    );
    cross_os_smoke_commands.insert(
        "ubuntu_bash".to_string(),
        "cargo fmt --all -- --check && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings".to_string(),
    );
    cross_os_smoke_commands.insert(
        "windows_powershell".to_string(),
        "cargo fmt --all -- --check; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cargo test --workspace; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cargo clippy --workspace --all-targets -- -D warnings".to_string(),
    );

    SupportBundleOperatorHandoff {
        control_plane_role: "read_only_observer".to_string(),
        mutates_ao_artifacts: false,
        relative_endpoints,
        cross_os_smoke_commands,
        recommended_follow_up: vec![
            "Review signed evidence and phase readiness dashboards before release-line decisions."
                .to_string(),
            "Use Factory v3 / AO Operator evaluator-closer workflow for release approval."
                .to_string(),
            "Use AO2 signed evidence exports as the trusted execution record; this support bundle is diagnostic observer context only."
                .to_string(),
        ],
    }
}

fn support_bundle_phase1_readiness(entries: &[IndexEntry]) -> SupportBundlePhase1Readiness {
    let mut observed_artifacts = BTreeMap::new();
    observed_artifacts.insert(
        "provider_readiness".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "factory-v3/hermes-provider-phase1-readiness/v1",
            |_| "/api/v1/provider/readiness/latest".to_string(),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );
    observed_artifacts.insert(
        "codex_live_acceptance".to_string(),
        latest_artifact_summary(
            entries,
            |entry| {
                entry.schema == "ao2.codex-provider-pilot-acceptance.v1"
                    || entry.provider.as_deref() == Some("codex")
            },
            |sha| format!("/api/v1/acceptance/{sha}"),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );
    observed_artifacts.insert(
        "claude_live_acceptance".to_string(),
        latest_artifact_summary(
            entries,
            |entry| {
                entry.schema == "ao2.claude-provider-pilot-acceptance.v1"
                    || entry.provider.as_deref() == Some("claude")
            },
            |sha| format!("/api/v1/acceptance/{sha}"),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );
    observed_artifacts.insert(
        "phase1_promotion_checklist".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "factory-v3/ao2-phase1-promotion-checklist/v1",
            |_| "/api/v1/phase1/promotion/checklist/latest".to_string(),
            None,
        ),
    );
    observed_artifacts.insert(
        "signed_phase1_promotion_decision".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "factory-v3/ao2-phase1-promotion-decision/v1",
            |_| "/api/v1/phase1/promotion/decision/latest".to_string(),
            None,
        ),
    );
    observed_artifacts.insert(
        "three_os_release_smoke".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "ao2-control-plane.three-os-release-smoke.v1",
            |_| "/api/v1/phase1/promotion/three-os-smoke/latest".to_string(),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );
    observed_artifacts.insert(
        "release_publication".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "ao2.release-publication-summary.v1",
            |_| "/api/v1/release/publication/latest".to_string(),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );
    observed_artifacts.insert(
        "release_evaluator_decision".to_string(),
        latest_artifact_summary(
            entries,
            |entry| entry.schema == "factory-v3/ao2-release-evaluator-decision/v1",
            |_| "/api/v1/release/evaluator-decision/latest".to_string(),
            Some(PHASE1_RELEASE_FRESHNESS_SECONDS),
        ),
    );

    let mut blocking_gaps = Vec::new();
    for (id, evidence_needed, next_action) in [
        (
            "provider_readiness",
            "latest provider readiness evidence",
            "publish provider readiness evidence through the governed Factory v3 / AO Operator workflow",
        ),
        (
            "codex_live_acceptance",
            "live Codex provider acceptance artifact",
            "publish live Codex acceptance evidence from AO2 signed execution",
        ),
        (
            "claude_live_acceptance",
            "live Claude provider acceptance artifact",
            "publish live Claude acceptance evidence from AO2 signed execution",
        ),
        (
            "phase1_promotion_checklist",
            "Factory v3 Phase 1 promotion checklist artifact",
            "publish the evaluator/closer Phase 1 promotion checklist",
        ),
        (
            "signed_phase1_promotion_decision",
            "signed Phase 1 promotion decision",
            "publish the signed release-line decision after evaluator/closer review",
        ),
        (
            "three_os_release_smoke",
            "latest clean macOS, Ubuntu, and Windows release-smoke summary",
            "publish the ao2-control-plane three-OS release-smoke summary",
        ),
        (
            "release_publication",
            "AO2 published release evidence with provenance, rollback, and release doctor status",
            "publish the AO2 release-publication summary from the governed release workflow",
        ),
        (
            "release_evaluator_decision",
            "Factory v3 release evaluator-closer decision artifact",
            "publish the Factory v3 release evaluator-closer decision after governed readiness comparison",
        ),
    ] {
        match observed_artifacts.get(id).and_then(Option::as_ref) {
            None => blocking_gaps.push(SupportBundleGap {
                id: id.to_string(),
                severity: "blocking".to_string(),
                gap_kind: "missing_artifact".to_string(),
                evidence_needed: evidence_needed.to_string(),
                next_action: next_action.to_string(),
            }),
            Some(summary) if summary.is_stale => blocking_gaps.push(SupportBundleGap {
                id: id.to_string(),
                severity: "blocking".to_string(),
                gap_kind: "stale_artifact".to_string(),
                evidence_needed: format!(
                    "fresh {evidence_needed}; observed artifact is {} seconds old and exceeds the {} second freshness window",
                    summary.age_seconds,
                    summary.stale_after_seconds.unwrap_or_default()
                ),
                next_action: format!("refresh stale evidence: {next_action}"),
            }),
            Some(summary) if artifact_status_is_blocking(summary.status.as_deref()) => {
                let status = summary.status.as_deref().unwrap_or("unknown");
                blocking_gaps.push(SupportBundleGap {
                    id: id.to_string(),
                    severity: "blocking".to_string(),
                    gap_kind: "failed_status".to_string(),
                    evidence_needed: format!(
                        "non-failing {evidence_needed}; observed artifact status is {status}"
                    ),
                    next_action: format!(
                        "resolve failed artifact status {status} and republish: {next_action}"
                    ),
                });
            }
            Some(_) => {}
        }
    }

    let release_decision_allowed = blocking_gaps.is_empty();
    let readiness_status = if release_decision_allowed {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    let next_recommended_action = blocking_gaps
        .first()
        .map(|gap| gap.next_action.clone())
        .unwrap_or_else(|| {
            "all support-bundle Phase 1 observer artifacts are present; verify release readiness in Factory v3 evaluator/closer before promotion".to_string()
        });
    let trust_boundary = SupportBundlePhase1TrustBoundary {
        role: "read_only_observer".to_string(),
        mutates_ao_artifacts: false,
        release_acceptance_owner: "factory-v3 evaluator-closer".to_string(),
    };
    let gap_summary = support_bundle_gap_summary(&blocking_gaps, trust_boundary.clone());
    let critical_path = support_bundle_critical_path(&blocking_gaps);

    SupportBundlePhase1Readiness {
        schema_version: "ao2.cp-support-bundle-phase1-readiness.v1".to_string(),
        trust_boundary,
        operator_links: BTreeMap::from([
            (
                "phase1_promotion_dashboard".to_string(),
                "/api/v1/phase1/promotion/dashboard".to_string(),
            ),
            (
                "provider_registry_dashboard".to_string(),
                "/api/v1/provider/registry/dashboard".to_string(),
            ),
            (
                "provider_registry_dashboard_json".to_string(),
                "/api/v1/provider/registry/dashboard.json".to_string(),
            ),
            (
                "phase1_promotion_dashboard_json".to_string(),
                "/api/v1/phase1/promotion/dashboard.json".to_string(),
            ),
            (
                "phase1_operator_panel".to_string(),
                "/api/v1/phase1/promotion/operator-panel".to_string(),
            ),
            (
                "phase1_operator_panel_json".to_string(),
                "/api/v1/phase1/promotion/operator-panel.json".to_string(),
            ),
            (
                "phase1_operator_support_bundle_json".to_string(),
                "/api/v1/phase1/promotion/operator-support-bundle.json".to_string(),
            ),
            (
                "phase1_operator_support_bundle_download".to_string(),
                "/api/v1/phase1/promotion/operator-support-bundle/download".to_string(),
            ),
            (
                "phase1_operator_support_bundle_checksums".to_string(),
                "/api/v1/phase1/promotion/operator-support-bundle/SHA256SUMS".to_string(),
            ),
            (
                "phase1_promotion_history_json".to_string(),
                "/api/v1/phase1/promotion/history.json".to_string(),
            ),
            (
                "phase1_promotion_gap_report_json".to_string(),
                "/api/v1/phase1/promotion/gap-report.json".to_string(),
            ),
            (
                "release_cockpit".to_string(),
                "/api/v1/release/cockpit".to_string(),
            ),
            (
                "release_cockpit_json".to_string(),
                "/api/v1/release/cockpit.json".to_string(),
            ),
            (
                "release_handoff".to_string(),
                "/api/v1/release/handoff".to_string(),
            ),
            (
                "release_handoff_json".to_string(),
                "/api/v1/release/handoff.json".to_string(),
            ),
            (
                "release_readiness".to_string(),
                "/api/v1/release/readiness".to_string(),
            ),
            (
                "release_readiness_json".to_string(),
                "/api/v1/release/readiness.json".to_string(),
            ),
            (
                "release_evaluator_decision_dashboard".to_string(),
                "/api/v1/release/evaluator-decision/dashboard".to_string(),
            ),
            (
                "release_evaluator_decision_dashboard_json".to_string(),
                "/api/v1/release/evaluator-decision/dashboard.json".to_string(),
            ),
            (
                "factory_phase1_promotion_panel".to_string(),
                "factory-v3:scripts/hermes_ao_bridge.py phase1-promotion-panel".to_string(),
            ),
        ]),
        observed_artifacts,
        readiness_status,
        release_decision_allowed,
        total_open_gaps: blocking_gaps.len(),
        gap_summary,
        critical_path,
        blocking_gaps,
        next_recommended_action,
    }
}

fn support_bundle_gap_summary(
    gaps: &[SupportBundleGap],
    trust_boundary: SupportBundlePhase1TrustBoundary,
) -> SupportBundleGapSummary {
    SupportBundleGapSummary {
        schema_version: "ao2.cp-support-bundle-phase1-gap-summary.v1".to_string(),
        total_blocking: gaps.len(),
        missing_artifact_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "missing_artifact")
            .count(),
        stale_artifact_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "stale_artifact")
            .count(),
        failed_status_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "failed_status")
            .count(),
        missing_signature_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "missing_signature")
            .count(),
        unverified_signature_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "unverified_signature")
            .count(),
        untrusted_signature_count: gaps
            .iter()
            .filter(|gap| gap.gap_kind == "untrusted_signature")
            .count(),
        trust_boundary,
    }
}

fn support_bundle_critical_path(gaps: &[SupportBundleGap]) -> Vec<SupportBundleCriticalPathStep> {
    gaps.iter()
        .enumerate()
        .map(|(index, gap)| SupportBundleCriticalPathStep {
            operator_step: index + 1,
            id: gap.id.clone(),
            severity: gap.severity.clone(),
            gap_kind: gap.gap_kind.clone(),
            evidence_needed: gap.evidence_needed.clone(),
            next_action: gap.next_action.clone(),
        })
        .collect()
}

fn latest_artifact_summary(
    entries: &[IndexEntry],
    predicate: impl Fn(&IndexEntry) -> bool,
    raw_url: impl Fn(&str) -> String,
    stale_after_seconds: Option<i64>,
) -> Option<SupportBundleArtifactSummary> {
    let now = chrono::Utc::now();
    entries
        .iter()
        .filter(|entry| predicate(entry))
        .max_by_key(|entry| entry.ingested_at)
        .map(|entry| {
            let age_seconds = now
                .signed_duration_since(entry.ingested_at)
                .num_seconds()
                .max(0);
            let is_stale = stale_after_seconds
                .map(|threshold| age_seconds > threshold)
                .unwrap_or(false);
            SupportBundleArtifactSummary {
                sha256: entry.sha256.clone(),
                schema: entry.schema.clone(),
                status: entry.status.clone(),
                ingested_at: entry.ingested_at,
                age_seconds,
                stale_after_seconds,
                is_stale,
                raw_url: raw_url(&entry.sha256),
                signature: None,
            }
        })
}

fn artifact_status_is_blocking(status: Option<&str>) -> bool {
    let Some(status) = status else {
        return false;
    };
    let normalized = status.trim().to_ascii_lowercase();
    normalized.contains("fail")
        || normalized.contains("error")
        || normalized.contains("reject")
        || normalized.contains("block")
}

fn enforce_required_signed_artifact_sidecars(readiness: &mut SupportBundlePhase1Readiness) {
    if let Some(Some(summary)) = readiness.observed_artifacts.get("provider_readiness") {
        match summary.signature.as_ref() {
            Some(signature) if signature.signature_verified != Some(true) => {
                readiness.blocking_gaps.push(SupportBundleGap {
                    id: "provider_readiness_signature".to_string(),
                    severity: "blocking".to_string(),
                    gap_kind: "unverified_signature".to_string(),
                    evidence_needed: format!(
                        "verified release-authoritative pinned-key signature sidecar for provider readiness evidence; observed signature_verified is {:?}",
                        signature.signature_verified
                    ),
                    next_action: "replace or republish unverified provider readiness signature sidecar using configured trusted public-key digest verification".to_string(),
                });
            }
            Some(signature)
                if !provider_readiness_signature_is_release_authoritative(signature) =>
            {
                readiness.blocking_gaps.push(SupportBundleGap {
                    id: "provider_readiness_signature".to_string(),
                    severity: "blocking".to_string(),
                    gap_kind: "untrusted_signature".to_string(),
                    evidence_needed: "release-authoritative pinned-key signature sidecar for provider readiness evidence; observer-only upload-key signatures are not release-authoritative".to_string(),
                    next_action: "configure trusted provider-readiness public-key SHA256 digests and republish provider readiness so trust_policy.release_authoritative and trusted_key_match are true".to_string(),
                });
            }
            Some(_) | None => {}
        }
    }

    for (artifact_id, evidence_needed, next_action) in [
        (
            "signed_phase1_promotion_decision",
            "verified signature sidecar for the signed Phase 1 promotion decision",
            "publish the signature sidecar for the signed Phase 1 promotion decision from the governed evaluator/closer workflow",
        ),
        (
            "release_evaluator_decision",
            "verified signature sidecar for the Factory v3 release evaluator-closer decision",
            "publish the signature sidecar for the Factory v3 release evaluator-closer decision from the governed evaluator/closer workflow",
        ),
    ] {
        let Some(Some(summary)) = readiness.observed_artifacts.get(artifact_id) else {
            continue;
        };
        let signature_gap_id = format!("{artifact_id}_signature");
        match summary.signature.as_ref() {
            None => readiness.blocking_gaps.push(SupportBundleGap {
                id: signature_gap_id,
                severity: "blocking".to_string(),
                gap_kind: "missing_signature".to_string(),
                evidence_needed: evidence_needed.to_string(),
                next_action: next_action.to_string(),
            }),
            Some(signature) if signature.signature_verified != Some(true) => {
                readiness.blocking_gaps.push(SupportBundleGap {
                    id: signature_gap_id,
                    severity: "blocking".to_string(),
                    gap_kind: "unverified_signature".to_string(),
                    evidence_needed: format!(
                        "{evidence_needed}; observed signature_verified is {:?}",
                        signature.signature_verified
                    ),
                    next_action: format!(
                        "replace or republish unverified signature sidecar: {next_action}"
                    ),
                });
            }
            Some(_) => {}
        }
    }

    readiness.release_decision_allowed = readiness.blocking_gaps.is_empty();
    readiness.readiness_status = if readiness.release_decision_allowed {
        "ready"
    } else {
        "blocked"
    }
    .to_string();
    readiness.total_open_gaps = readiness.blocking_gaps.len();
    readiness.next_recommended_action = readiness
        .blocking_gaps
        .first()
        .map(|gap| gap.next_action.clone())
        .unwrap_or_else(|| {
            "all support-bundle Phase 1 observer artifacts and required signature sidecars are present; verify release readiness in Factory v3 evaluator/closer before promotion".to_string()
        });
    readiness.gap_summary =
        support_bundle_gap_summary(&readiness.blocking_gaps, readiness.trust_boundary.clone());
    readiness.critical_path = support_bundle_critical_path(&readiness.blocking_gaps);
}

fn provider_readiness_signature_is_release_authoritative(
    signature: &SupportBundleSignatureSummary,
) -> bool {
    if signature.signature_verified != Some(true) {
        return false;
    }

    let Some(trust_policy) = signature.trust_policy.as_ref() else {
        return false;
    };

    trust_policy
        .get("release_authoritative")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && trust_policy
            .get("trusted_key_match")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

impl Storage {
    pub async fn open(root: PathBuf) -> Result<Self, StorageError> {
        tokio::fs::create_dir_all(&root).await?;
        let bundles = BundleStore::new(root.clone());
        let index = IndexStore::new(root.join("index.jsonl"));
        let storage = Self { bundles, index };
        storage.sweep_orphans().await?;
        Ok(storage)
    }

    pub async fn retention_report(
        &self,
        policy: RetentionPolicy,
    ) -> Result<RetentionReport, StorageError> {
        let entries = self.index.read_all().await?;
        self.retention_report_for_entries(&entries, policy).await
    }

    async fn retention_report_for_entries(
        &self,
        entries: &[IndexEntry],
        policy: RetentionPolicy,
    ) -> Result<RetentionReport, StorageError> {
        let mut candidates = self.retention_candidates(entries, policy).await?;
        let mut kinds = Vec::new();
        let mut total_bundle_files = 0usize;
        let mut total_size_bytes = 0u64;

        for kind in all_bundle_kinds() {
            let listed = self.bundles.list(kind).await?;
            let mut kind_size = 0u64;
            for sha in &listed {
                if let Ok(size) = self.bundles.size(kind, sha).await {
                    kind_size += size;
                }
            }
            total_bundle_files += listed.len();
            total_size_bytes += kind_size;
            kinds.push(RetentionKindReport {
                kind: kind.subdir().to_string(),
                indexed_entries: entries
                    .iter()
                    .filter(|entry| entry_kind(entry) == Some(kind))
                    .count(),
                bundle_files: listed.len(),
                size_bytes: kind_size,
                prune_candidates: candidates
                    .iter()
                    .filter(|candidate| candidate.kind == kind.subdir())
                    .count(),
            });
        }

        let reclaimable_bytes = candidates
            .iter()
            .map(|candidate| candidate.size_bytes)
            .sum();
        let total_prune_candidates = candidates.len();
        let prune_candidates_truncated =
            total_prune_candidates > RETENTION_REPORT_MAX_PRUNE_CANDIDATES;
        candidates.truncate(RETENTION_REPORT_MAX_PRUNE_CANDIDATES);
        Ok(RetentionReport {
            schema_version: "ao2.cp-storage-retention-report.v1".to_string(),
            keep_latest: policy.keep_latest,
            total_index_entries: entries.len(),
            total_bundle_files,
            total_size_bytes,
            reclaimable_bytes,
            total_prune_candidates,
            prune_candidates_limit: RETENTION_REPORT_MAX_PRUNE_CANDIDATES,
            prune_candidates_truncated,
            kinds,
            prune_candidates: candidates,
        })
    }

    pub async fn support_bundle(
        &self,
        policy: RetentionPolicy,
    ) -> Result<SupportBundle, StorageError> {
        let mut latest_index_entries = self.index.read_all().await?;
        latest_index_entries.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
        let retention_report = self
            .retention_report_for_entries(&latest_index_entries, policy)
            .await?;
        let phase1_release_readiness = self
            .support_bundle_phase1_readiness(&latest_index_entries)
            .await?;
        latest_index_entries.truncate(SUPPORT_BUNDLE_MAX_INDEX_ENTRIES);

        Ok(SupportBundle {
            schema_version: "ao2.cp-support-bundle.v1".to_string(),
            generated_at: chrono::Utc::now(),
            trust_boundary: SupportBundleTrustBoundary {
                frontend: "Hermes".to_string(),
                governed_backend: "Factory v3 / AO Operator".to_string(),
                trusted_execution: "AO2".to_string(),
                role: "read_only_observer".to_string(),
                mutates_ao_artifacts: false,
            },
            operator_handoff: support_bundle_operator_handoff(policy.keep_latest),
            phase1_release_readiness,
            retention_report,
            latest_index_entries,
        })
    }

    async fn support_bundle_phase1_readiness(
        &self,
        entries: &[IndexEntry],
    ) -> Result<SupportBundlePhase1Readiness, StorageError> {
        let mut readiness = support_bundle_phase1_readiness(entries);
        if let Some(Some(summary)) = readiness.observed_artifacts.get_mut("provider_readiness") {
            summary.signature = self
                .support_bundle_signature_summary(
                    BundleKind::ProviderReadinessSignature,
                    &summary.sha256,
                    format!("/api/v1/provider/readiness/{}/signature", summary.sha256),
                )
                .await?;
        }
        if let Some(Some(summary)) = readiness
            .observed_artifacts
            .get_mut("signed_phase1_promotion_decision")
        {
            summary.signature = self
                .support_bundle_signature_summary(
                    BundleKind::Phase1PromotionDecisionSignature,
                    &summary.sha256,
                    format!(
                        "/api/v1/phase1/promotion/decision/{}/signature",
                        summary.sha256
                    ),
                )
                .await?;
        }
        if let Some(Some(summary)) = readiness
            .observed_artifacts
            .get_mut("release_evaluator_decision")
        {
            summary.signature = self
                .support_bundle_signature_summary(
                    BundleKind::ReleaseEvaluatorDecisionSignature,
                    &summary.sha256,
                    format!(
                        "/api/v1/release/evaluator-decision/{}/signature",
                        summary.sha256
                    ),
                )
                .await?;
        }
        enforce_required_signed_artifact_sidecars(&mut readiness);
        Ok(readiness)
    }

    async fn support_bundle_signature_summary(
        &self,
        kind: BundleKind,
        sha: &str,
        raw_url: String,
    ) -> Result<Option<SupportBundleSignatureSummary>, StorageError> {
        if !self.bundles.exists(kind, sha).await {
            return Ok(None);
        }
        let raw = self.bundles.read(kind, sha).await?;
        let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|err| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid signature sidecar JSON for {sha}: {err}"),
            ))
        })?;
        let signature = value
            .get("signature")
            .and_then(serde_json::Value::as_object);
        Ok(Some(SupportBundleSignatureSummary {
            schema_version: value
                .get("schema_version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(kind.subdir())
                .to_string(),
            raw_url,
            signature_algorithm: signature
                .and_then(|sig| sig.get("signature_algorithm"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            signature_verified: signature
                .and_then(|sig| sig.get("signature_verified"))
                .and_then(serde_json::Value::as_bool),
            signer_id: signature
                .and_then(|sig| sig.get("signer_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            public_key_sha256: signature
                .and_then(|sig| sig.get("public_key_sha256"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            trust_anchor: signature
                .and_then(|sig| sig.get("trust_anchor"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            verification_scope: signature
                .and_then(|sig| sig.get("verification_scope"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            trust_policy: signature.and_then(|sig| sig.get("trust_policy")).cloned(),
        }))
    }

    pub async fn prune_retention(
        &self,
        policy: RetentionPolicy,
        dry_run: bool,
    ) -> Result<RetentionPruneResult, StorageError> {
        let entries = self.index.read_all().await?;
        let candidates = self.retention_candidates(&entries, policy).await?;
        let pruned_hashes: std::collections::HashSet<String> = candidates
            .iter()
            .map(|candidate| candidate.sha256.clone())
            .collect();

        if !dry_run {
            for candidate in &candidates {
                for kind_name in std::iter::once(candidate.kind.as_str())
                    .chain(candidate.related_bundle_kinds.iter().map(String::as_str))
                {
                    if let Some(kind) = bundle_kind_from_subdir(kind_name) {
                        self.bundles
                            .remove_if_exists(kind, &candidate.sha256)
                            .await?;
                    }
                }
            }
            let retained: Vec<IndexEntry> = entries
                .iter()
                .filter(|entry| !pruned_hashes.contains(&entry.sha256))
                .cloned()
                .collect();
            self.index.rewrite(&retained).await?;
        }

        let retained_index_entries = entries
            .iter()
            .filter(|entry| !pruned_hashes.contains(&entry.sha256))
            .count();
        let reclaimed_bytes = candidates
            .iter()
            .map(|candidate| candidate.size_bytes)
            .sum();
        Ok(RetentionPruneResult {
            schema_version: "ao2.cp-storage-prune.v1".to_string(),
            dry_run,
            keep_latest: policy.keep_latest,
            pruned: candidates,
            retained_index_entries,
            reclaimed_bytes,
        })
    }

    async fn retention_candidates(
        &self,
        entries: &[IndexEntry],
        policy: RetentionPolicy,
    ) -> Result<Vec<RetentionCandidate>, StorageError> {
        let mut candidates = Vec::new();
        for kind in all_prunable_primary_kinds() {
            let mut matching: Vec<&IndexEntry> = entries
                .iter()
                .filter(|entry| entry_kind(entry) == Some(kind))
                .collect();
            matching.sort_by_key(|entry| std::cmp::Reverse(entry.ingested_at));
            for entry in matching.into_iter().skip(policy.keep_latest) {
                let mut related_bundle_kinds = Vec::new();
                let mut size_bytes = self.bundles.size(kind, &entry.sha256).await.unwrap_or(0);
                for &related in related_kinds(kind) {
                    if self.bundles.exists(related, &entry.sha256).await {
                        related_bundle_kinds.push(related.subdir().to_string());
                        size_bytes += self.bundles.size(related, &entry.sha256).await.unwrap_or(0);
                    }
                }
                candidates.push(RetentionCandidate {
                    kind: kind.subdir().to_string(),
                    sha256: entry.sha256.clone(),
                    schema: entry.schema.clone(),
                    ingested_at: entry.ingested_at,
                    size_bytes,
                    related_bundle_kinds,
                });
            }
        }
        candidates.sort_by_key(|candidate| candidate.ingested_at);
        Ok(candidates)
    }

    async fn sweep_orphans(&self) -> Result<(), StorageError> {
        let known: std::collections::HashSet<String> = self
            .index
            .read_all()
            .await?
            .into_iter()
            .map(|e| e.sha256)
            .collect();

        for kind in [
            BundleKind::AcceptanceCodex,
            BundleKind::AcceptanceClaude,
            BundleKind::AcceptanceAntigravity,
            BundleKind::ControlPlaneBundle,
            BundleKind::EvidencePack,
            BundleKind::EvidencePackSignature,
            BundleKind::HermesWatchdogPanel,
            BundleKind::MemoryExport,
            BundleKind::MemoryExportSignature,
            BundleKind::Phase1PromotionChecklist,
            BundleKind::Phase1PromotionDecision,
            BundleKind::Phase1PromotionDecisionSignature,
            BundleKind::ProviderReadiness,
            BundleKind::ProviderReadinessSignature,
            BundleKind::ProviderRegistry,
            BundleKind::ProviderRegistrySignature,
            BundleKind::ReleaseEvaluatorDecision,
            BundleKind::ReleaseEvaluatorDecisionSignature,
            BundleKind::ReleasePublication,
            BundleKind::ThreeOsReleaseSmoke,
        ] {
            let listed = self.bundles.list(kind).await?;
            for sha in listed {
                if !known.contains(&sha) {
                    let path = self
                        .bundles
                        .root()
                        .join(kind.subdir())
                        .join(format!("{sha}.json"));
                    tracing::warn!(
                        path = %path.display(),
                        sha256 = %sha,
                        "removing orphan bundle file (not in index)",
                    );
                    tokio::fs::remove_file(&path).await?;
                }
            }
        }
        Ok(())
    }
}

fn all_bundle_kinds() -> [BundleKind; 21] {
    [
        BundleKind::AcceptanceCodex,
        BundleKind::AcceptanceClaude,
        BundleKind::AcceptanceAntigravity,
        BundleKind::ControlPlaneBundle,
        BundleKind::EvidencePack,
        BundleKind::EvidencePackSignature,
        BundleKind::HermesWatchdogPanel,
        BundleKind::MemoryExport,
        BundleKind::MemoryExportSignature,
        BundleKind::Phase1PromotionChecklist,
        BundleKind::Phase1PromotionDecision,
        BundleKind::Phase1PromotionDecisionSignature,
        BundleKind::Phase1PromotionInputsVerification,
        BundleKind::ProviderReadiness,
        BundleKind::ProviderReadinessSignature,
        BundleKind::ProviderRegistry,
        BundleKind::ProviderRegistrySignature,
        BundleKind::ReleaseEvaluatorDecision,
        BundleKind::ReleaseEvaluatorDecisionSignature,
        BundleKind::ReleasePublication,
        BundleKind::ThreeOsReleaseSmoke,
    ]
}

fn all_prunable_primary_kinds() -> [BundleKind; 15] {
    [
        BundleKind::AcceptanceCodex,
        BundleKind::AcceptanceClaude,
        BundleKind::AcceptanceAntigravity,
        BundleKind::ControlPlaneBundle,
        BundleKind::EvidencePack,
        BundleKind::HermesWatchdogPanel,
        BundleKind::MemoryExport,
        BundleKind::Phase1PromotionChecklist,
        BundleKind::Phase1PromotionDecision,
        BundleKind::Phase1PromotionInputsVerification,
        BundleKind::ProviderReadiness,
        BundleKind::ProviderRegistry,
        BundleKind::ReleaseEvaluatorDecision,
        BundleKind::ReleasePublication,
        BundleKind::ThreeOsReleaseSmoke,
    ]
}

fn related_kinds(kind: BundleKind) -> &'static [BundleKind] {
    match kind {
        BundleKind::EvidencePack => &[BundleKind::EvidencePackSignature],
        BundleKind::MemoryExport => &[BundleKind::MemoryExportSignature],
        BundleKind::Phase1PromotionDecision => &[BundleKind::Phase1PromotionDecisionSignature],
        BundleKind::ProviderReadiness => &[BundleKind::ProviderReadinessSignature],
        BundleKind::ProviderRegistry => &[BundleKind::ProviderRegistrySignature],
        BundleKind::ReleaseEvaluatorDecision => &[BundleKind::ReleaseEvaluatorDecisionSignature],
        _ => &[],
    }
}

fn entry_kind(entry: &IndexEntry) -> Option<BundleKind> {
    match entry.schema.as_str() {
        "ao2.codex-provider-pilot-acceptance.v1" => Some(BundleKind::AcceptanceCodex),
        "ao2.claude-provider-pilot-acceptance.v1" => Some(BundleKind::AcceptanceClaude),
        "ao2.antigravity-provider-pilot-acceptance.v1" => Some(BundleKind::AcceptanceAntigravity),
        "ao2.control-plane-fleet-bundle.v1" => Some(BundleKind::ControlPlaneBundle),
        "ao2.evidence-pack.v1" => Some(BundleKind::EvidencePack),
        "factory-v3/hermes-ao2-watchdog-panel/v1" => Some(BundleKind::HermesWatchdogPanel),
        "ao2.memory-export.v1" => Some(BundleKind::MemoryExport),
        "factory-v3/ao2-phase1-promotion-checklist/v1" => {
            Some(BundleKind::Phase1PromotionChecklist)
        }
        "factory-v3/ao2-phase1-promotion-decision/v1" => Some(BundleKind::Phase1PromotionDecision),
        "ao2.phase1-replacement-promotion-inputs-verification.v1" => {
            Some(BundleKind::Phase1PromotionInputsVerification)
        }
        "factory-v3/hermes-provider-phase1-readiness/v1" => Some(BundleKind::ProviderReadiness),
        "ao2.provider-plugin-registry.v1" => Some(BundleKind::ProviderRegistry),
        "factory-v3/ao2-release-evaluator-decision/v1" => {
            Some(BundleKind::ReleaseEvaluatorDecision)
        }
        "ao2.release-publication-summary.v1" => Some(BundleKind::ReleasePublication),
        "ao2-control-plane.three-os-release-smoke.v1" => Some(BundleKind::ThreeOsReleaseSmoke),
        _ if entry.provider.as_deref() == Some("codex") => Some(BundleKind::AcceptanceCodex),
        _ if entry.provider.as_deref() == Some("claude") => Some(BundleKind::AcceptanceClaude),
        _ if entry.provider.as_deref() == Some("antigravity") => {
            Some(BundleKind::AcceptanceAntigravity)
        }
        _ => None,
    }
}

fn bundle_kind_from_subdir(subdir: &str) -> Option<BundleKind> {
    all_bundle_kinds()
        .into_iter()
        .find(|kind| kind.subdir() == subdir)
}
