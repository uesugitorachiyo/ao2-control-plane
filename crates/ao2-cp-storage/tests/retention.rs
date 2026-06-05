use ao2_cp_storage::{bundle::BundleKind, index::IndexEntry, RetentionPolicy, Storage};
use chrono::{Duration, Utc};
use tempfile::tempdir;

fn entry(schema: &str, provider: Option<&str>, sha256: &str, age_seconds: i64) -> IndexEntry {
    IndexEntry {
        ingested_at: Utc::now() - Duration::seconds(age_seconds),
        schema: schema.to_string(),
        provider: provider.map(str::to_string),
        sha256: sha256.to_string(),
        status: Some("accepted".to_string()),
        size_bytes: 2,
    }
}

async fn write_indexed(
    storage: &Storage,
    kind: BundleKind,
    schema: &str,
    provider: Option<&str>,
    sha: &str,
    age_seconds: i64,
) {
    storage.bundles.write(kind, sha, b"{}").await.unwrap();
    storage
        .index
        .append(entry(schema, provider, sha, age_seconds))
        .await
        .unwrap();
}

#[tokio::test]
async fn retention_report_marks_oldest_entries_per_kind_without_deleting() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let old_sha = "1".repeat(64);
    let kept_sha = "2".repeat(64);

    write_indexed(
        &storage,
        BundleKind::EvidencePack,
        "ao2.evidence-pack.v1",
        None,
        &old_sha,
        120,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::EvidencePackSignature, &old_sha, b"{}")
        .await
        .unwrap();
    write_indexed(
        &storage,
        BundleKind::EvidencePack,
        "ao2.evidence-pack.v1",
        None,
        &kept_sha,
        30,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::EvidencePackSignature, &kept_sha, b"{}")
        .await
        .unwrap();

    let report = storage
        .retention_report(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(report.schema_version, "ao2.cp-storage-retention-report.v1");
    assert_eq!(report.keep_latest, 1);
    assert_eq!(report.prune_candidates.len(), 1);
    assert_eq!(report.prune_candidates[0].sha256, old_sha);
    assert_eq!(report.prune_candidates[0].kind, "evidence-pack");
    assert!(report.prune_candidates[0]
        .related_bundle_kinds
        .contains(&"evidence-pack-signature".to_string()));
    assert!(
        storage
            .bundles
            .exists(BundleKind::EvidencePack, &old_sha)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(BundleKind::EvidencePackSignature, &old_sha)
            .await
    );
}

#[tokio::test]
async fn support_bundle_is_bounded_newest_first_and_read_only() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    for i in 0..55 {
        let sha = format!("{i:064x}");
        write_indexed(
            &storage,
            BundleKind::MemoryExport,
            "ao2.memory-export.v1",
            None,
            &sha,
            i,
        )
        .await;
    }

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(bundle.schema_version, "ao2.cp-support-bundle.v1");
    assert_eq!(bundle.retention_report.total_index_entries, 55);
    assert_eq!(bundle.latest_index_entries.len(), 50);
    assert_eq!(bundle.latest_index_entries[0].sha256, format!("{:064x}", 0));
    assert_eq!(
        bundle.latest_index_entries[49].sha256,
        format!("{:064x}", 49)
    );
    assert_eq!(storage.index.read_all().await.unwrap().len(), 55);
    assert_eq!(
        bundle
            .operator_handoff
            .relative_endpoints
            .get("release_handoff")
            .map(String::as_str),
        Some("/api/v1/release/handoff")
    );
    assert_eq!(
        bundle
            .operator_handoff
            .relative_endpoints
            .get("release_readiness_json")
            .map(String::as_str),
        Some("/api/v1/release/readiness.json")
    );
    assert_eq!(
        bundle
            .operator_handoff
            .relative_endpoints
            .get("release_evaluator_decision_dashboard")
            .map(String::as_str),
        Some("/api/v1/release/evaluator-decision/dashboard")
    );
    assert_eq!(
        bundle
            .operator_handoff
            .relative_endpoints
            .get("release_evaluator_decision_dashboard_json")
            .map(String::as_str),
        Some("/api/v1/release/evaluator-decision/dashboard.json")
    );
    assert_eq!(
        bundle
            .operator_handoff
            .relative_endpoints
            .get("phase1_promotion_gap_report_json")
            .map(String::as_str),
        Some("/api/v1/phase1/promotion/gap-report.json")
    );
    assert_eq!(
        bundle
            .phase1_release_readiness
            .operator_links
            .get("release_handoff_json")
            .map(String::as_str),
        Some("/api/v1/release/handoff.json")
    );
    assert_eq!(
        bundle
            .phase1_release_readiness
            .operator_links
            .get("release_readiness")
            .map(String::as_str),
        Some("/api/v1/release/readiness")
    );
}

#[tokio::test]
async fn retention_report_counts_release_evaluator_decision_bundles() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let sha = "d".repeat(64);

    write_indexed(
        &storage,
        BundleKind::ReleaseEvaluatorDecision,
        "factory-v3/ao2-release-evaluator-decision/v1",
        None,
        &sha,
        10,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::ReleaseEvaluatorDecisionSignature, &sha, b"{}")
        .await
        .unwrap();

    let report = storage
        .retention_report(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    let release_decision = report
        .kinds
        .iter()
        .find(|kind| kind.kind == "release-evaluator-decision")
        .expect("release evaluator decision kind is included in retention reports");
    assert_eq!(release_decision.indexed_entries, 1);
    assert_eq!(release_decision.bundle_files, 1);
    assert_eq!(release_decision.size_bytes, 2);
    let release_decision_signature = report
        .kinds
        .iter()
        .find(|kind| kind.kind == "release-evaluator-decision-signature")
        .expect(
            "release evaluator decision signature sidecar kind is included in retention reports",
        );
    assert_eq!(release_decision_signature.indexed_entries, 0);
    assert_eq!(release_decision_signature.bundle_files, 1);
    assert_eq!(release_decision_signature.size_bytes, 2);
}

#[tokio::test]
async fn support_bundle_summarizes_provider_readiness_signature_sidecar_without_pem() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let sha = "c".repeat(64);

    write_indexed(
        &storage,
        BundleKind::ProviderReadiness,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &sha,
        10,
    )
    .await;
    storage
        .bundles
        .write(
            BundleKind::ProviderReadinessSignature,
            &sha,
            br#"{
                "schema_version":"ao2.cp-provider-readiness-signature.v1",
                "provider_readiness_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "signature":{
                    "signature_algorithm":"RSA/SHA-256",
                    "signature_verified":true,
                    "signer_id":"provider-readiness-evaluator",
                    "public_key_sha256":"pubkey-digest",
                    "public_key_pem":"must-not-appear",
                    "trust_anchor":"upload-public-key-not-authority",
                    "verification_scope":"cryptographic-only",
                    "trust_policy":{
                        "policy":"observer-only-upload-key",
                        "trusted_key_match":false,
                        "release_authoritative":false,
                        "matched_public_key_sha256":""
                    }
                }
            }"#,
        )
        .await
        .unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();
    let provider_readiness = bundle
        .phase1_release_readiness
        .observed_artifacts
        .get("provider_readiness")
        .and_then(Option::as_ref)
        .expect("provider readiness artifact summary is present");
    let signature = provider_readiness
        .signature
        .as_ref()
        .expect("provider readiness signature sidecar is summarized");

    assert_eq!(
        signature.schema_version,
        "ao2.cp-provider-readiness-signature.v1"
    );
    assert_eq!(
        signature.signature_algorithm.as_deref(),
        Some("RSA/SHA-256")
    );
    assert_eq!(signature.signature_verified, Some(true));
    assert_eq!(
        signature.signer_id.as_deref(),
        Some("provider-readiness-evaluator")
    );
    assert_eq!(
        signature.public_key_sha256.as_deref(),
        Some("pubkey-digest")
    );
    assert_eq!(
        signature.trust_anchor.as_deref(),
        Some("upload-public-key-not-authority")
    );
    assert_eq!(
        signature.verification_scope.as_deref(),
        Some("cryptographic-only")
    );
    assert_eq!(
        signature.raw_url,
        "/api/v1/provider/readiness/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/signature"
    );
    assert!(!serde_json::to_string(&signature)
        .unwrap()
        .contains("must-not-appear"));
}

#[tokio::test]
async fn retention_report_counts_provider_readiness_signature_sidecars() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let old_sha = "a".repeat(64);
    let kept_sha = "b".repeat(64);

    write_indexed(
        &storage,
        BundleKind::ProviderReadiness,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &old_sha,
        120,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::ProviderReadinessSignature, &old_sha, b"{}")
        .await
        .unwrap();
    write_indexed(
        &storage,
        BundleKind::ProviderReadiness,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &kept_sha,
        30,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::ProviderReadinessSignature, &kept_sha, b"{}")
        .await
        .unwrap();

    let report = storage
        .retention_report(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    let readiness_signature = report
        .kinds
        .iter()
        .find(|kind| kind.kind == "provider-readiness-signature")
        .expect("provider readiness signature sidecar kind is included in retention reports");
    assert_eq!(readiness_signature.indexed_entries, 0);
    assert_eq!(readiness_signature.bundle_files, 2);
    assert_eq!(readiness_signature.size_bytes, 4);
    assert_eq!(report.prune_candidates.len(), 1);
    assert_eq!(report.prune_candidates[0].sha256, old_sha);
    assert_eq!(report.prune_candidates[0].kind, "provider-readiness");
    assert!(report.prune_candidates[0]
        .related_bundle_kinds
        .contains(&"provider-readiness-signature".to_string()));

    let result = storage
        .prune_retention(RetentionPolicy { keep_latest: 1 }, false)
        .await
        .unwrap();
    assert_eq!(result.pruned.len(), 1);
    assert_eq!(result.pruned[0].related_bundle_kinds.len(), 1);
    assert_eq!(result.reclaimed_bytes, 4);
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ProviderReadinessSignature, &old_sha)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(BundleKind::ProviderReadinessSignature, &kept_sha)
            .await
    );
}

#[tokio::test]
async fn retention_report_bounds_prune_candidate_preview_without_losing_totals() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();

    for i in 0..125 {
        let sha = format!("{i:064x}");
        write_indexed(
            &storage,
            BundleKind::MemoryExport,
            "ao2.memory-export.v1",
            None,
            &sha,
            i,
        )
        .await;
    }

    let report = storage
        .retention_report(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(report.total_index_entries, 125);
    assert_eq!(report.total_prune_candidates, 124);
    assert_eq!(report.prune_candidates_limit, 100);
    assert!(report.prune_candidates_truncated);
    assert_eq!(report.prune_candidates.len(), 100);
    assert_eq!(report.prune_candidates[0].sha256, format!("{:064x}", 124));
    assert_eq!(report.prune_candidates[99].sha256, format!("{:064x}", 25));
    assert_eq!(storage.index.read_all().await.unwrap().len(), 125);
}

#[tokio::test]
async fn support_bundle_blocks_release_handoff_until_evaluator_decision_is_observed() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let observed = [
        (
            BundleKind::ProviderReadiness,
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1".repeat(64),
        ),
        (
            BundleKind::AcceptanceCodex,
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2".repeat(64),
        ),
        (
            BundleKind::AcceptanceClaude,
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionChecklist,
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionDecision,
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5".repeat(64),
        ),
        (
            BundleKind::ThreeOsReleaseSmoke,
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6".repeat(64),
        ),
        (
            BundleKind::ReleasePublication,
            "ao2.release-publication-summary.v1",
            None,
            "7".repeat(64),
        ),
    ];

    for (index, (kind, schema, provider, sha)) in observed.into_iter().enumerate() {
        write_indexed(&storage, kind, schema, provider, &sha, index as i64).await;
    }
    storage
        .bundles
        .write(
            BundleKind::Phase1PromotionDecisionSignature,
            &"5".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(bundle.phase1_release_readiness.readiness_status, "blocked");
    assert!(!bundle.phase1_release_readiness.release_decision_allowed);
    assert_eq!(bundle.phase1_release_readiness.total_open_gaps, 1);
    assert_eq!(
        bundle.phase1_release_readiness.blocking_gaps[0].id,
        "release_evaluator_decision"
    );
    assert_eq!(
        bundle.phase1_release_readiness.blocking_gaps[0].evidence_needed,
        "Factory v3 release evaluator-closer decision artifact"
    );
    assert!(bundle
        .phase1_release_readiness
        .next_recommended_action
        .contains("publish the Factory v3 release evaluator-closer decision"));
}

#[tokio::test]
async fn support_bundle_marks_stale_release_readiness_and_evaluator_evidence_as_blocking() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let observed = [
        (
            BundleKind::ProviderReadiness,
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1".repeat(64),
            49 * 60 * 60,
        ),
        (
            BundleKind::AcceptanceCodex,
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2".repeat(64),
            60,
        ),
        (
            BundleKind::AcceptanceClaude,
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3".repeat(64),
            60,
        ),
        (
            BundleKind::Phase1PromotionChecklist,
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4".repeat(64),
            60,
        ),
        (
            BundleKind::Phase1PromotionDecision,
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5".repeat(64),
            60,
        ),
        (
            BundleKind::ThreeOsReleaseSmoke,
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6".repeat(64),
            60,
        ),
        (
            BundleKind::ReleasePublication,
            "ao2.release-publication-summary.v1",
            None,
            "7".repeat(64),
            60,
        ),
        (
            BundleKind::ReleaseEvaluatorDecision,
            "factory-v3/ao2-release-evaluator-decision/v1",
            None,
            "8".repeat(64),
            49 * 60 * 60,
        ),
    ];

    for (kind, schema, provider, sha, age_seconds) in observed {
        write_indexed(&storage, kind, schema, provider, &sha, age_seconds).await;
    }
    storage
        .bundles
        .write(
            BundleKind::Phase1PromotionDecisionSignature,
            &"5".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &"8".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    let provider_readiness = bundle
        .phase1_release_readiness
        .observed_artifacts
        .get("provider_readiness")
        .and_then(Option::as_ref)
        .expect("provider readiness summary is present");
    assert!(provider_readiness.is_stale);
    assert_eq!(provider_readiness.stale_after_seconds, Some(24 * 60 * 60));
    assert!(provider_readiness.age_seconds >= 49 * 60 * 60 - 5);

    let evaluator_decision = bundle
        .phase1_release_readiness
        .observed_artifacts
        .get("release_evaluator_decision")
        .and_then(Option::as_ref)
        .expect("release evaluator decision summary is present");
    assert!(evaluator_decision.is_stale);

    let gap_ids: Vec<&str> = bundle
        .phase1_release_readiness
        .blocking_gaps
        .iter()
        .map(|gap| gap.id.as_str())
        .collect();
    assert_eq!(
        gap_ids,
        vec!["provider_readiness", "release_evaluator_decision"]
    );
    assert!(bundle.phase1_release_readiness.blocking_gaps[0]
        .evidence_needed
        .contains("fresh"));
    assert!(bundle.phase1_release_readiness.blocking_gaps[1]
        .next_action
        .contains("refresh"));
}

#[tokio::test]
async fn support_bundle_blocks_release_readiness_when_signed_artifact_signature_sidecars_are_missing(
) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let observed = [
        (
            BundleKind::ProviderReadiness,
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1".repeat(64),
        ),
        (
            BundleKind::AcceptanceCodex,
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2".repeat(64),
        ),
        (
            BundleKind::AcceptanceClaude,
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionChecklist,
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionDecision,
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5".repeat(64),
        ),
        (
            BundleKind::ThreeOsReleaseSmoke,
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6".repeat(64),
        ),
        (
            BundleKind::ReleasePublication,
            "ao2.release-publication-summary.v1",
            None,
            "7".repeat(64),
        ),
        (
            BundleKind::ReleaseEvaluatorDecision,
            "factory-v3/ao2-release-evaluator-decision/v1",
            None,
            "8".repeat(64),
        ),
    ];

    for (kind, schema, provider, sha) in observed {
        write_indexed(&storage, kind, schema, provider, &sha, 60).await;
    }

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    let gap_ids: Vec<&str> = bundle
        .phase1_release_readiness
        .blocking_gaps
        .iter()
        .map(|gap| gap.id.as_str())
        .collect();
    assert_eq!(
        gap_ids,
        vec![
            "signed_phase1_promotion_decision_signature",
            "release_evaluator_decision_signature"
        ]
    );
    assert_eq!(bundle.phase1_release_readiness.readiness_status, "blocked");
    assert!(!bundle.phase1_release_readiness.release_decision_allowed);
    assert_eq!(
        bundle
            .phase1_release_readiness
            .gap_summary
            .missing_signature_count,
        2
    );
    assert!(bundle.phase1_release_readiness.blocking_gaps[0]
        .next_action
        .contains("publish the signature sidecar"));
}

#[tokio::test]
async fn support_bundle_blocks_release_readiness_when_signed_artifact_signature_is_unverified() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let observed = [
        (
            BundleKind::ProviderReadiness,
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1".repeat(64),
        ),
        (
            BundleKind::AcceptanceCodex,
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2".repeat(64),
        ),
        (
            BundleKind::AcceptanceClaude,
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionChecklist,
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionDecision,
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5".repeat(64),
        ),
        (
            BundleKind::ThreeOsReleaseSmoke,
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6".repeat(64),
        ),
        (
            BundleKind::ReleasePublication,
            "ao2.release-publication-summary.v1",
            None,
            "7".repeat(64),
        ),
        (
            BundleKind::ReleaseEvaluatorDecision,
            "factory-v3/ao2-release-evaluator-decision/v1",
            None,
            "8".repeat(64),
        ),
    ];

    for (kind, schema, provider, sha) in observed {
        write_indexed(&storage, kind, schema, provider, &sha, 60).await;
    }
    storage
        .bundles
        .write(
            BundleKind::Phase1PromotionDecisionSignature,
            &"5".repeat(64),
            br#"{"signature":{"signature_verified":false,"public_key_pem":"must-not-leak"}}"#,
        )
        .await
        .unwrap();
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &"8".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(bundle.phase1_release_readiness.total_open_gaps, 1);
    assert_eq!(
        bundle.phase1_release_readiness.blocking_gaps[0].id,
        "signed_phase1_promotion_decision_signature"
    );
    assert_eq!(
        bundle.phase1_release_readiness.blocking_gaps[0].gap_kind,
        "unverified_signature"
    );
    assert_eq!(
        bundle
            .phase1_release_readiness
            .gap_summary
            .unverified_signature_count,
        1
    );
    assert!(!serde_json::to_string(&bundle)
        .unwrap()
        .contains("must-not-leak"));
}

#[tokio::test]
async fn support_bundle_blocks_release_readiness_when_observed_artifact_status_failed() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let observed = [
        (
            BundleKind::ProviderReadiness,
            "factory-v3/hermes-provider-phase1-readiness/v1",
            None,
            "1".repeat(64),
        ),
        (
            BundleKind::AcceptanceCodex,
            "ao2.codex-provider-pilot-acceptance.v1",
            Some("codex"),
            "2".repeat(64),
        ),
        (
            BundleKind::AcceptanceClaude,
            "ao2.claude-provider-pilot-acceptance.v1",
            Some("claude"),
            "3".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionChecklist,
            "factory-v3/ao2-phase1-promotion-checklist/v1",
            None,
            "4".repeat(64),
        ),
        (
            BundleKind::Phase1PromotionDecision,
            "factory-v3/ao2-phase1-promotion-decision/v1",
            None,
            "5".repeat(64),
        ),
        (
            BundleKind::ThreeOsReleaseSmoke,
            "ao2-control-plane.three-os-release-smoke.v1",
            None,
            "6".repeat(64),
        ),
        (
            BundleKind::ReleasePublication,
            "ao2.release-publication-summary.v1",
            None,
            "7".repeat(64),
        ),
        (
            BundleKind::ReleaseEvaluatorDecision,
            "factory-v3/ao2-release-evaluator-decision/v1",
            None,
            "8".repeat(64),
        ),
    ];

    for (kind, schema, provider, sha) in observed {
        write_indexed(&storage, kind, schema, provider, &sha, 60).await;
    }
    storage
        .bundles
        .write(
            BundleKind::Phase1PromotionDecisionSignature,
            &"5".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &"8".repeat(64),
            br#"{"signature":{"signature_verified":true}}"#,
        )
        .await
        .unwrap();
    let mut entries = storage.index.read_all().await.unwrap();
    let smoke = entries
        .iter_mut()
        .find(|entry| entry.schema == "ao2-control-plane.three-os-release-smoke.v1")
        .expect("three-OS smoke entry exists");
    smoke.status = Some("failed".to_string());
    storage.index.rewrite(&entries).await.unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    assert_eq!(bundle.phase1_release_readiness.readiness_status, "blocked");
    assert!(!bundle.phase1_release_readiness.release_decision_allowed);
    assert_eq!(bundle.phase1_release_readiness.total_open_gaps, 1);
    assert_eq!(
        bundle.phase1_release_readiness.blocking_gaps[0].id,
        "three_os_release_smoke"
    );
    assert!(bundle.phase1_release_readiness.blocking_gaps[0]
        .evidence_needed
        .contains("non-failing"));
    assert!(bundle.phase1_release_readiness.blocking_gaps[0]
        .next_action
        .contains("failed"));
}

#[tokio::test]
async fn retention_prune_removes_only_control_plane_copies_and_rewrites_index() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let old_memory = "a".repeat(64);
    let kept_memory = "b".repeat(64);
    let kept_bundle = "c".repeat(64);

    write_indexed(
        &storage,
        BundleKind::MemoryExport,
        "ao2.memory-export.v1",
        None,
        &old_memory,
        300,
    )
    .await;
    storage
        .bundles
        .write(BundleKind::MemoryExportSignature, &old_memory, b"{}")
        .await
        .unwrap();
    write_indexed(
        &storage,
        BundleKind::MemoryExport,
        "ao2.memory-export.v1",
        None,
        &kept_memory,
        20,
    )
    .await;
    write_indexed(
        &storage,
        BundleKind::ControlPlaneBundle,
        "ao2.control-plane-fleet-bundle.v1",
        None,
        &kept_bundle,
        400,
    )
    .await;

    let result = storage
        .prune_retention(RetentionPolicy { keep_latest: 1 }, false)
        .await
        .unwrap();

    assert_eq!(result.schema_version, "ao2.cp-storage-prune.v1");
    assert!(!result.dry_run);
    assert_eq!(result.pruned.len(), 1);
    assert_eq!(result.pruned[0].sha256, old_memory);
    assert!(
        !storage
            .bundles
            .exists(BundleKind::MemoryExport, &old_memory)
            .await
    );
    assert!(
        !storage
            .bundles
            .exists(BundleKind::MemoryExportSignature, &old_memory)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(BundleKind::MemoryExport, &kept_memory)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(BundleKind::ControlPlaneBundle, &kept_bundle)
            .await
    );

    let indexed: Vec<String> = storage
        .index
        .read_all()
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.sha256)
        .collect();
    assert_eq!(indexed, vec![kept_memory, kept_bundle]);
}

#[tokio::test]
async fn retention_prune_removes_release_evaluator_decision_signature_sidecars() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let old_decision = "e".repeat(64);
    let kept_decision = "f".repeat(64);

    write_indexed(
        &storage,
        BundleKind::ReleaseEvaluatorDecision,
        "factory-v3/ao2-release-evaluator-decision/v1",
        None,
        &old_decision,
        300,
    )
    .await;
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &old_decision,
            b"{}",
        )
        .await
        .unwrap();
    write_indexed(
        &storage,
        BundleKind::ReleaseEvaluatorDecision,
        "factory-v3/ao2-release-evaluator-decision/v1",
        None,
        &kept_decision,
        20,
    )
    .await;
    storage
        .bundles
        .write(
            BundleKind::ReleaseEvaluatorDecisionSignature,
            &kept_decision,
            b"{}",
        )
        .await
        .unwrap();

    let report = storage
        .retention_report(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();
    assert_eq!(report.prune_candidates.len(), 1);
    assert_eq!(report.prune_candidates[0].sha256, old_decision);
    assert!(report.prune_candidates[0]
        .related_bundle_kinds
        .contains(&"release-evaluator-decision-signature".to_string()));

    let result = storage
        .prune_retention(RetentionPolicy { keep_latest: 1 }, false)
        .await
        .unwrap();

    assert_eq!(result.pruned.len(), 1);
    assert_eq!(result.pruned[0].sha256, old_decision);
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecision, &old_decision)
            .await
    );
    assert!(
        !storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecisionSignature, &old_decision)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(BundleKind::ReleaseEvaluatorDecision, &kept_decision)
            .await
    );
    assert!(
        storage
            .bundles
            .exists(
                BundleKind::ReleaseEvaluatorDecisionSignature,
                &kept_decision
            )
            .await
    );
}

#[tokio::test]
async fn support_bundle_blocks_provider_readiness_signed_by_unpinned_upload_key() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let sha = "a".repeat(64);

    write_indexed(
        &storage,
        BundleKind::ProviderReadiness,
        "factory-v3/hermes-provider-phase1-readiness/v1",
        None,
        &sha,
        10,
    )
    .await;
    storage
        .bundles
        .write(
            BundleKind::ProviderReadinessSignature,
            &sha,
            br#"{
                "schema_version":"ao2.cp-provider-readiness-signature.v1",
                "signature":{
                    "signature_verified":true,
                    "verification_scope":"cryptographic-only",
                    "trust_policy":{
                        "policy":"observer-only-upload-key",
                        "trusted_key_match":false,
                        "release_authoritative":false
                    }
                }
            }"#,
        )
        .await
        .unwrap();

    let bundle = storage
        .support_bundle(RetentionPolicy { keep_latest: 1 })
        .await
        .unwrap();

    let provider_signature_gap = bundle
        .phase1_release_readiness
        .blocking_gaps
        .iter()
        .find(|gap| gap.id == "provider_readiness_signature")
        .expect("observer-only provider readiness upload-key signature is a blocking gap");
    assert_eq!(provider_signature_gap.gap_kind, "untrusted_signature");
    assert!(provider_signature_gap
        .evidence_needed
        .contains("release-authoritative pinned-key signature"));
    assert!(!bundle.phase1_release_readiness.release_decision_allowed);
    assert_eq!(bundle.phase1_release_readiness.readiness_status, "blocked");
    assert_eq!(
        bundle
            .phase1_release_readiness
            .gap_summary
            .untrusted_signature_count,
        1
    );
}
