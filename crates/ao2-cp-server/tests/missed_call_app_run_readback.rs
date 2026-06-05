//! K5 follow-up to BOARD.md Claude lane: prove the control-plane observer can
//! identify and preserve the realistic `missed-call-recovery` product fixture
//! that AO2 C3 emits, on top of the integrity invariants already proved by
//! K3/K4. Tests are pure-integrity (no server spin-up) because the C3 bundle
//! reuses the same `ao2.factory-app-run-bundle.v1` schema as C2 — its
//! observer-ingest behavior is already covered by
//! `factory_app_run_bundle_readback.rs`.
//!
//! Fixture origin: ao2 commit `d47c04e` factory-app-run-smoke
//! `20260528T030540Z`. The 4 fixtures committed here cover the bundle's
//! `manifest.json` + `SHA256SUMS` + `release-review.json` plus the C3 product
//! summary `factory-app-run-summary.json` (`ao2.factory-app-run-smoke.v1`),
//! which is where the product fixture/domain metadata lives.

use sha2::Digest;
use std::collections::HashMap;

const BUNDLE_MANIFEST: &str = include_str!("fixtures/missed-call-app-run/manifest.json");
const BUNDLE_SHA256SUMS: &str = include_str!("fixtures/missed-call-app-run/SHA256SUMS");
const BUNDLE_RELEASE_REVIEW: &str =
    include_str!("fixtures/missed-call-app-run/release-review.json");
const APP_RUN_SUMMARY: &str =
    include_str!("fixtures/missed-call-app-run/factory-app-run-summary.json");

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_sha256sums(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let sha = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").trim().to_string();
        if !sha.is_empty() && !path.is_empty() {
            map.insert(path, sha);
        }
    }
    map
}

#[test]
fn missed_call_app_run_summary_carries_product_fixture_and_domain() {
    let summary: serde_json::Value =
        serde_json::from_str(APP_RUN_SUMMARY).expect("summary must parse");
    assert_eq!(
        summary["schema_version"], "ao2.factory-app-run-smoke.v1",
        "C3 summary must declare the smoke schema"
    );
    assert_eq!(
        summary["product_fixture"], "missed-call-recovery",
        "C3 summary must identify the product fixture as missed-call-recovery"
    );
    assert_eq!(
        summary["product_domain"], "missed-call revenue recovery",
        "C3 summary must identify the product domain"
    );
    // The summary names the same trust-boundary signals the bundle manifest
    // carries; the control plane must not silently relax them.
    assert_eq!(summary["control_plane_approves_release"], false);
    assert_eq!(summary["mutates_ao_artifacts"], false);
    assert_eq!(
        summary["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(summary["factory_v3_role"], "parity_oracle_only");
    assert_eq!(
        summary["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    // The C3 run must claim the release-review-ready discipline.
    assert_eq!(summary["release_review_artifacts_ready"], true);
    assert_eq!(summary["app_run_bundle_status"], "bundled");
    assert_eq!(summary["evaluator_decision_status"], "accepted");
}

#[test]
fn missed_call_app_run_bundle_manifest_and_sha256sums_are_internally_consistent() {
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-app-run-bundle.v1",
        "C3 reuses the C2 bundle schema; observer guarantees carry over"
    );

    let tb = &manifest["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"], false);
    assert_eq!(tb["mutates_ao_artifacts"], false);
    assert_eq!(
        tb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );

    // release-review.json is the only embedded artifact whose bytes we can
    // hash against the manifest in this test; the remaining 6 artifacts'
    // sha256 entries are cross-validated via SHA256SUMS below.
    let bundled_release_review_sha = hex_sha256(BUNDLE_RELEASE_REVIEW.as_bytes());

    let manifest_files = manifest["files"].as_array().expect("manifest.files");
    let mut release_review_seen = false;
    for entry in manifest_files {
        if entry["path"] == "release-review.json" {
            assert_eq!(
                entry["sha256"], bundled_release_review_sha,
                "manifest sha256 for release-review.json drifted from bundled bytes"
            );
            release_review_seen = true;
        }
    }
    assert!(
        release_review_seen,
        "manifest must list release-review.json"
    );

    // SHA256SUMS must agree with manifest.files[] for every entry, including
    // the unembedded artifacts that the AO2 producer hashed. Proves the
    // bundle's two manifests are derived from the same source-of-truth.
    let sums = parse_sha256sums(BUNDLE_SHA256SUMS);
    for entry in manifest_files {
        let path = entry["path"].as_str().unwrap();
        let claimed = entry["sha256"].as_str().unwrap();
        let sums_sha = sums
            .get(path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing path {path}"));
        assert_eq!(
            sums_sha, claimed,
            "SHA256SUMS disagrees with manifest.files[] for {path}"
        );
    }
    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
}

#[test]
fn missed_call_release_review_preserves_evaluator_closer_ownership() {
    // Same observer-only contract as K4: the release-review file must name
    // factory-v3 evaluator-closer as the release-acceptance owner. C3
    // (product dogfood) must not silently transfer that ownership to the
    // control plane.
    let release_review: serde_json::Value =
        serde_json::from_str(BUNDLE_RELEASE_REVIEW).expect("release-review.json must parse");
    let owner = release_review
        .pointer("/release_acceptance_owner")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            release_review
                .pointer("/trust_boundary/release_acceptance_owner")
                .and_then(serde_json::Value::as_str)
        });
    assert_eq!(
        owner,
        Some("factory-v3 evaluator-closer"),
        "C3 release-review must record factory-v3 evaluator-closer as the release acceptance owner; got {owner:?}"
    );
}
