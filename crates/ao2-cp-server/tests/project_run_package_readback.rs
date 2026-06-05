//! K6 follow-up to BOARD.md Claude lane: prove the control-plane observer can
//! cross-validate the `ao2.factory-project-run.v1` release-review package
//! produced by AO2 C4, including its top-level manifest, SHA256SUMS, nested
//! app-run bundle references, and trust-boundary metadata.
//!
//! Fixture origin: ao2 commit `128d760` factory-project-run-smoke
//! `20260528T032728Z/project-run/missed-call-recovery-project-release-review-package.tgz`.
//! The 4 fixtures committed here cover the package's `manifest.json`,
//! `SHA256SUMS`, `project-run.json` (the C4 envelope), and the missed-call
//! project spec markdown. The two nested app-run bundles are not embedded —
//! their integrity is asserted via the manifest's `bundle_sha256` cross-check
//! against `SHA256SUMS`. Their observer-side ingest behavior is already
//! covered by `factory_app_run_bundle_readback.rs`.

use sha2::Digest;
use std::collections::HashMap;

const PACKAGE_MANIFEST: &str = include_str!("fixtures/project-run-package/manifest.json");
const PACKAGE_SHA256SUMS: &str = include_str!("fixtures/project-run-package/SHA256SUMS");
const PACKAGE_PROJECT_RUN: &str = include_str!("fixtures/project-run-package/project-run.json");
const PACKAGE_PROJECT_SPEC: &str =
    include_str!("fixtures/project-run-package/missed-call-recovery-project.md");

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
fn project_run_package_manifest_schema_and_trust_boundary_are_observer_safe() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-project-run.v1",
        "C4 release-review package manifest must declare the project-run schema"
    );
    assert_eq!(
        manifest["run_id"], "missed-call-recovery-project",
        "C4 package must carry the missed-call project run_id"
    );
    assert_eq!(
        manifest["app_run_count"], 2,
        "C4 package must reference 2 app-runs (intake + messaging)"
    );

    let tb = &manifest["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"], false);
    assert_eq!(tb["mutates_ao_artifacts"], false);
    assert_eq!(
        tb["control_plane_role"],
        "read_only_observer_after_signed_evidence"
    );
    assert_eq!(
        tb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(tb["factory_v3_role"], "parity_oracle_only");
    assert_eq!(tb["execution_owner"], "ao2");
    assert_eq!(
        tb["provider_auth"], "local OAuth CLI only; API-key provider auth forbidden",
        "C4 package must forbid API-key provider auth"
    );

    // Every app_run entry must carry the observer-safe owner. This catches a
    // future regression where a single nested app-run silently transfers
    // release acceptance back to ao2/control-plane.
    let app_runs = manifest["app_runs"].as_array().expect("manifest.app_runs");
    assert_eq!(app_runs.len(), 2);
    for app_run in app_runs {
        assert_eq!(
            app_run["release_acceptance_owner"], "factory-v3 evaluator-closer",
            "nested app_run must preserve evaluator-closer ownership"
        );
        assert_eq!(app_run["control_plane_approves_release"], false);
        assert_eq!(app_run["release_review_ready"], true);
        assert!(
            app_run["bundle_sha256"].as_str().is_some(),
            "nested app_run must carry bundle_sha256"
        );
    }
}

#[test]
fn project_run_package_manifest_files_match_sha256sums_for_every_entry() {
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");
    let sums = parse_sha256sums(PACKAGE_SHA256SUMS);

    // Every manifest.files[] entry must match SHA256SUMS. Both files are
    // produced by AO2 from the same canonical hashing routine; any
    // disagreement is a producer bug or post-bundle tamper.
    let manifest_files = manifest["files"].as_array().expect("manifest.files");
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

    // Each nested app-run bundle reference must also match SHA256SUMS by
    // explicit path. This is the K6-specific cross-check: project-package
    // manifest exposes nested bundles via app_runs[].bundle_sha256, and
    // SHA256SUMS reports them via the file path.
    let app_runs = manifest["app_runs"].as_array().expect("manifest.app_runs");
    for app_run in app_runs {
        let index = app_run["index"].as_u64().unwrap();
        let claimed = app_run["bundle_sha256"].as_str().unwrap();
        let path = format!("app-run-bundles/{index}/app-run-evidence-bundle.tgz");
        let sums_sha = sums
            .get(&path)
            .unwrap_or_else(|| panic!("SHA256SUMS missing nested bundle path {path}"));
        assert_eq!(
            sums_sha, claimed,
            "nested bundle sha256 mismatch between manifest.app_runs[] and SHA256SUMS for {path}"
        );
    }

    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
}

#[test]
fn project_run_package_embedded_text_files_match_manifest_sha256() {
    // For the two text artifacts whose bytes are embedded here, recomputed
    // sha256 must equal the manifest's claim. Proves no fixture round-trip
    // altered the bytes.
    let manifest: serde_json::Value =
        serde_json::from_str(PACKAGE_MANIFEST).expect("manifest.json must parse");

    let mut bundled_sha: HashMap<&str, String> = HashMap::new();
    bundled_sha.insert(
        "project-run.json",
        hex_sha256(PACKAGE_PROJECT_RUN.as_bytes()),
    );
    bundled_sha.insert(
        "project-spec/missed-call-recovery-project.md",
        hex_sha256(PACKAGE_PROJECT_SPEC.as_bytes()),
    );

    let manifest_files = manifest["files"].as_array().expect("manifest.files");
    let mut matched = 0;
    for entry in manifest_files {
        let path = entry["path"].as_str().unwrap();
        if let Some(computed) = bundled_sha.get(path) {
            let claimed = entry["sha256"].as_str().unwrap();
            assert_eq!(
                claimed, computed,
                "manifest sha256 for {path} drifted from bundled bytes"
            );
            matched += 1;
        }
    }
    assert_eq!(
        matched, 2,
        "expected to match both embedded text fixtures against manifest.files[]"
    );
}

#[test]
fn project_run_envelope_preserves_trust_boundary_and_app_runs() {
    let envelope: serde_json::Value =
        serde_json::from_str(PACKAGE_PROJECT_RUN).expect("project-run.json must parse");
    assert_eq!(
        envelope["schema_version"], "ao2.factory-project-run.v1",
        "C4 project-run envelope schema"
    );
    assert_eq!(envelope["status"], "accepted");
    let tb = &envelope["trust_boundary"];
    assert_eq!(tb["control_plane_approves_release"], false);
    assert_eq!(tb["mutates_ao_artifacts"], false);
    assert_eq!(
        tb["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(tb["factory_v3_role"], "parity_oracle_only");
    let app_run_count = envelope["app_run_count"].as_u64().unwrap_or(0);
    assert!(
        app_run_count >= 2,
        "C4 envelope must reference at least 2 app-runs; got {app_run_count}"
    );
}
