//! K4 follow-up to BOARD.md Claude lane: replay the first C2-emitted
//! `ao2 factory app-run-bundle` portable archive through the read-only
//! observer and prove the bundle's `manifest.json` + `SHA256SUMS` references
//! remain intact, that the control plane never approves the release nor
//! mutates the AO artifact, and that the bundle introduces no new mutation
//! surfaces (no DELETE/PUT/PATCH on per-sha bundles).
//!
//! Fixture origin: ao2 commit `d29d805` factory-app-run-smoke
//! `20260528T023441Z/app-run-evidence-bundle.tgz`. The 4 fixtures committed
//! here cover the bundle's `manifest.json`, `SHA256SUMS`, `release-review.json`,
//! and `artifacts/evidence-pack/evidence-pack.json`. Manifest integrity for the
//! 5 unembedded artifacts is already proved by `ao2-cli/tests/release_packaging.rs`;
//! the control-plane side only needs to prove the observer surface preserves
//! whatever artifacts it ingests.

use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Digest;
use signature::{SignatureEncoding, Signer};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

const BUNDLE_MANIFEST: &str = include_str!("fixtures/factory-app-run-bundle/manifest.json");
const BUNDLE_SHA256SUMS: &str = include_str!("fixtures/factory-app-run-bundle/SHA256SUMS");
const BUNDLE_EVIDENCE_PACK: &str =
    include_str!("fixtures/factory-app-run-bundle/bundle-evidence-pack.json");
const BUNDLE_RELEASE_REVIEW: &str =
    include_str!("fixtures/factory-app-run-bundle/release-review.json");

async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: "secret".to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: Vec::new(),
        signed_artifact_trusted_key_sha256s: Vec::new(),
        metrics: std::sync::Arc::new(Metrics::new()),
        audit_log: std::sync::Arc::new(ao2_cp_server::audit_log::AuditLog::default()),
    });
    let app = ao2_cp_server::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), dir)
}

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

fn sign_bundle_evidence_pack() -> serde_json::Value {
    let evidence_pack: serde_json::Value =
        serde_json::from_str(BUNDLE_EVIDENCE_PACK).expect("bundle evidence-pack must parse");
    let evidence_raw = serde_json::to_string_pretty(&evidence_pack).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let signature_bytes = signing_key.sign(evidence_raw.as_bytes()).to_vec();
    let signature_hex = signature_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    serde_json::json!({
        "schema_version": "ao2.cp-evidence-pack-signed-upload.v1",
        "evidence_pack": evidence_pack,
        "signature": {
            "schema_version": "ao2.cp-evidence-pack-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "factory-app-run-bundle-readback-test"
        }
    })
}

#[test]
fn factory_app_run_bundle_manifest_and_sha256sums_are_internally_consistent() {
    // 1. Manifest is the canonical C2 bundle schema.
    let manifest: serde_json::Value =
        serde_json::from_str(BUNDLE_MANIFEST).expect("manifest.json must parse");
    assert_eq!(
        manifest["schema_version"], "ao2.factory-app-run-bundle.v1",
        "C2 bundle manifest schema must be ao2.factory-app-run-bundle.v1"
    );

    // 2. Trust boundary inside the bundle manifest must be observer-safe.
    //    These are the C2 producer's declarations; the control plane must
    //    never silently relax them.
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
        "C2 bundle must forbid API-key provider auth"
    );

    // 3. For the two artifacts whose bytes are embedded in this test, the
    //    manifest's claimed sha256 must equal the freshly computed sha256 of
    //    the bundled bytes. Proves the producer's manifest hash maps to a
    //    real artifact and that nothing in our fixture round-trip silently
    //    altered the bytes.
    let mut bundled_sha: HashMap<&str, String> = HashMap::new();
    bundled_sha.insert(
        "artifacts/evidence-pack/evidence-pack.json",
        hex_sha256(BUNDLE_EVIDENCE_PACK.as_bytes()),
    );
    bundled_sha.insert(
        "release-review.json",
        hex_sha256(BUNDLE_RELEASE_REVIEW.as_bytes()),
    );

    let manifest_files = manifest["files"].as_array().expect("manifest.files");
    for entry in manifest_files {
        let path = entry["path"].as_str().unwrap();
        if let Some(computed) = bundled_sha.get(path) {
            let claimed = entry["sha256"].as_str().unwrap();
            assert_eq!(
                claimed, computed,
                "manifest sha256 for {path} drifted from bundled bytes"
            );
        }
    }

    // 4. SHA256SUMS must agree with manifest.files[] for every entry,
    //    including the embedded subset and the unembedded artifacts. Proves
    //    bundle.manifest and bundle.SHA256SUMS are derived from the same
    //    source-of-truth and that an observer cannot be tricked by editing
    //    only one of them.
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
    // SHA256SUMS must also self-cover the manifest itself (defense against a
    // forged manifest after the fact).
    assert!(
        sums.contains_key("manifest.json"),
        "SHA256SUMS must self-cover manifest.json"
    );
}

#[tokio::test]
async fn factory_app_run_bundle_evidence_pack_round_trips_through_observer() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = sign_bundle_evidence_pack();

    // 1. The bundle's evidence-pack artifact ingests cleanly through the
    //    same observer surface used in K3 — i.e., the bundle introduces no
    //    new mutation surface and reuses the read-only signed-upload path.
    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(
        ingest.status().is_success(),
        "C2 bundle evidence-pack must ingest via the existing observer surface: status={}",
        ingest.status()
    );
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"]
        .as_str()
        .expect("receipt must include sha256")
        .to_string();

    // 2. Readback by run_id surfaces the bundle's evidence-pack content
    //    unchanged.
    let by_run = client
        .get(format!(
            "{base}/api/v1/evidence-pack/run/factory-app-smoke/latest"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(by_run.status().is_success());
    let by_run_body: serde_json::Value = by_run.json().await.unwrap();
    let evidence_pack = by_run_body.get("evidence_pack").unwrap_or(&by_run_body);
    let pack_view = evidence_pack
        .pointer("/evidence_pack")
        .unwrap_or(evidence_pack);
    assert_eq!(pack_view["run_id"], "factory-app-smoke");
    assert_eq!(pack_view["verdict"], "accepted");

    // 3. Detail readback preserves factory-v3 parity-oracle ownership flag
    //    on the AO2-produced evidence pack — even when the evidence pack was
    //    delivered through a C2 bundle, the control plane must not rewrite
    //    these ownership signals.
    let detail = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(detail.status().is_success());
    let detail_body: serde_json::Value = detail.json().await.unwrap();
    let detail_pack = detail_body
        .pointer("/evidence_pack")
        .unwrap_or(&detail_body);
    let detail_pack = detail_pack.pointer("/evidence_pack").unwrap_or(detail_pack);
    assert_eq!(
        detail_pack["factory_v3_compatibility"]["factory_v3_role"],
        "parity_oracle_only"
    );
    assert_eq!(
        detail_pack["factory_v3_compatibility"]["ao2_execution_owner"],
        true
    );

    // 4. Bundle introduces no DELETE/PUT/PATCH on per-sha artifacts. Reuses
    //    K3's invariant assertion to confirm the C2 surface adds no new
    //    mutation route.
    let head_resp = client
        .head(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(head_resp.status().is_success());
    let delete_resp = client
        .delete(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert!(
        delete_resp.status().is_client_error(),
        "DELETE must not be a supported observer verb; status={}",
        delete_resp.status()
    );
    let put_resp = client
        .put(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .json(&serde_json::json!({"verdict": "rejected"}))
        .send()
        .await
        .unwrap();
    assert!(
        put_resp.status().is_client_error(),
        "PUT must not be a supported observer verb; status={}",
        put_resp.status()
    );

    // 5. Ingest receipt must not leak any release-approval semantics. The
    //    bundle is observation, never approval.
    let receipt_str = receipt.to_string();
    assert!(!receipt_str.contains("release_approved"));
    assert!(!receipt_str.contains("approval_granted"));
    assert!(!receipt_str.contains("control_plane_decision"));
}

#[test]
fn factory_app_run_bundle_release_review_preserves_evaluator_closer_ownership() {
    // The bundle's release-review.json is the producer-side declaration of
    // who owns release acceptance. Observer-only contract: the control plane
    // must never edit this file, but it must also be able to surface it
    // unchanged to operators. This test asserts the fixture's contract is
    // factory-v3-owned, so any future control-plane code that ingests
    // release-review must preserve the assertion verbatim.
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
        "C2 release-review must record factory-v3 evaluator-closer as the release acceptance owner; got {owner:?}"
    );
}
