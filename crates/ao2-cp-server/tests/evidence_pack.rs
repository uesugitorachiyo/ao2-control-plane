use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{SignatureEncoding, Signer};
use std::sync::Arc;
use tempfile::tempdir;

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

fn signed_evidence_pack(tamper_signature: bool) -> serde_json::Value {
    let evidence_pack = serde_json::json!({
        "schema_version": "ao2.evidence-pack.v1",
        "run_id": "observer-run-001",
        "verdict": "accepted",
        "artifacts": [{
            "kind": "obligation-gate",
            "gate": {
                "schema_version": "ao2.obligation-gate.v1",
                "stage": "midpoint",
                "status": "passed",
                "verdict": "accepted",
                "summary": {"pass": 3, "fail": 0, "unverified": 0, "waived": 0}
            }
        }],
        "approvals": []
    });
    signed_evidence_pack_with_body(evidence_pack, tamper_signature)
}

fn signed_evidence_pack_with_gate(
    run_id: &str,
    status: &str,
    verdict: &str,
    fail: u64,
    unverified: u64,
) -> serde_json::Value {
    let evidence_pack = serde_json::json!({
        "schema_version": "ao2.evidence-pack.v1",
        "run_id": run_id,
        "verdict": verdict,
        "artifacts": [{
            "kind": "obligation-gate",
            "gate": {
                "schema_version": "ao2.obligation-gate.v1",
                "stage": "closure",
                "status": status,
                "verdict": verdict,
                "summary": {"pass": 2, "fail": fail, "unverified": unverified, "waived": 0}
            }
        }],
        "approvals": []
    });
    signed_evidence_pack_with_body(evidence_pack, false)
}

fn signed_evidence_pack_with_run_health(
    run_id: &str,
    verdict: &str,
    repair_status: &str,
    attention_required: bool,
) -> serde_json::Value {
    let evidence_pack = serde_json::json!({
        "schema_version": "ao2.evidence-pack.v1",
        "run_id": run_id,
        "verdict": verdict,
        "run_health": {
            "schema_version": "ao2.run-health.v1",
            "verdict": verdict,
            "repair_status": repair_status,
            "repair_attempt_count": 2,
            "failed_repair_attempts": 2,
            "accepted_repair_attempts": 0,
            "budget_exhausted": attention_required,
            "unresolved_concerns": ["verifier_failed"],
            "attention_required": attention_required,
            "next_action": "Open the latest verifier artifact, revise the repair prompt, and rerun.",
            "evidence_refs": ["artifact-verifier"],
            "timeline": [{
                "kind": "repair_attempt",
                "attempt": 2,
                "trigger": "verifier_failed",
                "status": repair_status,
                "evidence_refs": ["artifact-verifier"]
            }]
        },
        "artifacts": [],
        "approvals": []
    });
    signed_evidence_pack_with_body(evidence_pack, false)
}

fn signed_evidence_pack_with_repair_source() -> serde_json::Value {
    let evidence_pack = serde_json::json!({
        "schema_version": "ao2.evidence-pack.v1",
        "run_id": "observer-run-repair-resumed",
        "verdict": "accepted",
        "run_health": {
            "schema_version": "ao2.run-health.v1",
            "verdict": "accepted",
            "repair_status": "accepted",
            "repair_attempt_count": 1,
            "failed_repair_attempts": 0,
            "accepted_repair_attempts": 1,
            "attention_required": false,
            "next_action": "Run accepted after repair resume.",
            "evidence_refs": ["artifact-repair-source"]
        },
        "repair_source": {
            "schema_version": "ao2.repair-source.v1",
            "source_run_id": "observer-run-rejected-source",
            "evidence_pack_path": "/work/ao2/.ao2/runs/observer-run-rejected-source/evidence-pack/evidence-pack.json",
            "source_verdict": "rejected",
            "run_health": {
                "schema_version": "ao2.run-health.v1",
                "repair_status": "budget_exhausted",
                "attention_required": true
            },
            "unresolved_concerns": ["verifier_failed", "budget_exhausted"],
            "evidence_refs": ["artifact-verifier", "artifact-closure"],
            "latest_verifier_output": "missing docs/fixed.txt",
            "latest_verifier_output_digest": "abc123"
        },
        "artifacts": [],
        "approvals": []
    });
    signed_evidence_pack_with_body(evidence_pack, false)
}

fn signed_evidence_pack_with_body(
    evidence_pack: serde_json::Value,
    tamper_signature: bool,
) -> serde_json::Value {
    let evidence_raw = serde_json::to_string_pretty(&evidence_pack).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut signature = signing_key.sign(evidence_raw.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
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
            "signer_id": "ao2-local-observer"
        }
    })
}

/// A schema-valid evidence pack whose on-the-wire bytes deliberately differ from the
/// server's `to_string_pretty(&evidence_pack)`: compact separators plus a float carrying
/// more significant digits than an `f64` round-trips to. Re-serializing the parsed value
/// both reflows the whitespace and shortens the float, so a server that verifies over the
/// reconstruction (instead of the producer's exact signed bytes) fail-closes this
/// untampered upload.
const DIVERGENT_EVIDENCE_PACK_BYTES: &str = r#"{"schema_version":"ao2.evidence-pack.v1","run_id":"observer-run-divergent","verdict":"accepted","score":0.12345678901234567890123456789,"artifacts":[],"approvals":[]}"#;

/// Build a signed evidence-pack upload whose signature covers EXACTLY `signed_bytes`,
/// carried verbatim in `evidence_pack_b64`. The parsed `evidence_pack` is included too
/// (as a real producer ships it), but it re-serializes to different bytes — so verifying
/// over `evidence_pack` rather than `evidence_pack_b64` would reject this untampered
/// upload.
fn signed_evidence_pack_over_exact_bytes(
    signed_bytes: &str,
    tamper_signature: bool,
) -> serde_json::Value {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    let evidence_pack: serde_json::Value = serde_json::from_str(signed_bytes).unwrap();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut signature = signing_key.sign(signed_bytes.as_bytes()).to_vec();
    if tamper_signature {
        signature[0] ^= 0xff;
    }
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    serde_json::json!({
        "schema_version": "ao2.cp-evidence-pack-signed-upload.v1",
        "evidence_pack": evidence_pack,
        "evidence_pack_b64": BASE64_STANDARD.encode(signed_bytes.as_bytes()),
        "signature": {
            "schema_version": "ao2.cp-evidence-pack-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem,
            "signer_id": "ao2-local-observer"
        }
    })
}

#[tokio::test]
async fn post_signed_evidence_pack_verifies_over_exact_bytes_not_reserialization() {
    // Regression for the latent fail-closed bug: the server must verify the signature
    // over the producer's exact signed bytes (supplied verbatim in `evidence_pack_b64`),
    // not over a `to_string_pretty(&upload.evidence_pack)` reconstruction that can reflow
    // whitespace and shorten floats. Here the signed bytes are compact and carry a
    // many-significant-digit float, so the reconstruction differs from what was signed;
    // an untampered upload must still be accepted.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack_over_exact_bytes(DIVERGENT_EVIDENCE_PACK_BYTES, false);

    let resp = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "untampered signed upload must verify over its exact signed bytes (evidence_pack_b64)"
    );
}

#[tokio::test]
async fn post_signed_evidence_pack_stores_exact_signed_bytes_ignoring_evidence_pack_field() {
    // The `evidence_pack_b64` bytes are the *only* trusted content: the signature is
    // verified over them, and they (not the parallel `evidence_pack` JSON field) are what
    // gets parsed, hashed, and stored. Ship a VALID signature over the divergent bytes but
    // replace `evidence_pack` with attacker-controlled content. The upload must be accepted
    // (proving verification used `evidence_pack_b64`, not the now-mismatched field) and
    // GET-by-sha must return the exact signed bytes verbatim (proving the inert field was
    // never parsed or stored). Guards against a regression to trusting/storing the lossy
    // `evidence_pack` reconstruction.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let mut payload = signed_evidence_pack_over_exact_bytes(DIVERGENT_EVIDENCE_PACK_BYTES, false);
    payload["evidence_pack"] = serde_json::json!({
        "schema_version": "ao2.evidence-pack.v1",
        "run_id": "ATTACKER-CONTROLLED-NOT-SIGNED",
        "verdict": "accepted",
        "artifacts": [],
        "approvals": []
    });

    let post = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        200,
        "signature must verify over evidence_pack_b64, not the mismatched evidence_pack field"
    );
    let receipt: serde_json::Value = post.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();

    let get = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(
        &body[..],
        DIVERGENT_EVIDENCE_PACK_BYTES.as_bytes(),
        "server must store the exact signed bytes, never the inert evidence_pack field"
    );
}

#[tokio::test]
async fn evidence_pack_dashboard_json_surfaces_run_health_attention() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack_with_run_health(
        "observer-run-health-attention",
        "rejected",
        "budget_exhausted",
        true,
    );

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);

    let response = client
        .get(format!("{base}/api/v1/evidence-pack/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["summary"]["run_health_attention_count"], 1);
    assert_eq!(
        body["entries"][0]["run_health"]["repair_status"],
        "budget_exhausted"
    );
    assert_eq!(body["entries"][0]["run_health"]["attention_required"], true);

    let html = client
        .get(format!("{base}/api/v1/evidence-pack/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Run Health"));
    assert!(html.contains("budget_exhausted"));

    let sha = body["entries"][0]["sha256"].as_str().unwrap();
    let detail_html = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(detail_html.contains("Run Health"));
    assert!(detail_html.contains("Open the latest verifier artifact"));
}

#[tokio::test]
async fn evidence_pack_observer_surfaces_repair_source_context() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack_with_repair_source();

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let dashboard = client
        .get(format!("{base}/api/v1/evidence-pack/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let dashboard_body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(dashboard_body["summary"]["repair_source_count"], 1);
    assert_eq!(
        dashboard_body["entries"][0]["repair_source"]["source_run_id"],
        "observer-run-rejected-source"
    );
    assert_eq!(
        dashboard_body["entries"][0]["repair_source"]["source_verdict"],
        "rejected"
    );

    let detail_json = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail_json.status(), 200);
    let detail_body: serde_json::Value = detail_json.json().await.unwrap();
    assert_eq!(detail_body["repair_source"]["present"], true);
    assert_eq!(detail_body["repair_source"]["unresolved_concern_count"], 2);
    assert_eq!(
        detail_body["repair_source"]["has_latest_verifier_output"],
        true
    );

    let detail_html = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(detail_html.contains("Repair Source"));
    assert!(detail_html.contains("observer-run-rejected-source"));
    assert!(detail_html.contains("abc123"));
}

#[tokio::test]
async fn post_signed_evidence_pack_returns_receipt_and_sidecar() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let resp = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(body["ingested_schema_version"], "ao2.evidence-pack.v1");
    let sha = body["sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);

    let list = client
        .get(format!("{base}/api/v1/evidence-pack"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let list_body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(list_body["schema_version"], "ao2.cp-evidence-pack-list.v1");
    assert_eq!(list_body["entries"][0]["sha256"], sha);
    assert_eq!(list_body["entries"][0]["status"], "accepted");

    let signature = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-evidence-pack-signature.v1"
    );
    assert_eq!(signature_body["evidence_pack_sha256"], sha);
}

#[tokio::test]
async fn signed_evidence_pack_signature_sidecar_is_write_once_per_content_sha() {
    // The signature sidecar records *who signed* a given evidence-pack content
    // sha. A second signed upload of the *same pack bytes* but a *different*
    // signature (different key / provenance) must NOT silently overwrite the
    // first signer's sidecar — otherwise any holder of a valid signing key could
    // rewrite the recorded provenance of already-ingested evidence. First write
    // wins; a conflicting re-sign is rejected. Mirrors the write-once guard on
    // the provider-readiness / provider-registry signature sidecars.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let first = signed_evidence_pack(false);
    let second = signed_evidence_pack(false);
    // Precondition: same pack content (same sha) but independently generated
    // keys, so the signatures genuinely differ — a provenance conflict, not an
    // idempotent re-upload.
    assert_eq!(
        first["evidence_pack"], second["evidence_pack"],
        "fixtures must share identical evidence-pack content"
    );
    assert_ne!(
        first["signature"]["signature_hex"], second["signature"]["signature_hex"],
        "fixtures must use distinct keys to represent conflicting provenance"
    );
    let first_sig_hex = first["signature"]["signature_hex"]
        .as_str()
        .unwrap()
        .to_string();

    let post1 = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(post1.status(), 200, "first signed upload is accepted");
    let receipt: serde_json::Value = post1.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap().to_string();

    // Conflicting re-sign of an existing content sha: rejected, not stored.
    let post2 = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post2.status(),
        422,
        "a conflicting re-sign of an existing content sha must be rejected"
    );

    // The stored sidecar still reflects the FIRST signer's signature.
    let sidecar = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(sidecar.status(), 200);
    let sidecar_body: serde_json::Value = sidecar.json().await.unwrap();
    assert_eq!(
        sidecar_body["signature"]["signature_hex"], first_sig_hex,
        "first writer's provenance must be preserved, not overwritten"
    );
}

#[tokio::test]
async fn signed_evidence_pack_reupload_of_identical_artifact_stays_idempotent() {
    // The write-once guard must not break idempotent retries: re-POSTing the
    // *exact same* signed artifact (identical signature bytes) yields the same
    // sidecar_raw, so it is accepted as a no-op rather than rejected as a
    // conflict. Guards the `existing == sidecar_raw` branch of the guard.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let artifact = signed_evidence_pack(false);

    for attempt in 1..=2 {
        let post = client
            .post(format!("{base}/api/v1/evidence-pack/signed"))
            .header("authorization", "Bearer secret")
            .json(&artifact)
            .send()
            .await
            .unwrap();
        assert_eq!(
            post.status(),
            200,
            "identical signed artifact must be accepted idempotently (attempt {attempt})"
        );
    }
}

#[tokio::test]
async fn evidence_pack_dashboard_lists_verified_signed_packs_with_detail_links() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let dashboard = client
        .get(format!("{base}/api/v1/evidence-pack/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let content_type = dashboard
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/html"));
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("AO2 Signed Evidence Packs"));
    assert!(html.contains("observer-run-001"));
    assert!(html.contains("accepted"));
    assert!(html.contains("Summary"));
    assert!(html.contains("Gate attention"));
    assert!(html.contains("Unverified signatures"));
    assert!(html.contains(&format!("/api/v1/evidence-pack/{sha}/detail")));
    assert!(html.contains(&format!("/api/v1/evidence-pack/{sha}/signature")));
    assert!(html.contains("Verified"));
}

#[tokio::test]
async fn evidence_pack_dashboard_filters_obligation_gates_needing_attention() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for payload in [
        signed_evidence_pack_with_gate("observer-run-clear-gate", "passed", "accepted", 0, 0),
        signed_evidence_pack_with_gate("observer-run-failed-gate", "failed", "rejected", 1, 1),
    ] {
        let ingest = client
            .post(format!("{base}/api/v1/evidence-pack/signed"))
            .header("authorization", "Bearer secret")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(ingest.status(), 200);
    }

    let dashboard = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard?gate=attention"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();
    assert!(html.contains("Gate Filter"));
    assert!(html.contains("observer-run-failed-gate"));
    assert!(html.contains("Gate Attention"));
    assert!(!html.contains("observer-run-clear-gate"));
}

#[tokio::test]
async fn evidence_pack_dashboard_saved_views_filter_signature_and_verdict_risk() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for payload in [
        signed_evidence_pack_with_gate("observer-run-clear-gate", "passed", "accepted", 0, 0),
        signed_evidence_pack_with_gate("observer-run-rejected-gate", "failed", "rejected", 1, 0),
    ] {
        let ingest = client
            .post(format!("{base}/api/v1/evidence-pack/signed"))
            .header("authorization", "Bearer secret")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(ingest.status(), 200);
    }

    let verdict_view = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard?view=verdict_failed"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(verdict_view.status(), 200);
    let verdict_html = verdict_view.text().await.unwrap();
    assert!(verdict_html.contains("Saved Views"));
    assert!(verdict_html.contains("Failed Verdicts"));
    assert!(verdict_html.contains("observer-run-rejected-gate"));
    assert!(!verdict_html.contains("observer-run-clear-gate"));

    let signature_view = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard?view=signature_unverified"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature_view.status(), 200);
    let signature_html = signature_view.text().await.unwrap();
    assert!(signature_html.contains("Unverified Signatures"));
    assert!(signature_html.contains("No signed AO2 evidence packs match this filter."));
}

#[tokio::test]
async fn evidence_pack_dashboard_json_returns_saved_view_entries() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for payload in [
        signed_evidence_pack_with_gate("observer-run-clear-gate", "passed", "accepted", 0, 0),
        signed_evidence_pack_with_gate("observer-run-rejected-gate", "failed", "rejected", 1, 0),
    ] {
        let ingest = client
            .post(format!("{base}/api/v1/evidence-pack/signed"))
            .header("authorization", "Bearer secret")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(ingest.status(), 200);
    }

    let response = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard.json?view=verdict_failed"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-evidence-pack-dashboard.v1");
    assert_eq!(body["view"], "verdict_failed");
    assert_eq!(body["view_label"], "Failed Verdicts");
    assert!(body["presets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|preset| preset["id"] == "failed_verdicts"
            && preset["dashboard_json_url"]
                .as_str()
                .unwrap()
                .contains("view=verdict_failed")
            && preset["bookmark_url"]
                .as_str()
                .unwrap()
                .contains("view=verdict_failed")));
    assert_eq!(body["entry_count"], 1);
    assert_eq!(body["summary"]["total_entries"], 1);
    assert_eq!(body["summary"]["gate_attention_count"], 1);
    assert_eq!(body["summary"]["signature_unverified_count"], 0);
    assert_eq!(body["summary"]["verdict_counts"]["rejected"], 1);
    assert_eq!(body["summary"]["read_only_observer"], true);
    assert_eq!(body["entries"][0]["run_id"], "observer-run-rejected-gate");
    assert_eq!(body["entries"][0]["verdict"], "rejected");
    assert_eq!(body["entries"][0]["signature_verified"], true);
    assert_eq!(body["entries"][0]["gate_attention"], true);
    assert!(body["entries"][0]["detail_url"]
        .as_str()
        .unwrap()
        .contains("/api/v1/evidence-pack/"));

    let run_filter = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard.json?run_id=observer-run-clear-gate&signer_id=ao2-local-observer"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(run_filter.status(), 200);
    let run_body: serde_json::Value = run_filter.json().await.unwrap();
    assert_eq!(run_body["filters"]["run_id"], "observer-run-clear-gate");
    assert_eq!(run_body["filters"]["signer_id"], "ao2-local-observer");
    assert_eq!(run_body["entry_count"], 1);
    assert_eq!(run_body["entries"][0]["run_id"], "observer-run-clear-gate");

    let future_filter = client
        .get(format!(
            "{base}/api/v1/evidence-pack/dashboard.json?since=2999-01-01T00:00:00Z"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(future_filter.status(), 200);
    let future_body: serde_json::Value = future_filter.json().await.unwrap();
    assert_eq!(future_body["filters"]["since"], "2999-01-01T00:00:00Z");
    assert_eq!(future_body["entry_count"], 0);
    assert_eq!(future_body["summary"]["total_entries"], 0);
    assert_eq!(future_body["summary"]["gate_attention_count"], 0);
    assert_eq!(future_body["summary"]["signature_unverified_count"], 0);
    assert_eq!(
        future_body["summary"]["verdict_counts"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(future_body["summary"]["read_only_observer"], true);
}

#[tokio::test]
async fn evidence_pack_dashboard_html_renders_verdict_counts_and_token_safe_links() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for payload in [
        signed_evidence_pack_with_gate("observer-run-clear-gate", "passed", "accepted", 0, 0),
        signed_evidence_pack_with_gate("observer-run-rejected-gate", "failed", "rejected", 1, 0),
    ] {
        let ingest = client
            .post(format!("{base}/api/v1/evidence-pack/signed"))
            .header("authorization", "Bearer secret")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(ingest.status(), 200);
    }

    let dashboard = client
        .get(format!("{base}/api/v1/evidence-pack/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let html = dashboard.text().await.unwrap();

    assert!(html.contains("Verdict counts"));
    assert!(html.contains("accepted: 1"));
    assert!(html.contains("rejected: 1"));
    assert!(html.contains("Preset Bookmarks"));
    assert!(html.contains("download=\"failed_verdicts-dashboard.json\""));
    assert!(html.contains("/api/v1/evidence-pack/dashboard?view=verdict_failed"));
    assert!(html.contains("/api/v1/evidence-pack/dashboard.json?view=verdict_failed"));
    assert!(!html.contains("secret"));
    assert!(!html.contains("AO2_CP_API_TOKEN"));
}

#[tokio::test]
async fn evidence_pack_detail_page_summarizes_pack_without_mutating_ao2() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let detail = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let content_type = detail
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/html"));
    let html = detail.text().await.unwrap();
    assert!(html.contains("AO2 Evidence Pack Detail"));
    assert!(html.contains("observer-run-001"));
    assert!(html.contains("accepted"));
    assert!(html.contains("ao2-local-observer"));
    assert!(html.contains("Verified"));
    assert!(html.contains("Obligation Gates"));
    assert!(html.contains("midpoint"));
    assert!(html.contains("passed"));
    assert!(html.contains("pass=3 fail=0 unverified=0 waived=0"));
    assert!(html.contains("Read-only observer detail"));
    assert!(html.contains(&format!("/api/v1/evidence-pack/{sha}")));
    assert!(html.contains(&format!("/api/v1/evidence-pack/{sha}/signature")));

    let detail_with_workbench = client
        .get(format!(
            "{base}/api/v1/evidence-pack/{sha}/detail?workbench_url=http%3A%2F%2F127.0.0.1%3A17777%2F%3Ftoken%3Dviewer-token&release_gate_artifact=%2Ftmp%2Frelease-gate.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail_with_workbench.status(), 200);
    let linked_html = detail_with_workbench.text().await.unwrap();
    assert!(linked_html.contains("Open Release Gate Artifact in AO2 Workbench"));
    assert!(linked_html.contains("release_gate_artifact=%2Ftmp%2Frelease-gate.json"));
    assert!(linked_html.contains("token=viewer-token"));
}

#[tokio::test]
async fn evidence_pack_detail_json_exposes_structured_read_only_summary() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let detail = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/detail.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let content_type = detail
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("application/json"));
    let body: serde_json::Value = detail.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-evidence-pack-detail.v1");
    assert_eq!(body["sha256"], sha);
    assert_eq!(body["run_id"], "observer-run-001");
    assert_eq!(body["verdict"], "accepted");
    assert_eq!(body["signature"]["signer_id"], "ao2-local-observer");
    assert_eq!(body["signature"]["verified"], true);
    assert_eq!(body["obligation_gates"]["present"], true);
    assert_eq!(body["obligation_gates"]["count"], 1);
    assert_eq!(body["obligation_gates"]["gates"][0]["stage"], "midpoint");
    assert_eq!(body["obligation_gates"]["gates"][0]["status"], "passed");
    assert_eq!(body["obligation_gates"]["gates"][0]["summary"]["pass"], 3);
    assert_eq!(
        body["evidence_pack"]["schema_version"],
        "ao2.evidence-pack.v1"
    );
    assert_eq!(
        body["trust_boundary"]["role"],
        "read_only_observer_for_signed_evidence"
    );
}

#[tokio::test]
async fn evidence_pack_latest_by_run_id_returns_structured_detail_json() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();

    let detail = client
        .get(format!(
            "{base}/api/v1/evidence-pack/run/observer-run-001/latest"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let body: serde_json::Value = detail.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-evidence-pack-detail.v1");
    assert_eq!(body["sha256"], sha);
    assert_eq!(body["run_id"], "observer-run-001");
    assert_eq!(body["signature"]["verified"], true);
}

#[tokio::test]
async fn evidence_pack_signature_sidecar_must_match_requested_pack() {
    let (base, dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(false);

    let ingest = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), 200);
    let receipt: serde_json::Value = ingest.json().await.unwrap();
    let sha = receipt["sha256"].as_str().unwrap();
    let sidecar_path = dir
        .path()
        .join("evidence-pack-signature")
        .join(format!("{sha}.json"));
    let mut sidecar: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&sidecar_path).await.unwrap()).unwrap();
    sidecar["evidence_pack_sha256"] = serde_json::json!("0".repeat(64));
    tokio::fs::write(&sidecar_path, serde_json::to_vec_pretty(&sidecar).unwrap())
        .await
        .unwrap();

    let signature = client
        .get(format!("{base}/api/v1/evidence-pack/{sha}/signature"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 422);
    let body: serde_json::Value = signature.json().await.unwrap();
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("sidecar sha mismatch"));
}

#[tokio::test]
async fn post_signed_evidence_pack_rejects_invalid_signature() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let payload = signed_evidence_pack(true);

    let resp = client
        .post(format!("{base}/api/v1/evidence-pack/signed"))
        .header("authorization", "Bearer secret")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}
