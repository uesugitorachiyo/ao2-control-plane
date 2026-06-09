use ao2_cp_schema::canonical::sha256_of_canonical;
use ao2_cp_server::metrics::Metrics;
use ao2_cp_server::server::AppState;
use ao2_cp_storage::Storage;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use std::{fs, process::Command, sync::Arc};
use tempfile::tempdir;

mod common;

const CODEX_ACCEPTANCE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/codex-acceptance-v0.4.66.json");
const CLAUDE_ACCEPTANCE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/claude-acceptance-v0.4.66.json");

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

/// Like [`spawn_server`], but pins the given release-evaluator-decision
/// signing-key SHA-256 digests as the trust anchor, so a decision signed
/// by one of those keys is recorded as release-authoritative.
async fn spawn_server_with_trusted_evaluator_keys(
    trusted: Vec<String>,
) -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path().to_path_buf()).await.unwrap();
    let state = Arc::new(AppState {
        storage,
        api_token: "secret".to_string(),
        max_body_bytes: 10 * 1024 * 1024,
        provider_readiness_trusted_key_sha256s: Vec::new(),
        release_evaluator_decision_trusted_key_sha256s: trusted,
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

fn release_publication_fixture() -> String {
    serde_json::json!({
        "schema_version": "ao2.release-publication-summary.v1",
        "version": "0.4.79",
        "release_tag": "v0.4.79",
        "recorded_at": "2026-05-22T15:20:55Z",
        "status": "published_verified",
        "release_url": "https://github.com/example/ao2/releases/tag/v0.4.79",
        "repositories": {
            "ao2": {
                "head": "f8e039bd1d06d4b143b4e13e055d0d7659c3dc73",
                "tag_target": "f8e039bd1d06d4b143b4e13e055d0d7659c3dc73"
            }
        },
        "verification": {
            "release_ship": "passed",
            "release_gate": "passed",
            "release_download_verify": "passed",
            "release_doctor_status": "ok",
            "provenance_verified": true,
            "provenance_tag_matches": true,
            "rollback_status": "verified",
            "workbench_release_comparison_export": "passed",
            "three_os_smoke": "passed",
            "native_windows_smoke": "passed",
            "linux_x86_64_remote_smoke": "passed"
        },
        "archives": [
            {
                "target": "macos-aarch64",
                "path": "dist/ao2-0.4.79-macos-aarch64.tar.gz",
                "sha256": "a347b763ba2d697ede674ec53786c6916d50ff2a59915bf1f3c1055a160965a7"
            },
            {
                "target": "linux-x86_64",
                "path": "dist-linux-x86_64/ao2-0.4.79-linux-x86_64.tar.gz",
                "sha256": "8cf9ceb1f0bbbab9020272d03a2ac307a980232b71410aa15d1f6d641d7d721f"
            },
            {
                "target": "windows-x86_64",
                "path": "dist-windows/ao2-0.4.79-windows-x86_64.tar.gz",
                "sha256": "95ea7ac48f085cbf2747acf815beb9bf00eb65000d7b524c2193a778b29851da"
            }
        ],
        "artifacts": {
            "release_provenance": {
                "path": "/work/ao2/dist-provenance/ao2-release-provenance.json",
                "sha256": "6428ea154d905dfa22cdda6bfd009dd5f5e5ecbcd68aeb8ed03fbb8b03f6eb5f"
            },
            "release_doctor": {
                "path": "/work/ao2/target/release-download/v0.4.79/release-doctor.json",
                "sha256": "c99d8e85f64cff9964e29869668718c64fb33ae696f9e3658d2f503f47953f77"
            },
            "release_comparison_verification": {
                "path": "/work/ao2/target/release-download/v0.4.79/release-comparison-verification.json",
                "sha256": "cc5a2edb8c4ad2ecf5b19ebf1b95ad4dc85a8cfd816b5dfc81ca4ee52dc61729"
            }
        }
    })
    .to_string()
}

// Lane AA: a release-publication artifact with a tampered top-level
// `candidate_correlation` field claiming status=matched. The schema for
// `ao2.release-publication-summary.v1` does not include a
// `candidate_correlation` field, so validate_release_publication ignores
// unknown fields; an attacker who can reach the ingestion endpoint could
// hand-stamp this field hoping a downstream handler trusts it instead
// of recomputing. The server is required to recompute
// `candidate_correlation` from underlying artifact fields via
// `candidate_correlation_value()` in every rendered surface (cockpit,
// handoff, dashboard, readiness, assembly) — this fixture lets a
// positive-rejection test prove the tampered field has zero authority.
fn tampered_top_level_candidate_correlation_release_publication_fixture() -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(&release_publication_fixture()).expect("base fixture parses");
    let object = value
        .as_object_mut()
        .expect("release publication fixture is a JSON object");
    object.insert(
        "candidate_correlation".to_string(),
        serde_json::json!({
            "status": "matched",
            "release_version": "0.4.79",
            "release_tag": "v0.4.79",
            "three_os_version": "0.4.79",
            "release_evaluator_version": "0.4.79",
            "release_evaluator_tag": "v0.4.79",
            "codex_acceptance_version": "0.4.79",
            "claude_acceptance_version": "0.4.79",
            "blockers": [],
        }),
    );
    value.to_string()
}

fn provider_registry_fixture() -> String {
    serde_json::json!({
        "schema": "ao2.provider-plugin-registry.v1",
        "phase": "phase_2_registry_groundwork",
        "trust_boundary": {
            "execution_owner": "ao2-local-cli",
            "control_plane_role": "read_only_observer_only"
        },
        "providers": [
            {
                "provider": "scripted",
                "adapter_kind": "scripted",
                "crate": "ao2-adapters",
                "metadata_source": "ao2-adapters",
                "doctor": {"metadata_source": "ao2-adapters"},
                "guards": {"explicit_live_env": null}
            },
            {
                "provider": "codex",
                "adapter_kind": "local_cli",
                "crate": "ao2-adapter-codex",
                "metadata_source": "ao2-adapter-codex",
                "doctor": {"metadata_source": "ao2-adapter-codex"},
                "guards": {"explicit_live_env": "AO2_LIVE_CODEX_PILOT"}
            },
            {
                "provider": "claude",
                "adapter_kind": "local_cli",
                "crate": "ao2-adapter-claude",
                "metadata_source": "ao2-adapter-claude",
                "doctor": {"metadata_source": "ao2-adapter-claude"},
                "guards": {"explicit_live_env": "AO2_LIVE_CLAUDE_PILOT"}
            }
        ]
    })
    .to_string()
}

fn provider_readiness_fixture() -> String {
    serde_json::json!({
        "schema": "factory-v3/hermes-provider-phase1-readiness/v1",
        "status": "passed",
        "live_provider_policy": "not_run_by_default",
        "required_live_provider_pilots": ["codex"],
        "contracts": {
            "codex": {"status": "verified"},
            "claude": {"status": "verified"},
            "antigravity": {"status": "verified"}
        },
        "scripted_gate": {"verdict": "ready"},
        "codex_gate": {"verdict": "ready"},
        "codex_pilot": {"status": "ready"}
    })
    .to_string()
}

fn live_acceptance_fixture(raw: &str, provider: &str, version: &str) -> String {
    raw.replace(
        r#""root": "<root>""#,
        &format!(r#""root": "/work/ao2/target/provider-pilot-acceptance/v{version}/{provider}""#),
    )
    .replace(
        r#""target": "<target>""#,
        &format!(
            r#""target": "/work/ao2/target/provider-pilot-acceptance/v{version}/{provider}/discount-service""#
        ),
    )
    .replace(
        r#""evidence_pack": "<evidence>""#,
        &format!(
            r#""evidence_pack": "/work/ao2/target/provider-pilot-acceptance/v{version}/{provider}/discount-service/.ao2/runs/live-{provider}-provider-pilot/evidence-pack/evidence-pack.json""#
        ),
    )
}

fn phase1_promotion_checklist_fixture() -> String {
    serde_json::json!({
        "schema": "factory-v3/ao2-phase1-promotion-checklist/v1",
        "status": "passed",
        "phase1_state": "phase1_candidate_ready",
        "next_action": "operator release-line decision",
        "checklist": {
            "provider_readiness": {
                "status": "superseded_by_live_acceptance",
                "phase1_state": "blocked",
                "superseded_by": "live_provider_acceptance"
            },
            "live_provider_acceptance": {
                "status": "passed",
                "state": "live_acceptance_complete",
                "codex": "passed",
                "claude": "passed",
                "source_class": "live"
            },
            "release_gate": {
                "status": "passed",
                "state": "dry_run_passed"
            },
            "three_os_smoke": {
                "status": "passed",
                "local_smoke": "passed",
                "linux_x86_64_remote_smoke": "passed",
                "windows_native_smoke": "passed",
                "native_windows_required": true
            }
        }
    })
    .to_string()
}

fn three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "matched",
        "targets": {
            "macos": {
                "status": "passed",
                "duration_seconds": 42,
                "artifact_url": "/evidence/macos-smoke.json",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "duration_seconds": 57,
                "artifact_url": "/evidence/ubuntu-smoke.json",
                "candidate_correlation_status": "matched"
            },
            "windows": {
                "status": "passed",
                "duration_seconds": 91,
                "artifact_url": "/evidence/windows-smoke.json",
                "candidate_correlation_status": "matched"
            }
        },
        "surface_content_hash_parity": {
            "release_cockpit": "matched",
            "release_handoff": "matched",
            "release_readiness": "matched",
            "release_publication_dashboard": "matched",
            "release_assembly": "matched",
            "release_assembly_blockers": "matched"
        }
    })
    .to_string()
}

fn mismatched_three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.78",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    })
    .to_string()
}

fn failed_three_os_release_smoke_fixture() -> String {
    // Top-level status is "failed" (honest) because windows is skipped.
    // Lane DD rejects fixtures that post status="passed" with a
    // non-passing target; the readiness gate then derives "failed" via
    // three_os_smoke_clean_status() — the gate observation is unchanged.
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "failed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "skipped"}
        }
    })
    .to_string()
}

// Lane T: version evidence matches across release/three_os/evaluator/codex/claude
// (so server-computed candidate_correlation resolves to "matched"), but the
// three-OS aggregator reports candidate_correlation_parity = "drift"
// (i.e. macOS observed matched, ubuntu observed mismatched, windows observed
// matched — the per-OS smokes disagreed about candidate_correlation even
// though the canonical version evidence aligns). Proves the parity gate
// is an independent downgrade vector from candidate_correlation itself.
fn drift_three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "drift",
        "targets": {
            "macos": {
                "status": "passed",
                "duration_seconds": 42,
                "artifact_url": "/evidence/macos-smoke.json",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "duration_seconds": 57,
                "artifact_url": "/evidence/ubuntu-smoke.json",
                "candidate_correlation_status": "mismatched"
            },
            "windows": {
                "status": "passed",
                "duration_seconds": 91,
                "artifact_url": "/evidence/windows-smoke.json",
                "candidate_correlation_status": "matched"
            }
        }
    })
    .to_string()
}

// Lane CC: candidate_correlation_parity=matched (so the Lane S gate
// passes), all per-target candidate_correlation_status=matched (so
// Lane W's server-side recomputation accepts the ingestion), but the
// per-surface byte-identity verdict has one surface in drift (so the
// Lane CC gate fires independently of every prior parity layer). This
// proves the new readiness gate catches per-surface drift that
// candidate_correlation_parity alone cannot expose.
fn surface_content_hash_drift_three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "matched",
        "targets": {
            "macos": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "ubuntu": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            },
            "windows": {
                "status": "passed",
                "candidate_correlation_status": "matched"
            }
        },
        "surface_content_hash_parity": {
            "release_cockpit": "matched",
            "release_handoff": "matched",
            "release_readiness": "matched",
            "release_publication_dashboard": "matched",
            "release_assembly": "drift",
            "release_assembly_blockers": "matched"
        }
    })
    .to_string()
}

fn partial_surface_content_hash_three_os_release_smoke_fixture() -> String {
    serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": false,
        "candidate_correlation_parity": "matched",
        "targets": {
            "macos": {"status": "passed", "candidate_correlation_status": "matched"},
            "ubuntu": {"status": "passed", "candidate_correlation_status": "matched"},
            "windows": {"status": "passed", "candidate_correlation_status": "matched"}
        },
        "surface_content_hash_parity": {
            "release_cockpit": "matched"
        }
    })
    .to_string()
}

fn phase1_promotion_decision_fixture(checklist_sha: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "factory-v3/ao2-phase1-promotion-decision/v1",
        "status": "passed",
        "decision": "promote_phase1_candidate",
        "phase1_state": "phase1_candidate_ready",
        "checklist_sha256": checklist_sha,
        "operator": "release-lead",
        "rationale": "All required Phase 1 checklist evidence is present and observed."
    })
}

fn release_evaluator_decision_fixture() -> String {
    serde_json::json!({
        "schema": "factory-v3/ao2-release-evaluator-decision/v1",
        "status": "accepted",
        "decision": "accept_phase1_release_candidate",
        "release": {
            "version": "0.4.79",
            "release_tag": "v0.4.79",
            "sha256": "a".repeat(64)
        },
        "checks": [
            {
                "id": "readiness_status",
                "label": "Release readiness status",
                "observed": "ready",
                "expected": "ready",
                "status": "passed"
            },
            {
                "id": "handoff_checklist_status",
                "label": "Handoff checklist status",
                "observed": "ready_for_evaluator_closer",
                "expected": "ready_for_evaluator_closer",
                "status": "passed"
            }
        ],
        "blockers": [],
        "evidence": {
            "release_readiness_status": "/work/factory-v3/release-readiness-status.json",
            "release_handoff_checklist": "/work/factory-v3/release-handoff-checklist.json"
        },
        "trust_boundary": {
            "frontend": "Hermes front end / queue / memory surface",
            "governed_backend": "factory-v3 / AO Operator evaluator-closer",
            "trusted_execution": "ao2 signed evidence boundary",
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": false,
            "control_plane_approves_release": false,
            "release_acceptance_owner": "factory-v3 evaluator-closer"
        },
        "next_action": "release candidate is accepted by factory-v3 evaluator-closer for release-line handoff"
    })
    .to_string()
}

fn signed_phase1_promotion_decision_fixture(decision: serde_json::Value) -> serde_json::Value {
    let mut rng = rsa::rand_core::OsRng;
    let signing_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = signing_key.to_public_key();
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    let decision_raw = serde_json::to_string_pretty(&decision).unwrap();
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key);
    let signature = signer.sign(decision_raw.as_bytes()).to_vec();
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let signature_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&signature);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let public_key_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(public_key_pem.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::json!({
        "schema_version": "ao2.cp-phase1-promotion-decision-signed-upload.v1",
        "decision": decision,
        "signature": {
            "schema_version": "ao2.cp-phase1-promotion-decision-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "release-lead",
            "signature_sha256": signature_sha256,
            "signature_hex": signature_hex,
            "public_key_sha256": public_key_sha256,
            "public_key_pem": public_key_pem
        }
    })
}

fn signed_release_evaluator_decision_fixture(decision: serde_json::Value) -> serde_json::Value {
    let mut rng = rsa::rand_core::OsRng;
    let signing_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = signing_key.to_public_key();
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    let decision_raw = serde_json::to_string_pretty(&decision).unwrap();
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key);
    let signature = signer.sign(decision_raw.as_bytes()).to_vec();
    let signature_hex = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let signature_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&signature);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let public_key_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(public_key_pem.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::json!({
        "schema_version": "ao2.cp-release-evaluator-decision-signed-upload.v1",
        "decision": decision,
        "signature": {
            "schema_version": "ao2.cp-release-evaluator-decision-signature.v1",
            "signature_algorithm": "RSA/SHA-256",
            "signer_id": "factory-v3-evaluator-closer",
            "signature_sha256": signature_sha256,
            "signature_hex": signature_hex,
            "public_key_sha256": public_key_sha256,
            "public_key_pem": public_key_pem
        }
    })
}

#[tokio::test]
async fn signed_release_evaluator_decision_signature_sidecar_is_write_once_per_content_sha() {
    // The signature sidecar records *who signed* a given release-evaluator
    // decision content sha. A second signed upload of the *same decision bytes*
    // but a *different* signature (different key / provenance) must NOT silently
    // overwrite the first signer's sidecar — otherwise any holder of a valid
    // signing key could rewrite the recorded provenance of an already-observed
    // release decision. First write wins; a conflicting re-sign is rejected.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Same decision content, two independently generated signing keys.
    let decision: serde_json::Value =
        serde_json::from_str(&release_evaluator_decision_fixture()).unwrap();
    let first = signed_release_evaluator_decision_fixture(decision.clone());
    let second = signed_release_evaluator_decision_fixture(decision);
    assert_eq!(
        first["decision"], second["decision"],
        "fixtures must share identical decision content"
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
        .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
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
        .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
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
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/{sha}/signature"
        ))
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
async fn signed_release_evaluator_decision_reupload_of_identical_artifact_stays_idempotent() {
    // The write-once guard must not break idempotent retries: re-POSTing the
    // *exact same* signed artifact (identical signature bytes) yields the same
    // sidecar_raw, so it is accepted as a no-op rather than rejected as a
    // conflict. Guards the `existing == sidecar_raw` branch of the guard.
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let decision: serde_json::Value =
        serde_json::from_str(&release_evaluator_decision_fixture()).unwrap();
    let artifact = signed_release_evaluator_decision_fixture(decision);

    for attempt in 1..=2 {
        let post = client
            .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
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
async fn signed_release_evaluator_decision_persists_verified_signature_sidecar() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let decision: serde_json::Value =
        serde_json::from_str(&release_evaluator_decision_fixture()).unwrap();
    let upload = signed_release_evaluator_decision_fixture(decision);

    let post = client
        .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/ao2-release-evaluator-decision/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let signature = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/{sha}/signature"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(signature.status(), 200);
    let signature_body: serde_json::Value = signature.json().await.unwrap();
    assert_eq!(
        signature_body["schema_version"],
        "ao2.cp-release-evaluator-decision-signature.v1"
    );
    assert_eq!(signature_body["release_evaluator_decision_sha256"], sha);
    assert_eq!(signature_body["signature"]["signature_verified"], true);
    assert_eq!(
        signature_body["signature"]["signer_id"],
        "factory-v3-evaluator-closer"
    );

    let dashboard = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/dashboard.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    let dashboard_body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(
        dashboard_body["latest"]["signature_url"],
        format!("/api/v1/release/evaluator-decision/{sha}/signature")
    );
    assert_eq!(dashboard_body["latest"]["signature_verified"], true);
    assert!(!serde_json::to_string(&dashboard_body)
        .unwrap()
        .contains("secret"));
}

#[tokio::test]
async fn unpinned_evaluator_key_is_verified_but_not_release_authoritative() {
    // No trust anchor configured: a cryptographically-valid signature
    // from an arbitrary uploader-supplied key must be recorded, but
    // marked observer-only — NOT release-authoritative. This is the
    // guard against a token-holder minting a self-signed "decision".
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let decision: serde_json::Value =
        serde_json::from_str(&release_evaluator_decision_fixture()).unwrap();
    let upload = signed_release_evaluator_decision_fixture(decision);

    let post = client
        .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let sha = post.json::<serde_json::Value>().await.unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string();

    let signature_body: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/{sha}/signature"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = &signature_body["signature"];
    assert_eq!(sig["signature_verified"], true);
    assert_eq!(sig["verification_scope"], "cryptographic-only");
    assert_eq!(sig["trust_anchor"], "upload-public-key-not-authority");
    assert_eq!(sig["trust_policy"]["trusted_key_match"], false);
    assert_eq!(sig["trust_policy"]["release_authoritative"], false);

    let dashboard_body: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/dashboard.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dashboard_body["latest"]["release_authoritative"], false);
}

#[tokio::test]
async fn pinned_evaluator_key_is_release_authoritative() {
    // Trust anchor configured to the signing key's SHA-256: the same
    // decision is now recorded as release-authoritative.
    let decision: serde_json::Value =
        serde_json::from_str(&release_evaluator_decision_fixture()).unwrap();
    let upload = signed_release_evaluator_decision_fixture(decision);
    let pinned = upload["signature"]["public_key_sha256"]
        .as_str()
        .unwrap()
        .to_string();

    let (base, _dir) = spawn_server_with_trusted_evaluator_keys(vec![pinned.clone()]).await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/release/evaluator-decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let sha = post.json::<serde_json::Value>().await.unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string();

    let signature_body: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/{sha}/signature"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = &signature_body["signature"];
    assert_eq!(sig["signature_verified"], true);
    assert_eq!(sig["verification_scope"], "cryptographic-and-pinned-key");
    assert_eq!(
        sig["trust_anchor"],
        "configured-release-evaluator-decision-public-key-sha256"
    );
    assert_eq!(sig["trust_policy"]["trusted_key_match"], true);
    assert_eq!(sig["trust_policy"]["release_authoritative"], true);
    assert_eq!(sig["trust_policy"]["matched_public_key_sha256"], pinned);

    let dashboard_body: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/dashboard.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dashboard_body["latest"]["release_authoritative"], true);
}

#[tokio::test]
async fn release_evaluator_decision_is_observed_without_approving_release() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/release/evaluator-decision"))
        .header("authorization", "Bearer secret")
        .body(release_evaluator_decision_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "factory-v3/ao2-release-evaluator-decision/v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!("{base}/api/v1/release/evaluator-decision/latest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(latest_body["decision"], "accept_phase1_release_candidate");
    assert_eq!(
        latest_body["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        latest_body["trust_boundary"]["control_plane_approves_release"],
        false
    );

    let raw = client
        .get(format!("{base}/api/v1/release/evaluator-decision/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);

    let dashboard = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/dashboard.json"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(
        body["schema_version"],
        "ao2.cp-release-evaluator-decision-dashboard.v1"
    );
    assert_eq!(body["state"], "accepted");
    assert_eq!(body["latest"]["sha256"], sha);
    assert_eq!(
        body["latest"]["decision"],
        "accept_phase1_release_candidate"
    );
    assert_eq!(body["blockers"].as_array().unwrap().len(), 0);
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["links"]["latest_release_evaluator_decision"],
        "/api/v1/release/evaluator-decision/latest"
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));

    let html = client
        .get(format!(
            "{base}/api/v1/release/evaluator-decision/dashboard"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("AO2 Release Evaluator Decision"));
    assert!(html.contains("accept_phase1_release_candidate"));
    assert!(html.contains("factory-v3 evaluator-closer"));
    assert!(html.contains("/api/v1/release/evaluator-decision/latest"));
    assert!(!html.contains("secret"));
}

#[tokio::test]
async fn release_publication_is_observed_without_entering_trust_path() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/release/publication"))
        .header("authorization", "Bearer secret")
        .body(release_publication_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let receipt: serde_json::Value = post.json().await.unwrap();
    assert_eq!(receipt["schema_version"], "ao2.cp-ingest-receipt.v1");
    assert_eq!(
        receipt["ingested_schema_version"],
        "ao2.release-publication-summary.v1"
    );
    let sha = receipt["sha256"].as_str().unwrap();

    let latest = client
        .get(format!("{base}/api/v1/release/publication/latest"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest_body: serde_json::Value = latest.json().await.unwrap();
    assert_eq!(latest_body["version"], "0.4.79");
    assert_eq!(latest_body["verification"]["provenance_tag_matches"], true);

    let raw = client
        .get(format!("{base}/api/v1/release/publication/{sha}"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);

    let dashboard = client
        .get(format!("{base}/api/v1/release/publication/dashboard.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), 200);
    let body: serde_json::Value = dashboard.json().await.unwrap();
    assert_eq!(
        body["schema_version"],
        "ao2.cp-release-publication-dashboard.v1"
    );
    assert_eq!(body["state"], "release_published_verified");
    assert_eq!(body["latest"]["version"], "0.4.79");
    assert_eq!(body["latest"]["release_tag"], "v0.4.79");
    assert_eq!(body["latest"]["sha256"], sha);
    assert_eq!(body["verification"]["release_ship"], "passed");
    assert_eq!(body["verification"]["rollback_status"], "verified");
    assert_eq!(body["verification"]["provenance_tag_matches"], true);
    assert_eq!(body["archive_targets"], 3);
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["links"]["latest_release_publication"],
        "/api/v1/release/publication/latest"
    );

    // The publication dashboard now mirrors the cockpit candidate_correlation
    // surface so operators landing here see the same cross-evidence consistency
    // verdict as operators landing on the cockpit. Additive: existing dashboard
    // schema and shape are unchanged otherwise.
    let dashboard_correlation = &body["candidate_correlation"];
    assert!(
        dashboard_correlation.is_object(),
        "publication dashboard should expose candidate_correlation for operator triage"
    );
    let dashboard_correlation_status = dashboard_correlation["status"].as_str().unwrap_or("");
    assert!(
        dashboard_correlation_status == "matched" || dashboard_correlation_status == "mismatched",
        "candidate_correlation.status was {dashboard_correlation_status:?}"
    );
    assert_eq!(dashboard_correlation["release_version"], "0.4.79");
    assert_eq!(dashboard_correlation["release_tag"], "v0.4.79");
    assert!(dashboard_correlation["three_os_version"].is_string());
    assert!(dashboard_correlation["release_evaluator_version"].is_string());
    assert!(dashboard_correlation["codex_acceptance_version"].is_string());
    assert!(dashboard_correlation["claude_acceptance_version"].is_string());
    assert!(dashboard_correlation["blockers"].is_array());

    let html = client
        .get(format!("{base}/api/v1/release/publication/dashboard"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("AO2 Release Publication"));
    assert!(html.contains("v0.4.79"));
    assert!(html.contains("published_verified"));
    assert!(html.contains("provenance tag matches"));
    assert!(html.contains("rollback"));
    assert!(html.contains("Repository Heads"));
    assert!(html.contains("ao2"));
    assert!(html.contains("f8e039bd1d06d4b143b4e13e055d0d7659c3dc73"));
    assert!(html.contains("/api/v1/release/publication/latest"));
    // Dashboard HTML mirrors the cockpit "Candidate Correlation" section so
    // operators landing on either surface get the same triage information.
    assert!(html.contains("Candidate Correlation"));
    assert!(html.contains("Three-OS smoke version"));
    assert!(html.contains("Evaluator version"));
    assert!(html.contains("Codex acceptance version"));
    assert!(html.contains("Claude acceptance version"));
    assert!(html.contains("Blockers"));
    assert!(html.contains("/api/v1/release/cockpit"));
    assert!(!html.contains("secret"));
}

#[tokio::test]
async fn release_cockpit_correlates_phase1_and_provider_observer_surfaces() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        ("/api/v1/acceptance", CODEX_ACCEPTANCE_FIXTURE.to_string()),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let cockpit = client
        .get(format!("{base}/api/v1/release/cockpit.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(cockpit.status(), 200);
    let body: serde_json::Value = cockpit.json().await.unwrap();
    assert_eq!(body["schema_version"], "ao2.cp-release-cockpit.v1");
    assert_eq!(body["status"], "ready");
    assert_eq!(
        body["surfaces"]["release_publication"]["state"],
        "release_published_verified"
    );
    assert_eq!(body["surfaces"]["provider_registry"]["status"], "observed");
    assert_eq!(body["surfaces"]["provider_registry"]["provider_count"], 3);
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][1]["provider"],
        "codex"
    );
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][1]["metadata_source"],
        "ao2-adapter-codex"
    );
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][1]["doctor_metadata_source"],
        "ao2-adapter-codex"
    );
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][2]["provider"],
        "claude"
    );
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][2]["metadata_source"],
        "ao2-adapter-claude"
    );
    assert_eq!(
        body["surfaces"]["provider_registry"]["providers"][2]["doctor_metadata_source"],
        "ao2-adapter-claude"
    );
    assert_eq!(body["surfaces"]["provider_readiness"]["status"], "passed");
    assert_eq!(
        body["surfaces"]["provider_readiness"]["codex_gate"],
        "ready"
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["status"],
        "observed"
    );
    assert_eq!(body["surfaces"]["provider_acceptance"]["total_count"], 1);
    assert!(
        body["surfaces"]["provider_acceptance"]["latest_codex"]["sha256"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["latest_codex"]["provider"],
        "codex"
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["latest_codex"]["source_class"],
        "fixture"
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["latest_codex"]["run_id"],
        "live-codex-provider-pilot"
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["latest_codex"]["raw_url"],
        format!(
            "/api/v1/acceptance/{}",
            body["surfaces"]["provider_acceptance"]["latest_codex"]["sha256"]
                .as_str()
                .unwrap()
        )
    );
    assert!(body["surfaces"]["provider_acceptance"]["latest_codex"]["score"].is_number());
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["latest_by_provider"]["codex"]["status"],
        "passed"
    );
    assert_eq!(
        body["surfaces"]["provider_acceptance"]["links"]["dashboard_json"],
        "/api/v1/acceptance/dashboard.json"
    );
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["links"]["provider_registry_dashboard_json"],
        "/api/v1/provider/registry/dashboard.json"
    );
    assert_eq!(
        body["links"]["phase1_operator_panel_json"],
        "/api/v1/phase1/promotion/operator-panel.json"
    );
    let correlation = &body["candidate_correlation"];
    assert!(
        correlation.is_object(),
        "cockpit should expose candidate_correlation surface for operator triage"
    );
    let correlation_status = correlation["status"].as_str().unwrap_or("");
    assert!(
        correlation_status == "matched" || correlation_status == "mismatched",
        "candidate_correlation.status was {correlation_status:?}"
    );
    assert!(correlation["release_version"].is_string());
    assert!(correlation["release_tag"].is_string());
    assert!(correlation["three_os_version"].is_string());
    assert!(correlation["release_evaluator_version"].is_string());
    assert!(correlation["codex_acceptance_version"].is_string());
    assert!(correlation["claude_acceptance_version"].is_string());
    assert!(correlation["blockers"].is_array());
    let parity = body["candidate_correlation_parity"].as_str().unwrap_or("");
    assert!(
        matches!(parity, "matched" | "mismatched" | "missing" | "drift" | "unknown"),
        "cockpit candidate_correlation_parity must be matched|mismatched|missing|drift|unknown, was {parity:?}"
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));

    let html = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("AO2 Release Cockpit"));
    assert!(html.contains("release_published_verified"));
    assert!(html.contains("Provider Registry"));
    assert!(html.contains("Provider Acceptance Details"));
    assert!(html.contains("live-codex-provider-pilot"));
    assert!(html.contains("fixture"));
    assert!(html.contains("/api/v1/acceptance/"));
    assert!(html.contains("/api/v1/release/cockpit.json"));
    assert!(html.contains("Candidate Correlation"));
    assert!(html.contains("Three-OS smoke version"));
    assert!(html.contains("Three-OS smoke parity"));
    assert!(html.contains("Evaluator version"));
    assert!(html.contains("Codex acceptance version"));
    assert!(html.contains("Claude acceptance version"));
    assert!(html.contains("Provider Registry Metadata"));
    assert!(html.contains("ao2-adapter-codex"));
    assert!(html.contains("ao2-adapter-claude"));
    assert!(html.contains("Blockers"));
    assert!(!html.contains("secret"));
}

#[tokio::test]
async fn release_candidate_handoff_correlates_ready_release_without_mutating_trust_path() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let handoff = client
        .get(format!("{base}/api/v1/release/handoff.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let body: serde_json::Value = handoff.json().await.unwrap();

    assert_eq!(
        body["schema_version"],
        "ao2.cp-release-candidate-handoff.v1"
    );
    assert_eq!(body["status"], "ready");
    assert_eq!(body["handoff_kind"], "phase1_release_candidate");
    assert_eq!(body["release"]["version"], "0.4.79");
    assert_eq!(body["release"]["release_tag"], "v0.4.79");
    assert_eq!(
        body["release"]["repositories"]["ao2"]["head"],
        "f8e039bd1d06d4b143b4e13e055d0d7659c3dc73"
    );
    assert_eq!(body["gates"]["release_cockpit"], "ready");
    assert_eq!(body["gates"]["phase1_promotion"], "observed");
    assert_eq!(body["gates"]["decision_signature"], "present");
    assert_eq!(body["gates"]["provider_acceptance"], "live_complete");
    assert_eq!(body["gates"]["release_evaluator_decision"], "accepted");
    assert_eq!(body["gates"]["candidate_correlation"], "matched");
    assert_eq!(body["candidate_correlation"]["release_version"], "0.4.79");
    assert_eq!(body["candidate_correlation"]["three_os_version"], "0.4.79");
    assert_eq!(
        body["candidate_correlation"]["release_evaluator_version"],
        "0.4.79"
    );
    assert_eq!(
        body["candidate_correlation"]["codex_acceptance_version"],
        "0.4.79"
    );
    assert_eq!(
        body["candidate_correlation"]["claude_acceptance_version"],
        "0.4.79"
    );
    assert_eq!(body["acceptance"]["codex"]["source_class"], "live");
    assert_eq!(
        body["acceptance"]["codex"]["release_candidate_version"],
        "0.4.79"
    );
    assert_eq!(body["acceptance"]["claude"]["source_class"], "live");
    assert_eq!(
        body["acceptance"]["claude"]["release_candidate_version"],
        "0.4.79"
    );
    assert_eq!(
        body["artifacts"]["phase1_checklist"]["raw_url"],
        format!("/api/v1/phase1/promotion/checklist/{checklist_sha}")
    );
    assert_eq!(
        body["links"]["release_candidate_handoff_json"],
        "/api/v1/release/handoff.json"
    );
    assert_eq!(
        body["links"]["release_readiness_json"],
        "/api/v1/release/readiness.json"
    );
    assert_eq!(
        body["links"]["cockpit_json"],
        "/api/v1/release/cockpit.json"
    );
    assert_eq!(
        body["operator_handoff"]["control_plane_role"],
        "read_only_observer"
    );
    assert_eq!(body["operator_handoff"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["operator_handoff"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert!(body["next_actions"][0]
        .as_str()
        .unwrap()
        .contains("factory-v3 evaluator-closer"));
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));

    let html = client
        .get(format!("{base}/api/v1/release/handoff"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let html = html.text().await.unwrap();
    assert!(html.contains("AO2 Release Candidate Handoff"));
    assert!(html.contains("v0.4.79"));
    assert!(html.contains("phase1_release_candidate"));
    assert!(html.contains("Release Cockpit"));
    assert!(html.contains("ready"));
    assert!(html.contains("Phase 1 Promotion"));
    assert!(html.contains("observed"));
    assert!(html.contains("Decision Signature"));
    assert!(html.contains("present"));
    assert!(html.contains("Provider Acceptance"));
    assert!(html.contains("live_complete"));
    assert!(html.contains("Codex"));
    assert!(html.contains("passed"));
    assert!(html.contains("live"));
    assert!(html.contains("Claude"));
    assert!(html.contains("factory-v3 evaluator-closer"));
    assert!(html.contains("/api/v1/release/handoff.json"));
    assert!(html.contains("/api/v1/release/cockpit"));
    assert!(!html.contains("secret"));

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let readiness_body: serde_json::Value = readiness.json().await.unwrap();
    assert_eq!(
        readiness_body["schema_version"],
        "ao2.cp-release-readiness.v1"
    );
    assert_eq!(readiness_body["status"], "ready");
    assert_eq!(readiness_body["release"]["release_tag"], "v0.4.79");
    assert_eq!(readiness_body["blockers"].as_array().unwrap().len(), 0);
    assert_eq!(
        readiness_body["operator_decision"]["factory_v3_evaluator_closer_required"],
        true
    );
    assert_eq!(
        readiness_body["operator_decision"]["control_plane_approves_release"],
        false
    );
    assert_eq!(
        readiness_body["links"]["release_candidate_handoff"],
        "/api/v1/release/handoff"
    );
    assert!(readiness_body["gate_results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gate| gate["id"] == "provider_acceptance" && gate["status"] == "passed"));
    assert!(readiness_body["gate_results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gate| gate["id"] == "candidate_correlation" && gate["status"] == "passed"));
    assert_eq!(
        readiness_body["three_os_smoke_details"]["overall_status"],
        "passed"
    );
    assert_eq!(
        readiness_body["three_os_smoke_details"]["source_dirty"],
        false
    );
    assert_eq!(
        readiness_body["three_os_smoke_details"]["targets"]["macos"]["status"],
        "passed"
    );
    assert_eq!(
        readiness_body["three_os_smoke_details"]["targets"]["ubuntu"]["duration_seconds"],
        57
    );
    assert_eq!(
        readiness_body["three_os_smoke_details"]["targets"]["windows"]["artifact_url"],
        "/evidence/windows-smoke.json"
    );
    assert!(!serde_json::to_string(&readiness_body)
        .unwrap()
        .contains("secret"));

    let readiness_html = client
        .get(format!("{base}/api/v1/release/readiness"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness_html.status(), 200);
    let readiness_html = readiness_html.text().await.unwrap();
    assert!(readiness_html.contains("AO2 Release Readiness"));
    assert!(readiness_html.contains("factory-v3 evaluator-closer"));
    assert!(readiness_html.contains("Provider Acceptance"));
    assert!(readiness_html.contains("Three-OS Smoke Details"));
    assert!(readiness_html.contains("macOS"));
    assert!(readiness_html.contains("Ubuntu"));
    assert!(readiness_html.contains("Windows"));
    assert!(readiness_html.contains("/evidence/windows-smoke.json"));
    assert!(readiness_html.contains("91"));
    assert!(readiness_html.contains("/api/v1/release/handoff"));
    assert!(!readiness_html.contains("secret"));
}

async fn publish_release_readiness_inputs(
    client: &reqwest::Client,
    base: &str,
    three_os_smoke: String,
) {
    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        ("/api/v1/phase1/promotion/three-os-smoke", three_os_smoke),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);
}

#[tokio::test]
async fn release_readiness_blocks_three_os_smoke_without_required_windows_pass() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    publish_release_readiness_inputs(&client, &base, failed_three_os_release_smoke_fixture()).await;

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let body: serde_json::Value = readiness.json().await.unwrap();

    assert_eq!(body["status"], "attention");
    assert!(body["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("three_os_smoke: expected passed, observed failed")));
    assert!(body["gate_results"].as_array().unwrap().iter().any(|gate| {
        gate["id"] == "three_os_smoke"
            && gate["observed"] == "failed"
            && gate["status"] == "blocked"
    }));
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
}

#[tokio::test]
async fn release_readiness_blocks_three_os_candidate_correlation_parity_drift() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    publish_release_readiness_inputs(&client, &base, drift_three_os_release_smoke_fixture()).await;

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let body: serde_json::Value = readiness.json().await.unwrap();

    assert_eq!(body["status"], "attention");
    assert_eq!(body["candidate_correlation"]["status"], "matched");
    assert_eq!(body["candidate_correlation_parity"], "drift");
    assert!(body["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("candidate_correlation_parity: expected matched, observed drift")));
    assert!(body["gate_results"].as_array().unwrap().iter().any(|gate| {
        gate["id"] == "candidate_correlation_parity"
            && gate["observed"] == "drift"
            && gate["status"] == "blocked"
    }));
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
}

// Lane CC: prove the new surface_content_hash_parity readiness gate
// fires independently of every prior parity layer. The fixture has
// candidate_correlation_parity=matched (Lane S passes) and every
// per-target candidate_correlation_status=matched (Lane W's
// server-side recomputation accepts the ingestion), but the aggregator
// reports one of the six Lane Z/BB content-hash surfaces in drift.
// The readiness gate must observe drift and block the release.
#[tokio::test]
async fn release_readiness_blocks_three_os_surface_content_hash_parity_drift() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    publish_release_readiness_inputs(
        &client,
        &base,
        surface_content_hash_drift_three_os_release_smoke_fixture(),
    )
    .await;

    let handoff = client
        .get(format!("{base}/api/v1/release/handoff.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let handoff_body: serde_json::Value = handoff.json().await.unwrap();
    assert_eq!(handoff_body["status"], "attention");
    assert_eq!(
        handoff_body["gates"]["surface_content_hash_parity"],
        "drift"
    );

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let body: serde_json::Value = readiness.json().await.unwrap();

    assert_eq!(body["status"], "attention");
    // The fixture is engineered so every prior parity layer reports
    // matched; only the new Lane CC gate should fire.
    assert_eq!(body["candidate_correlation"]["status"], "matched");
    assert_eq!(body["candidate_correlation_parity"], "matched");
    // The aggregate verdict reduces a per-surface "drift" entry to the
    // composite "drift" verdict so a single readiness gate row exposes
    // any per-surface divergence.
    assert_eq!(body["surface_content_hash_parity"], "drift");
    // The per-surface detail dict is round-tripped from the ingested
    // smoke so operators reading the readiness payload can pinpoint
    // which surface drifted without re-running the aggregator.
    assert_eq!(
        body["surface_content_hash_parity_detail"]["release_assembly"],
        "drift"
    );
    assert_eq!(
        body["surface_content_hash_parity_detail"]["release_cockpit"],
        "matched"
    );
    assert_eq!(
        body["surface_content_hash_parity_detail"]["release_assembly_blockers"],
        "matched"
    );
    // The aggregate verdict is reflected as a readiness blocker.
    assert!(
        body["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("surface_content_hash_parity: expected matched, observed drift")),
        "readiness blockers must surface the new Lane CC gate"
    );
    // The new gate appears in gate_results with status=blocked,
    // observed=drift, and the per-surface detail in the detail field.
    let gate = body["gate_results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gate| gate["id"] == "surface_content_hash_parity")
        .expect("surface_content_hash_parity gate must be present in readiness gate_results");
    assert_eq!(gate["observed"], "drift");
    assert_eq!(gate["status"], "blocked");
    assert_eq!(gate["expected"], "matched");
    assert_eq!(gate["detail"]["release_assembly"], "drift");
    // Belt-and-braces: no credential leaks in the readiness payload.
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));

    // Lane GG: the cockpit HTML now renders the per-surface parity
    // verdict dict as a small operator-facing table so drift is visible
    // at-a-glance without reading JSON. The aggregate parity row also
    // appears in the Candidate Correlation section's dl, colored "warn"
    // when not matched.
    let cockpit_html = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Aggregate parity row in the correlation section.
    assert!(
        cockpit_html.contains("Surface content-hash parity"),
        "cockpit HTML must render the aggregate surface_content_hash_parity row"
    );
    assert!(
        cockpit_html.contains("warn\">drift"),
        "drift verdict must be colored 'warn' so operators see it at a glance"
    );
    // Per-surface table section header.
    assert!(
        cockpit_html.contains("Per-Surface Content-Hash Parity"),
        "cockpit HTML must render the per-surface parity table section"
    );
    // All six expected surface row labels must be present in operator-
    // friendly form so the table is self-describing.
    for label in [
        "Release Cockpit",
        "Release Candidate Handoff",
        "Release Readiness",
        "Release Publication Dashboard",
        "Release Assembly",
        "Release Assembly Blockers",
    ] {
        assert!(
            cockpit_html.contains(label),
            "cockpit parity table must include operator label {label}"
        );
    }
    // Verdict cells must be class-colored: matched=ok, drift=warn. The
    // drift row (release_assembly) is the only one tripped in this
    // fixture; the other five are matched.
    assert!(cockpit_html.contains("ok\">matched"));
    assert!(cockpit_html.contains("warn\">drift"));
    // Belt-and-braces: no credential leaks in the cockpit HTML.
    assert!(!cockpit_html.contains("secret"));

    // Lane JJ: the handoff HTML also renders the per-surface parity grid
    // AND adds the new surface_content_hash_parity row to its checklist
    // gate table so operators landing on /api/v1/release/handoff triage
    // drift without cross-referencing the readiness page.
    let handoff_html = client
        .get(format!("{base}/api/v1/release/handoff"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        handoff_html.contains("Surface Content-Hash Parity"),
        "handoff HTML must include the new gate row label"
    );
    assert!(
        handoff_html.contains("Per-Surface Content-Hash Parity"),
        "handoff HTML must render the per-surface parity table section"
    );
    for label in [
        "Release Cockpit",
        "Release Candidate Handoff",
        "Release Readiness",
        "Release Publication Dashboard",
        "Release Assembly",
        "Release Assembly Blockers",
    ] {
        assert!(
            handoff_html.contains(label),
            "handoff parity table must include operator label {label}"
        );
    }
    assert!(handoff_html.contains("warn\">drift"));
    assert!(!handoff_html.contains("secret"));

    // Lane JJ: the readiness HTML also renders the per-surface parity
    // table so the third operator-facing HTML surface is on parity with
    // cockpit and handoff.
    let readiness_html = client
        .get(format!("{base}/api/v1/release/readiness"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        readiness_html.contains("Per-Surface Content-Hash Parity"),
        "readiness HTML must render the per-surface parity table section"
    );
    for label in [
        "Release Cockpit",
        "Release Candidate Handoff",
        "Release Readiness",
        "Release Publication Dashboard",
        "Release Assembly",
        "Release Assembly Blockers",
    ] {
        assert!(
            readiness_html.contains(label),
            "readiness parity table must include operator label {label}"
        );
    }
    assert!(readiness_html.contains("warn\">drift"));
    assert!(!readiness_html.contains("secret"));
}

#[tokio::test]
async fn release_readiness_blocks_partial_surface_content_hash_parity() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    publish_release_readiness_inputs(
        &client,
        &base,
        partial_surface_content_hash_three_os_release_smoke_fixture(),
    )
    .await;

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let body: serde_json::Value = readiness.json().await.unwrap();

    assert_eq!(body["status"], "attention");
    assert_eq!(body["candidate_correlation"]["status"], "matched");
    assert_eq!(body["candidate_correlation_parity"], "matched");
    assert_eq!(body["surface_content_hash_parity"], "unknown");
    assert!(body["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("surface_content_hash_parity: expected matched, observed unknown")));
    let gate = body["gate_results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gate| gate["id"] == "surface_content_hash_parity")
        .expect("surface_content_hash_parity gate must be present in readiness gate_results");
    assert_eq!(gate["observed"], "unknown");
    assert_eq!(gate["status"], "blocked");
    assert_eq!(gate["detail"]["release_cockpit"], "matched");
    assert!(gate["detail"].get("release_handoff").is_none());
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
}

#[tokio::test]
async fn release_candidate_handoff_blocks_mismatched_provider_acceptance_evidence() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.78"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let handoff = client
        .get(format!("{base}/api/v1/release/handoff.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let body: serde_json::Value = handoff.json().await.unwrap();
    assert_eq!(body["status"], "attention");
    assert_eq!(body["gates"]["provider_acceptance"], "live_complete");
    assert_eq!(body["gates"]["candidate_correlation"], "mismatched");
    assert_eq!(body["candidate_correlation"]["release_version"], "0.4.79");
    assert_eq!(
        body["candidate_correlation"]["codex_acceptance_version"],
        "0.4.78"
    );
    assert_eq!(
        body["candidate_correlation"]["claude_acceptance_version"],
        "0.4.79"
    );
    assert!(body["candidate_correlation"]["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("codex_acceptance_version")));
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
}

#[tokio::test]
async fn release_candidate_handoff_blocks_mismatched_candidate_evidence() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            mismatched_three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let handoff = client
        .get(format!("{base}/api/v1/release/handoff.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let body: serde_json::Value = handoff.json().await.unwrap();
    assert_eq!(body["status"], "attention");
    assert_eq!(body["gates"]["candidate_correlation"], "mismatched");
    assert_eq!(body["candidate_correlation"]["release_version"], "0.4.79");
    assert_eq!(body["candidate_correlation"]["three_os_version"], "0.4.78");
    assert!(body["candidate_correlation"]["blockers"][0]
        .as_str()
        .unwrap()
        .contains("three_os_release_candidate_version"));

    let readiness = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), 200);
    let readiness_body: serde_json::Value = readiness.json().await.unwrap();
    assert_eq!(readiness_body["status"], "attention");
    assert!(readiness_body["gate_results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gate| gate["id"] == "candidate_correlation"
            && gate["status"] == "blocked"
            && gate["observed"] == "mismatched"));
    assert!(readiness_body["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|blocker| blocker.as_str().unwrap().contains("candidate_correlation")));
    assert!(!serde_json::to_string(&readiness_body)
        .unwrap()
        .contains("secret"));
}

// Lane AA: parallel positive-rejection test to Lane W's
// `three_os_release_smoke_ingestion_rejects_tampered_top_level_parity`.
// Lane W audited `candidate_correlation_parity` and proved the server
// rejects ingestion when the posted parity disagrees with per-target
// evidence. This test proves the parallel ingestion-time tampering
// vector does NOT exist for `candidate_correlation` itself: every
// consumer reads the server-recomputed surface produced by
// `candidate_correlation_value()`, never the posted artifact's field.
//
// The fixture combines:
//   - a release publication with a tampered top-level
//     `candidate_correlation: { status: "matched", ... }` field
//     (an attacker's attempt to claim correlation matched even when
//      the underlying evidence disagrees)
//   - a three-OS release smoke with
//     `release_candidate_version=0.4.78` (disagrees with the
//      publication's `version=0.4.79`)
//
// The server-rendered handoff must still resolve
// `candidate_correlation=mismatched` because the recomputation in
// `candidate_correlation_value()` reads the underlying
// `release_publication.version` and
// `phase1.three_os_smoke.release_candidate_version`, ignoring the
// tampered top-level field.
#[tokio::test]
async fn release_candidate_handoff_ignores_tampered_top_level_candidate_correlation_field() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        (
            "/api/v1/release/publication",
            tampered_top_level_candidate_correlation_release_publication_fixture(),
        ),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            mismatched_three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            post.status(),
            200,
            "tampered top-level candidate_correlation must be accepted at ingestion \
             (unknown fields are silently dropped); the server's defense is to \
             recompute on every render, not to reject at ingestion"
        );
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let handoff = client
        .get(format!("{base}/api/v1/release/handoff.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let body: serde_json::Value = handoff.json().await.unwrap();

    assert_eq!(
        body["gates"]["candidate_correlation"], "mismatched",
        "server must recompute candidate_correlation status from underlying \
         artifact fields and ignore the posted tampered top-level field"
    );
    assert_eq!(
        body["candidate_correlation"]["status"], "mismatched",
        "rendered candidate_correlation.status must reflect the recomputation, \
         not the posted tampered status=matched"
    );
    assert_eq!(
        body["candidate_correlation"]["release_version"], "0.4.79",
        "candidate_correlation.release_version must come from the publication's \
         `version` field, not from the posted tampered candidate_correlation block"
    );
    assert_eq!(
        body["candidate_correlation"]["three_os_version"], "0.4.78",
        "candidate_correlation.three_os_version must come from the smoke's \
         `release_candidate_version` field, exposing the real disagreement"
    );
    assert!(
        body["candidate_correlation"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains(
                "three_os_release_candidate_version 0.4.78 does not match release_version 0.4.79"
            )),
        "blockers must surface the recomputed disagreement, proving the tampered \
         blockers=[] field was discarded"
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));
}

#[tokio::test]
async fn release_support_bundle_packages_read_only_operator_handoff() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            three_os_release_smoke_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let evaluator = client
        .post(format!("{base}/api/v1/release/evaluator-decision"))
        .header("authorization", "Bearer secret")
        .body(release_evaluator_decision_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(evaluator.status(), 200);

    let bundle = client
        .get(format!(
            "{base}/api/v1/release/support-bundle.json?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(bundle.status(), 200);
    let body: serde_json::Value = bundle.json().await.unwrap();

    assert_eq!(body["schema_version"], "ao2.cp-release-support-bundle.v1");
    assert_eq!(body["bundle_kind"], "portable_release_operator_handoff");
    assert_eq!(body["release"]["version"], "0.4.79");
    assert_eq!(body["readiness"]["status"], "ready");
    assert_eq!(body["handoff"]["status"], "ready");
    assert_eq!(body["cockpit"]["status"], "ready");
    assert_eq!(body["evaluator_decision"]["state"], "accepted");
    assert_eq!(
        body["evaluator_decision"]["trust_boundary"]["role"],
        "read_only_observer"
    );
    assert_eq!(
        body["evaluator_decision"]["trust_boundary"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        body["release_assembly"]["schema_version"],
        "ao2.cp-release-assembly.v1"
    );
    assert_eq!(body["release_assembly"]["status"], "assembled");
    assert_eq!(
        body["release_assembly"]["release_candidate_version"],
        "0.4.79"
    );
    assert_eq!(body["release_assembly"]["candidate_correlation"], "matched");
    assert_eq!(
        body["release_assembly"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        body["release_assembly"]["control_plane_approves_release"],
        false
    );
    for artifact in [
        "release_publication",
        "phase1_checklist",
        "phase1_decision",
        "three_os_smoke",
    ] {
        assert_ne!(
            body["release_assembly"]["artifact_sha256s"][artifact],
            "missing"
        );
    }
    assert!(body["release_assembly"]["required_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["id"] == "provider_acceptance_codex"
            && artifact["release_candidate_version"] == "0.4.79"));
    assert!(body["release_assembly"]["required_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["id"] == "provider_acceptance_claude"
            && artifact["release_candidate_version"] == "0.4.79"));
    assert_eq!(
        body["storage_support"]["retention_report"]["keep_latest"],
        7
    );
    assert_eq!(body["trust_boundary"]["role"], "read_only_observer");
    assert_eq!(body["trust_boundary"]["mutates_ao_artifacts"], false);
    assert_eq!(
        body["operator_handoff"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        body["links"]["release_support_bundle_json"],
        "/api/v1/release/support-bundle.json?keep_latest=7"
    );
    assert_eq!(
        body["links"]["release_support_bundle_verification_json"],
        "/api/v1/release/support-bundle/verify.json?keep_latest=7"
    );
    assert_eq!(
        body["links"]["release_support_verifier_handoff_json"],
        "/api/v1/release/support-bundle/handoff.json?keep_latest=7"
    );
    assert_eq!(
        body["links"]["release_support_verifier_handoff"],
        "/api/v1/release/support-bundle/handoff?keep_latest=7"
    );
    assert_eq!(
        body["links"]["release_support_bundle_checksums"],
        "/api/v1/release/support-bundle/SHA256SUMS?keep_latest=7"
    );
    assert_eq!(
        body["portable_bundle_manifest"]["schema_version"],
        "ao2.cp-release-support-bundle-manifest.v1"
    );
    assert!(body["portable_bundle_manifest"]["included_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["id"] == "release_readiness"));
    assert!(body["portable_bundle_manifest"]["included_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["id"] == "release_assembly"
            && surface["schema_version"] == "ao2.cp-release-assembly.v1"));
    let integrity = &body["portable_bundle_manifest"]["integrity"];
    assert_eq!(integrity["algorithm"], "sha256-ao2-cp-canonical-json-v1");
    assert_eq!(integrity["scope"], "embedded_support_bundle_surfaces");
    for surface in [
        "ci_evidence_index",
        "release_assembly",
        "release_readiness",
        "release_candidate_handoff",
        "release_cockpit",
        "release_evaluator_decision",
        "storage_support_bundle",
    ] {
        let digest = integrity["surface_sha256"][surface].as_str().unwrap();
        assert_eq!(digest.len(), 64, "{surface} digest should be sha256 hex");
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
    for (surface, embedded_value) in [
        ("ci_evidence_index", &body["ci_evidence_index"]),
        ("release_assembly", &body["release_assembly"]),
        ("release_readiness", &body["readiness"]),
        ("release_candidate_handoff", &body["handoff"]),
        ("release_cockpit", &body["cockpit"]),
        ("release_evaluator_decision", &body["evaluator_decision"]),
        ("storage_support_bundle", &body["storage_support"]),
    ] {
        let expected = sha256_of_canonical(embedded_value).unwrap();
        assert_eq!(integrity["surface_sha256"][surface], expected);
        assert!(body["portable_bundle_manifest"]["included_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == surface && entry["sha256"] == expected));
    }
    assert!(body["portable_bundle_manifest"]["included_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["id"] == "release_evaluator_decision"
            && surface["path"] == "$.evaluator_decision"
            && surface["endpoint"] == "/api/v1/release/evaluator-decision/dashboard.json"
            && surface["sha256"] == integrity["surface_sha256"]["release_evaluator_decision"]));
    assert!(body["portable_bundle_manifest"]["included_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["id"] == "ci_evidence_index"
            && surface["path"] == "$.ci_evidence_index"
            && surface["endpoint"] == "/api/v1/ci/evidence-index.json"
            && surface["schema_version"] == "ao2.cp-ci-evidence-index.v1"
            && surface["sha256"] == integrity["surface_sha256"]["ci_evidence_index"]));
    assert!(body["portable_bundle_manifest"]["included_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["id"] == "storage_support_bundle"
            && surface["path"] == "$.storage_support"
            && surface["sha256"] == integrity["surface_sha256"]["storage_support_bundle"]));
    assert_eq!(
        integrity["verification_plan"]["surface_count"],
        body["portable_bundle_manifest"]["included_surfaces"]
            .as_array()
            .unwrap()
            .len()
    );
    assert_eq!(integrity["verification_plan"]["expected_fail_closed"], true);
    assert!(
        integrity["verification_plan"]["cross_platform_commands"]["macos_ubuntu"]
            .as_str()
            .unwrap()
            .contains("verify_release_support_bundle.py")
    );
    assert!(
        integrity["verification_plan"]["cross_platform_commands"]["windows_powershell"]
            .as_str()
            .unwrap()
            .contains("Verify-ReleaseSupportBundle.ps1")
    );
    assert_eq!(
        integrity["verification_plan"]["trust_boundary"],
        "offline digest verification only; no AO2 artifact mutation and no release approval"
    );
    assert!(body["operator_handoff"]["offline_review_commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|cmd| cmd.as_str().unwrap().contains("python3 -m json.tool")));
    assert_eq!(
        body["operator_handoff"]["credential_handoff"]["source"],
        "local_oauth_cli"
    );
    assert_eq!(
        body["operator_handoff"]["credential_handoff"]["environment_variable"],
        "AO2_CP_AUTH_VALUE"
    );
    assert_eq!(
        body["operator_handoff"]["credential_handoff"]["value_contract"],
        "HTTP Authorization header value only; never a URL query parameter, markdown literal, or committed artifact"
    );
    assert!(
        body["operator_handoff"]["credential_handoff"]["cross_platform_capture"]["posix_shell"]
            .as_str()
            .unwrap()
            .contains("set +x")
    );
    assert!(
        body["operator_handoff"]["credential_handoff"]["cross_platform_capture"]["powershell"]
            .as_str()
            .unwrap()
            .contains("Set-PSDebug -Off")
    );
    assert!(!serde_json::to_string(&body).unwrap().contains("secret"));

    let verification_page = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/verify?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(verification_page.status(), 200);
    assert_eq!(
        verification_page
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );
    let verification_html = verification_page.text().await.unwrap();
    assert!(verification_html.contains("AO2 Release Support Bundle Verification"));
    assert!(verification_html.contains("read_only_observer"));
    assert!(verification_html.contains("factory-v3 evaluator-closer"));
    assert!(verification_html.contains("release_assembly"));
    assert!(verification_html.contains("ci_evidence_index"));
    assert!(verification_html.contains("release_evaluator_decision"));
    assert!(verification_html.contains("storage_support_bundle"));
    assert!(verification_html.contains("/api/v1/release/support-bundle/verify.json?keep_latest=7"));
    assert!(!verification_html.contains("secret"));

    let verification = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/verify.json?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(verification.status(), 200);
    let verification_body: serde_json::Value = verification.json().await.unwrap();
    assert_eq!(
        verification_body["schema_version"],
        "ao2.cp-release-support-bundle-verification.v1"
    );
    assert_eq!(verification_body["status"], "passed");
    assert_eq!(verification_body["surface_count"], 7);
    assert_eq!(verification_body["blockers"].as_array().unwrap().len(), 0);
    assert_eq!(
        verification_body["trust_boundary_check"]["status"],
        "passed"
    );
    assert_eq!(
        verification_body["operator_handoff"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    for check in verification_body["checks"].as_array().unwrap() {
        assert_eq!(check["status"], "passed");
        assert_eq!(check["manifest_sha256"], check["integrity_sha256"]);
        assert_eq!(check["manifest_sha256"], check["recomputed_sha256"]);
        assert_eq!(check["path"], check["expected_path"]);
        assert_eq!(
            check["declared_schema_version"],
            check["embedded_schema_version"]
        );
    }
    assert!(!serde_json::to_string(&verification_body)
        .unwrap()
        .contains("secret"));

    let handoff = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/handoff.json?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff.status(), 200);
    let handoff_body: serde_json::Value = handoff.json().await.unwrap();
    assert_eq!(
        handoff_body["schema_version"],
        "ao2.cp-release-support-verifier-handoff.v1"
    );
    assert_eq!(handoff_body["status"], "passed");
    assert_eq!(
        handoff_body["bundle_sha256"],
        verification_body["bundle_sha256"]
    );
    assert_eq!(handoff_body["verification"]["status"], "passed");
    assert_eq!(
        handoff_body["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(handoff_body["control_plane_role"], "read_only_observer");
    assert_eq!(handoff_body["control_plane_approves_release"], false);
    assert_eq!(handoff_body["mutates_ao_artifacts"], false);
    assert_eq!(handoff_body["contains_bearer_token"], false);
    assert_eq!(
        handoff_body["links"]["release_support_bundle_verify_json"],
        "/api/v1/release/support-bundle/verify.json?keep_latest=7"
    );
    assert_eq!(
        handoff_body["links"]["release_support_verifier_handoff_json"],
        "/api/v1/release/support-bundle/handoff.json?keep_latest=7"
    );
    assert!(handoff_body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|check| check["status"] == "passed"));
    assert!(!serde_json::to_string(&handoff_body)
        .unwrap()
        .contains("secret"));

    let handoff_page = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/handoff?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(handoff_page.status(), 200);
    assert_eq!(
        handoff_page
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );
    let handoff_html = handoff_page.text().await.unwrap();
    assert!(handoff_html.contains("AO2 Release Support Verifier Handoff"));
    assert!(handoff_html.contains("factory-v3 evaluator-closer"));
    assert!(
        handoff_html.contains("read-only observer handoff")
            || handoff_html.contains("Read-only observer handoff")
    );
    assert!(handoff_html.contains("/api/v1/release/support-bundle/handoff.json?keep_latest=7"));
    assert!(!handoff_html.contains("secret"));

    let manifest_page = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/manifest?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(manifest_page.status(), 200);
    assert_eq!(
        manifest_page
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );
    let manifest_html = manifest_page.text().await.unwrap();
    assert!(manifest_html.contains("AO2 Release Support Bundle Manifest"));
    assert!(manifest_html.contains("ao2-release-support-bundle-0.4.79.json"));
    assert!(manifest_html.contains("release_assembly"));
    assert!(manifest_html.contains("ci_evidence_index"));
    assert!(manifest_html.contains("storage_support_bundle"));
    assert!(manifest_html.contains("/api/v1/release/support-bundle/download?keep_latest=7"));
    assert!(manifest_html.contains("/api/v1/release/support-bundle/SHA256SUMS?keep_latest=7"));
    assert!(manifest_html.contains("sha256sum -c SHA256SUMS"));
    assert!(manifest_html.contains("Get-FileHash"));
    assert!(manifest_html.contains("python3 verify_release_support_bundle.py"));
    assert!(manifest_html.contains("pwsh -File Verify-ReleaseSupportBundle.ps1"));
    assert!(manifest_html.contains("AO2_CP_AUTH_VALUE"));
    assert!(manifest_html.contains("local OAuth CLI"));
    assert!(manifest_html.contains("not a full header line"));
    assert!(manifest_html.contains(
        "Keep credential values out of URLs, logs, reports, markdown, and committed artifacts"
    ));
    assert!(manifest_html.contains("disable shell tracing around fetches"));
    assert!(manifest_html.contains("unset AO2_CP_AUTH_VALUE"));
    assert!(manifest_html.contains("Remove-Item Env:AO2_CP_AUTH_VALUE"));
    assert!(manifest_html.contains("POSIX shell fetch"));
    assert!(manifest_html.contains("curl -fsS --config -"));
    assert!(manifest_html.contains("PowerShell fetch"));
    assert!(manifest_html.contains("Invoke-WebRequest -Headers $Headers"));
    assert!(manifest_html.contains("HTTP Authorization header only"));
    assert!(manifest_html
        .contains("local OAuth/session CLI obtains credentials outside generated evidence"));
    assert!(manifest_html.contains("factory-v3 evaluator-closer"));
    assert!(!manifest_html.contains("secret"));
    assert!(!manifest_html.contains("Bearer &lt;token&gt;"));
    assert!(!manifest_html.contains("authorization: Bearer"));

    let manifest = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/manifest.json?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(manifest.status(), 200);
    let manifest_body: serde_json::Value = manifest.json().await.unwrap();
    assert_eq!(
        manifest_body["schema_version"],
        "ao2.cp-release-support-bundle-manifest.v1"
    );
    assert_eq!(manifest_body["status"], "passed");
    assert_eq!(
        manifest_body["bundle_kind"],
        "portable_release_operator_handoff"
    );
    assert_eq!(
        manifest_body["filename"],
        "ao2-release-support-bundle-0.4.79.json"
    );
    assert_eq!(manifest_body["keep_latest"], 7);
    assert_eq!(manifest_body["release"]["version"], "0.4.79");
    assert_eq!(manifest_body["verification"]["surface_count"], 7);
    assert_eq!(manifest_body["verification"]["blocker_count"], 0);
    assert_eq!(
        manifest_body["verification"]["trust_boundary_status"],
        "passed"
    );
    assert_eq!(
        manifest_body["portable_bundle_manifest"]["schema_version"],
        "ao2.cp-release-support-bundle-manifest.v1"
    );
    assert_eq!(
        manifest_body["portable_bundle_manifest"]["included_surface_count"],
        7
    );
    assert_eq!(
        manifest_body["portable_bundle_manifest"]["integrity_algorithm"],
        "sha256-ao2-cp-canonical-json-v1"
    );
    assert_eq!(manifest_body["surface_checks"].as_array().unwrap().len(), 7);
    assert!(manifest_body["surface_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["id"] == "release_evaluator_decision"
            && check["status"] == "passed"
            && check["path"] == "$.evaluator_decision"));
    assert!(manifest_body["surface_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["id"] == "ci_evidence_index"
            && check["status"] == "passed"
            && check["path"] == "$.ci_evidence_index"));
    assert_eq!(
        manifest_body["links"]["release_support_bundle_download"],
        "/api/v1/release/support-bundle/download?keep_latest=7"
    );
    assert_eq!(
        manifest_body["links"]["release_support_bundle_checksums"],
        "/api/v1/release/support-bundle/SHA256SUMS?keep_latest=7"
    );
    assert_eq!(
        manifest_body["operator_handoff"]["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(
        manifest_body["operator_handoff"]["contains_bearer_token"],
        false
    );
    assert_eq!(
        manifest_body["operator_handoff"]["mutates_ao_artifacts"],
        false
    );
    assert_eq!(
        manifest_body["operator_handoff"]["credential_handoff"]["source"],
        "local_oauth_cli"
    );
    assert_eq!(
        manifest_body["operator_handoff"]["credential_handoff"]["environment_variable"],
        "AO2_CP_AUTH_VALUE"
    );
    assert!(
        manifest_body["operator_handoff"]["credential_handoff"]["forbidden_locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| location == "urls")
    );
    assert!(
        manifest_body["operator_handoff"]["credential_handoff"]["forbidden_locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| location == "committed artifacts")
    );
    let verifier_sample = &manifest_body["verifier_output_schema_sample"];
    assert_eq!(
        verifier_sample["schema_version"],
        "ao2.cp-release-support-bundle-verifier-output-sample.v1"
    );
    assert_eq!(verifier_sample["status"], "passed");
    assert_eq!(verifier_sample["checksum_verified"], true);
    assert_eq!(verifier_sample["surface_count"], 7);
    assert_eq!(verifier_sample["control_plane_role"], "read_only_observer");
    assert_eq!(
        verifier_sample["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert_eq!(verifier_sample["mutates_ao_artifacts"], false);
    assert_eq!(verifier_sample["control_plane_approves_release"], false);
    assert!(verifier_sample["expected_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field == "checksum_verified"));
    assert!(verifier_sample["token_hygiene"]["contains_bearer_token"] == false);
    assert!(verifier_sample["token_hygiene"]["forbidden_locations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|location| location == "committed artifacts"));
    assert!(verifier_sample["platform_commands"]["macos_ubuntu"]
        .as_str()
        .unwrap()
        .contains("--json --checksums SHA256SUMS"));
    assert!(verifier_sample["platform_commands"]["windows_powershell"]
        .as_str()
        .unwrap()
        .contains("-Json -Checksums SHA256SUMS"));
    assert!(!serde_json::to_string(verifier_sample)
        .unwrap()
        .contains("secret"));
    let manifest_digest = manifest_body["bundle_sha256"].as_str().unwrap();
    assert_eq!(manifest_digest.len(), 64);
    assert!(manifest_digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(!serde_json::to_string(&manifest_body)
        .unwrap()
        .contains("secret"));

    let checksums = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/SHA256SUMS?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(checksums.status(), 200);
    assert_eq!(
        checksums
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        checksums
            .headers()
            .get("x-ao2-cp-control-plane-role")
            .unwrap()
            .to_str()
            .unwrap(),
        "read-only-observer"
    );
    let checksums_text = checksums.text().await.unwrap();
    assert!(checksums_text.contains("  ao2-release-support-bundle-0.4.79.json"));
    assert!(checksums_text.contains("  surfaces/ci_evidence_index.json"));
    assert!(checksums_text.contains("  surfaces/release_assembly.json"));
    assert!(checksums_text.contains("  surfaces/storage_support_bundle.json"));
    assert!(
        checksums_text.contains(manifest_digest),
        "SHA256SUMS should contain manifest bundle digest {manifest_digest}; body:\n{checksums_text}"
    );
    assert!(checksums_text.contains(
        integrity["surface_sha256"]["release_assembly"]
            .as_str()
            .unwrap()
    ));
    assert!(checksums_text.contains("# control-plane-role: read-only-observer"));
    assert!(checksums_text.contains("# release-acceptance-owner: factory-v3 evaluator-closer"));
    assert!(!checksums_text.contains("secret"));

    let download = client
        .get(format!(
            "{base}/api/v1/release/support-bundle/download?keep_latest=7"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json; charset=utf-8"
    );
    assert_eq!(
        download
            .headers()
            .get(reqwest::header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap(),
        "attachment; filename=\"ao2-release-support-bundle-0.4.79.json\""
    );
    assert_eq!(
        download
            .headers()
            .get("x-ao2-cp-control-plane-role")
            .unwrap()
            .to_str()
            .unwrap(),
        "read-only-observer"
    );
    let download_digest = download
        .headers()
        .get("x-ao2-cp-support-bundle-sha256")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let download_body: serde_json::Value = download.json().await.unwrap();
    assert_eq!(
        download_body["schema_version"],
        "ao2.cp-release-support-bundle.v1"
    );
    assert_eq!(
        download_body["operator_handoff"]["control_plane_role"],
        "read_only_observer"
    );
    assert_eq!(
        download_digest,
        sha256_of_canonical(&download_body).unwrap()
    );
    assert!(!serde_json::to_string(&download_body)
        .unwrap()
        .contains("secret"));

    let verifier_dir = tempdir().unwrap();
    let valid_bundle_path = verifier_dir.path().join("release-support-bundle.json");
    fs::write(
        &valid_bundle_path,
        serde_json::to_string_pretty(&download_body).unwrap(),
    )
    .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let verifier = root.join("scripts/verify_release_support_bundle.py");
    let valid_checksums_path = verifier_dir.path().join("SHA256SUMS");
    fs::write(&valid_checksums_path, &checksums_text).unwrap();
    let verifier_pass = Command::new("python3")
        .arg(&verifier)
        .arg(&valid_bundle_path)
        .output()
        .expect("run python support-bundle verifier");
    assert!(
        verifier_pass.status.success(),
        "verifier should accept downloaded support bundle\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verifier_pass.stdout),
        String::from_utf8_lossy(&verifier_pass.stderr)
    );

    let verifier_json_pass = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&valid_bundle_path)
        .output()
        .expect("run python support-bundle verifier in JSON mode");
    assert!(
        verifier_json_pass.status.success(),
        "JSON verifier should accept downloaded support bundle\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verifier_json_pass.stdout),
        String::from_utf8_lossy(&verifier_json_pass.stderr)
    );
    let verifier_json: serde_json::Value = serde_json::from_slice(&verifier_json_pass.stdout)
        .expect("JSON verifier emits machine-readable JSON");
    assert_eq!(verifier_json["status"], "passed");
    assert_eq!(verifier_json["surface_count"], 7);
    assert_eq!(verifier_json["control_plane_role"], "read_only_observer");
    assert_eq!(
        verifier_json["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert!(verifier_json["failures"].as_array().unwrap().is_empty());

    let verifier_checksum_pass = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--checksums")
        .arg(&valid_checksums_path)
        .arg(&valid_bundle_path)
        .output()
        .expect("run python support-bundle verifier with SHA256SUMS");
    assert!(
        verifier_checksum_pass.status.success(),
        "checksum verifier should accept downloaded support bundle\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verifier_checksum_pass.stdout),
        String::from_utf8_lossy(&verifier_checksum_pass.stderr)
    );
    let verifier_checksum_json: serde_json::Value =
        serde_json::from_slice(&verifier_checksum_pass.stdout)
            .expect("checksum verifier emits machine-readable JSON");
    assert_eq!(verifier_checksum_json["status"], "passed");
    assert_eq!(verifier_checksum_json["checksum_verified"], true);

    let mut tampered_ci_bundle = download_body.clone();
    tampered_ci_bundle["ci_evidence_index"]["evidence_families"] = serde_json::json!([]);
    let tampered_ci_sha = sha256_of_canonical(&tampered_ci_bundle["ci_evidence_index"]).unwrap();
    tampered_ci_bundle["portable_bundle_manifest"]["integrity"]["surface_sha256"]
        ["ci_evidence_index"] = serde_json::json!(tampered_ci_sha);
    for surface in tampered_ci_bundle["portable_bundle_manifest"]["included_surfaces"]
        .as_array_mut()
        .unwrap()
    {
        if surface["id"] == "ci_evidence_index" {
            surface["sha256"] = serde_json::json!(tampered_ci_sha.clone());
        }
    }
    let tampered_ci_bundle_path = verifier_dir
        .path()
        .join("release-support-bundle-ci-evidence-semantic-tamper.json");
    fs::write(
        &tampered_ci_bundle_path,
        serde_json::to_string_pretty(&tampered_ci_bundle).unwrap(),
    )
    .unwrap();
    let verifier_ci_semantic_fail = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&tampered_ci_bundle_path)
        .output()
        .expect("run python support-bundle verifier against CI evidence semantic tamper");
    assert!(
        !verifier_ci_semantic_fail.status.success(),
        "verifier should reject semantically invalid CI evidence index even when its manifest digest is recomputed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verifier_ci_semantic_fail.stdout),
        String::from_utf8_lossy(&verifier_ci_semantic_fail.stderr)
    );
    let verifier_ci_semantic_fail_json: serde_json::Value =
        serde_json::from_slice(&verifier_ci_semantic_fail.stdout)
            .expect("CI evidence semantic verifier failure emits machine-readable JSON");
    assert_eq!(verifier_ci_semantic_fail_json["status"], "failed");
    assert!(verifier_ci_semantic_fail_json["failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|failure| failure
            .as_str()
            .unwrap()
            .contains("ci_evidence_index.evidence_families")));

    let mismatched_checksums_path = verifier_dir.path().join("SHA256SUMS.mismatch");
    fs::write(
        &mismatched_checksums_path,
        "0000000000000000000000000000000000000000000000000000000000000000  release-support-bundle.json\n",
    )
    .unwrap();
    let verifier_checksum_fail = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--checksums")
        .arg(&mismatched_checksums_path)
        .arg(&valid_bundle_path)
        .output()
        .expect("run python support-bundle verifier with mismatched SHA256SUMS");
    assert!(!verifier_checksum_fail.status.success());
    let verifier_checksum_fail_json: serde_json::Value =
        serde_json::from_slice(&verifier_checksum_fail.stdout)
            .expect("checksum verifier failure emits machine-readable JSON");
    assert_eq!(verifier_checksum_fail_json["status"], "failed");
    assert_eq!(verifier_checksum_fail_json["checksum_verified"], false);
    assert!(verifier_checksum_fail_json["failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|failure| failure
            .as_str()
            .unwrap()
            .contains("canonical bundle digest not present")));

    let mut leaked_bundle = download_body.clone();
    leaked_bundle["operator_handoff"]["leaked_authorization"] =
        serde_json::json!("Authorization: Bearer secret");
    let leaked_bundle_path = verifier_dir
        .path()
        .join("release-support-bundle-leaked.json");
    fs::write(
        &leaked_bundle_path,
        serde_json::to_string_pretty(&leaked_bundle).unwrap(),
    )
    .unwrap();
    let verifier_fail = Command::new("python3")
        .arg(&verifier)
        .arg(&leaked_bundle_path)
        .output()
        .expect("run python support-bundle verifier with leaked marker");
    assert!(
        !verifier_fail.status.success(),
        "verifier should reject support bundle with bearer marker"
    );
    let verifier_fail_stdout = String::from_utf8_lossy(&verifier_fail.stdout);
    assert!(verifier_fail_stdout.contains("secret hygiene"));
    assert!(verifier_fail_stdout.contains("authorization_bearer_header"));

    let verifier_json_fail = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&leaked_bundle_path)
        .output()
        .expect("run python support-bundle verifier JSON mode with leaked marker");
    assert!(
        !verifier_json_fail.status.success(),
        "JSON verifier should reject support bundle with bearer marker"
    );
    let verifier_json_fail_body: serde_json::Value =
        serde_json::from_slice(&verifier_json_fail.stdout)
            .expect("JSON verifier failure emits machine-readable JSON");
    assert_eq!(verifier_json_fail_body["status"], "failed");
    assert_eq!(
        verifier_json_fail_body["control_plane_role"],
        "read_only_observer"
    );
    assert_eq!(
        verifier_json_fail_body["release_acceptance_owner"],
        "factory-v3 evaluator-closer"
    );
    assert!(verifier_json_fail_body["failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|failure| failure
            .as_str()
            .unwrap()
            .contains("authorization_bearer_header")));

    // A downgraded server that dropped the candidate_correlation surface on
    // ANY of cockpit / handoff / readiness / assembly must be caught by the
    // offline verifier — operators must not silently lose cross-evidence triage
    // visibility on the surfaces they triage from. release_assembly uses
    // candidate_correlation_detail because its top-level candidate_correlation
    // is the status string consumed by cross-OS smoke scripts.
    let mut dropped_correlation_bundle = download_body.clone();
    if let Some(cockpit) = dropped_correlation_bundle
        .get_mut("cockpit")
        .and_then(serde_json::Value::as_object_mut)
    {
        cockpit.remove("candidate_correlation");
    }
    if let Some(handoff) = dropped_correlation_bundle
        .get_mut("handoff")
        .and_then(serde_json::Value::as_object_mut)
    {
        handoff.remove("candidate_correlation");
    }
    if let Some(readiness) = dropped_correlation_bundle
        .get_mut("readiness")
        .and_then(serde_json::Value::as_object_mut)
    {
        readiness.remove("candidate_correlation");
    }
    if let Some(assembly) = dropped_correlation_bundle
        .get_mut("release_assembly")
        .and_then(serde_json::Value::as_object_mut)
    {
        assembly.remove("candidate_correlation_detail");
    }
    let dropped_correlation_bundle_path = verifier_dir
        .path()
        .join("release-support-bundle-dropped-correlation.json");
    fs::write(
        &dropped_correlation_bundle_path,
        serde_json::to_string_pretty(&dropped_correlation_bundle).unwrap(),
    )
    .unwrap();
    let verifier_dropped_fail = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&dropped_correlation_bundle_path)
        .output()
        .expect("run python support-bundle verifier against dropped-correlation bundle");
    assert!(
        !verifier_dropped_fail.status.success(),
        "verifier must reject support bundle whose cockpit/handoff/readiness/assembly dropped candidate_correlation"
    );
    let verifier_dropped_fail_body: serde_json::Value = serde_json::from_slice(
        &verifier_dropped_fail.stdout,
    )
    .expect("JSON verifier failure emits machine-readable JSON for dropped-correlation case");
    assert_eq!(verifier_dropped_fail_body["status"], "failed");
    let dropped_failures = verifier_dropped_fail_body["failures"]
        .as_array()
        .expect("verifier failures is an array");
    assert!(
        dropped_failures.iter().any(|failure| failure
            .as_str()
            .unwrap_or("")
            .contains("release_cockpit: candidate_correlation missing")),
        "verifier should flag cockpit's missing candidate_correlation"
    );
    assert!(
        dropped_failures.iter().any(|failure| failure
            .as_str()
            .unwrap_or("")
            .contains("release_candidate_handoff: candidate_correlation missing")),
        "verifier should flag handoff's missing candidate_correlation"
    );
    assert!(
        dropped_failures.iter().any(|failure| failure
            .as_str()
            .unwrap_or("")
            .contains("release_readiness: candidate_correlation missing")),
        "verifier should flag readiness's missing candidate_correlation"
    );
    assert!(
        dropped_failures.iter().any(|failure| failure
            .as_str()
            .unwrap_or("")
            .contains("release_assembly: candidate_correlation_detail missing")),
        "verifier should flag assembly's missing candidate_correlation_detail"
    );

    // Cross-OS parity at runtime: when pwsh is on PATH (CI Windows runners,
    // operator macOS / Ubuntu boxes with PowerShell installed), the PowerShell
    // verifier MUST reject the same dropped-correlation bundle with one
    // failure entry per dropped surface — same shape as the python verifier
    // emitted above. On boxes without pwsh (e.g. macOS dev runs without
    // PowerShell installed), the runtime check is skipped; the source-string
    // parity test verify_release_support_bundle_python_and_powershell_agree_on_verification_contract
    // still ensures the failure-message constants are identical.
    if common::pwsh_available_or_skip("ps1 runtime parity check (dropped-correlation)") {
        let ps_verifier = root.join("scripts/Verify-ReleaseSupportBundle.ps1");
        let ps_dropped = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-File")
            .arg(&ps_verifier)
            .arg("-Json")
            .arg("-Path")
            .arg(&dropped_correlation_bundle_path)
            .output()
            .expect("run powershell support-bundle verifier against dropped-correlation bundle");
        assert!(
            !ps_dropped.status.success(),
            "ps1 verifier must reject support bundle whose cockpit/handoff/readiness/assembly dropped candidate_correlation"
        );
        let ps_body: serde_json::Value = serde_json::from_slice(&ps_dropped.stdout).expect(
            "ps1 JSON verifier failure emits machine-readable JSON for dropped-correlation case",
        );
        assert_eq!(ps_body["status"], "failed");
        let ps_failures = ps_body["failures"]
            .as_array()
            .expect("ps1 verifier failures is an array");
        // ps1 uses "{surface_id} {field}" (space) where python uses
        // "{surface_id}: {field}" (colon), so substring on the surface +
        // field substring matches both.
        for (surface_id, field) in [
            ("release_cockpit", "candidate_correlation missing"),
            ("release_candidate_handoff", "candidate_correlation missing"),
            ("release_readiness", "candidate_correlation missing"),
            ("release_assembly", "candidate_correlation_detail missing"),
        ] {
            assert!(
                ps_failures.iter().any(|failure| {
                    let text = failure.as_str().unwrap_or("");
                    text.contains(surface_id) && text.contains(field)
                }),
                "ps1 verifier should flag {surface_id}'s missing {field}"
            );
        }
    }

    let invalid_keep_latest = client
        .get(format!(
            "{base}/api/v1/release/support-bundle.json?keep_latest=0"
        ))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_keep_latest.status(), 400);
}

#[tokio::test]
async fn all_release_publication_shaped_surfaces_agree_on_candidate_correlation() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let checklist = client
        .post(format!("{base}/api/v1/phase1/promotion/checklist"))
        .header("authorization", "Bearer secret")
        .body(phase1_promotion_checklist_fixture())
        .send()
        .await
        .unwrap();
    assert_eq!(checklist.status(), 200);
    let checklist_receipt: serde_json::Value = checklist.json().await.unwrap();
    let checklist_sha = checklist_receipt["sha256"].as_str().unwrap();

    let signed =
        signed_phase1_promotion_decision_fixture(phase1_promotion_decision_fixture(checklist_sha));
    let decision = client
        .post(format!("{base}/api/v1/phase1/promotion/decision/signed"))
        .header("authorization", "Bearer secret")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(decision.status(), 200);

    let surfaces = [
        ("release_cockpit", "/api/v1/release/cockpit.json"),
        (
            "release_publication_dashboard",
            "/api/v1/release/publication/dashboard.json",
        ),
        ("release_candidate_handoff", "/api/v1/release/handoff.json"),
        (
            "phase1_promotion_dashboard",
            "/api/v1/phase1/promotion/dashboard.json",
        ),
        (
            "phase1_operator_panel",
            "/api/v1/phase1/promotion/operator-panel.json",
        ),
    ];

    let mut observed: Vec<(&str, serde_json::Value)> = Vec::new();
    for (name, path) in surfaces.iter() {
        let response = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "surface {name} ({path}) must respond 200"
        );
        let body: serde_json::Value = response.json().await.unwrap();
        let correlation = body
            .get("candidate_correlation")
            .cloned()
            .unwrap_or_else(|| panic!("surface {name} ({path}) must embed candidate_correlation"));
        assert!(
            correlation.is_object(),
            "surface {name} candidate_correlation must be an object"
        );
        let status = correlation
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert!(
            status == "matched" || status == "mismatched",
            "surface {name} candidate_correlation.status must be matched|mismatched, was {status:?}"
        );
        assert!(
            correlation
                .get("blockers")
                .map(serde_json::Value::is_array)
                .unwrap_or(false),
            "surface {name} candidate_correlation.blockers must be an array"
        );
        for required_field in [
            "release_version",
            "release_tag",
            "three_os_version",
            "release_evaluator_version",
            "codex_acceptance_version",
            "claude_acceptance_version",
        ] {
            assert!(
                correlation
                    .get(required_field)
                    .map(serde_json::Value::is_string)
                    .unwrap_or(false),
                "surface {name} candidate_correlation.{required_field} must be a string"
            );
        }
        observed.push((name, correlation));
    }

    // Every surface must agree on the same correlation verdict because they
    // all read from the same governed evidence under a fixed scenario.
    let (canonical_name, canonical) = &observed[0];
    let canonical_status = canonical["status"].as_str().unwrap();
    let canonical_blockers = canonical["blockers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let canonical_release_version = canonical["release_version"].as_str().unwrap();
    let canonical_three_os_version = canonical["three_os_version"].as_str().unwrap();
    let canonical_evaluator_version = canonical["release_evaluator_version"].as_str().unwrap();
    let canonical_codex_version = canonical["codex_acceptance_version"].as_str().unwrap();
    let canonical_claude_version = canonical["claude_acceptance_version"].as_str().unwrap();

    for (name, correlation) in observed.iter().skip(1) {
        assert_eq!(
            correlation["status"].as_str().unwrap(),
            canonical_status,
            "surface {name} candidate_correlation.status disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["blockers"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
            canonical_blockers,
            "surface {name} candidate_correlation.blockers disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["release_version"].as_str().unwrap(),
            canonical_release_version,
            "surface {name} candidate_correlation.release_version disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["three_os_version"].as_str().unwrap(),
            canonical_three_os_version,
            "surface {name} candidate_correlation.three_os_version disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["release_evaluator_version"].as_str().unwrap(),
            canonical_evaluator_version,
            "surface {name} candidate_correlation.release_evaluator_version disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["codex_acceptance_version"].as_str().unwrap(),
            canonical_codex_version,
            "surface {name} candidate_correlation.codex_acceptance_version disagrees with {canonical_name}"
        );
        assert_eq!(
            correlation["claude_acceptance_version"].as_str().unwrap(),
            canonical_claude_version,
            "surface {name} candidate_correlation.claude_acceptance_version disagrees with {canonical_name}"
        );
    }

    // Sanity: the matched scenario from these fixtures should resolve to
    // "matched" — if a future refactor accidentally swaps status semantics
    // we want this test to fail loudly.
    assert_eq!(
        canonical_status, "matched",
        "fixed-scenario candidate_correlation should be matched; got {canonical_status}"
    );
    assert!(
        canonical_blockers.is_empty(),
        "matched candidate_correlation should have no blockers, got {canonical_blockers:?}"
    );

    // The cockpit/handoff/readiness surfaces all surface the three-OS smoke's
    // candidate_correlation_parity at top level — they must agree (Lane Q).
    let mut parity_observed: Vec<(&str, String)> = Vec::new();
    for (name, path) in [
        ("release_cockpit", "/api/v1/release/cockpit.json"),
        ("release_candidate_handoff", "/api/v1/release/handoff.json"),
        ("release_readiness", "/api/v1/release/readiness.json"),
    ] {
        let body: serde_json::Value = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let parity = body["candidate_correlation_parity"]
            .as_str()
            .unwrap_or_else(|| panic!("surface {name} missing candidate_correlation_parity"))
            .to_string();
        parity_observed.push((name, parity));
    }
    let (canonical_parity_name, canonical_parity) = &parity_observed[0];
    assert_eq!(
        canonical_parity, "matched",
        "fixed-scenario candidate_correlation_parity should be matched on {canonical_parity_name}; got {canonical_parity}"
    );
    for (name, parity) in parity_observed.iter().skip(1) {
        assert_eq!(
            parity, canonical_parity,
            "surface {name} candidate_correlation_parity disagrees with {canonical_parity_name}"
        );
    }
}

// Lane R: the negative-path counterpart to
// `all_release_publication_shaped_surfaces_agree_on_candidate_correlation`'s
// parity subsection. When no three-OS smoke artifact has ever been
// ingested, cockpit/handoff/readiness MUST surface
// `candidate_correlation_parity == "missing"` (not "matched") so a
// downgraded server cannot silently fool operators into believing the
// three OSes agreed on the latest live smoke.
#[tokio::test]
async fn cockpit_handoff_readiness_default_candidate_correlation_parity_to_missing_when_no_three_os_smoke(
) {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    // Intentionally do NOT POST /api/v1/phase1/promotion/three-os-smoke.
    // The cockpit/handoff/readiness JSON must still produce a defined
    // `candidate_correlation_parity` value — and it must be "missing", not
    // "matched", because no smoke evidence was observed.
    for (name, path) in [
        ("release_cockpit", "/api/v1/release/cockpit.json"),
        ("release_candidate_handoff", "/api/v1/release/handoff.json"),
        ("release_readiness", "/api/v1/release/readiness.json"),
    ] {
        let body: serde_json::Value = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let parity = body["candidate_correlation_parity"]
            .as_str()
            .unwrap_or_else(|| panic!("surface {name} missing candidate_correlation_parity"));
        assert_eq!(
            parity, "missing",
            "surface {name} candidate_correlation_parity must default to \"missing\" \
             when no three-OS smoke artifact has been ingested; got {parity:?}"
        );
    }

    // The cockpit HTML must render the warn-styled parity row so the
    // operator sees the downgrade at-a-glance (no silent matched).
    let html = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Three-OS smoke parity"));
    assert!(html.contains("warn\">missing"));

    // Lane S: the candidate_correlation_parity gate is registered on
    // readiness. Missing parity must surface as a blocked gate AND in
    // the blockers array so the readiness summary fails loudly.
    let readiness: serde_json::Value = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gates = readiness["gate_results"]
        .as_array()
        .expect("gate_results array");
    let parity_gate = gates
        .iter()
        .find(|gate| gate["id"] == "candidate_correlation_parity")
        .expect("candidate_correlation_parity gate must be registered on readiness");
    assert_eq!(parity_gate["status"], "blocked");
    assert_eq!(parity_gate["observed"], "missing");
    assert_eq!(parity_gate["expected"], "matched");
    let blockers = readiness["blockers"]
        .as_array()
        .expect("blockers array")
        .iter()
        .filter_map(|b| b.as_str())
        .collect::<Vec<_>>();
    assert!(
        blockers
            .iter()
            .any(|b| b.contains("candidate_correlation_parity")),
        "blockers must mention candidate_correlation_parity, got {blockers:?}"
    );
}

// Lane T: when canonical version evidence aligns across release publication
// / three-OS smoke / evaluator decision / codex acceptance / claude
// acceptance (server-computed candidate_correlation resolves to "matched"),
// but the three-OS aggregator reports candidate_correlation_parity = "drift"
// (per-OS smokes disagreed on candidate_correlation), the parity gate MUST
// fire independently of the candidate_correlation gate. Proves that
// candidate_correlation_parity is an independent downgrade vector — a
// matched correlation alone is not sufficient evidence that the three OSes
// observed the same release.
#[tokio::test]
async fn candidate_correlation_parity_gate_fires_independently_when_three_os_smoke_reports_drift() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for (path, body) in [
        ("/api/v1/release/publication", release_publication_fixture()),
        ("/api/v1/provider/registry", provider_registry_fixture()),
        ("/api/v1/provider/readiness", provider_readiness_fixture()),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CODEX_ACCEPTANCE_FIXTURE, "codex", "0.4.79"),
        ),
        (
            "/api/v1/acceptance",
            live_acceptance_fixture(CLAUDE_ACCEPTANCE_FIXTURE, "claude", "0.4.79"),
        ),
        (
            "/api/v1/phase1/promotion/three-os-smoke",
            drift_three_os_release_smoke_fixture(),
        ),
        (
            "/api/v1/release/evaluator-decision",
            release_evaluator_decision_fixture(),
        ),
    ] {
        let post = client
            .post(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);
    }

    let readiness: serde_json::Value = client
        .get(format!("{base}/api/v1/release/readiness.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let gates = readiness["gate_results"]
        .as_array()
        .expect("gate_results array");

    // candidate_correlation gate must PASS — version evidence aligns
    // across all five sources, so the server-computed correlation
    // resolves to "matched". This is the key property: the parity gate
    // is independent of the correlation gate.
    let correlation_gate = gates
        .iter()
        .find(|gate| gate["id"] == "candidate_correlation")
        .expect("candidate_correlation gate must be registered on readiness");
    assert_eq!(
        correlation_gate["status"], "passed",
        "candidate_correlation must resolve to passed when all version \
         evidence aligns; got {correlation_gate:?}"
    );
    assert_eq!(correlation_gate["observed"], "matched");

    // candidate_correlation_parity gate must BLOCK — the three-OS
    // aggregator reported drift even though the canonical versions agree.
    let parity_gate = gates
        .iter()
        .find(|gate| gate["id"] == "candidate_correlation_parity")
        .expect("candidate_correlation_parity gate must be registered on readiness");
    assert_eq!(
        parity_gate["status"], "blocked",
        "candidate_correlation_parity must block on drift even when \
         candidate_correlation itself passes; got {parity_gate:?}"
    );
    assert_eq!(parity_gate["observed"], "drift");
    assert_eq!(parity_gate["expected"], "matched");

    // Readiness top-level status must reflect the parity downgrade.
    let readiness_status = readiness["status"]
        .as_str()
        .expect("readiness status string");
    assert_ne!(
        readiness_status, "ready",
        "readiness must not be \"ready\" when parity gate is blocked; \
         got {readiness_status:?}"
    );

    // The blockers array must mention candidate_correlation_parity so an
    // operator scanning the readiness summary sees the parity downgrade
    // explicitly — not just buried in the gate_results array.
    let blockers = readiness["blockers"]
        .as_array()
        .expect("blockers array")
        .iter()
        .filter_map(|b| b.as_str())
        .collect::<Vec<_>>();
    assert!(
        blockers
            .iter()
            .any(|b| b.contains("candidate_correlation_parity")),
        "blockers must mention candidate_correlation_parity on drift, \
         got {blockers:?}"
    );

    // The cockpit HTML must render the warn-styled parity row so the
    // operator sees drift at-a-glance.
    let html = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Three-OS smoke parity"));
    assert!(html.contains("warn\">drift"));

    // Cockpit/handoff/readiness JSON all surface parity == "drift" at top
    // level — proves the parity verdict propagates through all three
    // release-publication-shaped surfaces.
    for (name, path) in [
        ("release_cockpit", "/api/v1/release/cockpit.json"),
        ("release_candidate_handoff", "/api/v1/release/handoff.json"),
        ("release_readiness", "/api/v1/release/readiness.json"),
    ] {
        let body: serde_json::Value = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let parity = body["candidate_correlation_parity"]
            .as_str()
            .unwrap_or_else(|| panic!("surface {name} missing candidate_correlation_parity"));
        assert_eq!(
            parity, "drift",
            "surface {name} must surface candidate_correlation_parity == \
             \"drift\" when the aggregator reported drift; got {parity:?}"
        );
    }
}

// Lane MM: the cockpit HTML must surface the Lane LL rejected-smoke
// audit count. Before any rejection, the section renders with a zero
// count colored "ok". After a tampered three-OS smoke is 422'd by the
// ingestion validator, the same cockpit HTML must show count >= 1
// (colored "warn") and the latest rejection reason. This is the only
// operator-facing surface that exposes the forensic audit log without
// requiring shell access to the storage root.
#[tokio::test]
async fn cockpit_html_surfaces_rejected_smoke_audit_count_lane_mm() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Pre-rejection: cockpit HTML must contain the section with a
    // zero count rendered as the ok-colored cell. No "Latest
    // timestamp" / "Latest rejection reason" rows render at count=0.
    let html_before = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html_before.contains("Rejected Smoke Ingestions"),
        "cockpit HTML must always render the Rejected Smoke Ingestions section so operators see the zero count as positive evidence the audit log is reachable"
    );
    assert!(
        html_before.contains("rejected-three-os-smoke.jsonl"),
        "section must name the audit log path so operators can locate it on disk"
    );
    assert!(
        html_before.contains("<dd class=\"ok\">0</dd>"),
        "pre-rejection cockpit must render count=0 as ok-styled: {html_before}"
    );
    assert!(
        !html_before.contains("Latest timestamp"),
        "no latest-record rows must render when count is zero"
    );
    // Lane VV: cockpit must always surface the audit-log rotation
    // budget — pre-rejection that's 0 / 1048576 bytes (1 MiB cap).
    // Without these rows operators cannot answer "is the Lane UU
    // rotation imminent?" without shelling into the storage root.
    assert!(
        html_before.contains("Audit log size"),
        "cockpit HTML must render the Lane VV audit-log size row pre-rejection so the rotation budget is visible"
    );
    assert!(
        html_before.contains("Lane UU rotation cap"),
        "cockpit HTML must reference the Lane UU rotation cap so operators know where the threshold comes from"
    );
    assert!(
        html_before.contains("<code>0</code> / <code>1048576</code> bytes"),
        "cockpit HTML must render the Lane VV size/cap pair as 0/1048576 bytes pre-rejection: {html_before}"
    );
    // Lane EEE: cockpit must surface the runbook 9.9 on-call triage
    // pointer adjacent to the audit-log row. The load-bearing literals
    // are: the section-9.9 pointer (the runbook target) and the
    // "tampering event, not audit-log corruption" framing (the
    // load-bearing triage takeaway from Lane DDD). An operator paged on
    // a Lane XX-doc rule-2 burst alert must land on this hint without
    // already knowing the runbook section number.
    assert!(
        html_before.contains("On-call triage"),
        "cockpit HTML must label the Lane EEE on-call triage row: {html_before}"
    );
    assert!(
        html_before.contains("runbook section 9.9"),
        "cockpit HTML must point at runbook section 9.9 for tampering-burst triage: {html_before}"
    );
    assert!(
        html_before.contains("tampering event, not audit-log corruption"),
        "cockpit HTML must surface the load-bearing on-call framing: {html_before}"
    );

    // POST a tampered three-OS smoke: source_dirty=true + status=passed
    // + all targets passed. Lane KK's tightened recomputation flips
    // this to recomputed=failed → 422, which trips Lane LL's append.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", "Bearer secret")
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        422,
        "tampered three-OS smoke must be rejected so Lane LL appends a record"
    );

    // Post-rejection: count must read 1 with warn styling, and the
    // latest rejection reason must surface the source_dirty diagnostic.
    let html_after = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html_after.contains("<dd class=\"warn\">1</dd>"),
        "post-rejection cockpit must render count=1 as warn-styled: {html_after}"
    );
    assert!(
        html_after.contains("Latest timestamp"),
        "latest-record rows must render once at least one rejection exists"
    );
    assert!(
        html_after.contains("Latest rejection reason"),
        "latest-record rows must surface the rejection reason"
    );
    assert!(
        html_after.contains("source_dirty=true"),
        "latest rejection reason must surface the Lane KK source_dirty diagnostic: {html_after}"
    );
    // Lane VV: post-rejection the audit-log size must be > 0 because
    // Lane LL just appended a record. The cap stays at 1048576. The
    // row must still render with "ok" class because a single record
    // is well under 75% of the 1 MiB cap.
    assert!(
        html_after.contains("Audit log size"),
        "cockpit HTML must continue rendering the Lane VV audit-log size row post-rejection"
    );
    assert!(
        !html_after.contains("<code>0</code> / <code>1048576</code> bytes"),
        "post-rejection size must no longer read 0 bytes — Lane LL just appended: {html_after}"
    );
    assert!(
        html_after.contains("/ <code>1048576</code> bytes"),
        "post-rejection cap must still read 1048576 bytes: {html_after}"
    );

    // The raw rejected body must NOT leak into the cockpit HTML — only
    // the rejection reason (a server-generated diagnostic string) is
    // safe to render. The body's source_commit (40-char SHA) must
    // appear nowhere on the cockpit; if a future change accidentally
    // wired the full payload through, this assertion catches it.
    assert!(
        !html_after.contains("52bbff188626315ca832c328570bc638260e5874"),
        "cockpit HTML must not leak the rejected body's full source_commit"
    );

    // A second rejection must increment the count to 2 — the renderer
    // counts non-empty lines in the audit log, not just "any > 0".
    let tampered_again = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "source_dirty": false,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "failed"}
        }
    });
    let post_again = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", "Bearer secret")
        .body(tampered_again.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(post_again.status(), 422);
    let html_two = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html_two.contains("<dd class=\"warn\">2</dd>"),
        "cockpit count must reflect every append; got: {html_two}"
    );
}

// Lane QQ: the rejected-smoke audit section that Lane MM added to the
// cockpit HTML must also render on the handoff + readiness HTML, so
// operators landing on /api/v1/release/handoff or /readiness see
// tampering-attempt volume without re-navigating to the cockpit. Same
// "always render" semantics: zero count is positive evidence the
// audit trail is reachable.
#[tokio::test]
async fn handoff_and_readiness_html_mirror_rejected_smoke_audit_section_lane_qq() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Pre-rejection: both surfaces render the section with count=0.
    for path in ["/api/v1/release/handoff", "/api/v1/release/readiness"] {
        let html = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("Rejected Smoke Ingestions"),
            "{path} HTML must render the Rejected Smoke Ingestions section pre-rejection"
        );
        assert!(
            html.contains("<dd class=\"ok\">0</dd>"),
            "{path} HTML must render count=0 as ok-styled pre-rejection: {html}"
        );
        assert!(
            !html.contains("Latest timestamp"),
            "{path} HTML must NOT render latest-record rows when count=0"
        );
        // Lane VV: both surfaces must mirror the audit-log rotation
        // budget that Lane MM now renders on the cockpit, so an
        // operator landing on handoff/readiness sees the same
        // rotation context without re-navigating.
        assert!(
            html.contains("Audit log size"),
            "{path} HTML must render the Lane VV audit-log size row pre-rejection: {html}"
        );
        assert!(
            html.contains("Lane UU rotation cap"),
            "{path} HTML must reference the Lane UU rotation cap"
        );
        assert!(
            html.contains("<code>0</code> / <code>1048576</code> bytes"),
            "{path} HTML must render the Lane VV size/cap pair as 0/1048576 bytes pre-rejection: {html}"
        );
        // Lane EEE: both handoff + readiness HTML must mirror the
        // cockpit's on-call triage pointer. Operators land on whichever
        // surface their alert linked them to; the runbook 9.9 hint
        // must be reachable from any of the three.
        assert!(
            html.contains("On-call triage"),
            "{path} HTML must render the Lane EEE on-call triage row: {html}"
        );
        assert!(
            html.contains("runbook section 9.9"),
            "{path} HTML must point at runbook section 9.9: {html}"
        );
        assert!(
            html.contains("tampering event, not audit-log corruption"),
            "{path} HTML must surface the Lane DDD on-call framing: {html}"
        );
    }

    // Force a Lane LL rejection via Lane KK's source_dirty trigger.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", "Bearer secret")
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);

    // Post-rejection: both surfaces flip to count=1 with warn styling
    // and surface the same Lane KK source_dirty diagnostic.
    for path in ["/api/v1/release/handoff", "/api/v1/release/readiness"] {
        let html = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("<dd class=\"warn\">1</dd>"),
            "{path} HTML must render count=1 as warn-styled post-rejection: {html}"
        );
        assert!(
            html.contains("Latest rejection reason"),
            "{path} HTML must render latest-record rows post-rejection"
        );
        assert!(
            html.contains("source_dirty=true"),
            "{path} HTML must surface the Lane KK source_dirty diagnostic"
        );
        // The raw rejected body's full source_commit must NOT leak.
        assert!(
            !html.contains("52bbff188626315ca832c328570bc638260e5874"),
            "{path} HTML must not leak the rejected body's full source_commit"
        );
        // Lane VV: post-rejection the size row must still render and
        // the cap must still read 1048576 bytes — the size itself is
        // non-zero now that Lane LL appended.
        assert!(
            html.contains("Audit log size"),
            "{path} HTML must continue rendering the Lane VV size row post-rejection"
        );
        assert!(
            !html.contains("<code>0</code> / <code>1048576</code> bytes"),
            "{path} HTML must reflect the just-appended audit log size post-rejection: {html}"
        );
        assert!(
            html.contains("/ <code>1048576</code> bytes"),
            "{path} HTML must still display the 1048576-byte cap post-rejection: {html}"
        );
    }
}

// Lane VV (warn threshold): the audit-log size row must flip from
// "ok" to "warn" once the on-disk file crosses 75% of the Lane UU
// rotation cap. Operators rely on this transition to know "rotation
// imminent" without watching the file system. Below the threshold
// (and at the empty default) the row reads "ok"; at or above 75% the
// row reads "warn". The threshold is policy, not protocol — if a
// future change moves it, this test surfaces that as a deliberate
// signal rather than a silent regression.
#[tokio::test]
async fn cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv() {
    let (base, dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // Pre-fill the audit log with an opaque blob sized at ~80% of
    // the 1 MiB cap (838860 bytes > 786432 = 75% of 1048576). The
    // contents are NOT a valid record schema — that's intentional:
    // the rotation-budget surface reads file size only, never
    // parses records. If a future change starts parsing the file in
    // the summary path, this test breaks loudly. We avoid spamming
    // a million synthetic records (the Lane UU test already does
    // that for the rotation behavior).
    let target_bytes: usize = 838_860;
    let blob = vec![b'x'; target_bytes];
    fs::write(&audit_path, &blob).expect("write near-cap audit log");

    let html = client
        .get(format!("{base}/api/v1/release/cockpit"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // The size row must render with the warn class once size >= 75%
    // of cap. The exact byte literal is asserted so a future
    // off-by-one or off-by-percent regression surfaces here.
    let warn_size_marker = format!(
        "<dt>Audit log size</dt><dd class=\"warn\"><code>{target_bytes}</code> / <code>1048576</code> bytes"
    );
    assert!(
        html.contains(&warn_size_marker),
        "cockpit HTML must flip the audit-log size row to warn-styled at >=75% of the 1 MiB cap; expected marker {warn_size_marker:?} not found in HTML"
    );
}

// Lane XX: the audit-log rotation budget that Lane VV surfaces on
// the cockpit/handoff/readiness HTML must also appear on the
// matching JSON endpoints. External monitors (a Prometheus
// exporter, an oncall dashboard) should be able to alert on
// `audit_log_size_bytes / audit_log_cap_bytes > 0.75` without
// parsing HTML — and they should see the same numbers regardless
// of which of the three JSON surfaces they happen to poll.
#[tokio::test]
async fn cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    // Pre-rejection: all three JSON surfaces must expose
    // rejected_smoke_audit with the exact 5-field shape the HTML
    // renderer consumes. A monitor must be able to read these
    // fields without first triggering a rejection, so the audit
    // section is "always rendered" parity to the HTML.
    for path in [
        "/api/v1/release/cockpit.json",
        "/api/v1/release/handoff.json",
        "/api/v1/release/readiness.json",
    ] {
        let body: serde_json::Value = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let audit = body
            .get("rejected_smoke_audit")
            .unwrap_or_else(|| panic!("{path} JSON must include rejected_smoke_audit"));
        assert_eq!(
            audit.get("count").and_then(serde_json::Value::as_u64),
            Some(0),
            "{path} pre-rejection rejected_smoke_audit.count must be 0; got {audit:?}"
        );
        assert_eq!(
            audit
                .get("audit_log_size_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "{path} pre-rejection audit_log_size_bytes must be 0; got {audit:?}"
        );
        assert_eq!(
            audit
                .get("audit_log_cap_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(1024 * 1024),
            "{path} pre-rejection audit_log_cap_bytes must be 1 MiB (1048576); got {audit:?}"
        );
        // latest_timestamp_utc + latest_rejection_reason are present
        // (as JSON null) so a monitor sees a stable shape — never a
        // missing key.
        assert!(
            audit.get("latest_timestamp_utc").is_some(),
            "{path} pre-rejection rejected_smoke_audit must include latest_timestamp_utc (as null); got {audit:?}"
        );
        assert!(
            audit.get("latest_rejection_reason").is_some(),
            "{path} pre-rejection rejected_smoke_audit must include latest_rejection_reason (as null); got {audit:?}"
        );
    }

    // Trigger a Lane LL rejection via the Lane KK source_dirty path.
    let tampered = serde_json::json!({
        "schema": "ao2-control-plane.three-os-release-smoke.v1",
        "version": "0.1.0",
        "release_candidate_version": "0.4.79",
        "status": "passed",
        "source_commit": "52bbff188626315ca832c328570bc638260e5874",
        "source_dirty": true,
        "targets": {
            "macos": {"status": "passed"},
            "ubuntu": {"status": "passed"},
            "windows": {"status": "passed"}
        }
    });
    let post = client
        .post(format!("{base}/api/v1/phase1/promotion/three-os-smoke"))
        .header("authorization", "Bearer secret")
        .body(tampered.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 422);

    // Post-rejection: every JSON surface must mirror the count + the
    // non-zero size + the unchanged cap.
    for path in [
        "/api/v1/release/cockpit.json",
        "/api/v1/release/handoff.json",
        "/api/v1/release/readiness.json",
    ] {
        let body: serde_json::Value = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer secret")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let audit = body
            .get("rejected_smoke_audit")
            .unwrap_or_else(|| panic!("{path} JSON must include rejected_smoke_audit"));
        assert_eq!(
            audit.get("count").and_then(serde_json::Value::as_u64),
            Some(1),
            "{path} post-rejection rejected_smoke_audit.count must be 1; got {audit:?}"
        );
        let size = audit
            .get("audit_log_size_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{path} must include audit_log_size_bytes"));
        assert!(
            size > 0,
            "{path} post-rejection audit_log_size_bytes must be > 0 (Lane LL just appended a record); got {size}"
        );
        assert!(
            size < 1024 * 1024,
            "{path} post-rejection audit_log_size_bytes must still be under the 1 MiB cap (a single record is small); got {size}"
        );
        assert_eq!(
            audit
                .get("audit_log_cap_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(1024 * 1024),
            "{path} post-rejection audit_log_cap_bytes must remain 1 MiB"
        );
        // Diagnostic surface: the latest_rejection_reason should
        // surface the Lane KK source_dirty diagnostic so a monitor
        // can correlate the budget-tick to a known cause.
        let reason = audit
            .get("latest_rejection_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert!(
            reason.contains("source_dirty=true"),
            "{path} latest_rejection_reason must carry the Lane KK source_dirty diagnostic; got {reason:?}"
        );
        // The raw rejected body's full source_commit must NOT leak
        // into the JSON surface either.
        let serialized = serde_json::to_string(audit).unwrap();
        assert!(
            !serialized.contains("52bbff188626315ca832c328570bc638260e5874"),
            "{path} rejected_smoke_audit must not leak the rejected body's full source_commit; got {serialized}"
        );
    }
}

// Lane WW: under sustained tampering load, the cockpit's
// rejected_smoke_audit.count must stay consistent with the on-disk
// JSONL file's line count. The Lane LL appender uses POSIX O_APPEND
// (atomic for small lines on macOS/Linux), but a regression that
// dropped the append flag or introduced a read-modify-write race
// could silently lose records. This test exercises the concurrent
// path that production sees during a scanning attack: N concurrent
// 422 ingestion attempts arriving at the same instant.
#[tokio::test]
async fn cockpit_count_matches_audit_log_under_concurrent_rejection_load_lane_ww() {
    let (base, dir) = spawn_server().await;
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // Choose N at a level high enough to surface common races but
    // low enough to keep the test fast (~1 second on a developer
    // laptop). 50 concurrent in-flight requests is well above what
    // a single sequential client would produce; if there's a race
    // in the append path it surfaces here.
    const N: usize = 50;

    // Each request is identical except for an opaque per-request
    // marker — but since the appender records body_sha256, distinct
    // bodies would create distinct records. We want to test the
    // worst case: identical bodies arriving simultaneously. The
    // appender does NOT dedupe (the audit log is forensic — a burst
    // of identical attempts is itself a forensic signal), so all N
    // must land. To verify "all N landed without loss" we count
    // file lines + cockpit count.
    //
    // Lane FFF: share one reqwest::Client across all N tasks (same
    // pattern Lane BBB uses for higher-N rotation tests) and assert
    // a wall-clock budget. The shared client bounds FD usage; the
    // wall-clock budget surfaces lock-starvation regressions in the
    // append path long before the count/size invariants would.
    let client = std::sync::Arc::new(reqwest::Client::new());
    let start = std::time::Instant::now();
    let wall_clock_budget = std::time::Duration::from_secs(10);
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let base_clone = base.clone();
        let client_clone = client.clone();
        handles.push(tokio::spawn(async move {
            let tampered = serde_json::json!({
                "schema": "ao2-control-plane.three-os-release-smoke.v1",
                "version": "0.1.0",
                "release_candidate_version": "0.4.79",
                "status": "passed",
                "source_commit": "52bbff188626315ca832c328570bc638260e5874",
                "source_dirty": true,
                "targets": {
                    "macos": {"status": "passed"},
                    "ubuntu": {"status": "passed"},
                    "windows": {"status": "passed"}
                }
            });
            let resp = client_clone
                .post(format!(
                    "{base_clone}/api/v1/phase1/promotion/three-os-smoke"
                ))
                .header("authorization", "Bearer secret")
                .body(tampered.to_string())
                .send()
                .await
                .unwrap();
            resp.status().as_u16()
        }));
    }

    // Collect every response — every one must be 422 (Lane KK
    // source_dirty=true paired with status=passed triggers the
    // rejection). Await each spawned handle in turn rather than
    // pulling in a futures::join_all dependency just for this test.
    let mut statuses: Vec<u16> = Vec::with_capacity(N);
    for handle in handles {
        statuses.push(handle.await.unwrap());
    }
    // Lane FFF: assert wall-clock budget BEFORE inspecting the
    // append-side invariants so a lock-starvation regression
    // surfaces with the right diagnostic rather than getting masked
    // by an inferred-from-final-state assertion downstream.
    let elapsed = start.elapsed();
    assert!(
        elapsed <= wall_clock_budget,
        "Lane FFF: {N}-burst must finish within {wall_clock_budget:?}; took {elapsed:?} — likely lock-starvation regression in append_rejected_smoke_audit"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 422).count(),
        N,
        "every concurrent request must 422; statuses observed: {statuses:?}"
    );

    // (1) The on-disk file must contain exactly N records. Lost
    // records would surface as line_count < N — a concurrent
    // appender race.
    let contents = std::fs::read_to_string(&audit_path).expect("audit log readable after burst");
    let line_count = contents.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        line_count, N,
        "audit log must contain exactly {N} records after a burst of {N} concurrent rejections; got {line_count}"
    );

    // (2) Every line must be valid JSON. Partial lines (mid-line
    // races) would surface as parse errors.
    for (idx, line) in contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
    {
        let _: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!(
                "audit log line {idx} must parse as JSON after concurrent burst: {e}; line={line}"
            )
        });
    }

    // (3) The cockpit JSON's count must agree with the file's line
    // count. A divergence here means the rejected_smoke_audit_summary
    // reader is seeing a different view than the appender wrote.
    // Reuse the shared Arc<Client> introduced by Lane FFF rather than
    // opening a fresh connection pool just for this fetch.
    let body: serde_json::Value = client
        .get(format!("{base}/api/v1/release/cockpit.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cockpit_count = body
        .get("rejected_smoke_audit")
        .and_then(|audit| audit.get("count"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert_eq!(
        cockpit_count as usize, N,
        "cockpit JSON count must match on-disk file line count after burst; cockpit={cockpit_count}, file={line_count}"
    );

    // (4) The audit_log_size_bytes JSON field must equal the actual
    // file size. A divergence means the summary read a stale
    // snapshot.
    let cockpit_size = body
        .get("rejected_smoke_audit")
        .and_then(|audit| audit.get("audit_log_size_bytes"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let actual_size = std::fs::metadata(&audit_path).unwrap().len();
    assert_eq!(
        cockpit_size, actual_size,
        "cockpit audit_log_size_bytes must match actual file size; cockpit={cockpit_size}, actual={actual_size}"
    );

    // (5) The file size must remain under the 1 MiB cap — 50
    // single-record rejections are far below the cap, so rotation
    // should not trigger. If a future change accidentally widens
    // a single record so the burst pushes past 1 MiB, this fails
    // and surfaces the regression.
    assert!(
        actual_size <= 1024 * 1024,
        "audit log must stay <= 1 MiB cap under {N}-rejection burst; got {actual_size}"
    );
}

// Lane WW-rotation: when concurrent rejections cross the Lane UU
// 1 MiB cap, the rotation path runs. The Lane UU rotation path is
// read-projection-write (read the file, compute the rebuilt content
// keeping newest records, write the rebuilt content with
// tokio::fs::write). Without a serializer, two concurrent rotations
// both read a stale view and the second writer overwrites the
// first — silently losing records and briefly pushing the file
// above the cap.
//
// The Lane WW-rotation fix (REJECTED_SMOKE_AUDIT_WRITER_LOCK in
// phase1_promotion.rs) serializes the read-projection-write region
// behind a process-global tokio::sync::Mutex<()>. The test
// pre-fills the audit log to just under the cap so every one of
// the N concurrent rejections triggers rotation, then asserts:
//
//  (a) The file stays at or under the cap after the burst settles.
//  (b) Every surviving record is valid JSON (no corruption from
//      interleaved truncate-writes).
//  (c) The cockpit count agrees with the on-disk file's record
//      count (no reader/writer divergence).
//  (d) At least one record survives — Lane UU guarantees the
//      newest record is retained, even under contention.
//
// Lane BBB extends the same contract to N=200 and N=500 with a
// wall-clock budget assertion. The mutex is held only across local
// I/O (no network, no DB), so under fair scheduling tail latency
// scales linearly with N. A budget regression at higher N would
// surface lock-starvation issues or kernel-level contention that
// the N=50 test would not catch.
async fn audit_log_rotation_burst_invariants(n: usize, wall_clock_budget: std::time::Duration) {
    let (base, dir) = spawn_server().await;
    let audit_path = dir.path().join("rejected-three-os-smoke.jsonl");

    // Pre-fill the audit log to ~990 KiB so every concurrent
    // append crosses the cap and forces rotation. Use the same
    // synthetic-record shape Lane UU's rotation test uses so the
    // Lane RR per-line schema validator stays satisfied even on
    // surviving pre-fill records.
    let synthetic_record = |idx: usize| {
        format!(
            "{{\"schema\":\"ao2.cp-rejected-three-os-smoke.v1\",\"timestamp_utc\":\"2026-05-24T00:00:00+00:00\",\"rejection_reason\":\"synthetic-fill-{idx}\",\"body_sha256\":\"{}\",\"body_size_bytes\":42,\"posted_summary\":{{\"schema\":\"ao2-control-plane.three-os-release-smoke.v1\",\"status\":\"passed\",\"version\":\"0.1.0\",\"release_candidate_version\":\"0.4.79\",\"source_commit_short\":\"abcdef012345\",\"source_dirty\":false,\"candidate_correlation_parity\":null,\"surface_content_hash_parity\":null,\"target_statuses\":{{\"macos\":\"passed\",\"ubuntu\":\"passed\",\"windows\":\"passed\"}}}}}}",
            "0".repeat(64),
        )
    };
    let mut pre_fill = String::new();
    let mut next_idx: usize = 0;
    let prefill_target = 1024 * 1024 - 10 * 1024;
    loop {
        let next = synthetic_record(next_idx);
        if pre_fill.len() + next.len() + 1 > prefill_target {
            break;
        }
        pre_fill.push_str(&next);
        pre_fill.push('\n');
        next_idx += 1;
    }
    std::fs::write(&audit_path, &pre_fill).expect("write pre-fill audit log");

    // Share one reqwest::Client across all spawned tasks. At N=500
    // creating a fresh Client per task wastes a thread + a
    // connection-pool per request and would invite test flakes
    // due to file-descriptor exhaustion on shorter CI runners.
    let client = std::sync::Arc::new(reqwest::Client::new());
    let start = std::time::Instant::now();
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let base_clone = base.clone();
        let client_clone = client.clone();
        handles.push(tokio::spawn(async move {
            let tampered = serde_json::json!({
                "schema": "ao2-control-plane.three-os-release-smoke.v1",
                "version": "0.1.0",
                "release_candidate_version": "0.4.79",
                "status": "passed",
                "source_commit": "fedcba9876543210fedcba9876543210fedcba98",
                "source_dirty": true,
                "targets": {
                    "macos": {"status": "passed"},
                    "ubuntu": {"status": "passed"},
                    "windows": {"status": "passed"}
                }
            });
            let resp = client_clone
                .post(format!(
                    "{base_clone}/api/v1/phase1/promotion/three-os-smoke"
                ))
                .header("authorization", "Bearer secret")
                .body(tampered.to_string())
                .send()
                .await
                .unwrap();
            resp.status().as_u16()
        }));
    }
    let mut statuses = Vec::with_capacity(n);
    for h in handles {
        statuses.push(h.await.unwrap());
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed <= wall_clock_budget,
        "rotation burst at N={n} exceeded wall-clock budget; got {elapsed:?}, budget {wall_clock_budget:?}. A future regression in REJECTED_SMOKE_AUDIT_WRITER_LOCK fairness or in tokio::fs::write performance would surface here before it becomes operator-visible."
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 422).count(),
        n,
        "every concurrent rejection in the rotation burst at N={n} must 422"
    );

    // (a) File size at or under cap.
    let actual_size = std::fs::metadata(&audit_path).unwrap().len() as usize;
    assert!(
        actual_size <= 1024 * 1024,
        "audit log must stay <= 1 MiB cap under rotation burst at N={n}; got {actual_size}"
    );

    // (b) Every surviving record is valid JSON. tokio::fs::write
    // truncates + writes in one syscall, so even with multiple
    // racing writers the final on-disk content is always the
    // complete output of ONE writer — no partial-write corruption.
    let contents = std::fs::read_to_string(&audit_path).expect("audit log readable");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    for (idx, line) in lines.iter().enumerate() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("rotated audit log line {idx} at N={n} must parse as JSON: {e}; line={line}")
        });
    }

    // (c) The cockpit JSON's count must agree with the on-disk
    // file's line count.
    let body: serde_json::Value = client
        .get(format!("{base}/api/v1/release/cockpit.json"))
        .header("authorization", "Bearer secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cockpit_count = body
        .get("rejected_smoke_audit")
        .and_then(|audit| audit.get("count"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    assert_eq!(
        cockpit_count,
        lines.len(),
        "cockpit count must match on-disk line count after rotation burst at N={n}; cockpit={cockpit_count}, file={}",
        lines.len()
    );

    // (d) At least one record must survive — Lane UU guarantees
    // the newest record is retained, even under contention.
    assert!(
        cockpit_count >= 1,
        "at least one record must survive a rotation burst at N={n}; cockpit_count={cockpit_count}"
    );
}

#[tokio::test]
async fn audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation() {
    // Original Lane WW-rotation contract: N=50 concurrent rotations
    // settle under the cap and stay well-formed. Budget is 10s — the
    // test consistently runs in ~50ms post-fix, so a 200x slowdown
    // would still leave room. The wall-clock assertion is purely a
    // regression guard.
    audit_log_rotation_burst_invariants(50, std::time::Duration::from_secs(10)).await;
}

// Lane BBB: extend the Lane WW-rotation contract to N=200. This
// exercises the mutex under 4x the contention without changing the
// invariants. A budget regression here would surface lock-fairness
// issues that N=50 can't see.
#[tokio::test]
async fn audit_log_rotation_stays_well_formed_under_n200_burst_lane_bbb() {
    audit_log_rotation_burst_invariants(200, std::time::Duration::from_secs(20)).await;
}

// Lane BBB: extend the Lane WW-rotation contract to N=500. This is
// the upper end of bursts an actual coordinated tampering attempt
// could produce against a single-host control plane in a short
// window. The wall-clock budget is the only assertion that scales
// with N — the four invariants (cap, JSON validity, count agreement,
// survivor count) hold at every N.
#[tokio::test]
async fn audit_log_rotation_stays_well_formed_under_n500_burst_lane_bbb() {
    audit_log_rotation_burst_invariants(500, std::time::Duration::from_secs(45)).await;
}
