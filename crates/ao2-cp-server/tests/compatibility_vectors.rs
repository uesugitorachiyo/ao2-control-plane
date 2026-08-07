use ao2_cp_schema::canonical::sha256_of_canonical;
use chrono::{DateTime, TimeDelta};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const AO2_TAG_TARGET: &str = "fec09515dfe4e550eeaddc7da497b1fe912012b4";
const CP_TAG_TARGET: &str = "5de3541e9007e12d95b125e7f911c02932e21479";
const MANIFEST_DIGEST: &str = "5f82c24b239c50dadb72e2bfafe1a310b04724cfacff5acee88f5164ec3c59cd";
const PROMOTION_PLAN_DIGEST: &str =
    "4e61e689432e9eddb7885448bd7bf2a70ccb46cc8ca5103be76ec9814d09c591";
const PHYSICAL_WINDOWS_EVIDENCE_DIGEST: &str =
    "df4384874bb2f89c67fe0b5c588cfbcbb89d2e50b123595dd5d1ca4a5b38a8f0";
const VECTOR_SHA256: &str = "00ee9978b5325bc40d5d5de8f63227716d2ca2fe88c81182fdf6e68448d15a7d";
const PRODUCER_VERIFIER_BASE_SHA: &str = "1ea4c482ad105227a5701f6b8eafcd16c42d06e9";
const CONSUMER_VERIFIER_BASE_SHA: &str = "eb420864794ceb9ebadef8f3f551772095edb758";
const V056_AO2_TAG_TARGET: &str = "5706ec9cf3a108d20984973975c2a56b905a8173";
const V018_CP_TAG_TARGET: &str = "6257ec23fde726d4a0133c5b62231881fb6aaa9a";
const V056_MANIFEST_DIGEST: &str =
    "f3d7a5040de8e6fd2703791235fa67841db480d3401c7deadfb3288464d31a45";
const LEGACY_AO2_TAG_TARGET: &str = "80ec5321f42d4bab17d5e64fdae6aa099ba59d4a";
const LEGACY_CP_TAG_TARGET: &str = "f4f5fea9fefa1081cebcbabac550b0e08b9f0e3d";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("compatibility")
        .join(name)
}

fn load_json(name: &str) -> Value {
    let path = fixture_path(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid JSON {}: {error}", path.display()))
}

fn load_current_vector() -> Value {
    let path = fixture_path("ao2-execution-receipt-v0.5.9.json");
    let metadata = std::fs::symlink_metadata(&path).expect("current vector metadata");
    assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() <= 65_536);
    let raw = std::fs::read(&path).expect("current vector bytes");
    assert_eq!(format!("{:x}", Sha256::digest(&raw)), VECTOR_SHA256);
    serde_json::from_slice(&raw).expect("current vector JSON")
}

fn assert_public_safe(value: &Value) {
    match value {
        Value::String(text) => {
            assert!(!text.contains("/Users/"));
            assert!(!text.contains("Documents/canary-test"));
            assert!(!text.to_lowercase().contains("password"));
            assert!(!text.to_lowercase().contains("token"));
            assert!(!text.to_lowercase().contains("secret"));
        }
        Value::Array(values) => values.iter().for_each(assert_public_safe),
        Value::Object(values) => values.values().for_each(assert_public_safe),
        _ => {}
    }
}

fn canonical_sha256(value: &Value) -> String {
    sha256_of_canonical(value).expect("canonical JSON")
}

fn validate_current_execution_vector(vector: &Value, now: &str) -> Result<(), String> {
    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    let bridge = &vector["compatibility_bridge"];

    if vector["schema_version"] != "ao.compatibility.execution-receipt-vector.v1"
        || receipt["schema_version"] != "ao2.execution-receipt.v1"
        || event["schema_version"] != "ao2-control-plane.evidence-event.v1"
    {
        return Err("unsupported schema".into());
    }
    if vector["producer"]["version"] != "v0.5.9"
        || receipt["release"]["version"] != "v0.5.9"
        || event["producer_release_version"] != "v0.5.9"
        || vector["consumer"]["version"] != "v0.1.19"
    {
        return Err("unsupported release pair".into());
    }
    if vector["producer"]["tag_target"] != AO2_TAG_TARGET
        || receipt["release"]["tag_target"] != AO2_TAG_TARGET
        || event["producer_release_tag_target"] != AO2_TAG_TARGET
        || vector["consumer"]["tag_target"] != CP_TAG_TARGET
    {
        return Err("source head mismatch".into());
    }
    if vector["producer"]["release_url"]
        != "https://github.com/uesugitorachiyo/ao2/releases/tag/v0.5.9"
        || vector["consumer"]["release_url"]
            != "https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.19"
    {
        return Err("release locator mismatch".into());
    }
    if vector["producer"]["approved_manifest_digest"] != MANIFEST_DIGEST
        || receipt["release"]["approved_manifest_digest"] != MANIFEST_DIGEST
    {
        return Err("manifest digest mismatch".into());
    }
    if bridge["predecessor_producer_version"] != "v0.5.8"
        || bridge["predecessor_producer_tag_target"] != "a879ae7969a26d13432c7cc402174861b2444c05"
        || bridge["predecessor_consumer_version"] != "v0.1.19"
        || bridge["predecessor_consumer_tag_target"] != CP_TAG_TARGET
        || bridge["contract_change"] != "unchanged"
        || bridge["producer_schema_version"] != receipt["schema_version"]
        || bridge["consumer_schema_version"] != event["schema_version"]
    {
        return Err("unsupported compatibility bridge".into());
    }
    if vector["release_evidence"]["promotion_plan_sha256"] != PROMOTION_PLAN_DIGEST
        || vector["release_evidence"]["physical_windows_evidence_sha256"]
            != PHYSICAL_WINDOWS_EVIDENCE_DIGEST
    {
        return Err("release evidence mismatch".into());
    }
    if receipt["status"] != "passed"
        || receipt["provider_execution_required"] != false
        || event["status"] != "accepted"
        || event["producer_receipt_id"] != receipt["receipt_id"]
        || event["producer_schema_version"] != receipt["schema_version"]
        || event["producer_status"] != receipt["status"]
        || event["observed_evidence_path"] != receipt["evidence_path"]
    {
        return Err("receipt mapping mismatch".into());
    }
    let binding = &vector["evidence_binding"];
    if binding["request_id"] != receipt["receipt_id"]
        || binding["observation_id"] != event["event_id"]
        || binding["artifact_id"] != receipt["evidence_path"]
        || binding["producer_schema"] != receipt["schema_version"]
        || binding["consumer_schema"] != event["schema_version"]
        || binding["execution_receipt_sha256"] != canonical_sha256(receipt)
        || binding["expected_control_plane_event_sha256"] != canonical_sha256(event)
        || binding["producer_verifier_base_sha"] != PRODUCER_VERIFIER_BASE_SHA
        || binding["consumer_verifier_base_sha"] != CONSUMER_VERIFIER_BASE_SHA
    {
        return Err("evidence binding mismatch".into());
    }
    let generated =
        DateTime::parse_from_rfc3339(binding["generated_at_utc"].as_str().unwrap_or(""))
            .map_err(|_| "generated timestamp malformed")?;
    let fresh_until =
        DateTime::parse_from_rfc3339(binding["fresh_until_utc"].as_str().unwrap_or(""))
            .map_err(|_| "freshness timestamp malformed")?;
    let verified_at =
        DateTime::parse_from_rfc3339(now).map_err(|_| "verification timestamp malformed")?;
    if generated > verified_at
        || verified_at > fresh_until
        || fresh_until <= generated
        || fresh_until - generated > TimeDelta::hours(24)
    {
        return Err("evidence is stale or has an invalid freshness window".into());
    }
    if receipt["authority"]["requires_provider_credentials"] != false
        || receipt["authority"]["approves_execution"] != false
        || receipt["authority"]["permits_release"] != false
        || event["authority"]["control_plane_approves_execution"] != false
        || event["authority"]["mutates_ao2_artifacts"] != false
        || event["authority"]["permits_release"] != false
        || vector["boundary"]["provider_pilot"] != false
        || vector["boundary"]["external_user_contact"] != false
        || vector["boundary"]["release_or_tag_created"] != false
        || vector["boundary"]["upload_or_deployment"] != false
        || vector["boundary"]["rsi_work"] != false
        || vector["boundary"]["rsi_remains_denied"] != true
    {
        return Err("authority boundary changed".into());
    }
    Ok(())
}

fn valid_v056_execution_vector(vector: &Value) -> bool {
    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    let bridge = &vector["compatibility_bridge"];
    vector["schema_version"] == "ao.compatibility.execution-receipt-vector.v1"
        && vector["vector_id"] == "ao2-v0.5.6-execution-receipt-to-control-plane-evidence-event"
        && vector["edge"] == "ao2.execution_receipt -> ao2-control-plane.evidence_event"
        && vector["producer"]["repository"] == "ao2"
        && vector["producer"]["version"] == "v0.5.6"
        && vector["producer"]["tag_target"] == V056_AO2_TAG_TARGET
        && vector["producer"]["approved_manifest_digest"] == V056_MANIFEST_DIGEST
        && vector["producer"]["release_url"]
            == "https://github.com/uesugitorachiyo/ao2/releases/tag/v0.5.6"
        && vector["consumer"]["repository"] == "ao2-control-plane"
        && vector["consumer"]["version"] == "v0.1.18"
        && vector["consumer"]["tag_target"] == V018_CP_TAG_TARGET
        && vector["consumer"]["release_url"]
            == "https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.18"
        && vector["release_evidence"]["promotion_plan_sha256"]
            == "5b1e1aec01a107d36a118265ba2a046a2995aa6a9e7be9048dc9d04320d60a67"
        && vector["release_evidence"]["physical_windows_evidence_sha256"]
            == "00d102508ba75904aebc61962c19e63f74da95109437072f200e8cc806c8e6ba"
        && receipt["schema_version"] == "ao2.execution-receipt.v1"
        && receipt["status"] == "passed"
        && receipt["provider_execution_required"] == false
        && receipt["release"]["version"] == "v0.5.6"
        && receipt["release"]["tag_target"] == V056_AO2_TAG_TARGET
        && receipt["release"]["approved_manifest_digest"] == V056_MANIFEST_DIGEST
        && event["schema_version"] == "ao2-control-plane.evidence-event.v1"
        && event["event_type"] == "ao2.execution_receipt.observed"
        && event["status"] == "accepted"
        && event["producer_receipt_id"] == receipt["receipt_id"]
        && event["producer_schema_version"] == receipt["schema_version"]
        && event["producer_status"] == receipt["status"]
        && event["producer_release_version"] == receipt["release"]["version"]
        && event["producer_release_tag_target"] == receipt["release"]["tag_target"]
        && event["observed_evidence_path"] == receipt["evidence_path"]
        && bridge["predecessor_producer_version"] == "v0.5.1"
        && bridge["predecessor_producer_tag_target"] == LEGACY_AO2_TAG_TARGET
        && bridge["predecessor_consumer_version"] == "v0.1.16"
        && bridge["predecessor_consumer_tag_target"] == LEGACY_CP_TAG_TARGET
        && bridge["producer_schema_version"] == receipt["schema_version"]
        && bridge["consumer_schema_version"] == event["schema_version"]
        && bridge["contract_change"] == "unchanged"
        && receipt["authority"]["requires_provider_credentials"] == false
        && receipt["authority"]["approves_execution"] == false
        && receipt["authority"]["permits_release"] == false
        && event["authority"]["control_plane_approves_execution"] == false
        && event["authority"]["mutates_ao2_artifacts"] == false
        && event["authority"]["permits_release"] == false
        && vector["boundary"]["provider_pilot"] == false
        && vector["boundary"]["external_user_contact"] == false
        && vector["boundary"]["release_or_tag_created"] == false
        && vector["boundary"]["upload_or_deployment"] == false
        && vector["boundary"]["rsi_work"] == false
        && vector["boundary"]["rsi_remains_denied"] == true
}

#[test]
fn consumes_ao2_execution_receipt_as_expected_evidence_event() {
    let vector = load_current_vector();
    assert_public_safe(&vector);
    assert_eq!(
        validate_current_execution_vector(&vector, "2026-08-08T00:00:00Z"),
        Ok(())
    );

    assert_eq!(
        vector["schema_version"],
        "ao.compatibility.execution-receipt-vector.v1"
    );
    assert_eq!(
        vector["vector_id"],
        "ao2-v0.5.9-execution-receipt-to-control-plane-evidence-event"
    );
    assert_eq!(
        vector["edge"],
        "ao2.execution_receipt -> ao2-control-plane.evidence_event"
    );

    assert_eq!(vector["producer"]["repository"], "ao2");
    assert_eq!(vector["producer"]["version"], "v0.5.9");
    assert_eq!(vector["producer"]["tag_target"], AO2_TAG_TARGET);
    assert_eq!(
        vector["producer"]["approved_manifest_digest"],
        MANIFEST_DIGEST
    );
    assert_eq!(vector["consumer"]["repository"], "ao2-control-plane");
    assert_eq!(vector["consumer"]["version"], "v0.1.19");
    assert_eq!(vector["consumer"]["tag_target"], CP_TAG_TARGET);

    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    assert_eq!(receipt["schema_version"], "ao2.execution-receipt.v1");
    assert_eq!(receipt["status"], "passed");
    assert_eq!(receipt["provider_execution_required"], false);
    assert_eq!(receipt["release"]["version"], "v0.5.9");
    assert_eq!(receipt["release"]["tag_target"], AO2_TAG_TARGET);

    assert_eq!(
        event["schema_version"],
        "ao2-control-plane.evidence-event.v1"
    );
    assert_eq!(event["event_type"], "ao2.execution_receipt.observed");
    assert_eq!(event["producer_receipt_id"], receipt["receipt_id"]);
    assert_eq!(event["producer_schema_version"], receipt["schema_version"]);
    assert_eq!(event["producer_status"], receipt["status"]);
    assert_eq!(
        event["producer_release_version"],
        receipt["release"]["version"]
    );
    assert_eq!(
        event["producer_release_tag_target"],
        receipt["release"]["tag_target"]
    );
    assert_eq!(event["observed_evidence_path"], receipt["evidence_path"]);
    assert_eq!(event["status"], "accepted");

    assert_eq!(receipt["authority"]["requires_provider_credentials"], false);
    assert_eq!(receipt["authority"]["approves_execution"], false);
    assert_eq!(receipt["authority"]["permits_release"], false);
    assert_eq!(
        event["authority"]["control_plane_approves_execution"],
        false
    );
    assert_eq!(event["authority"]["mutates_ao2_artifacts"], false);
    assert_eq!(event["authority"]["permits_release"], false);
}

#[test]
fn rejects_mismatched_or_authority_changing_execution_vectors() {
    let vector = load_current_vector();
    let mutations = [
        (
            "/execution_receipt/schema_version",
            Value::from("ao2.execution-receipt.v2"),
        ),
        ("/producer/version", Value::from("v0.5.8")),
        ("/producer/release_url", Value::from("https://example.com")),
        (
            "/producer/tag_target",
            Value::from("0000000000000000000000000000000000000000"),
        ),
        ("/producer/approved_manifest_digest", Value::from("altered")),
        ("/consumer/version", Value::from("v0.1.18")),
        ("/consumer/release_url", Value::from("https://example.com")),
        (
            "/release_evidence/promotion_plan_sha256",
            Value::from("altered"),
        ),
        (
            "/compatibility_bridge/contract_change",
            Value::from("breaking"),
        ),
        (
            "/compatibility_bridge/predecessor_producer_tag_target",
            Value::from("0000000000000000000000000000000000000000"),
        ),
        ("/execution_receipt/status", Value::from("failed")),
        (
            "/expected_control_plane_event/status",
            Value::from("rejected"),
        ),
        (
            "/evidence_binding/execution_receipt_sha256",
            Value::from("altered"),
        ),
        ("/evidence_binding/request_id", Value::from("wrong-request")),
        (
            "/evidence_binding/observation_id",
            Value::from("wrong-observation"),
        ),
        (
            "/evidence_binding/artifact_id",
            Value::from("wrong-artifact"),
        ),
        (
            "/evidence_binding/fresh_until_utc",
            Value::from("2026-08-07T20:40:04Z"),
        ),
        (
            "/evidence_binding/producer_verifier_base_sha",
            Value::from("0000000000000000000000000000000000000000"),
        ),
        (
            "/execution_receipt/authority/permits_release",
            Value::from(true),
        ),
        (
            "/expected_control_plane_event/authority/mutates_ao2_artifacts",
            Value::from(true),
        ),
        ("/boundary/provider_pilot", Value::from(true)),
        ("/boundary/external_user_contact", Value::from(true)),
        ("/boundary/rsi_remains_denied", Value::from(false)),
    ];

    for (pointer, replacement) in mutations {
        let mut candidate = vector.clone();
        *candidate.pointer_mut(pointer).expect("fixture pointer") = replacement;
        assert!(
            validate_current_execution_vector(&candidate, "2026-08-08T00:00:00Z").is_err(),
            "mutation at {pointer} must fail closed"
        );
    }
}

#[test]
fn rejects_stale_future_and_malformed_compatibility_evidence() {
    let vector = load_current_vector();
    for now in [
        "2026-08-07T20:40:04Z",
        "2026-08-08T20:40:06Z",
        "not-a-timestamp",
    ] {
        assert!(validate_current_execution_vector(&vector, now).is_err());
    }
}

#[test]
fn retains_v056_execution_vector_coverage() {
    let vector = load_json("ao2-execution-receipt-v0.5.6.json");
    assert_public_safe(&vector);
    assert!(valid_v056_execution_vector(&vector));

    for (pointer, replacement) in [
        ("/vector_id", Value::from("altered")),
        ("/edge", Value::from("altered")),
        ("/producer/repository", Value::from("altered")),
        ("/producer/version", Value::from("v0.5.5")),
        ("/producer/tag_target", Value::from("altered")),
        ("/producer/approved_manifest_digest", Value::from("altered")),
        ("/producer/release_url", Value::from("https://example.com")),
        ("/consumer/repository", Value::from("altered")),
        ("/consumer/release_url", Value::from("https://example.com")),
        (
            "/release_evidence/promotion_plan_sha256",
            Value::from("altered"),
        ),
        (
            "/release_evidence/physical_windows_evidence_sha256",
            Value::from("altered"),
        ),
        (
            "/execution_receipt/schema_version",
            Value::from("ao2.execution-receipt.v2"),
        ),
        ("/execution_receipt/status", Value::from("failed")),
        (
            "/execution_receipt/provider_execution_required",
            Value::from(true),
        ),
        (
            "/expected_control_plane_event/schema_version",
            Value::from("ao2-control-plane.evidence-event.v2"),
        ),
        (
            "/expected_control_plane_event/event_type",
            Value::from("ao2.execution_receipt.mutated"),
        ),
        (
            "/expected_control_plane_event/status",
            Value::from("rejected"),
        ),
        (
            "/compatibility_bridge/predecessor_producer_version",
            Value::from("v0.5.0"),
        ),
        (
            "/compatibility_bridge/predecessor_producer_tag_target",
            Value::from("altered"),
        ),
        (
            "/compatibility_bridge/predecessor_consumer_version",
            Value::from("v0.1.15"),
        ),
        (
            "/compatibility_bridge/predecessor_consumer_tag_target",
            Value::from("altered"),
        ),
        (
            "/compatibility_bridge/producer_schema_version",
            Value::from("ao2.execution-receipt.v2"),
        ),
        (
            "/compatibility_bridge/consumer_schema_version",
            Value::from("ao2-control-plane.evidence-event.v2"),
        ),
        (
            "/compatibility_bridge/contract_change",
            Value::from("breaking"),
        ),
        (
            "/execution_receipt/authority/permits_release",
            Value::from(true),
        ),
        ("/boundary/provider_pilot", Value::from(true)),
        ("/boundary/external_user_contact", Value::from(true)),
        ("/boundary/rsi_work", Value::from(true)),
    ] {
        let mut candidate = vector.clone();
        *candidate
            .pointer_mut(pointer)
            .expect("legacy fixture pointer") = replacement;
        assert!(!valid_v056_execution_vector(&candidate));
    }
}

#[test]
fn produces_control_plane_readback_for_command_operator_status() {
    let vector = load_json("control-plane-readback-v0.1.16.json");
    assert_public_safe(&vector);

    assert_eq!(
        vector["schema_version"],
        "ao.compatibility.control-plane-readback-vector.v1"
    );
    assert_eq!(
        vector["vector_id"],
        "ao2-control-plane-v0.1.16-readback-to-ao-command-operator-status"
    );
    assert_eq!(
        vector["edge"],
        "ao2-control-plane.evidence_readback -> ao-command.operator_status"
    );
    assert_eq!(vector["producer"]["repository"], "ao2-control-plane");
    assert_eq!(vector["producer"]["version"], "v0.1.16");
    assert_eq!(vector["producer"]["tag_target"], LEGACY_CP_TAG_TARGET);
    assert_eq!(vector["consumer"]["repository"], "ao-command");

    let readback = &vector["control_plane_readback"];
    let status = &vector["expected_command_operator_status"];
    assert_eq!(
        readback["schema_version"],
        "ao2-control-plane.current-release-readback.v1"
    );
    assert_eq!(readback["status"], "observed");
    assert_eq!(
        readback["current_public_release_pair"]["ao2_version"],
        "v0.5.1"
    );
    assert_eq!(
        readback["current_public_release_pair"]["ao2_tag_target"],
        LEGACY_AO2_TAG_TARGET
    );
    assert_eq!(
        readback["current_public_release_pair"]["control_plane_version"],
        "v0.1.16"
    );
    assert_eq!(
        readback["current_public_release_pair"]["control_plane_tag_target"],
        LEGACY_CP_TAG_TARGET
    );
    assert_eq!(readback["compatibility"]["canonical_vector_count"], 1);
    assert_eq!(readback["compatibility"]["consumer_test_count"], 1);
    assert_eq!(
        readback["compatibility"]["full_stack_compatibility_complete"],
        false
    );

    assert_eq!(status["schema_version"], "ao-command.operator-status.v1");
    assert_eq!(status["status"], "current_release_pair_observed");
    assert_eq!(
        status["source_readback_schema_version"],
        readback["schema_version"]
    );
    assert_eq!(
        status["current_public_release_pair"]["ao2_version"],
        readback["current_public_release_pair"]["ao2_version"]
    );
    assert_eq!(
        status["current_public_release_pair"]["control_plane_version"],
        readback["current_public_release_pair"]["control_plane_version"]
    );
    assert_eq!(
        status["compatibility"]["full_stack_compatibility_complete"],
        false
    );
    assert_eq!(status["authority"]["executes_work"], false);
    assert_eq!(status["authority"]["approves_work"], false);
    assert_eq!(status["authority"]["mutates_repositories"], false);
    assert_eq!(status["authority"]["calls_providers"], false);
    assert_eq!(status["authority"]["releases_or_deploys"], false);
}
