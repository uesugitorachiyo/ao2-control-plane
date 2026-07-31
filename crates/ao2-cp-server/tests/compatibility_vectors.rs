use serde_json::Value;
use std::path::PathBuf;

const AO2_TAG_TARGET: &str = "5706ec9cf3a108d20984973975c2a56b905a8173";
const CP_TAG_TARGET: &str = "6257ec23fde726d4a0133c5b62231881fb6aaa9a";
const MANIFEST_DIGEST: &str = "f3d7a5040de8e6fd2703791235fa67841db480d3401c7deadfb3288464d31a45";
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

fn validate_current_execution_vector(vector: &Value) -> Result<(), &'static str> {
    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    let bridge = &vector["compatibility_bridge"];

    if vector["schema_version"] != "ao.compatibility.execution-receipt-vector.v1"
        || receipt["schema_version"] != "ao2.execution-receipt.v1"
        || event["schema_version"] != "ao2-control-plane.evidence-event.v1"
    {
        return Err("unsupported schema");
    }
    if vector["producer"]["version"] != "v0.5.6"
        || receipt["release"]["version"] != "v0.5.6"
        || event["producer_release_version"] != "v0.5.6"
        || vector["consumer"]["version"] != "v0.1.18"
    {
        return Err("unsupported release pair");
    }
    if vector["producer"]["tag_target"] != AO2_TAG_TARGET
        || receipt["release"]["tag_target"] != AO2_TAG_TARGET
        || event["producer_release_tag_target"] != AO2_TAG_TARGET
        || vector["consumer"]["tag_target"] != CP_TAG_TARGET
    {
        return Err("source head mismatch");
    }
    if vector["producer"]["approved_manifest_digest"] != MANIFEST_DIGEST
        || receipt["release"]["approved_manifest_digest"] != MANIFEST_DIGEST
    {
        return Err("manifest digest mismatch");
    }
    if bridge["predecessor_producer_version"] != "v0.5.1"
        || bridge["predecessor_consumer_version"] != "v0.1.16"
        || bridge["contract_change"] != "unchanged"
        || bridge["producer_schema_version"] != receipt["schema_version"]
        || bridge["consumer_schema_version"] != event["schema_version"]
    {
        return Err("unsupported compatibility bridge");
    }
    if receipt["status"] != "passed"
        || receipt["provider_execution_required"] != false
        || event["status"] != "accepted"
        || event["producer_receipt_id"] != receipt["receipt_id"]
        || event["producer_schema_version"] != receipt["schema_version"]
        || event["producer_status"] != receipt["status"]
        || event["observed_evidence_path"] != receipt["evidence_path"]
    {
        return Err("receipt mapping mismatch");
    }
    if receipt["authority"]["requires_provider_credentials"] != false
        || receipt["authority"]["approves_execution"] != false
        || receipt["authority"]["permits_release"] != false
        || event["authority"]["control_plane_approves_execution"] != false
        || event["authority"]["mutates_ao2_artifacts"] != false
        || event["authority"]["permits_release"] != false
        || vector["boundary"]["release_or_tag_created"] != false
        || vector["boundary"]["upload_or_deployment"] != false
        || vector["boundary"]["rsi_remains_denied"] != true
    {
        return Err("authority boundary changed");
    }
    Ok(())
}

#[test]
fn consumes_ao2_execution_receipt_as_expected_evidence_event() {
    let vector = load_json("ao2-execution-receipt-v0.5.6.json");
    assert_public_safe(&vector);
    assert_eq!(validate_current_execution_vector(&vector), Ok(()));

    assert_eq!(
        vector["schema_version"],
        "ao.compatibility.execution-receipt-vector.v1"
    );
    assert_eq!(
        vector["vector_id"],
        "ao2-v0.5.6-execution-receipt-to-control-plane-evidence-event"
    );
    assert_eq!(
        vector["edge"],
        "ao2.execution_receipt -> ao2-control-plane.evidence_event"
    );

    assert_eq!(vector["producer"]["repository"], "ao2");
    assert_eq!(vector["producer"]["version"], "v0.5.6");
    assert_eq!(vector["producer"]["tag_target"], AO2_TAG_TARGET);
    assert_eq!(
        vector["producer"]["approved_manifest_digest"],
        MANIFEST_DIGEST
    );
    assert_eq!(vector["consumer"]["repository"], "ao2-control-plane");
    assert_eq!(vector["consumer"]["version"], "v0.1.18");
    assert_eq!(vector["consumer"]["tag_target"], CP_TAG_TARGET);

    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    assert_eq!(receipt["schema_version"], "ao2.execution-receipt.v1");
    assert_eq!(receipt["status"], "passed");
    assert_eq!(receipt["provider_execution_required"], false);
    assert_eq!(receipt["release"]["version"], "v0.5.6");
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
    let vector = load_json("ao2-execution-receipt-v0.5.6.json");
    let mutations = [
        (
            "/execution_receipt/schema_version",
            Value::from("ao2.execution-receipt.v2"),
        ),
        ("/producer/version", Value::from("v0.5.5")),
        (
            "/producer/tag_target",
            Value::from("0000000000000000000000000000000000000000"),
        ),
        ("/producer/approved_manifest_digest", Value::from("altered")),
        ("/consumer/version", Value::from("v0.1.17")),
        (
            "/compatibility_bridge/contract_change",
            Value::from("breaking"),
        ),
        ("/execution_receipt/status", Value::from("failed")),
        (
            "/execution_receipt/authority/permits_release",
            Value::from(true),
        ),
        (
            "/expected_control_plane_event/authority/mutates_ao2_artifacts",
            Value::from(true),
        ),
        ("/boundary/rsi_remains_denied", Value::from(false)),
    ];

    for (pointer, replacement) in mutations {
        let mut candidate = vector.clone();
        *candidate.pointer_mut(pointer).expect("fixture pointer") = replacement;
        assert!(
            validate_current_execution_vector(&candidate).is_err(),
            "mutation at {pointer} must fail closed"
        );
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
