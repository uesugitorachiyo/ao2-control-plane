use serde_json::Value;
use std::path::PathBuf;

const AO2_TAG_TARGET: &str = "80ec5321f42d4bab17d5e64fdae6aa099ba59d4a";
const CP_TAG_TARGET: &str = "f1702b387607566cac457458af9adb5871a5c412";
const MANIFEST_DIGEST: &str = "bd8103e7a038f47e1b4fef1a2a19ae65cc221675ea11149d39cfb679ae2a08fc";

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

#[test]
fn consumes_ao2_execution_receipt_as_expected_evidence_event() {
    let vector = load_json("ao2-execution-receipt-v0.5.1.json");
    assert_public_safe(&vector);

    assert_eq!(
        vector["schema_version"],
        "ao.compatibility.execution-receipt-vector.v1"
    );
    assert_eq!(
        vector["vector_id"],
        "ao2-v0.5.1-execution-receipt-to-control-plane-evidence-event"
    );
    assert_eq!(
        vector["edge"],
        "ao2.execution_receipt -> ao2-control-plane.evidence_event"
    );

    assert_eq!(vector["producer"]["repository"], "ao2");
    assert_eq!(vector["producer"]["version"], "v0.5.1");
    assert_eq!(vector["producer"]["tag_target"], AO2_TAG_TARGET);
    assert_eq!(
        vector["producer"]["approved_manifest_digest"],
        MANIFEST_DIGEST
    );
    assert_eq!(vector["consumer"]["repository"], "ao2-control-plane");
    assert_eq!(vector["consumer"]["version"], "v0.1.15");
    assert_eq!(vector["consumer"]["tag_target"], CP_TAG_TARGET);

    let receipt = &vector["execution_receipt"];
    let event = &vector["expected_control_plane_event"];
    assert_eq!(receipt["schema_version"], "ao2.execution-receipt.v1");
    assert_eq!(receipt["status"], "passed");
    assert_eq!(receipt["provider_execution_required"], false);
    assert_eq!(receipt["release"]["version"], "v0.5.1");
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
fn produces_control_plane_readback_for_command_operator_status() {
    let vector = load_json("control-plane-readback-v0.1.15.json");
    assert_public_safe(&vector);

    assert_eq!(
        vector["schema_version"],
        "ao.compatibility.control-plane-readback-vector.v1"
    );
    assert_eq!(
        vector["vector_id"],
        "ao2-control-plane-v0.1.15-readback-to-ao-command-operator-status"
    );
    assert_eq!(
        vector["edge"],
        "ao2-control-plane.evidence_readback -> ao-command.operator_status"
    );
    assert_eq!(vector["producer"]["repository"], "ao2-control-plane");
    assert_eq!(vector["producer"]["version"], "v0.1.15");
    assert_eq!(vector["producer"]["tag_target"], CP_TAG_TARGET);
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
        AO2_TAG_TARGET
    );
    assert_eq!(
        readback["current_public_release_pair"]["control_plane_version"],
        "v0.1.15"
    );
    assert_eq!(
        readback["current_public_release_pair"]["control_plane_tag_target"],
        CP_TAG_TARGET
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
