//! K37: read-only control-plane observation of AO2 plugin readiness evidence.
//!
//! AO2 produces the plugin distribution, adapter scaffold, and adapter
//! install-smoke observer bundles. The control plane must only read those
//! summaries: no provider execution, queue mutation, memory writes, AO artifact
//! mutation, control-plane mutation, or release approval.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const PLUGIN_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/plugin-observer-bundle.json");
const ADAPTER_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/adapter-observer-bundle.json");
const ADAPTER_INSTALL_SMOKE_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/adapter-install-smoke-observer-bundle.json");
const CONSUMER_LIFECYCLE_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/consumer-lifecycle-observer-bundle.json");
const RELEASE_CANDIDATE_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/release-candidate-observer-bundle.json");
const FINAL_INSTALL_TRANSCRIPT_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/final-install-transcript-observer-bundle.json");
const SHIPMENT_READINESS_MACOS: &str =
    include_str!("fixtures/k37-plugin-observer/shipment-readiness-macos.json");
const SHIPMENT_READINESS_UBUNTU: &str =
    include_str!("fixtures/k37-plugin-observer/shipment-readiness-ubuntu.json");
const SHIPMENT_READINESS_WINDOWS: &str =
    include_str!("fixtures/k37-plugin-observer/shipment-readiness-windows.json");
const CLEAN_PACKAGE_OPERATOR_INDEX: &str =
    include_str!("fixtures/k37-plugin-observer/clean-package-operator-index.json");
const PACKAGED_REPLACEMENT_HARDENING_MACOS: &str =
    include_str!("fixtures/k37-plugin-observer/packaged-replacement-hardening-macos.json");
const PACKAGED_REPLACEMENT_HARDENING_UBUNTU: &str =
    include_str!("fixtures/k37-plugin-observer/packaged-replacement-hardening-ubuntu.json");
const PACKAGED_REPLACEMENT_HARDENING_WINDOWS: &str =
    include_str!("fixtures/k37-plugin-observer/packaged-replacement-hardening-windows.json");
const PACKAGED_REPLACEMENT_HARDENING_OBSERVER_BUNDLE: &str = include_str!(
    "fixtures/k37-plugin-observer/packaged-replacement-hardening-observer-bundle.json"
);
const REPLACEMENT_PARITY_VERIFICATION: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-parity-verification.json");
const RELEASE_GATE_WITH_REPLACEMENT_ROLLUP: &str =
    include_str!("fixtures/k37-plugin-observer/release-gate-with-replacement-rollup.json");
const REPLACEMENT_PARITY_VERIFICATION_MACOS: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-parity-verification-macos.json");
const RELEASE_GATE_ROLLUP_MACOS: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-gate-rollup-macos.json");
const REPLACEMENT_PARITY_VERIFICATION_UBUNTU: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-parity-verification-ubuntu.json");
const RELEASE_GATE_ROLLUP_UBUNTU: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-gate-rollup-ubuntu.json");
const REPLACEMENT_PARITY_VERIFICATION_WINDOWS: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-parity-verification-windows.json");
const RELEASE_GATE_ROLLUP_WINDOWS: &str =
    include_str!("fixtures/k37-plugin-observer/replacement-gate-rollup-windows.json");
const RELEASE_GATE_WITH_REPLACEMENT_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/release-gate-with-replacement-observer-bundle.json");
const SELF_CONTAINED_PLUGIN_PACKAGE_OBSERVER_BUNDLE: &str =
    include_str!("fixtures/k37-plugin-observer/self-contained-plugin-package-observer-bundle.json");
const SKILL_CONTRACT_MANIFEST: &str =
    include_str!("fixtures/k37-plugin-observer/skill-contract-manifest.json");
const CLOSER_DECISION: &str = include_str!("fixtures/k37-plugin-observer/closer-decision.json");
const PULSE_ONCE_OBSERVER_BUNDLE: &str =
    "fixtures/k37-plugin-observer/pulse-once-observer-bundle.json";
const PULSE_CHAIN_OBSERVER_BUNDLE: &str =
    "fixtures/k37-plugin-observer/pulse-chain-observer-bundle.json";
const PULSE_EVAL_LOOP_OBSERVER_BUNDLE: &str =
    "fixtures/k37-plugin-observer/pulse-eval-loop-observer-bundle.json";
const PULSE_EXECUTOR_OBSERVER_BUNDLE: &str =
    "fixtures/k37-plugin-observer/pulse-executor-observer-bundle.json";
const PULSE_APPLY_RESULT_OBSERVER_BUNDLE: &str =
    "fixtures/k37-plugin-observer/pulse-apply-result-observer-bundle.json";

fn parse_fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("K37 observer fixture parses")
}

fn read_fixture(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(path);
    let text = std::fs::read_to_string(&path).expect("K37 observer fixture exists");
    parse_fixture(&text)
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_hex_without_fixture_newline(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n");
    let normalized = normalized.strip_suffix('\n').unwrap_or(&normalized);
    Sha256::digest(normalized.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_top_level_observer_boundary(value: &Value) {
    assert_eq!(value["producer"].as_str(), Some("ao2"));
    assert_eq!(value["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(value["platform_count"].as_u64(), Some(3));
    assert_eq!(
        value["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        value["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["control_plane_observation"]["may_observe_evidence_bundle_path"].as_bool(),
        Some(true)
    );

    let tb = &value["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
}

fn assert_side_effects_false(side_effects: &Value) {
    for key in [
        "would_approve_release",
        "would_execute_provider",
        "would_execute_queue",
        "would_mutate_ao_artifacts",
        "would_mutate_control_plane",
        "would_write_memory",
    ] {
        assert_eq!(
            side_effects[key].as_bool(),
            Some(false),
            "observer side effect {key} must remain false"
        );
    }
}

fn assert_platform_verification_is_observer_safe(platform: &str, verification: &Value) {
    assert_eq!(
        verification["status"].as_str(),
        Some("passed"),
        "{platform} verification must have passed before observation"
    );
    assert_eq!(
        verification["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        verification["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        verification["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        verification["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true),
        "{platform} verification must preserve local OAuth CLI-only auth"
    );
    assert_eq!(
        verification["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false),
        "{platform} verification must forbid provider API-key auth"
    );

    let side_effects = &verification["side_effects"];
    for key in [
        "ao_artifacts_mutated",
        "control_plane_mutated",
        "memory_written",
        "provider_execution_started",
        "queue_mutated",
        "release_approved",
    ] {
        assert_eq!(
            side_effects[key].as_bool(),
            Some(false),
            "{platform} side effect {key} must remain false"
        );
    }

    let tb = &verification["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
}

fn assert_consumer_lifecycle_is_observer_safe(platform: &str, lifecycle: &Value) {
    assert_eq!(
        lifecycle["schema_version"].as_str(),
        Some("ao2.plugin-consumer-lifecycle.v1")
    );
    assert_eq!(
        lifecycle["status"].as_str(),
        Some("passed"),
        "{platform} consumer lifecycle must pass before observation"
    );
    assert_eq!(
        lifecycle["targets"].as_array().map(Vec::len),
        Some(2),
        "{platform} consumer lifecycle must include Codex and Claude targets"
    );
    assert_eq!(
        lifecycle["factory_v3_role"].as_str(),
        Some("parity_auditor")
    );
    assert_eq!(
        lifecycle["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true),
        "{platform} consumer lifecycle must preserve local OAuth CLI-only auth"
    );
    assert_eq!(
        lifecycle["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false),
        "{platform} consumer lifecycle must forbid provider API-key auth"
    );
    assert_eq!(
        lifecycle["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false),
        "{platform} consumer lifecycle must not require provider API-key env"
    );

    let side_effects = &lifecycle["side_effects"];
    for key in [
        "ao_artifacts_mutated",
        "control_plane_mutated",
        "memory_written",
        "provider_execution_started",
        "queue_mutated",
        "release_approved",
    ] {
        assert_eq!(
            side_effects[key].as_bool(),
            Some(false),
            "{platform} consumer lifecycle side effect {key} must remain false"
        );
    }

    let tb = &lifecycle["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));

    assert_eq!(
        lifecycle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        lifecycle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        lifecycle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );

    for target in ["codex", "claude"] {
        let target_result = &lifecycle["target_results"][target];
        assert_eq!(
            target_result["status"].as_str(),
            Some("passed"),
            "{platform}/{target} consumer lifecycle must pass before observation"
        );
        assert_eq!(
            target_result["installed_package_paths_only"].as_bool(),
            Some(true),
            "{platform}/{target} must use installed package paths only"
        );
        for key in [
            "ao_artifacts_mutated",
            "control_plane_mutated",
            "memory_written",
            "provider_execution_started",
            "queue_mutated",
            "release_approved",
        ] {
            assert_eq!(
                target_result[key].as_bool(),
                Some(false),
                "{platform}/{target} side effect {key} must remain false"
            );
        }
        assert_eq!(
            target_result["control_plane_observation"]["role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            target_result["control_plane_observation"]["may_approve_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            target_result["control_plane_observation"]["may_mutate_evidence"].as_bool(),
            Some(false)
        );
    }
}

#[test]
fn plugin_distribution_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(PLUGIN_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("89c7e613179b7230b132acbe4c9ded9b4126e92ee87982d0b6c55bce54707427")
    );
    assert_top_level_observer_boundary(&bundle);

    for platform in ["macos", "ubuntu", "windows"] {
        let input = &bundle["platform_inputs"][platform];
        assert_eq!(
            input["schema_version"].as_str(),
            Some("ao2.k37-plugin-observer-input.v1"),
            "{platform} input schema must be observable"
        );
        assert_eq!(input["producer"].as_str(), Some("ao2"));
        assert_eq!(input["status"].as_str(), Some("ready_for_k37_observation"));
        assert_eq!(input["sha256"].as_str().map(str::len), Some(64));
        assert_eq!(
            input["trust_boundary"]["control_plane_role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            input["trust_boundary"]["control_plane_approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            input["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false)
        );

        for target in ["codex", "claude"] {
            let target_result = &input["target_results"][target];
            assert_eq!(
                target_result["status"].as_str(),
                Some("passed"),
                "{platform}/{target} wrapper result must pass before observation"
            );
            assert_eq!(
                target_result["commands_from_installed_package_paths"].as_bool(),
                Some(true),
                "{platform}/{target} must use installed package paths"
            );
            assert_eq!(
                target_result["control_plane_observation"]["role"].as_str(),
                Some("read_only_observer")
            );
            assert_eq!(
                target_result["control_plane_observation"]["may_approve_release"].as_bool(),
                Some(false)
            );
            assert_eq!(
                target_result["control_plane_observation"]["may_mutate_evidence"].as_bool(),
                Some(false)
            );
        }
    }
}

#[test]
fn adapter_scaffold_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(ADAPTER_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-adapter-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("4900170afc260fabba60149ea605ea315af89d2a87be820f066af5baf7017c01")
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(2)
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));

    for platform in ["macos", "ubuntu", "windows"] {
        let verification = &bundle["platform_verifications"][platform];
        assert_eq!(
            verification["schema_version"].as_str(),
            Some("ao2.plugin-adapter-scaffold-verification.v1")
        );
        assert_eq!(verification["targets"].as_array().map(Vec::len), Some(2));
        assert_platform_verification_is_observer_safe(platform, verification);
    }
}

#[test]
fn adapter_install_smoke_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(ADAPTER_INSTALL_SMOKE_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-adapter-install-smoke-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("20ecc48ff8f13b0516c4560464af22a9a39ed28f8d463d6bee55b26975f43d8e")
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(2)
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));

    for platform in ["macos", "ubuntu", "windows"] {
        let verification = &bundle["platform_verifications"][platform];
        assert_eq!(
            verification["schema_version"].as_str(),
            Some("ao2.plugin-adapter-install-smoke-verification.v1")
        );
        assert_eq!(
            verification["adapter_install_smoke_schema_version"].as_str(),
            Some("ao2.plugin-adapter-install-smoke.v1")
        );
        assert_eq!(verification["targets"].as_array().map(Vec::len), Some(2));
        assert_platform_verification_is_observer_safe(platform, verification);
    }
}

#[test]
fn consumer_lifecycle_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(CONSUMER_LIFECYCLE_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-consumer-lifecycle-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("3e2222ee92fecf20ce5d7ae6bd2227ea2021338cb930ae5ee1cd84cfba6bd51a")
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(1)
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);

    for platform in ["macos", "ubuntu", "windows"] {
        let lifecycle = &bundle["platform_lifecycles"][platform];
        assert_consumer_lifecycle_is_observer_safe(platform, lifecycle);
    }
}

#[test]
fn release_candidate_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(RELEASE_CANDIDATE_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-release-candidate-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("1b98c9a5055ed7f19d868cb9234d2ea1cfc3b2cfcd68af40cecdaaecde9a6790")
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(2)
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));

    for platform in ["macos", "ubuntu", "windows"] {
        let verification = &bundle["platform_release_candidates"][platform];
        assert_eq!(
            verification["schema_version"].as_str(),
            Some("ao2.plugin-release-candidate-verification.v1")
        );
        assert_eq!(
            verification["source_schema_version"].as_str(),
            Some("ao2.plugin-release-candidate.v1")
        );
        assert_eq!(
            verification["status"].as_str(),
            Some("passed"),
            "{platform} release candidate verification must pass before observation"
        );
        assert_eq!(
            verification["provider_auth"]["local_oauth_cli_only"].as_bool(),
            Some(true),
            "{platform} release candidate must preserve local OAuth CLI-only auth"
        );
        assert_eq!(
            verification["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
            Some(false),
            "{platform} release candidate must forbid provider API-key auth"
        );
        assert_eq!(
            verification["provider_auth"]["provider_api_key_env_required"].as_bool(),
            Some(false),
            "{platform} release candidate must not require provider API-key env"
        );
        assert_side_effects_false(&verification["side_effects"]);
        assert_eq!(
            verification["token_safe_output_verified"].as_bool(),
            Some(true),
            "{platform} release candidate must have token-safe output verified"
        );
        assert_eq!(
            verification["trust_boundary"]["control_plane_role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            verification["trust_boundary"]["control_plane_approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            verification["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false)
        );
        assert_eq!(
            verification["control_plane_observation"]["role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            verification["control_plane_observation"]["may_approve_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            verification["control_plane_observation"]["may_mutate_evidence"].as_bool(),
            Some(false)
        );
        assert_eq!(
            verification["release_review_inputs"]
                .as_array()
                .map(Vec::len),
            Some(7),
            "{platform} release candidate must cover all plugin shipment inputs"
        );
        assert!(
            verification["release_review_inputs"]
                .as_array()
                .expect("release review inputs are present")
                .iter()
                .any(|value| value.as_str()
                    == Some("ao2.k37-release-gate-with-replacement-observer-bundle.v1")),
            "{platform} release candidate must include release-gate replacement observer proof"
        );
        assert_eq!(
            verification["control_plane_readback"]["repo"].as_str(),
            Some("ao2-control-plane")
        );
        assert_eq!(
            verification["control_plane_readback"]["commit"].as_str(),
            Some("bd0c6426867194968ac09d230bbe59f0d25216af")
        );
        assert_eq!(
            verification["control_plane_readback"]["role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            verification["control_plane_readback"]["approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            verification["control_plane_readback"]["mutated_by_this_command"].as_bool(),
            Some(false)
        );
    }
}

#[test]
fn final_install_transcript_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(FINAL_INSTALL_TRANSCRIPT_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-plugin-final-install-transcript-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("2dd15738237b9ca160cc71857410789080b2fd91046d88cdf84ed748b1c0cdb9")
    );
    assert_eq!(
        bundle["platform_transcripts_sha256"].as_str(),
        Some("6f79d538f0e81025631bcc5858b7ec7fd7fbdbb5953ad1715997b54922c649e6")
    );
    assert_eq!(bundle["target_count"].as_u64(), Some(2));
    assert_eq!(bundle["transcript_count"].as_u64(), Some(6));
    assert_eq!(bundle["consumer_targets"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(1)
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));
    assert_eq!(
        bundle["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false)
    );

    for platform in ["macos", "ubuntu", "windows"] {
        for target in ["codex", "claude"] {
            let transcript = &bundle["platform_transcripts"][platform][target];
            assert_eq!(
                transcript["schema_version"].as_str(),
                Some("ao2.plugin-final-install-transcript.v1"),
                "{platform}/{target} transcript schema must be observable"
            );
            assert_eq!(
                transcript["status"].as_str(),
                Some("ready_for_plugin_consumers"),
                "{platform}/{target} transcript must be consumer-ready"
            );
            assert_eq!(
                transcript["source_schema_version"].as_str(),
                Some("ao2.k37-plugin-release-candidate-observer-bundle.v1"),
                "{platform}/{target} transcript must be pinned to the observed release candidate bundle"
            );
            assert_eq!(
                transcript["summary_sha256"].as_str(),
                Some("c172a3e234d34fc272fcad2245f44215ed0a255f5859f29b964f4e763511212d"),
                "{platform}/{target} transcript must reference the K37-observed release candidate summary"
            );
            assert_eq!(
                transcript["archive_sha256"].as_str(),
                Some("1b98c9a5055ed7f19d868cb9234d2ea1cfc3b2cfcd68af40cecdaaecde9a6790"),
                "{platform}/{target} transcript must reference the K37-observed release candidate archive"
            );
            assert_eq!(
                transcript["sha256"].as_str().map(str::len),
                Some(64),
                "{platform}/{target} transcript summary SHA256 must be recorded"
            );
            assert_eq!(
                transcript["install_transcript_sha256"]
                    .as_str()
                    .map(str::len),
                Some(64),
                "{platform}/{target} markdown transcript SHA256 must be recorded"
            );
            assert_eq!(
                transcript["consumer_targets"].as_array().map(Vec::len),
                Some(2),
                "{platform}/{target} transcript must cover Codex and Claude consumers"
            );
            assert_eq!(
                transcript["observed_evidence_scope"]
                    .as_array()
                    .map(Vec::len),
                Some(2),
                "{platform}/{target} transcript must describe release-candidate evidence scope"
            );
            assert_eq!(
                transcript["provider_auth"]["local_oauth_cli_only"].as_bool(),
                Some(true),
                "{platform}/{target} transcript must preserve local OAuth CLI-only auth"
            );
            assert_eq!(
                transcript["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
                Some(false),
                "{platform}/{target} transcript must forbid provider API-key auth"
            );
            assert_eq!(
                transcript["provider_auth"]["provider_api_key_env_required"].as_bool(),
                Some(false),
                "{platform}/{target} transcript must not require provider API-key env"
            );
            assert_side_effects_false(&transcript["side_effects"]);
            assert_eq!(
                transcript["token_safe_output_verified"].as_bool(),
                Some(true),
                "{platform}/{target} transcript must have token-safe output verified"
            );
            assert_eq!(
                transcript["trust_boundary"]["control_plane_role"].as_str(),
                Some("read_only_observer")
            );
            assert_eq!(
                transcript["trust_boundary"]["control_plane_approves_release"].as_bool(),
                Some(false)
            );
            assert_eq!(
                transcript["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
                Some(false)
            );
            assert_eq!(
                transcript["control_plane_observation"]["role"].as_str(),
                Some("read_only_observer")
            );
            assert_eq!(
                transcript["control_plane_observation"]["may_approve_release"].as_bool(),
                Some(false)
            );
            assert_eq!(
                transcript["control_plane_observation"]["may_mutate_evidence"].as_bool(),
                Some(false)
            );
        }
    }
}

#[test]
fn shipment_readiness_observer_proofs_are_read_only_three_platform_evidence() {
    for (platform, fixture) in [
        ("macos", SHIPMENT_READINESS_MACOS),
        ("ubuntu", SHIPMENT_READINESS_UBUNTU),
        ("windows", SHIPMENT_READINESS_WINDOWS),
    ] {
        let readiness = parse_fixture(fixture);

        assert_eq!(
            readiness["schema_version"].as_str(),
            Some("ao2.plugin-shipment-readiness.v1")
        );
        assert_eq!(
            readiness["status"].as_str(),
            Some("ready_for_operator_handoff"),
            "{platform} shipment-readiness proof must be operator-ready"
        );
        assert_eq!(readiness["producer"].as_str(), Some("ao2"));
        assert_eq!(
            readiness["factory_v3_role"].as_str(),
            Some("parity_auditor")
        );
        assert_eq!(
            readiness["summary_path"]
                .as_str()
                .map(|path| path.ends_with("plugin-shipment-readiness.json")),
            Some(true),
            "{platform} proof must identify the aggregate shipment-readiness summary path"
        );
        assert_eq!(
            readiness["plugin_targets"].as_array().map(Vec::len),
            Some(2),
            "{platform} proof must cover Codex and Claude plugin targets"
        );
        for target in ["codex", "claude"] {
            assert!(
                readiness["plugin_targets"]
                    .as_array()
                    .expect("plugin targets are present")
                    .iter()
                    .any(|value| value.as_str() == Some(target)),
                "{platform} proof must include {target}"
            );
        }
        assert_eq!(
            readiness["platforms"].as_array().map(Vec::len),
            Some(3),
            "{platform} proof must record three-platform coverage"
        );
        for observed_platform in ["macos", "ubuntu", "windows"] {
            assert!(
                readiness["platforms"]
                    .as_array()
                    .expect("platforms are present")
                    .iter()
                    .any(|value| value.as_str() == Some(observed_platform)),
                "{platform} proof must include {observed_platform} coverage"
            );
        }
        assert_eq!(
            readiness["shipment_inputs"].as_array().map(Vec::len),
            Some(6),
            "{platform} proof must cover all shipment input classes"
        );
        for input_schema in [
            "ao2.plugin-package.v1",
            "ao2.k37-plugin-adapter-observer-bundle.v1",
            "ao2.k37-plugin-adapter-install-smoke-observer-bundle.v1",
            "ao2.k37-plugin-consumer-lifecycle-observer-bundle.v1",
            "ao2.k37-plugin-release-candidate-observer-bundle.v1",
            "ao2.k37-plugin-final-install-transcript-observer-bundle.v1",
        ] {
            assert!(
                readiness["shipment_inputs"]
                    .as_array()
                    .expect("shipment inputs are present")
                    .iter()
                    .any(|value| value.as_str() == Some(input_schema)),
                "{platform} proof must include shipment input {input_schema}"
            );
        }
        assert_eq!(
            readiness["shipment_evidence_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} proof must pin shipment evidence"
        );
        assert_eq!(
            readiness["provider_auth"]["local_oauth_cli_only"].as_bool(),
            Some(true),
            "{platform} proof must preserve local OAuth CLI-only auth"
        );
        assert_eq!(
            readiness["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
            Some(false),
            "{platform} proof must forbid provider API-key auth"
        );
        assert_eq!(
            readiness["provider_auth"]["provider_api_key_env_required"].as_bool(),
            Some(false),
            "{platform} proof must not require provider API-key env"
        );
        assert_side_effects_false(&readiness["side_effects"]);
        assert_eq!(
            readiness["token_safe_output_verified"].as_bool(),
            Some(true),
            "{platform} proof must verify token-safe output"
        );

        let tb = &readiness["trust_boundary"];
        assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
        assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
        assert_eq!(
            tb["control_plane_role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
        assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));

        assert_eq!(
            readiness["control_plane_observation"]["role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            readiness["control_plane_observation"]["may_approve_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            readiness["control_plane_observation"]["may_mutate_evidence"].as_bool(),
            Some(false)
        );
        assert_eq!(
            readiness["control_plane_readback"]["repo"].as_str(),
            Some("ao2-control-plane")
        );
        assert_eq!(
            readiness["control_plane_readback"]["commit"].as_str(),
            Some("bd0c6426867194968ac09d230bbe59f0d25216af")
        );
        assert_eq!(
            readiness["control_plane_readback"]["role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            readiness["control_plane_readback"]["approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            readiness["control_plane_readback"]["mutated_by_this_command"].as_bool(),
            Some(false)
        );
    }
}

#[test]
fn clean_package_operator_index_is_read_only_three_platform_evidence() {
    let index = parse_fixture(CLEAN_PACKAGE_OPERATOR_INDEX);

    assert_eq!(
        index["schema_version"].as_str(),
        Some("ao2.k37-clean-package-operator-index.v1")
    );
    assert_eq!(index["status"].as_str(), Some("ready_for_k37_observation"));
    assert_top_level_observer_boundary(&index);
    assert_side_effects_false(&index["side_effects"]);
    assert_eq!(
        index["token_safe_output_verified"].as_bool(),
        Some(true),
        "clean package operator index must verify token-safe output"
    );
    assert_eq!(
        index["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true),
        "clean package operator index must preserve local OAuth CLI-only auth"
    );
    assert_eq!(
        index["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false),
        "clean package operator index must forbid provider API-key auth"
    );
    assert_eq!(
        index["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false),
        "clean package operator index must not require provider API-key env"
    );
    assert_eq!(
        index["plugin_targets"].as_array().map(Vec::len),
        Some(2),
        "clean package operator index must cover Codex and Claude"
    );
    for target in ["codex", "claude"] {
        assert!(
            index["plugin_targets"]
                .as_array()
                .expect("plugin targets are present")
                .iter()
                .any(|value| value.as_str() == Some(target)),
            "clean package operator index must include {target}"
        );
    }
    for platform in ["macos", "ubuntu", "windows"] {
        let rehearsal = &index["platform_rehearsals"][platform];
        assert_eq!(
            rehearsal["schema_version"].as_str(),
            Some("ao2.plugin-distribution-rehearsal.v1"),
            "{platform} rehearsal must be an AO2 distribution rehearsal"
        );
        assert_eq!(
            rehearsal["status"].as_str(),
            Some("passed"),
            "{platform} clean package rehearsal must have passed"
        );
        assert_eq!(
            rehearsal["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} rehearsal must be digest pinned"
        );
        assert_eq!(
            rehearsal["observer_input"]["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} observer input must be digest pinned"
        );
        for target in ["codex", "claude"] {
            assert_eq!(
                rehearsal["target_results"][target]["status"].as_str(),
                Some("passed"),
                "{platform}/{target} clean package rehearsal must pass"
            );
        }
        assert_eq!(
            rehearsal["provider_auth"]["local_oauth_cli_only"].as_bool(),
            Some(true),
            "{platform} rehearsal must preserve local OAuth CLI-only auth"
        );
        assert_eq!(
            rehearsal["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
            Some(false),
            "{platform} rehearsal must forbid provider API-key auth"
        );
        assert_eq!(
            rehearsal["control_plane_observation"]["role"].as_str(),
            Some("read_only_observer"),
            "{platform} rehearsal must preserve read-only observation"
        );
        assert_eq!(
            rehearsal["trust_boundary"]["control_plane_role"].as_str(),
            Some("read_only_observer"),
            "{platform} rehearsal trust boundary must keep control-plane observer-only"
        );
        assert_eq!(
            rehearsal["trust_boundary"]["control_plane_approves_release"].as_bool(),
            Some(false),
            "{platform} rehearsal must not approve releases"
        );
        assert_eq!(
            rehearsal["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false),
            "{platform} rehearsal must not mutate AO artifacts"
        );
        assert_eq!(
            rehearsal["token_safe_output_verified"].as_bool(),
            Some(true),
            "{platform} rehearsal must be token-safe"
        );
    }
}

#[test]
fn packaged_replacement_hardening_is_read_only_three_platform_evidence() {
    for (platform, fixture) in [
        ("macos", PACKAGED_REPLACEMENT_HARDENING_MACOS),
        ("ubuntu", PACKAGED_REPLACEMENT_HARDENING_UBUNTU),
        ("windows", PACKAGED_REPLACEMENT_HARDENING_WINDOWS),
    ] {
        let proof = parse_fixture(fixture);
        assert_eq!(
            proof["schema_version"].as_str(),
            Some("ao2.packaged-replacement-hardening.v1"),
            "{platform} proof must use the packaged replacement hardening schema"
        );
        assert_eq!(
            proof["status"].as_str(),
            Some("passed"),
            "{platform} packaged replacement hardening proof must pass before observation"
        );
        assert_eq!(
            proof["platform"].as_str(),
            Some(platform),
            "{platform} proof must identify its platform"
        );

        assert_eq!(
            proof["package"]["summary_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} package summary must be digest pinned"
        );
        assert_eq!(
            proof["package"]["archive_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} package archive must be digest pinned"
        );
        assert_eq!(
            proof["package"]["package_verify_sha256"]
                .as_str()
                .map(str::len),
            Some(64),
            "{platform} package verification must be digest pinned"
        );

        let replacement = &proof["factory_replacement"];
        for key in [
            "app_run_sha256",
            "app_run_bundle_sha256",
            "project_plan_sha256",
            "project_run_sha256",
            "release_review_package_sha256",
            "rubric_sha256",
            "project_acceptance_rubric_sha256",
        ] {
            assert_eq!(
                replacement[key].as_str().map(str::len),
                Some(64),
                "{platform} replacement field {key} must be digest pinned"
            );
        }

        assert_eq!(
            proof["provider_auth"]["local_oauth_cli_only"].as_bool(),
            Some(true),
            "{platform} proof must preserve local OAuth CLI-only auth"
        );
        assert_eq!(
            proof["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
            Some(false),
            "{platform} proof must forbid provider API-key auth"
        );

        let tb = &proof["trust_boundary"];
        assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
        assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
        assert_eq!(
            tb["control_plane_role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
        assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));

        let side_effects = &proof["side_effects"];
        for key in [
            "provider_execution",
            "queue_mutation",
            "memory_write",
            "control_plane_mutation",
            "ao_artifact_mutation",
            "release_approval",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} side effect {key} must remain false"
            );
        }

        assert_eq!(
            proof["token_safe_output"]["bearer_tokens_serialized"].as_bool(),
            Some(false),
            "{platform} proof must not serialize bearer tokens"
        );
        assert_eq!(
            proof["token_safe_output"]["cookies_serialized"].as_bool(),
            Some(false),
            "{platform} proof must not serialize cookies"
        );
        assert_eq!(
            proof["token_safe_output"]["private_keys_serialized"].as_bool(),
            Some(false),
            "{platform} proof must not serialize private keys"
        );
    }
}

#[test]
fn packaged_replacement_hardening_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(PACKAGED_REPLACEMENT_HARDENING_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-packaged-replacement-hardening-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(
        bundle["archive_sha256"].as_str(),
        Some("ef79bc17a432fd05dae3fc0957fe10766dbe95848342a8330ba8b58f228dbeca")
    );
    assert_eq!(
        bundle["platform_proofs_sha256"].as_str(),
        Some("20b4452e75dc09409f056e49cf4b5bbaae66b10d3ee953bce8810fb736b25510")
    );
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(Vec::len),
        Some(3),
        "bundle must cover macOS, Ubuntu, and Windows"
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        bundle["observed_evidence_scope"][0].as_str(),
        Some("ao2.packaged-replacement-hardening.v1")
    );
    assert_eq!(
        bundle["observed_evidence_scope"][1].as_str(),
        Some("ao2.factory-closer-decision.v1")
    );
    assert_eq!(
        bundle["observed_evidence_scope"][2].as_str(),
        Some("ao2.factory-closer-decision-verification.v1")
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));
    assert_eq!(
        bundle["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false)
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let proof = &bundle["platform_proofs"][platform];
        assert_eq!(
            proof["schema_version"].as_str(),
            Some("ao2.packaged-replacement-hardening.v1"),
            "{platform} bundled proof schema must be observable"
        );
        assert_eq!(
            proof["status"].as_str(),
            Some("passed"),
            "{platform} bundled proof must pass before observation"
        );
        assert_eq!(
            proof["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} bundled proof must be digest pinned"
        );
        assert_eq!(
            proof["source_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} source proof must preserve the source digest"
        );
        assert_eq!(
            proof["package"]["summary_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} package summary must be digest pinned"
        );
        assert_eq!(
            proof["package"]["archive_sha256"].as_str().map(str::len),
            Some(64),
            "{platform} package archive must be digest pinned"
        );
        for key in [
            "app_run_sha256",
            "app_run_bundle_sha256",
            "project_plan_sha256",
            "project_run_sha256",
            "release_review_package_sha256",
            "rubric_sha256",
            "project_acceptance_rubric_sha256",
        ] {
            assert_eq!(
                proof["factory_replacement"][key].as_str().map(str::len),
                Some(64),
                "{platform} replacement field {key} must be digest pinned"
            );
        }
        assert_eq!(
            proof["provider_auth"]["local_oauth_cli_only"].as_bool(),
            Some(true),
            "{platform} proof must preserve local OAuth CLI-only auth"
        );
        assert_eq!(
            proof["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
            Some(false),
            "{platform} proof must forbid provider API-key auth"
        );
        assert_eq!(
            proof["trust_boundary"]["control_plane_role"].as_str(),
            Some("read_only_observer")
        );
        assert_eq!(
            proof["trust_boundary"]["control_plane_approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            proof["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false)
        );

        let side_effects = &proof["side_effects"];
        for key in [
            "provider_execution",
            "queue_mutation",
            "memory_write",
            "control_plane_mutation",
            "ao_artifact_mutation",
            "release_approval",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} side effect {key} must remain false"
            );
        }
    }
    assert_eq!(
        bundle["platform_proofs"]["windows"]["normalized_utf8_bom"].as_bool(),
        Some(true),
        "Windows PowerShell proof must be normalized before read-only observation"
    );
}

#[test]
fn replacement_gate_rollup_is_read_only_ao2_produced_evidence() {
    let replacement = parse_fixture(REPLACEMENT_PARITY_VERIFICATION);
    let rollup = parse_fixture(RELEASE_GATE_WITH_REPLACEMENT_ROLLUP);

    assert_eq!(
        sha256_hex_without_fixture_newline(REPLACEMENT_PARITY_VERIFICATION),
        "84926979976122f50d8a5269265ac54ce25c2ec64a4de502fc01b212997d0f64"
    );
    assert_eq!(
        sha256_hex_without_fixture_newline(RELEASE_GATE_WITH_REPLACEMENT_ROLLUP),
        "ab54de09a5a314ab6d0a5a37f12e3d6162143339a28ca51ea83099b9031b9cb2"
    );

    assert_eq!(
        replacement["schema_version"].as_str(),
        Some("ao2.replacement-parity-verification.v1")
    );
    assert_eq!(
        rollup["schema_version"].as_str(),
        Some("ao2.release-gate-with-replacement-parity.v1")
    );

    for evidence in [&replacement, &rollup] {
        assert_eq!(
            evidence["ao2_git_head"].as_str(),
            Some("b762fa7b5224bba9c45ae5c61776d9ecc9da1b6b")
        );
        assert_eq!(evidence["overall_verdict"].as_str(), Some("PASS"));
        assert_eq!(
            evidence["trust_boundary"]["ao2_role"].as_str(),
            Some("canonical_producer")
        );
        assert_eq!(
            evidence["trust_boundary"]["factory_v3_role"].as_str(),
            Some("parity_oracle_only")
        );
        assert_eq!(
            evidence["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false)
        );
        assert_eq!(
            evidence["trust_boundary"]["mutates_control_plane"].as_bool(),
            Some(false)
        );
    }

    assert_eq!(replacement["counts"]["failed"].as_u64(), Some(0));
    assert_eq!(replacement["counts"]["passed"].as_u64(), Some(4));
    assert_eq!(replacement["counts"]["total_steps"].as_u64(), Some(4));
    let replacement_steps = replacement["steps"]
        .as_array()
        .expect("replacement parity steps must be an array");
    assert_eq!(replacement_steps.len(), 4);
    assert_eq!(
        replacement_steps
            .iter()
            .map(|step| step["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![
            "provider_readiness_producer",
            "factory_v3_parity_oracle",
            "provider_contract_verify_all",
            "license_provenance_gate",
        ]
    );
    assert!(replacement_steps
        .iter()
        .all(|step| step["status"].as_str() == Some("PASS")));

    assert_eq!(rollup["counts"]["non_passed"].as_u64(), Some(0));
    assert_eq!(rollup["counts"]["passed"].as_u64(), Some(3));
    assert_eq!(rollup["counts"]["total_stages"].as_u64(), Some(3));
    let stages = rollup["stages"]
        .as_array()
        .expect("release gate stages must be an array");
    assert_eq!(stages.len(), 3);
    assert_eq!(
        stages
            .iter()
            .map(|stage| stage["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![
            "no_factory_v3_green_path",
            "replacement_parity",
            "release_gate",
        ]
    );
    assert!(stages
        .iter()
        .all(|stage| stage["status"].as_str() == Some("PASS")));
    assert_eq!(stages[1]["detail"].as_str(), Some("passed=4/4"));
}

#[test]
fn replacement_gate_rollups_observe_three_platform_current_proof() {
    let cases = [
        (
            "macos",
            REPLACEMENT_PARITY_VERIFICATION_MACOS,
            "5e40cdf6e610277408ceb861badcb079676dc1f1b7a504ef625e4497104b32d1",
            RELEASE_GATE_ROLLUP_MACOS,
            "9e537e308104630d46637310971403e9a0a4ac086aad4962c52a3b4b4d24eac5",
        ),
        (
            "ubuntu",
            REPLACEMENT_PARITY_VERIFICATION_UBUNTU,
            "7b01a88348a60e775e5a17b12d78f6f7fd7ee6266c0018400c7d9f98ab18fd50",
            RELEASE_GATE_ROLLUP_UBUNTU,
            "7c61ef56687ab6f5231504b8001816635cf3464babf02eff7b26e009a977170c",
        ),
        (
            "windows",
            REPLACEMENT_PARITY_VERIFICATION_WINDOWS,
            "8b708bd2dc66f5fb246c79ac9cbf7315cf258952544391d9e450b9a9a440afaf",
            RELEASE_GATE_ROLLUP_WINDOWS,
            "377e2935afd7bf2ff777a7e2afa1f5ba9ad1135a61de44b4fa0b243d17bf9eb2",
        ),
    ];

    for (platform, replacement_text, replacement_sha, rollup_text, rollup_sha) in cases {
        assert_eq!(
            sha256_hex_without_fixture_newline(replacement_text),
            replacement_sha,
            "{platform} replacement parity fixture must be digest pinned"
        );
        assert_eq!(
            sha256_hex_without_fixture_newline(rollup_text),
            rollup_sha,
            "{platform} release-gate rollup fixture must be digest pinned"
        );

        let replacement = parse_fixture(replacement_text);
        let rollup = parse_fixture(rollup_text);

        assert_eq!(
            replacement["schema_version"].as_str(),
            Some("ao2.replacement-parity-verification.v1"),
            "{platform} replacement parity schema must remain AO2-produced"
        );
        assert_eq!(
            rollup["schema_version"].as_str(),
            Some("ao2.release-gate-with-replacement-parity.v1"),
            "{platform} release-gate rollup schema must remain AO2-produced"
        );

        for evidence in [&replacement, &rollup] {
            assert_eq!(
                evidence["ao2_git_head"].as_str(),
                Some("b762fa7b5224bba9c45ae5c61776d9ecc9da1b6b"),
                "{platform} evidence must observe current AO2 replacement-hardening commit"
            );
            assert_eq!(
                evidence["overall_verdict"].as_str(),
                Some("PASS"),
                "{platform} evidence must be passing before K37 observation"
            );
            assert_eq!(
                evidence["trust_boundary"]["ao2_role"].as_str(),
                Some("canonical_producer"),
                "{platform} evidence must keep AO2 as producer"
            );
            assert_eq!(
                evidence["trust_boundary"]["factory_v3_role"].as_str(),
                Some("parity_oracle_only"),
                "{platform} evidence must keep factory-v3 read-only"
            );
            assert_eq!(
                evidence["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
                Some(false),
                "{platform} evidence must not mutate AO artifacts"
            );
            assert_eq!(
                evidence["trust_boundary"]["mutates_control_plane"].as_bool(),
                Some(false),
                "{platform} evidence must not mutate control-plane state"
            );
        }

        assert_eq!(
            replacement["counts"]["failed"].as_u64(),
            Some(0),
            "{platform} replacement parity must have no failed steps"
        );
        assert_eq!(
            replacement["counts"]["passed"].as_u64(),
            Some(4),
            "{platform} replacement parity must pass all four steps"
        );
        assert_eq!(
            rollup["counts"]["non_passed"].as_u64(),
            Some(0),
            "{platform} release-gate rollup must have no non-passing stages"
        );
        assert_eq!(
            rollup["counts"]["passed"].as_u64(),
            Some(3),
            "{platform} release-gate rollup must pass all three stages"
        );
        assert_eq!(
            rollup["stages"][1]["detail"].as_str(),
            Some("passed=4/4"),
            "{platform} release gate must be bound to passing replacement parity"
        );
    }
}

#[test]
fn release_gate_with_replacement_observer_bundle_is_read_only_current_three_platform_proof() {
    assert_eq!(
        sha256_hex_without_fixture_newline(RELEASE_GATE_WITH_REPLACEMENT_OBSERVER_BUNDLE),
        "bc0fb7b555b221b6d3bdd8f2aa5230de896ce697f9075b2b257f3ea8f1776a8a"
    );
    let bundle = parse_fixture(RELEASE_GATE_WITH_REPLACEMENT_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-release-gate-with-replacement-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));
    assert_eq!(
        bundle["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["observed_evidence_scope"],
        serde_json::json!(["ao2.release-gate-with-replacement-parity.v1"])
    );
    assert_eq!(
        bundle["platforms"],
        serde_json::json!(["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        bundle["platform_rollups_sha256"].as_str().map(str::len),
        Some(64)
    );

    let rollups = bundle["platform_rollups"]
        .as_object()
        .expect("platform rollups must be an object");
    for (platform, expected_sha) in [
        (
            "macos",
            "635af8a6765c04468558d67247fd3b84edfaa97eb722b99058efd4af126f13bd",
        ),
        (
            "ubuntu",
            "56f1da7033e516dfc941fe8962ffa1a1c07d424d38d2340aa4d1647af107ba1a",
        ),
        (
            "windows",
            "63398b3deb7d93a898847f4233e0c9ae88cd0990503d7b5d2459db3beca6a85a",
        ),
    ] {
        let rollup = rollups.get(platform).expect("platform rollup present");
        assert_eq!(
            rollup["schema_version"].as_str(),
            Some("ao2.release-gate-with-replacement-parity.v1")
        );
        assert_eq!(rollup["sha256"].as_str(), Some(expected_sha));
        assert_eq!(
            rollup["ao2_git_head"].as_str(),
            Some("6c2aa6725e2358113c10b565a5df4425c5374e13")
        );
        assert_eq!(rollup["overall_verdict"].as_str(), Some("PASS"));
        assert_eq!(rollup["counts"]["non_passed"].as_u64(), Some(0));
        assert_eq!(rollup["counts"]["passed"].as_u64(), Some(7));
        assert_eq!(rollup["counts"]["total_stages"].as_u64(), Some(7));
        assert_eq!(
            rollup["trust_boundary"]["ao2_role"].as_str(),
            Some("canonical_producer")
        );
        assert_eq!(
            rollup["trust_boundary"]["factory_v3_role"].as_str(),
            Some("parity_oracle_only")
        );
        assert_eq!(
            rollup["trust_boundary"]["mutates_ao_artifacts"].as_bool(),
            Some(false)
        );
        assert_eq!(
            rollup["trust_boundary"]["mutates_control_plane"].as_bool(),
            Some(false)
        );
    }
}

#[test]
fn self_contained_plugin_package_observer_bundle_is_read_only_three_platform_evidence() {
    let bundle = parse_fixture(SELF_CONTAINED_PLUGIN_PACKAGE_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-self-contained-plugin-package-observer-bundle.v1")
    );
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["source_commit"].as_str().map(str::len), Some(40));
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(Vec::len),
        Some(3),
        "self-contained package observation must cover macOS, Ubuntu, and Windows"
    );
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        bundle["observed_evidence_scope"][0].as_str(),
        Some("ao2.plugin-package.v1")
    );
    assert_eq!(
        bundle["observed_evidence_scope"][1].as_str(),
        Some("ao2.plugin-package-verification.v1")
    );
    assert_eq!(
        bundle["observed_evidence_scope"][2].as_str(),
        Some("ao2.plugin-wrapper-harness.v1")
    );
    assert_top_level_observer_boundary(&bundle);
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["token_safe_output_verified"].as_bool(), Some(true));
    assert_eq!(
        bundle["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false)
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let proof = &bundle["platform_proofs"][platform];
        assert_eq!(
            proof["package_summary"]["schema_version"].as_str(),
            Some("ao2.plugin-package.v1"),
            "{platform} package summary schema must be observable"
        );
        assert_eq!(
            proof["package_summary"]["status"].as_str(),
            Some("packaged"),
            "{platform} package must be packaged before observation"
        );
        assert_eq!(
            proof["package_verification"]["schema_version"].as_str(),
            Some("ao2.plugin-package-verification.v1"),
            "{platform} package verification schema must be observable"
        );
        assert_eq!(
            proof["package_verification"]["status"].as_str(),
            Some("passed"),
            "{platform} package verification must pass before observation"
        );

        for (scope, value) in [
            ("package summary", &proof["package_summary"]),
            ("package verification", &proof["package_verification"]),
            ("app wrapper harness", &proof["wrapper_harness"]["app_run"]),
            (
                "project wrapper harness",
                &proof["wrapper_harness"]["project_run"],
            ),
        ] {
            assert_eq!(
                value["sha256"].as_str().map(str::len),
                Some(64),
                "{platform} {scope} must preserve the observed source digest"
            );
            assert!(
                value["path"].as_str().is_some_and(|path| !path.is_empty()),
                "{platform} {scope} must retain the observed evidence path"
            );
        }

        for key in [
            "archive_sha256",
            "manifest_sha256",
            "manifest_verification_sha256",
            "install_smoke_sha256",
        ] {
            assert_eq!(
                proof["package_summary"][key].as_str().map(str::len),
                Some(64),
                "{platform} package summary field {key} must be digest pinned"
            );
        }

        for run_kind in ["app_run", "project_run"] {
            let wrapper = &proof["wrapper_harness"][run_kind];
            assert_eq!(
                wrapper["schema_version"].as_str(),
                Some("ao2.plugin-wrapper-harness.v1"),
                "{platform} {run_kind} wrapper schema must be observable"
            );
            assert_eq!(
                wrapper["status"].as_str(),
                Some("accepted"),
                "{platform} {run_kind} wrapper must be accepted before observation"
            );
            assert_eq!(
                wrapper["args_sha256"].as_str().map(str::len),
                Some(64),
                "{platform} {run_kind} wrapper args must be digest pinned"
            );
            assert_eq!(
                wrapper["readiness_sha256"].as_str().map(str::len),
                Some(64),
                "{platform} {run_kind} readiness must be digest pinned"
            );
        }
    }

    assert_eq!(
        bundle["platform_proofs"]["windows"]["normalized_utf8_bom"].as_bool(),
        Some(true),
        "Windows PowerShell evidence must be normalized before observation"
    );
}

#[test]
fn skill_contract_manifest_is_read_only_replacement_parity_evidence() {
    let manifest = parse_fixture(SKILL_CONTRACT_MANIFEST);

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("ao2.skill-contract-manifest.v1")
    );
    assert_eq!(manifest["status"].as_str(), Some("accepted"));
    assert_eq!(manifest["producer"].as_str(), Some("ao2"));
    assert_eq!(manifest["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(manifest["entry_count"].as_u64(), Some(7));
    assert_eq!(
        manifest["guardrails"]["runtime_critical_checked"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["guardrails"]["runtime_critical_requires_enforcement_or_blocker"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["guardrails"]["raw_factory_v3_skill_copy_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["provider_auth"]["provider_api_key_env_required"].as_bool(),
        Some(false)
    );

    let tb = &manifest["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
    assert_eq!(
        tb["release_acceptance_owner"].as_str(),
        Some("factory-v3 evaluator-closer")
    );

    assert_eq!(
        manifest["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        manifest["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&manifest["side_effects"]);
    assert_eq!(manifest["token_safe_output_verified"].as_bool(), Some(true));

    let required = manifest["required_inventory"]
        .as_array()
        .expect("required inventory is present");
    for name in [
        "intake",
        "closure_verification",
        "evaluator_closer_acceptance",
        "provider_auth_rules",
        "redaction_token_safety",
        "cross_platform_proof",
        "plugin_shipment_runbook_rules",
    ] {
        assert!(
            required.iter().any(|value| value.as_str() == Some(name)),
            "skill-contract manifest must require {name}"
        );
    }

    let entries = manifest["entries"].as_array().expect("entries are present");
    assert_eq!(entries.len(), 7);
    for entry in entries {
        let name = entry["name"].as_str().expect("entry has name");
        assert_eq!(entry["source_repo"].as_str(), Some("factory-v3"));
        assert!(
            entry["source_path"]
                .as_str()
                .is_some_and(|path| !path.is_empty()),
            "{name} must include source path"
        );
        assert!(
            entry["source_sha256"]
                .as_str()
                .is_some_and(|sha| sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit())),
            "{name} must include source sha256"
        );
        assert!(
            entry["trust_boundary_notes"]
                .as_str()
                .is_some_and(|notes| !notes.is_empty()),
            "{name} must include trust-boundary notes"
        );
        if entry["category"].as_str() == Some("runtime_critical") {
            let enforcement = &entry["enforcement"];
            let has_enforcement = ["ao2_command", "ao2_test", "ao2_artifact"]
                .iter()
                .all(|key| {
                    enforcement[*key]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                });
            let has_blocker = entry["blocker"]
                .as_str()
                .is_some_and(|value| !value.is_empty());
            assert!(
                has_enforcement || has_blocker,
                "runtime-critical entry {name} must be enforced or explicitly blocked"
            );
        }
    }

    let closure = entries
        .iter()
        .find(|entry| entry["name"].as_str() == Some("closure_verification"))
        .expect("closure entry exists");
    assert_eq!(closure["ao2_disposition"].as_str(), Some("enforced"));
    assert_eq!(
        closure["enforcement"]["ao2_command"].as_str(),
        Some("ao2 factory closer-decision")
    );
    assert_eq!(
        closure["enforcement"]["ao2_artifact"].as_str(),
        Some("ao2.factory-closer-decision.v1")
    );
    assert!(closure["blocker"].is_null());
}

#[test]
fn closer_decision_is_read_only_signed_replacement_parity_evidence() {
    let decision = parse_fixture(CLOSER_DECISION);

    assert_eq!(
        decision["schema_version"].as_str(),
        Some("ao2.factory-closer-decision.v1")
    );
    assert_eq!(decision["status"].as_str(), Some("accepted"));
    assert_eq!(decision["decision"].as_str(), Some("accepted"));
    assert_eq!(decision["producer"].as_str(), Some("ao2"));
    assert_eq!(decision["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        decision["rubric"]["schema_version"].as_str(),
        Some("ao2.factory-evaluator-rubric.v1")
    );
    assert_eq!(decision["rubric"]["status"].as_str(), Some("accepted"));
    assert_eq!(
        decision["rubric"]["signature_status"].as_str(),
        Some("signed")
    );
    assert_eq!(
        decision["rubric"]["signature_verified"].as_bool(),
        Some(true)
    );
    assert!(decision["rubric_sha256"]
        .as_str()
        .is_some_and(|sha| sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit())));
    assert!(decision["evidence_sha256"]
        .as_str()
        .is_some_and(|sha| sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit())));
    assert!(decision["skill_contract_manifest_sha256"]
        .as_str()
        .is_some_and(|sha| sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit())));
    assert_eq!(
        decision["skill_contract_manifest_sha256"].as_str(),
        Some(sha256_hex(SKILL_CONTRACT_MANIFEST).as_str()),
        "closer decision must be digest-bound to the observed skill-contract manifest"
    );

    let closure = &decision["closure_verification"];
    assert_eq!(closure["name"].as_str(), Some("closure_verification"));
    assert_eq!(closure["category"].as_str(), Some("runtime_critical"));
    assert_eq!(closure["ao2_disposition"].as_str(), Some("enforced"));
    assert_eq!(
        closure["enforcement"]["ao2_command"].as_str(),
        Some("ao2 factory closer-decision")
    );
    assert_eq!(
        closure["enforcement"]["ao2_artifact"].as_str(),
        Some("ao2.factory-closer-decision.v1")
    );
    assert!(closure["blocker"].is_null());

    assert_eq!(
        decision["provider_auth"]["local_oauth_cli_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        decision["provider_auth"]["provider_api_key_auth_allowed"].as_bool(),
        Some(false)
    );
    let tb = &decision["trust_boundary"];
    assert_eq!(tb["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(tb["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        tb["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(tb["mutates_ao_artifacts"].as_bool(), Some(false));
    assert_eq!(tb["control_plane_approves_release"].as_bool(), Some(false));
    assert_eq!(
        decision["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        decision["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        decision["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&decision["side_effects"]);
    assert_eq!(decision["token_safe_output_verified"].as_bool(), Some(true));

    assert_eq!(
        decision["signature"]["schema_version"].as_str(),
        Some("ao2.factory-closer-decision-signature.v1")
    );
    assert_eq!(
        decision["signature"]["signature_status"].as_str(),
        Some("signed")
    );
    assert_eq!(
        decision["signature"]["signature_verified"].as_bool(),
        Some(true)
    );
}

#[test]
fn pulse_executor_observer_bundle_is_read_only_ao2_produced_evidence() {
    let bundle = read_fixture(PULSE_EXECUTOR_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-pulse-executor-observer-bundle.v1")
    );
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(
        bundle["current_ao2_head"].as_str(),
        Some("d968ada29f8706314a7555c43af7d63742b7968d")
    );
    assert_eq!(
        bundle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );

    let c85 = &bundle["c85"];
    assert_eq!(c85["status"].as_str(), Some("passed"));
    assert_eq!(c85["hosted_github_actions_checked"].as_bool(), Some(true));
    assert_eq!(
        c85["rerun_allowed_without_user_billing_fix"].as_bool(),
        Some(true)
    );

    let side_effects = &bundle["side_effects"];
    for key in [
        "control_plane_mutation",
        "hermes_cron_watchdog_mutation",
        "memory_write",
        "mutates_ao_artifacts",
        "provider_execution",
        "queue_execution",
    ] {
        assert_eq!(
            side_effects[key].as_bool(),
            Some(false),
            "pulse observer bundle side effect {key} must remain false"
        );
    }

    let task_result_observation = &bundle["task_result_observation"];
    assert_eq!(
        task_result_observation["schema_version"].as_str(),
        Some("ao2.k37-pulse-task-result-observation.v1")
    );
    assert_eq!(
        task_result_observation["status"].as_str(),
        Some("ready_for_k37_observation")
    );
    assert_eq!(
        task_result_observation["required_schema_version"].as_str(),
        Some("ao2.pulse-task-result.v1")
    );
    assert_eq!(
        task_result_observation["source_ao2_head"].as_str(),
        Some("d968ada29f8706314a7555c43af7d63742b7968d")
    );
    let task_result_platforms: Vec<&str> = task_result_observation["observed_platforms"]
        .as_array()
        .expect("task-result observation lists observed platforms")
        .iter()
        .map(|platform| {
            platform
                .as_str()
                .expect("task-result observed platform is a string")
        })
        .collect();
    assert_eq!(task_result_platforms, vec!["macos", "ubuntu", "windows"]);
    assert_eq!(
        task_result_observation["unavailable_platforms"]
            .as_object()
            .map(serde_json::Map::len),
        Some(0)
    );
    let platform_progress = &bundle["platform_progress"];
    assert_eq!(
        platform_progress["schema_version"].as_str(),
        Some("ao2.pulse-platform-progress.v1")
    );
    assert_eq!(platform_progress["status"].as_str(), Some("closure_ready"));
    assert_eq!(
        platform_progress["required_platforms"],
        serde_json::json!(["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        platform_progress["blocked_platforms"],
        serde_json::json!([])
    );
    assert_eq!(
        platform_progress["windows"]["current_state"].as_str(),
        Some("closure_ready"),
        "Windows progress must be explicit so macOS requests cannot be mistaken for completed Windows proof"
    );
    assert_eq!(
        platform_progress["windows"]["state_history"],
        serde_json::json!([
            "pending",
            "reachable",
            "staged",
            "running",
            "passed",
            "evidence_collected",
            "closure_ready"
        ])
    );
    let dry_run_task_observation = &bundle["dry_run_task_observation"];
    assert_eq!(
        dry_run_task_observation["schema_version"].as_str(),
        Some("ao2.k37-pulse-dry-run-task-observation.v1")
    );
    assert_eq!(
        dry_run_task_observation["status"].as_str(),
        Some("not_collected_in_current_executor_refresh")
    );
    assert_eq!(
        dry_run_task_observation["required_schema_version"].as_str(),
        Some("ao2.pulse-dry-run-task.v1")
    );
    assert_eq!(
        dry_run_task_observation["source_ao2_head"].as_str(),
        Some("d968ada29f8706314a7555c43af7d63742b7968d")
    );
    let dry_run_task_platforms: Vec<&str> = dry_run_task_observation["observed_platforms"]
        .as_array()
        .expect("dry-run task observation lists observed platforms")
        .iter()
        .map(|platform| {
            platform
                .as_str()
                .expect("dry-run observed platform is a string")
        })
        .collect();
    assert!(dry_run_task_platforms.is_empty());
    assert_eq!(
        dry_run_task_observation["unavailable_platforms"]
            .as_object()
            .map(serde_json::Map::len),
        Some(3)
    );
    let apply_result_observation = &bundle["apply_result_observation"];
    assert_eq!(
        apply_result_observation["schema_version"].as_str(),
        Some("ao2.k37-pulse-apply-result-observation.v1")
    );
    assert_eq!(
        apply_result_observation["status"].as_str(),
        Some("not_collected_in_current_executor_refresh")
    );
    assert_eq!(
        apply_result_observation["required_schema_version"].as_str(),
        Some("ao2.pulse-apply-result.v1")
    );
    assert_eq!(
        apply_result_observation["source_ao2_head"].as_str(),
        Some("d968ada29f8706314a7555c43af7d63742b7968d")
    );
    let apply_result_platforms: Vec<&str> = apply_result_observation["observed_platforms"]
        .as_array()
        .expect("apply-result observation lists observed platforms")
        .iter()
        .map(|platform| {
            platform
                .as_str()
                .expect("apply-result observed platform is a string")
        })
        .collect();
    assert!(apply_result_platforms.is_empty());
    assert_eq!(
        apply_result_observation["unavailable_platforms"]
            .as_object()
            .map(serde_json::Map::len),
        Some(3)
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let evidence = &bundle["platform_evidence"][platform];
        assert_eq!(
            evidence["schema_version"].as_str(),
            Some("ao2.pulse-executor.v1"),
            "{platform} Pulse executor evidence must stay AO2-produced"
        );
        assert_eq!(
            evidence["status"].as_str(),
            if dry_run_task_platforms.contains(&platform) {
                Some("executed_dry_run_task")
            } else {
                Some("executed_governed_task")
            },
            "{platform} Pulse executor evidence must include governed task execution"
        );
        assert_eq!(
            evidence["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} Pulse executor evidence must be digest-pinned"
        );
        assert_eq!(
            evidence["c85"]["status"].as_str(),
            Some("passed"),
            "{platform} Pulse executor evidence must carry post-C85 passed state"
        );
        assert_eq!(
            evidence["c85"]["hosted_github_actions_checked"].as_bool(),
            Some(true),
            "{platform} Pulse executor evidence must be tied to checked C85"
        );
        assert_eq!(
            evidence["selected_task"]["c85"].as_bool(),
            Some(false),
            "{platform} selected task must not be C85 while billing is blocked"
        );
        assert_eq!(
            evidence["selected_task"]["classification"].as_str(),
            Some("COMPLEX"),
            "{platform} selected task must preserve task contract classification"
        );
        assert_eq!(
            evidence["selected_task"]["shape"].as_str(),
            Some("governed_eval_loop_chain"),
            "{platform} selected task must preserve task contract shape"
        );

        let evidence_side_effects = &evidence["side_effects"];
        for key in [
            "control_plane_mutation",
            "hermes_cron_watchdog_mutation",
            "memory_write",
            "mutates_ao_artifacts",
            "provider_execution",
            "queue_execution",
        ] {
            assert_eq!(
                evidence_side_effects[key].as_bool(),
                Some(false),
                "{platform} Pulse executor side effect {key} must remain false"
            );
        }

        let task_contract = &evidence["task_contract"];
        assert_eq!(
            task_contract["schema_version"].as_str(),
            Some("ao2.pulse-task-contract.v1"),
            "{platform} Pulse executor evidence must be task-contract backed"
        );
        assert_eq!(
            task_contract["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} task contract must be digest-pinned"
        );
        assert_eq!(
            task_contract["id"].as_str(),
            evidence["selected_task"]["id"].as_str(),
            "{platform} task contract id must match selected task id"
        );

        let governed_task = &evidence["governed_task_evidence"];
        assert_eq!(
            governed_task["schema_version"].as_str(),
            Some("ao2.pulse-governed-task.v1"),
            "{platform} governed task evidence must stay AO2-produced"
        );
        assert_eq!(
            governed_task["status"].as_str(),
            Some("accepted"),
            "{platform} governed task evidence must be evaluator/closer accepted"
        );
        assert_eq!(
            governed_task["c85"]["status"].as_str(),
            Some("passed"),
            "{platform} governed task evidence must carry post-C85 passed state"
        );
        assert_eq!(
            governed_task["sha256"].as_str(),
            evidence["artifacts"]["governed_task_evidence_sha256"].as_str(),
            "{platform} governed task digest must match executor artifact digest"
        );
        assert_eq!(
            governed_task["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} governed task evidence must be digest-pinned"
        );
        assert_eq!(
            governed_task["task_contract"]["schema_version"].as_str(),
            Some("ao2.pulse-task-contract.v1"),
            "{platform} governed task evidence must carry task contract schema"
        );
        assert_eq!(
            governed_task["task_contract"]["sha256"].as_str(),
            task_contract["sha256"].as_str(),
            "{platform} governed task task-contract digest must match executor"
        );
        assert_eq!(
            governed_task["executed_task"]["execution_kind"].as_str(),
            Some("governed_task_contract"),
            "{platform} executed task must be a governed task contract"
        );
        assert_eq!(
            governed_task["executed_task"]["evaluator_closer"]["release_acceptance_owner"].as_str(),
            Some("factory-v3 evaluator-closer"),
            "{platform} governed task acceptance must remain with factory-v3 evaluator/closer"
        );
        assert_eq!(
            governed_task["trust_boundary"]["control_plane_observer_only"].as_bool(),
            Some(true),
            "{platform} governed task evidence must keep control plane observer-only"
        );

        if task_result_platforms.contains(&platform) {
            let task_result = &evidence["pulse_task_result"];
            assert_eq!(
                task_result["schema_version"].as_str(),
                Some("ao2.pulse-task-result.v1"),
                "{platform} task result evidence must stay AO2-produced"
            );
            assert_eq!(
                task_result["status"].as_str(),
                Some("accepted"),
                "{platform} task result must be evaluator/closer accepted"
            );
            assert_eq!(
                task_result["c85"]["status"].as_str(),
                Some("passed"),
                "{platform} task result must carry post-C85 passed state"
            );
            assert_eq!(
                task_result["execution_mode"].as_str(),
                Some("deterministic_local_evidence"),
                "{platform} task result must preserve deterministic execution mode"
            );
            assert_eq!(
                task_result["sha256"].as_str(),
                evidence["artifacts"]["pulse_task_result_sha256"].as_str(),
                "{platform} task result digest must match executor artifact digest"
            );
            assert_eq!(
                task_result["sha256"].as_str().map(str::len),
                Some(64),
                "{platform} task result evidence must be digest-pinned"
            );
            assert_eq!(
                task_result["task_contract"]["sha256"].as_str(),
                task_contract["sha256"].as_str(),
                "{platform} task result task-contract digest must match executor"
            );
            assert_eq!(
                task_result["prior_chain"]["sha256"].as_str(),
                evidence["prior_chain"]["sha256"].as_str(),
                "{platform} task result chain digest must match executor"
            );
            assert_eq!(
                task_result["governed_task_evidence"]["sha256"].as_str(),
                governed_task["sha256"].as_str(),
                "{platform} task result must bind the governed-task evidence digest"
            );
            assert_eq!(
                task_result["evaluator_closer"]["release_acceptance_owner"].as_str(),
                Some("factory-v3 evaluator-closer"),
                "{platform} task result acceptance must remain with factory-v3 evaluator/closer"
            );
            assert_eq!(
                task_result["selected_task"]["c85"].as_bool(),
                Some(false),
                "{platform} task result selected task must not be C85"
            );
            assert_eq!(
                task_result["trust_boundary"]["control_plane_observer_only"].as_bool(),
                Some(true),
                "{platform} task result must keep control plane observer-only"
            );
            let task_result_side_effects = &task_result["side_effects"];
            for key in [
                "control_plane_mutation",
                "hermes_cron_watchdog_mutation",
                "memory_write",
                "mutates_ao_artifacts",
                "provider_execution",
                "queue_execution",
            ] {
                assert_eq!(
                    task_result_side_effects[key].as_bool(),
                    Some(false),
                    "{platform} Pulse task-result side effect {key} must remain false"
                );
            }
        } else {
            assert!(
                task_result_observation["unavailable_platforms"][platform].is_object(),
                "{platform} without task-result evidence must be recorded unavailable"
            );
        }

        if dry_run_task_platforms.contains(&platform) {
            let dry_run_task = &evidence["pulse_dry_run_task"];
            assert_eq!(
                dry_run_task["schema_version"].as_str(),
                Some("ao2.pulse-dry-run-task.v1"),
                "{platform} dry-run task evidence must stay AO2-produced"
            );
            assert_eq!(
                dry_run_task["status"].as_str(),
                Some("planned_without_mutation"),
                "{platform} dry-run task must plan without mutation"
            );
            assert_eq!(
                dry_run_task["execution_mode"].as_str(),
                Some("dry_run_planned_file_operations"),
                "{platform} dry-run task must expose planned file operations"
            );
            assert_eq!(
                dry_run_task["sha256"].as_str(),
                evidence["artifacts"]["pulse_dry_run_task_sha256"].as_str(),
                "{platform} dry-run task digest must match executor artifact digest"
            );
            assert_eq!(
                dry_run_task["sha256"].as_str().map(str::len),
                Some(64),
                "{platform} dry-run task evidence must be digest-pinned"
            );
            assert_eq!(
                dry_run_task["task_contract"]["sha256"].as_str(),
                task_contract["sha256"].as_str(),
                "{platform} dry-run task contract digest must match executor"
            );
            assert_eq!(
                dry_run_task["governed_task_evidence"]["sha256"].as_str(),
                governed_task["sha256"].as_str(),
                "{platform} dry-run task must bind governed-task evidence"
            );
            assert_eq!(
                dry_run_task["task_result"]["sha256"].as_str(),
                evidence["artifacts"]["pulse_task_result_sha256"].as_str(),
                "{platform} dry-run task must bind task-result evidence"
            );
            assert_eq!(
                dry_run_task["planned_file_operations"]
                    .as_array()
                    .map(Vec::len),
                Some(3),
                "{platform} dry-run task must expose three planned file operations"
            );
            for operation in dry_run_task["planned_file_operations"]
                .as_array()
                .expect("dry-run task planned operations are an array")
            {
                assert_eq!(
                    operation["executed"].as_bool(),
                    Some(false),
                    "{platform} dry-run task operation must not execute"
                );
                assert_eq!(
                    operation["mode"].as_str(),
                    Some("planned_only"),
                    "{platform} dry-run task operation must be planned-only"
                );
            }
            assert_eq!(
                dry_run_task["trust_boundary"]["control_plane_observer_only"].as_bool(),
                Some(true),
                "{platform} dry-run task must keep control plane observer-only"
            );
            let dry_run_side_effects = &dry_run_task["side_effects"];
            for key in [
                "control_plane_mutation",
                "hermes_cron_watchdog_mutation",
                "memory_write",
                "mutates_ao_artifacts",
                "provider_execution",
                "queue_execution",
            ] {
                assert_eq!(
                    dry_run_side_effects[key].as_bool(),
                    Some(false),
                    "{platform} Pulse dry-run side effect {key} must remain false"
                );
            }
        } else {
            assert!(
                dry_run_task_observation["unavailable_platforms"][platform].is_object(),
                "{platform} without dry-run task evidence must be recorded unavailable"
            );
        }

        if apply_result_platforms.contains(&platform) {
            let apply_result = &evidence["pulse_apply_result"];
            assert_eq!(
                apply_result["schema_version"].as_str(),
                Some("ao2.pulse-apply-result.v1"),
                "{platform} apply result evidence must stay AO2-produced"
            );
            assert_eq!(
                apply_result["status"].as_str(),
                Some("accepted"),
                "{platform} apply result must be evaluator/closer accepted"
            );
            assert_eq!(
                apply_result["execution_mode"].as_str(),
                Some("bounded_planned_file_apply"),
                "{platform} apply result must be bounded to planned file operations"
            );
            assert_eq!(
                apply_result["sha256"].as_str(),
                evidence["artifacts"]["pulse_apply_result_sha256"].as_str(),
                "{platform} apply result digest must match executor artifact digest"
            );
            assert_eq!(
                apply_result["sha256"].as_str().map(str::len),
                Some(64),
                "{platform} apply result evidence must be digest-pinned"
            );
            assert_eq!(
                apply_result["dry_run_task"]["sha256"].as_str(),
                evidence["artifacts"]["pulse_dry_run_task_sha256"].as_str(),
                "{platform} apply result must bind the exact dry-run task digest"
            );
            assert_eq!(
                apply_result["task_contract"]["sha256"].as_str(),
                task_contract["sha256"].as_str(),
                "{platform} apply result task-contract digest must match executor"
            );
            assert_eq!(
                apply_result["governed_task_evidence"]["sha256"].as_str(),
                governed_task["sha256"].as_str(),
                "{platform} apply result must bind governed-task evidence"
            );
            assert_eq!(
                apply_result["task_result"]["sha256"].as_str(),
                evidence["artifacts"]["pulse_task_result_sha256"].as_str(),
                "{platform} apply result must bind task-result evidence"
            );
            assert_eq!(
                apply_result["evaluator_closer"]["release_acceptance_owner"].as_str(),
                Some("factory-v3 evaluator-closer"),
                "{platform} apply result acceptance must remain with factory-v3 evaluator/closer"
            );
            assert_eq!(
                apply_result["applied_file_operations"]
                    .as_array()
                    .map(Vec::len),
                Some(3),
                "{platform} apply result must record exactly three applied operations"
            );
            for operation in apply_result["applied_file_operations"]
                .as_array()
                .expect("apply result operations are an array")
            {
                assert_eq!(
                    operation["allowed_by_dry_run"].as_bool(),
                    Some(true),
                    "{platform} apply operation must be allowed by the dry-run evidence"
                );
                assert_eq!(
                    operation["executed"].as_bool(),
                    Some(true),
                    "{platform} apply operation must be marked executed"
                );
            }
            let apply_side_effects = &apply_result["side_effects"];
            for key in [
                "control_plane_mutation",
                "hermes_cron_watchdog_mutation",
                "memory_write",
                "mutates_ao_artifacts",
                "provider_execution",
                "queue_execution",
            ] {
                assert_eq!(
                    apply_side_effects[key].as_bool(),
                    Some(false),
                    "{platform} Pulse apply side effect {key} must remain false"
                );
            }
        } else {
            assert!(
                apply_result_observation["unavailable_platforms"][platform].is_object(),
                "{platform} without apply-result evidence must be recorded unavailable"
            );
        }

        let trust_boundary = &evidence["trust_boundary"];
        assert_eq!(
            trust_boundary["ao2_execution_evidence_owner"].as_bool(),
            Some(true)
        );
        assert_eq!(
            trust_boundary["factory_v3_evaluator_closer_reference"].as_bool(),
            Some(true)
        );
        assert_eq!(
            trust_boundary["control_plane_observer_only"].as_bool(),
            Some(true)
        );
        assert_eq!(
            trust_boundary["control_plane_approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            trust_boundary["control_plane_mutates_ao_artifacts"].as_bool(),
            Some(false)
        );
    }

    assert_eq!(
        bundle["task_contract"]["schema_version"].as_str(),
        Some("ao2.pulse-task-contract.v1")
    );
    assert_eq!(
        bundle["task_contract"]["sha256"].as_str().map(str::len),
        Some(64)
    );
    assert_eq!(bundle["task_contract"]["c85"].as_bool(), Some(false));
    assert_eq!(
        bundle["task_contract"]["ao2_owned_execution"].as_bool(),
        Some(true)
    );
    assert_eq!(
        bundle["task_contract"]["factory_v3_evaluator_closer_required"].as_bool(),
        Some(true)
    );
}

#[test]
fn pulse_apply_observer_bundle_is_read_only_ao2_produced_evidence() {
    let bundle = read_fixture(PULSE_APPLY_RESULT_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-pulse-apply-result-observer-bundle.v1")
    );
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(
        bundle["observed_evidence_scope"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        bundle["observed_evidence_scope"][0].as_str(),
        Some("ao2.pulse-apply-result.v1")
    );
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(|platforms| {
            platforms
                .iter()
                .map(|platform| platform.as_str().expect("platform is string"))
                .collect::<Vec<_>>()
        }),
        Some(vec!["macos", "ubuntu", "windows"])
    );
    assert!(
        bundle["unavailable_platforms"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        "fresh Pulse apply observer bundle must include direct Windows proof"
    );
    assert_eq!(
        bundle["platform_apply_results_sha256"]
            .as_str()
            .map(str::len),
        Some(64)
    );

    assert_eq!(
        bundle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_observe_evidence_bundle_path"].as_bool(),
        Some(true)
    );

    let trust_boundary = &bundle["trust_boundary"];
    assert_eq!(trust_boundary["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        trust_boundary["factory_v3_role"].as_str(),
        Some("parity_auditor")
    );
    assert_eq!(
        trust_boundary["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        trust_boundary["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_boundary["mutates_ao_artifacts"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&bundle["side_effects"]);

    for platform in ["macos", "ubuntu", "windows"] {
        let apply_result = &bundle["platform_apply_results"][platform];
        assert_eq!(
            apply_result["schema_version"].as_str(),
            Some("ao2.pulse-apply-result.v1"),
            "{platform} apply-result schema must stay AO2-produced"
        );
        assert_eq!(
            apply_result["status"].as_str(),
            Some("accepted"),
            "{platform} apply-result must be evaluator/closer accepted"
        );
        assert_eq!(
            apply_result["execution_mode"].as_str(),
            Some("bounded_planned_file_apply"),
            "{platform} apply-result must remain bounded to planned operations"
        );
        assert_eq!(
            apply_result["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} apply-result must be digest-pinned"
        );
        assert_eq!(
            apply_result["selected_task"]["c85"].as_bool(),
            Some(false),
            "{platform} apply-result must remain non-C85 while billing is blocked"
        );
        assert_eq!(
            apply_result["evaluator_closer"]["release_acceptance_owner"].as_str(),
            Some("factory-v3 evaluator-closer"),
            "{platform} evaluator/closer owner must remain factory-v3"
        );
        assert_eq!(
            apply_result["evaluator_closer"]["status"].as_str(),
            Some("accepted"),
            "{platform} evaluator/closer status must be accepted"
        );
        assert_eq!(
            apply_result["dry_run_task"]["schema_version"].as_str(),
            Some("ao2.pulse-dry-run-task.v1")
        );
        assert_eq!(
            apply_result["governed_task_evidence"]["schema_version"].as_str(),
            Some("ao2.pulse-governed-task.v1")
        );
        assert_eq!(
            apply_result["task_result"]["schema_version"].as_str(),
            Some("ao2.pulse-task-result.v1")
        );

        let operations = apply_result["applied_file_operations"]
            .as_array()
            .expect("apply-result operations are an array");
        assert_eq!(
            operations.len(),
            3,
            "{platform} apply-result must record exactly three applied operations"
        );
        for operation in operations {
            assert_eq!(
                operation["allowed_by_dry_run"].as_bool(),
                Some(true),
                "{platform} operation must be allowed by dry-run evidence"
            );
            assert_eq!(
                operation["executed"].as_bool(),
                Some(true),
                "{platform} operation must be marked executed"
            );
        }

        let apply_trust_boundary = &apply_result["trust_boundary"];
        assert_eq!(
            apply_trust_boundary["ao2_execution_evidence_owner"].as_bool(),
            Some(true)
        );
        assert_eq!(
            apply_trust_boundary["factory_v3_evaluator_closer_reference"].as_bool(),
            Some(true)
        );
        assert_eq!(
            apply_trust_boundary["control_plane_observer_only"].as_bool(),
            Some(true)
        );
        assert_eq!(
            apply_trust_boundary["control_plane_approves_release"].as_bool(),
            Some(false)
        );
        assert_eq!(
            apply_trust_boundary["control_plane_mutates_ao_artifacts"].as_bool(),
            Some(false)
        );

        let side_effects = &apply_result["side_effects"];
        for key in [
            "control_plane_mutation",
            "hermes_cron_watchdog_mutation",
            "memory_write",
            "mutates_ao_artifacts",
            "provider_execution",
            "queue_execution",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} Pulse apply side effect {key} must remain false"
            );
        }
    }
}

#[test]
fn pulse_once_observer_bundle_is_read_only_ao2_produced_evidence() {
    let bundle = read_fixture(PULSE_ONCE_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-pulse-once-observer-bundle.v1")
    );
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(|platforms| {
            platforms
                .iter()
                .map(|platform| platform.as_str().expect("platform is string"))
                .collect::<Vec<_>>()
        }),
        Some(vec!["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        bundle["observed_evidence_scope"],
        serde_json::json!(["ao2.pulse-once.v1"])
    );
    assert_eq!(
        bundle["platform_once_sha256"].as_str().map(str::len),
        Some(64)
    );

    assert_eq!(
        bundle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_observe_evidence_bundle_path"].as_bool(),
        Some(true)
    );

    let trust_boundary = &bundle["trust_boundary"];
    assert_eq!(trust_boundary["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        trust_boundary["factory_v3_role"].as_str(),
        Some("parity_auditor")
    );
    assert_eq!(
        trust_boundary["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        trust_boundary["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_boundary["mutates_ao_artifacts"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&bundle["side_effects"]);

    let platform_progress = &bundle["platform_progress"];
    assert_eq!(
        platform_progress["schema_version"].as_str(),
        Some("ao2.pulse-platform-progress.v1")
    );
    assert_eq!(platform_progress["status"].as_str(), Some("closure_ready"));
    assert_eq!(
        platform_progress["required_platforms"],
        serde_json::json!(["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        platform_progress["blocked_platforms"],
        serde_json::json!([])
    );
    assert_eq!(
        platform_progress["windows"]["current_state"].as_str(),
        Some("closure_ready"),
        "Windows once-mode progress must be explicit before K37 closure"
    );
    assert_eq!(
        platform_progress["windows"]["state_history"],
        serde_json::json!([
            "pending",
            "reachable",
            "staged",
            "running",
            "passed",
            "evidence_collected",
            "closure_ready"
        ])
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let once = &bundle["platform_once"][platform];
        assert_eq!(
            once["schema_version"].as_str(),
            Some("ao2.pulse-once.v1"),
            "{platform} once evidence must stay AO2-produced"
        );
        assert_eq!(
            once["status"].as_str(),
            Some("ready_for_operator_execution"),
            "{platform} once evidence must be operator-ready"
        );
        assert_eq!(
            once["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} once evidence must be digest-pinned"
        );
        assert_eq!(
            once["c85"]["status"].as_str(),
            Some("passed"),
            "{platform} once evidence must be post-C85"
        );
        assert_eq!(
            once["observed_inputs"]["packet_mentions_c85_passed"].as_bool(),
            Some(true),
            "{platform} once evidence must bind the post-C85 packet"
        );
        assert_eq!(
            once["observed_inputs"]["packet_mentions_c85_deferred"].as_bool(),
            Some(false),
            "{platform} once evidence must not carry stale C85 deferral"
        );

        let side_effects = &once["side_effects"];
        for key in [
            "control_plane_mutation",
            "hermes_cron_watchdog_mutation",
            "memory_write",
            "mutates_ao_artifacts",
            "provider_execution",
            "queue_execution",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} Pulse once side effect {key} must remain false"
            );
        }
    }
}

#[test]
fn pulse_chain_observer_bundle_is_read_only_ao2_produced_evidence() {
    let bundle = read_fixture(PULSE_CHAIN_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-pulse-chain-observer-bundle.v1")
    );
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(|platforms| {
            platforms
                .iter()
                .map(|platform| platform.as_str().expect("platform is string"))
                .collect::<Vec<_>>()
        }),
        Some(vec!["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        bundle["observed_evidence_scope"],
        serde_json::json!(["ao2.pulse-chain.v1"])
    );
    assert_eq!(
        bundle["platform_chain_sha256"].as_str().map(str::len),
        Some(64)
    );

    assert_eq!(
        bundle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_observe_evidence_bundle_path"].as_bool(),
        Some(true)
    );

    let trust_boundary = &bundle["trust_boundary"];
    assert_eq!(trust_boundary["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        trust_boundary["factory_v3_role"].as_str(),
        Some("parity_auditor")
    );
    assert_eq!(
        trust_boundary["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        trust_boundary["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_boundary["mutates_ao_artifacts"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&bundle["side_effects"]);

    let platform_progress = &bundle["platform_progress"];
    assert_eq!(
        platform_progress["schema_version"].as_str(),
        Some("ao2.pulse-platform-progress.v1")
    );
    assert_eq!(platform_progress["status"].as_str(), Some("closure_ready"));
    assert_eq!(
        platform_progress["required_platforms"],
        serde_json::json!(["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        platform_progress["blocked_platforms"],
        serde_json::json!([])
    );
    assert_eq!(
        platform_progress["windows"]["current_state"].as_str(),
        Some("closure_ready"),
        "Windows chain-mode progress must be explicit before K37 closure"
    );
    assert_eq!(
        platform_progress["windows"]["state_history"],
        serde_json::json!([
            "pending",
            "reachable",
            "staged",
            "running",
            "passed",
            "evidence_collected",
            "closure_ready"
        ])
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let chain = &bundle["platform_chain"][platform];
        assert_eq!(
            chain["schema_version"].as_str(),
            Some("ao2.pulse-chain.v1"),
            "{platform} chain evidence must stay AO2-produced"
        );
        assert_eq!(
            chain["status"].as_str(),
            Some("planned_without_execution"),
            "{platform} chain evidence must be plan-only"
        );
        assert_eq!(
            chain["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} chain evidence must be digest-pinned"
        );
        assert_eq!(
            chain["c85"]["status"].as_str(),
            Some("passed"),
            "{platform} chain evidence must be post-C85"
        );
        assert_eq!(
            chain["observed_inputs"]["packet_mentions_c85_passed"].as_bool(),
            Some(true),
            "{platform} chain evidence must bind the post-C85 packet"
        );
        assert_eq!(
            chain["observed_inputs"]["packet_mentions_c85_deferred"].as_bool(),
            Some(false),
            "{platform} chain evidence must not carry stale C85 deferral"
        );
        assert_eq!(
            chain["prior_once"]["schema_version"].as_str(),
            Some("ao2.pulse-once.v1"),
            "{platform} chain evidence must digest-bind once evidence"
        );
        assert_eq!(
            chain["prior_once"]["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} chain prior_once must be digest-pinned"
        );

        let side_effects = &chain["side_effects"];
        for key in [
            "control_plane_mutation",
            "hermes_cron_watchdog_mutation",
            "memory_write",
            "mutates_ao_artifacts",
            "provider_execution",
            "queue_execution",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} Pulse chain side effect {key} must remain false"
            );
        }
    }
}

#[test]
fn pulse_eval_loop_observer_bundle_is_read_only_ao2_produced_evidence() {
    let bundle = read_fixture(PULSE_EVAL_LOOP_OBSERVER_BUNDLE);

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("ao2.k37-pulse-eval-loop-observer-bundle.v1")
    );
    assert_eq!(bundle["producer"].as_str(), Some("ao2"));
    assert_eq!(bundle["status"].as_str(), Some("ready_for_k37_observation"));
    assert_eq!(bundle["factory_v3_role"].as_str(), Some("parity_auditor"));
    assert_eq!(bundle["platform_count"].as_u64(), Some(3));
    assert_eq!(
        bundle["platforms"].as_array().map(|platforms| {
            platforms
                .iter()
                .map(|platform| platform.as_str().expect("platform is string"))
                .collect::<Vec<_>>()
        }),
        Some(vec!["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        bundle["observed_evidence_scope"],
        serde_json::json!(["ao2.pulse-eval-loop.v1"])
    );
    assert_eq!(
        bundle["platform_eval_loop_sha256"].as_str().map(str::len),
        Some(64)
    );

    assert_eq!(
        bundle["control_plane_observation"]["role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_approve_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_mutate_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        bundle["control_plane_observation"]["may_observe_evidence_bundle_path"].as_bool(),
        Some(true)
    );

    let trust_boundary = &bundle["trust_boundary"];
    assert_eq!(trust_boundary["execution_owner"].as_str(), Some("ao2"));
    assert_eq!(
        trust_boundary["factory_v3_role"].as_str(),
        Some("parity_auditor")
    );
    assert_eq!(
        trust_boundary["control_plane_role"].as_str(),
        Some("read_only_observer")
    );
    assert_eq!(
        trust_boundary["control_plane_approves_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_boundary["mutates_ao_artifacts"].as_bool(),
        Some(false)
    );
    assert_side_effects_false(&bundle["side_effects"]);
    assert_eq!(bundle["side_effects"]["repo_apply"].as_bool(), Some(false));

    let platform_progress = &bundle["platform_progress"];
    assert_eq!(
        platform_progress["schema_version"].as_str(),
        Some("ao2.pulse-platform-progress.v1")
    );
    assert_eq!(platform_progress["status"].as_str(), Some("closure_ready"));
    assert_eq!(
        platform_progress["required_platforms"],
        serde_json::json!(["macos", "ubuntu", "windows"])
    );
    assert_eq!(
        platform_progress["blocked_platforms"],
        serde_json::json!([])
    );
    assert_eq!(
        platform_progress["windows"]["current_state"].as_str(),
        Some("closure_ready"),
        "Windows eval-loop progress must be explicit before K37 closure"
    );

    for platform in ["macos", "ubuntu", "windows"] {
        let eval_loop = &bundle["platform_eval_loop"][platform];
        assert_eq!(
            eval_loop["schema_version"].as_str(),
            Some("ao2.pulse-eval-loop.v1"),
            "{platform} eval-loop evidence must stay AO2-produced"
        );
        assert_eq!(
            eval_loop["status"].as_str(),
            Some("ready_for_next_pulse_task"),
            "{platform} eval-loop evidence must be ready for the next Pulse task"
        );
        assert_eq!(
            eval_loop["sha256"].as_str().map(str::len),
            Some(64),
            "{platform} eval-loop evidence must be digest-pinned"
        );
        assert_eq!(
            eval_loop["loop"]["chain_depth"].as_u64(),
            Some(1),
            "{platform} eval-loop chain depth must show a chained proof"
        );
        assert_eq!(
            eval_loop["loop"]["terminal"].as_bool(),
            Some(true),
            "{platform} eval-loop must be terminal"
        );
        assert_eq!(
            eval_loop["loop"]["continues_automatically"].as_bool(),
            Some(false),
            "{platform} eval-loop must not continue automatically"
        );
        assert_eq!(
            eval_loop["evaluator"]["decision"].as_str(),
            Some("recommend_next_task"),
            "{platform} eval-loop must be evaluator-closed as a recommendation"
        );

        let side_effects = &eval_loop["side_effects"];
        for key in [
            "control_plane_mutation",
            "hermes_cron_watchdog_mutation",
            "memory_write",
            "mutates_ao_artifacts",
            "provider_execution",
            "queue_execution",
            "repo_apply",
        ] {
            assert_eq!(
                side_effects[key].as_bool(),
                Some(false),
                "{platform} Pulse eval-loop side effect {key} must remain false"
            );
        }
    }
}

#[test]
fn k37_observer_fixtures_do_not_expose_credentials() {
    fn contains_credential_marker(text: &str, marker: &str) -> bool {
        if marker != "sk-" {
            return text.contains(marker);
        }
        let bytes = text.as_bytes();
        for (index, _) in text.match_indices(marker) {
            if index > 0 && bytes[index - 1].is_ascii_alphanumeric() {
                continue;
            }
            let tokenish_len = bytes[index + marker.len()..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                .count();
            if tokenish_len >= 16 {
                return true;
            }
        }
        false
    }

    for fixture in [
        PLUGIN_OBSERVER_BUNDLE,
        ADAPTER_OBSERVER_BUNDLE,
        ADAPTER_INSTALL_SMOKE_OBSERVER_BUNDLE,
        CONSUMER_LIFECYCLE_OBSERVER_BUNDLE,
        RELEASE_CANDIDATE_OBSERVER_BUNDLE,
        FINAL_INSTALL_TRANSCRIPT_OBSERVER_BUNDLE,
        SHIPMENT_READINESS_MACOS,
        SHIPMENT_READINESS_UBUNTU,
        SHIPMENT_READINESS_WINDOWS,
        CLEAN_PACKAGE_OPERATOR_INDEX,
        PACKAGED_REPLACEMENT_HARDENING_MACOS,
        PACKAGED_REPLACEMENT_HARDENING_UBUNTU,
        PACKAGED_REPLACEMENT_HARDENING_WINDOWS,
        PACKAGED_REPLACEMENT_HARDENING_OBSERVER_BUNDLE,
        SELF_CONTAINED_PLUGIN_PACKAGE_OBSERVER_BUNDLE,
        SKILL_CONTRACT_MANIFEST,
        CLOSER_DECISION,
    ] {
        for marker in [
            "Bearer ",
            "Authorization:",
            "BEGIN PRIVATE KEY",
            "OPENAI_API_KEY=",
            "ANTHROPIC_API_KEY=",
            "sk-",
            "xoxb-",
        ] {
            assert!(
                !contains_credential_marker(fixture, marker),
                "K37 observer fixture must not expose credential marker {marker}"
            );
        }
    }

    let pulse_bundle = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(PULSE_EXECUTOR_OBSERVER_BUNDLE),
    )
    .expect("K37 Pulse observer fixture exists");
    let pulse_once_bundle = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(PULSE_ONCE_OBSERVER_BUNDLE),
    )
    .expect("K37 Pulse once observer fixture exists");
    let pulse_chain_bundle = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(PULSE_CHAIN_OBSERVER_BUNDLE),
    )
    .expect("K37 Pulse chain observer fixture exists");
    let pulse_eval_loop_bundle = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(PULSE_EVAL_LOOP_OBSERVER_BUNDLE),
    )
    .expect("K37 Pulse eval-loop observer fixture exists");
    let pulse_apply_bundle = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(PULSE_APPLY_RESULT_OBSERVER_BUNDLE),
    )
    .expect("K37 Pulse apply observer fixture exists");
    for (label, fixture) in [
        ("K37 Pulse observer fixture", pulse_bundle.as_str()),
        (
            "K37 Pulse once observer fixture",
            pulse_once_bundle.as_str(),
        ),
        (
            "K37 Pulse chain observer fixture",
            pulse_chain_bundle.as_str(),
        ),
        (
            "K37 Pulse eval-loop observer fixture",
            pulse_eval_loop_bundle.as_str(),
        ),
        (
            "K37 Pulse apply observer fixture",
            pulse_apply_bundle.as_str(),
        ),
    ] {
        for marker in [
            "Bearer ",
            "Authorization:",
            "BEGIN PRIVATE KEY",
            "OPENAI_API_KEY=",
            "ANTHROPIC_API_KEY=",
            "sk-",
            "xoxb-",
        ] {
            assert!(
                !contains_credential_marker(fixture, marker),
                "{label} must not expose credential marker {marker}"
            );
        }
    }
}
