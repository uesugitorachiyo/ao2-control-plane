#!/usr/bin/env python3
"""Verify bounded governed RSI chain binding as observer-only readback."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao-stack-rsi-chain-binding-readback.v1"
BLUEPRINT_SCHEMA = "ao.blueprint.build-authorization.v0.1"
FOUNDRY_CHAIN_SCHEMA = "ao.forge.goal-run-retained-evidence.v0.1"
FORGE_GOAL_RUN_SCHEMA = "ao.forge.goal-run.v0.1"
AO2_CROSS_REPO_SCHEMA = "ao2.rsi-cross-repo-e2e.v1"
CONTROL_SURFACE_SCHEMA = "ao2.cp-ao2-rsi-control-surface-readback.v1"
FULL_RSI_CLAIM = "full_autonomous_self_mutating_rsi"
CLAIM_RESOURCE = "full-autonomous-self-mutating-rsi"
CONTROL_SURFACE_GOAL = "bounded_governed_rsi_control_surface_readback"
IMPROVEMENT_INTERPRETATION = "workflow_hardening_coverage_not_publication_authority"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "rsi_chain_binding_blocker", "details": details})


def captured_outputs(foundry_chain: dict[str, Any]) -> dict[str, dict[str, Any]]:
    outputs = foundry_chain.get("captured_outputs")
    if not isinstance(outputs, list):
        return {}
    return {
        item.get("label"): item
        for item in outputs
        if isinstance(item, dict) and isinstance(item.get("label"), str)
    }


def nested_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def validate_blueprint(blueprint: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    details = []
    if blueprint.get("schema") != BLUEPRINT_SCHEMA:
        details.append(f"schema must be {BLUEPRINT_SCHEMA}")
    if blueprint.get("status") != "ready":
        details.append("status must be ready")
    if blueprint.get("score") != 100:
        details.append("score must be 100")
    if blueprint.get("approved_by_user") is not True:
        details.append("approved_by_user must be true")
    if blueprint.get("next_allowed_action") != "ao-foundry":
        details.append("next_allowed_action must be ao-foundry")
    add_gap(gaps, "blueprint_authorization_not_ready", details)
    return {
        "stage": "blueprint_authorization",
        "source": "ao-blueprint",
        "schema_version": blueprint.get("schema"),
        "status": blueprint.get("status"),
        "score": blueprint.get("score"),
        "approved_by_user": blueprint.get("approved_by_user"),
        "next_allowed_action": blueprint.get("next_allowed_action"),
        "authorizes_claim_publication": False,
        "authorizes_blueprint_self_change": False,
    }


def validate_foundry(foundry_chain: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    details = []
    if foundry_chain.get("schema_version") != FOUNDRY_CHAIN_SCHEMA:
        details.append(f"schema_version must be {FOUNDRY_CHAIN_SCHEMA}")
    if nested_dict(foundry_chain.get("retention_policy")).get("temporary_paths_allowed") is not False:
        details.append("retention_policy.temporary_paths_allowed must be false")
    if nested_dict(foundry_chain.get("retention_metadata")).get("deletion_requires_review") is not True:
        details.append("retention_metadata.deletion_requires_review must be true")

    outputs = captured_outputs(foundry_chain)
    required = {
        "ao-foundry-rsi-candidate": ("ao.foundry.rsi-candidate.v0.1", "ready"),
        "ao-foundry-rsi-improvement-gate": ("ao.foundry.rsi-improvement-gate.v0.1", "passed"),
        "ao-foundry-rsi-next-improvement-task": ("ao.foundry.rsi-next-improvement-task.v0.1", "ready"),
    }
    for label, (schema_version, status) in required.items():
        output = outputs.get(label)
        if not output:
            details.append(f"{label} must be present")
            continue
        if output.get("schema_version") != schema_version:
            details.append(f"{label}.schema_version must be {schema_version}")
        if output.get("status") != status:
            details.append(f"{label}.status must be {status}")
        if output.get("mutates_repositories") is not False:
            details.append(f"{label}.mutates_repositories must be false")
        if output.get("autonomous_claim") == FULL_RSI_CLAIM:
            details.append(f"{label}.autonomous_claim must not be {FULL_RSI_CLAIM}")

    gate = outputs.get("ao-foundry-rsi-improvement-gate", {})
    if isinstance(gate, dict) and gate:
        if gate.get("actual_improvement_percent", 0) < gate.get("required_improvement_percent", 0):
            details.append("ao-foundry-rsi-improvement-gate actual improvement must meet required improvement")

    add_gap(gaps, "foundry_candidate_gate_authority_drift", details)
    return {
        "stage": "foundry_candidate_gate",
        "source": "ao-foundry retained by ao-forge",
        "schema_version": foundry_chain.get("schema_version"),
        "goal_id": foundry_chain.get("goal_id"),
        "iteration": foundry_chain.get("iteration"),
        "status": "passed" if not details else "blocked",
        "required_outputs": sorted(required),
        "mutates_repositories": False,
        "claim_level": "bounded_governed_rsi",
    }


def validate_forge(goal_run: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    details = []
    if goal_run.get("schema_version") != FORGE_GOAL_RUN_SCHEMA:
        details.append(f"schema_version must be {FORGE_GOAL_RUN_SCHEMA}")
    if goal_run.get("repo") != "ao2":
        details.append("repo must be ao2")
    if nested_dict(goal_run.get("loop_owner")).get("state_owner") != "ao-forge":
        details.append("loop_owner.state_owner must be ao-forge")
    guard = nested_dict(goal_run.get("next_action_guard"))
    for key in ["must_read_latest_goal_run", "must_match_allowed_scope", "must_satisfy_acceptance_criteria"]:
        if guard.get(key) is not True:
            details.append(f"next_action_guard.{key} must be true")
    if nested_dict(goal_run.get("last_iteration")).get("status") != "passed":
        details.append("last_iteration.status must be passed")
    evidence = nested_dict(goal_run.get("last_iteration")).get("evidence")
    evidence_labels = [item.get("label") for item in evidence if isinstance(item, dict)] if isinstance(evidence, list) else []
    if "bounded-rsi-improvement-chain-retention-proof.json" not in evidence_labels:
        details.append("last_iteration.evidence must include bounded-rsi-improvement-chain-retention-proof.json")
    if not goal_run.get("stop_conditions"):
        details.append("stop_conditions must be present")
    add_gap(gaps, "forge_goal_run_not_bound", details)
    return {
        "stage": "forge_goal_run",
        "source": "ao-forge",
        "schema_version": goal_run.get("schema_version"),
        "goal_id": goal_run.get("goal_id"),
        "repo": goal_run.get("repo"),
        "state_owner": nested_dict(goal_run.get("loop_owner")).get("state_owner"),
        "last_iteration_status": nested_dict(goal_run.get("last_iteration")).get("status"),
        "retained_chain_evidence_present": "bounded-rsi-improvement-chain-retention-proof.json" in evidence_labels,
    }


def validate_covenant(ao2_summary: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    observed = nested_dict(ao2_summary.get("observed_evidence"))
    details = []
    if ao2_summary.get("claim_level") != FULL_RSI_CLAIM:
        details.append(f"claim_level must be {FULL_RSI_CLAIM}")
    if ao2_summary.get("claim_publish_decision") != "deny":
        details.append("claim_publish_decision must be deny")
    if ao2_summary.get("claim_publish_authority") is not False:
        details.append("claim_publish_authority must be false")
    if ao2_summary.get("claim_publish_resource") != CLAIM_RESOURCE:
        details.append(f"claim_publish_resource must be {CLAIM_RESOURCE}")
    if observed.get("covenant_gate_schema_version") != "covenant.rsi-claim-publish-gate.v1":
        details.append("observed_evidence.covenant_gate_schema_version must be covenant.rsi-claim-publish-gate.v1")
    if observed.get("covenant_gate_status") != "denied":
        details.append("observed_evidence.covenant_gate_status must be denied")
    add_gap(gaps, "covenant_claim_decision_not_denied", details)
    return {
        "stage": "covenant_claim_decision",
        "source": "ao-covenant via AO2 cross-repo E2E",
        "schema_version": observed.get("covenant_gate_schema_version"),
        "claim_level": ao2_summary.get("claim_level"),
        "resource": ao2_summary.get("claim_publish_resource"),
        "decision": ao2_summary.get("claim_publish_decision"),
        "publish_authority": ao2_summary.get("claim_publish_authority"),
    }


def validate_ao2(ao2_summary: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    details = []
    if ao2_summary.get("schema_version") != AO2_CROSS_REPO_SCHEMA:
        details.append(f"schema_version must be {AO2_CROSS_REPO_SCHEMA}")
    if ao2_summary.get("status") != "passed":
        details.append("status must be passed")
    checks = ao2_summary.get("checks")
    check_map = {
        item.get("name"): item.get("status")
        for item in checks
        if isinstance(checks, list) and isinstance(item, dict)
    }
    for name in [
        "live_self_change_rehearsal",
        "control_plane_readback",
        "readback_index",
        "claim_readiness",
        "blueprint_authorization",
        "covenant_claim_publish_gate",
        "improvement_evidence_gate",
        "improvement_trend",
    ]:
        if check_map.get(name) != "passed":
            details.append(f"checks.{name} must be passed")

    blueprint_gate = nested_dict(ao2_summary.get("blueprint_authorization"))
    blueprint_details = []
    if blueprint_gate.get("blueprint_authorization_ready") is not True:
        blueprint_details.append("blueprint_authorization_ready must be true")
    if blueprint_gate.get("self_authorized_by_rsi") is not False:
        blueprint_details.append("self_authorized_by_rsi must be false")
    if blueprint_gate.get("authorizes_ao_blueprint_self_change") is not False:
        blueprint_details.append("authorizes_ao_blueprint_self_change must be false")
    if blueprint_gate.get("authorizes_claim_publication") is not False:
        blueprint_details.append("authorizes_claim_publication must be false")
    add_gap(gaps, "ao2_blueprint_gate_authority_drift", blueprint_details)

    observed = nested_dict(ao2_summary.get("observed_evidence"))
    for key in ["control_plane_readback_status", "readback_index_status", "improvement_gate_status", "improvement_trend_status"]:
        if observed.get(key) != "passed":
            details.append(f"observed_evidence.{key} must be passed")
    if observed.get("claim_readiness_status") != "claim_boundary_enforced":
        details.append("observed_evidence.claim_readiness_status must be claim_boundary_enforced")

    trust = nested_dict(ao2_summary.get("trust_boundary"))
    trust_details = []
    expected = {
        "approves_rsi_claims": False,
        "publishes_claims": False,
        "requires_provider_api_key": False,
        "stores_credentials": False,
        "uses_network": False,
    }
    for key, expected_value in expected.items():
        if trust.get(key) is not expected_value:
            trust_details.append(f"trust_boundary.{key} must be {str(expected_value).lower()}")
    add_gap(gaps, "ao2_trust_boundary_drift", trust_details)
    add_gap(gaps, "ao2_cross_repo_evidence_not_passing", details)
    return {
        "stage": "ao2_execution_evidence",
        "source": "ao2",
        "schema_version": ao2_summary.get("schema_version"),
        "status": ao2_summary.get("status"),
        "checks_passed": sorted([name for name, status in check_map.items() if status == "passed"]),
        "claim_boundary": observed.get("claim_readiness_status"),
    }


def validate_control_surface(control: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    details = []
    if control.get("schema_version") != CONTROL_SURFACE_SCHEMA:
        details.append(f"schema_version must be {CONTROL_SURFACE_SCHEMA}")
    if control.get("status") != "passed":
        details.append("status must be passed")
    surface = nested_dict(control.get("control_surface_readback"))
    if surface.get("loop_goal") != CONTROL_SURFACE_GOAL:
        details.append(f"control_surface_readback.loop_goal must be {CONTROL_SURFACE_GOAL}")
    bounded = nested_dict(surface.get("bounded_governed_rsi"))
    if bounded.get("status") != "supported":
        details.append("bounded_governed_rsi.status must be supported")
    if bounded.get("evidence_state") != "passing":
        details.append("bounded_governed_rsi.evidence_state must be passing")
    full = nested_dict(surface.get("full_autonomous_self_mutating_rsi"))
    if full.get("status") != "denied":
        details.append("full_autonomous_self_mutating_rsi.status must be denied")
    if full.get("decision") != "deny":
        details.append("full_autonomous_self_mutating_rsi.decision must be deny")
    if full.get("publish_authority") is not False:
        details.append("full_autonomous_self_mutating_rsi.publish_authority must be false")
    if full.get("boundary_state") != "enforced_by_design":
        details.append("full_autonomous_self_mutating_rsi.boundary_state must be enforced_by_design")
    score = nested_dict(surface.get("improvement_score"))
    if score.get("target_exceeded") is not True:
        details.append("improvement_score.target_exceeded must be true")
    if score.get("interpretation") != IMPROVEMENT_INTERPRETATION:
        details.append(f"improvement_score.interpretation must be {IMPROVEMENT_INTERPRETATION}")

    trust = nested_dict(control.get("trust_boundary"))
    for key in [
        "control_plane_approves_rsi_claims",
        "mutates_ao_artifacts",
        "applies_ao_patches",
        "mutates_github_repositories",
        "mutates_observer_storage",
        "publishes_claims",
        "credential_material_included",
        "provider_api_keys_allowed",
    ]:
        if trust.get(key) is not False:
            details.append(f"trust_boundary.{key} must be false")
    add_gap(gaps, "control_plane_readback_not_observer_only", details)
    return {
        "stage": "control_plane_readback",
        "source": "ao2-control-plane",
        "schema_version": control.get("schema_version"),
        "status": control.get("status"),
        "loop_goal": surface.get("loop_goal"),
        "control_plane_approves_rsi_claims": trust.get("control_plane_approves_rsi_claims"),
        "publishes_claims": trust.get("publishes_claims"),
    }


def build_summary(
    blueprint: dict[str, Any],
    foundry_chain: dict[str, Any],
    forge_goal_run: dict[str, Any],
    ao2_summary: dict[str, Any],
    control_surface: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    chain = [
        validate_blueprint(blueprint, gaps),
        validate_foundry(foundry_chain, gaps),
        validate_forge(forge_goal_run, gaps),
        validate_covenant(ao2_summary, gaps),
        validate_ao2(ao2_summary, gaps),
        validate_control_surface(control_surface, gaps),
    ]
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_paths": {name: str(path) for name, path in paths.items()},
        "producer_schema_versions": {
            "blueprint_authorization": blueprint.get("schema"),
            "foundry_chain": foundry_chain.get("schema_version"),
            "forge_goal_run": forge_goal_run.get("schema_version"),
            "ao2_cross_repo_e2e": ao2_summary.get("schema_version"),
            "control_surface_readback": control_surface.get("schema_version"),
        },
        "chain_binding": chain,
        "operator_interpretation": {
            "bounded_governed_rsi": "supported_by_bound_chain",
            "full_autonomous_self_mutating_rsi": "denied_by_covenant_and_control_surface",
            "control_plane_role": "observer_readback_only",
        },
        "claim_boundary": {
            "bounded_governed_rsi": "supported",
            "full_autonomous_self_mutating_rsi": "denied",
            "publication_authority": False,
        },
        "gaps": gaps,
        "trust_boundary": {
            "control_plane_approves_rsi_claims": False,
            "control_plane_executes_ao_work": False,
            "control_plane_mutates_repositories": False,
            "control_plane_publishes_claims": False,
            "control_plane_authorizes_blueprint_self_change": False,
            "provider_api_keys_allowed": False,
            "credential_material_included": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint-authorization-json", required=True, type=Path)
    parser.add_argument("--foundry-chain-json", required=True, type=Path)
    parser.add_argument("--forge-goal-run-json", required=True, type=Path)
    parser.add_argument("--ao2-cross-repo-summary-json", required=True, type=Path)
    parser.add_argument("--control-surface-readback-json", required=True, type=Path)
    parser.add_argument("--out-json", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "blueprint_authorization": args.blueprint_authorization_json,
        "foundry_chain": args.foundry_chain_json,
        "forge_goal_run": args.forge_goal_run_json,
        "ao2_cross_repo_e2e": args.ao2_cross_repo_summary_json,
        "control_surface_readback": args.control_surface_readback_json,
    }
    summary = build_summary(
        read_json(args.blueprint_authorization_json),
        read_json(args.foundry_chain_json),
        read_json(args.forge_goal_run_json),
        read_json(args.ao2_cross_repo_summary_json),
        read_json(args.control_surface_readback_json),
        paths,
    )
    write_summary(args.out_json, summary)
    print(f"control_plane_ao_stack_rsi_chain_binding_readback={summary['status']}")
    print("chain=blueprint->foundry->forge->covenant->ao2->control-plane")
    print("bounded_governed_rsi=supported chain_binding=passed" if summary["status"] == "passed" else "bounded_governed_rsi=blocked")
    print("full_autonomous_self_mutating_rsi=denied boundary_state=enforced_by_design")
    for gap in summary["gaps"]:
        print(f"{gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
