#!/usr/bin/env python3
"""Verify AO2 Month 4 controlled self-improvement dry-run evidence as read-only observation."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-month4-controlled-self-improvement-observation.v0.1"
PRODUCER_SCHEMA_VERSION = "ao2.controlled-self-improvement-dry-run-evidence-pack.v0.1"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "month4_gate_blocker", "details": details})


def as_map(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def validate(payload: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if payload.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if payload.get("status") != "dry_run_passed":
        add_gap(gaps, "producer_status_not_passed", ["status must be dry_run_passed"])

    proposal = as_map(payload, "proposal")
    proposal_details = []
    if proposal.get("change_class") != "fixture_only_dry_run":
        proposal_details.append("proposal.change_class must be fixture_only_dry_run")
    if proposal.get("human_approval_required") is not True:
        proposal_details.append("proposal.human_approval_required must be true")
    add_gap(gaps, "proposal_contract_drift", proposal_details)

    policy = as_map(payload, "policy")
    policy_details = []
    if policy.get("approval_state") != "required":
        policy_details.append("policy.approval_state must be required")
    if policy.get("execution_scope") != "temporary_fixture_workspace":
        policy_details.append("policy.execution_scope must be temporary_fixture_workspace")
    if policy.get("rollback_required") is not True:
        policy_details.append("policy.rollback_required must be true")
    add_gap(gaps, "policy_gate_drift", policy_details)

    authority = as_map(payload, "authority")
    authority_details = []
    expected_authority = {
        "dry_run_only": True,
        "live_self_modification_authorized": False,
        "provider_execution_performed": False,
        "rsi_authorized": False,
        "promotion_requested": False,
    }
    for key, expected in expected_authority.items():
        if authority.get(key) is not expected:
            authority_details.append(f"authority.{key} must be {str(expected).lower()}")
    if authority.get("provider_execution_required") is not False:
        authority_details.append("authority.provider_execution_required must be false")
    if authority.get("live_repository_mutation_performed") is not False:
        authority_details.append("authority.live_repository_mutation_performed must be false")
    add_gap(gaps, "authority_boundary_drift", authority_details)

    approval = as_map(payload, "approval_replay")
    approval_details = []
    if approval.get("required_digest_field") != "action_digest":
        approval_details.append("approval_replay.required_digest_field must be action_digest")
    if approval.get("wrong_digest_rejected") is not True:
        approval_details.append("approval_replay.wrong_digest_rejected must be true")
    if approval.get("correct_digest_accepted_for_dry_run") is not True:
        approval_details.append("approval_replay.correct_digest_accepted_for_dry_run must be true")
    if approval.get("correct_digest_grants_live_authority") is not False:
        approval_details.append("approval_replay.correct_digest_grants_live_authority must be false")
    add_gap(gaps, "approval_replay_drift", approval_details)

    workspace = as_map(payload, "fixture_workspace")
    rollback = as_map(payload, "rollback")
    rollback_details = []
    if rollback.get("rollback_verified") is not True:
        rollback_details.append("rollback_verified must be true")
    if rollback.get("scope") != "temporary_fixture_workspace":
        rollback_details.append("rollback.scope must be temporary_fixture_workspace")
    if rollback.get("restored_sha256") != workspace.get("before_sha256"):
        rollback_details.append("rollback.restored_sha256 must match fixture_workspace.before_sha256")
    if workspace.get("after_sha256") != workspace.get("before_sha256"):
        rollback_details.append("fixture_workspace.after_sha256 must match fixture_workspace.before_sha256")
    if workspace.get("during_sha256") == workspace.get("before_sha256"):
        rollback_details.append("fixture_workspace.during_sha256 must differ from before_sha256")
    add_gap(gaps, "rollback_not_verified", rollback_details)

    evidence = as_map(payload, "evidence")
    evidence_details = []
    if evidence.get("public_safe") is not True:
        evidence_details.append("evidence.public_safe must be true")
    commands = evidence.get("commands")
    if not isinstance(commands, list) or "fixture: observe" not in commands:
        evidence_details.append("evidence.commands must include fixture: observe")
    add_gap(gaps, "evidence_not_public_safe", evidence_details)

    return gaps


def build_summary(payload: dict[str, Any], source_path: Path) -> dict[str, Any]:
    gaps = validate(payload)
    authority = as_map(payload, "authority")
    rollback = as_map(payload, "rollback")
    proposal = as_map(payload, "proposal")
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_path": str(source_path),
        "producer_schema_version": payload.get("schema_version"),
        "producer_status": payload.get("status"),
        "proposal_id": proposal.get("proposal_id"),
        "observation": {
            "dry_run_only": authority.get("dry_run_only") is True,
            "rollback_verified": rollback.get("rollback_verified") is True,
            "approval_required": proposal.get("human_approval_required") is True,
            "provider_execution": authority.get("provider_execution_performed") is True,
            "rsi_authorized": authority.get("rsi_authorized") is True,
            "promotion_requested": authority.get("promotion_requested") is True,
        },
        "gaps": gaps,
        "trust_boundary": {
            "control_plane_approves_self_change": False,
            "mutates_ao_artifacts": False,
            "applies_ao_patches": False,
            "mutates_github_repositories": False,
            "provider_api_keys_allowed": False,
            "credential_material_included": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO2 Month 4 dry-run evidence as read-only control-plane observation."
    )
    parser.add_argument("--dry-run-evidence-json", required=True, type=Path)
    parser.add_argument("--out-json", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = read_json(args.dry_run_evidence_json)
    summary = build_summary(payload, args.dry_run_evidence_json)
    write_json(args.out_json, summary)
    if summary["status"] == "passed":
        print("control_plane_month4_controlled_self_improvement_observation=passed")
        return 0
    print("control_plane_month4_controlled_self_improvement_observation=blocked")
    return 1


if __name__ == "__main__":
    sys.exit(main())
