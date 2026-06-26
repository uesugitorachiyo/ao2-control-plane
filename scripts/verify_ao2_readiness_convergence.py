#!/usr/bin/env python3
"""Verify AO2 readiness convergence as control-plane observer-only readback."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-readiness-convergence-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.readiness-convergence-gate.v1"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append(
            {
                "gap_kind": gap_kind,
                "severity": "readiness_convergence_blocker",
                "details": details,
            }
        )


def component_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("component_id") or value.get("id") or value.get("name") or "unknown")
    return str(value)


def validate_producer(summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    details = []
    if summary.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        details.append(f"schema_version must be {PRODUCER_SCHEMA_VERSION}")
    if summary.get("status") != "passed":
        details.append("status must be passed")
    if summary.get("readiness_converged") is not True:
        details.append("readiness_converged must be true")
    add_gap(gaps, "producer_not_converged", details)


def validate_decision(summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    decision = summary.get("decision") if isinstance(summary.get("decision"), dict) else {}
    details = []
    if summary.get("continue_pulse_loop") is not False:
        details.append("continue_pulse_loop must be false")
    if summary.get("recommended_next_action") != "operator_release_decision_required":
        details.append("recommended_next_action must be operator_release_decision_required")
    if decision.get("release_mutation_authority") is not False:
        details.append("decision.release_mutation_authority must be false")
    if decision.get("control_plane_observer_only") is not True:
        details.append("decision.control_plane_observer_only must be true")
    add_gap(gaps, "convergence_decision_drift", details)


def validate_rsi_boundary(summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    boundary = (
        summary.get("rsi_claim_boundary")
        if isinstance(summary.get("rsi_claim_boundary"), dict)
        else {}
    )
    details = []
    if boundary.get("bounded_governed_rsi") != "supported":
        details.append("rsi_claim_boundary.bounded_governed_rsi must be supported")
    if boundary.get("full_autonomous_self_mutating_rsi") != "denied":
        details.append("rsi_claim_boundary.full_autonomous_self_mutating_rsi must be denied")
    if boundary.get("claim_publish_authority") is not False:
        details.append("rsi_claim_boundary.claim_publish_authority must be false")
    add_gap(gaps, "rsi_claim_boundary_drift", details)


def validate_components(summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    blockers = summary.get("blocking_next_actions")
    blocker_ids = []
    if isinstance(blockers, list):
        blocker_ids = [component_id(item) for item in blockers]
    elif blockers:
        blocker_ids = [str(blockers)]
    add_gap(gaps, "producer_blockers_present", blocker_ids)

    components = summary.get("components")
    if not isinstance(components, list) or len(components) < 1:
        add_gap(gaps, "components_missing", ["components must be a non-empty list"])
        return
    failed_components = [
        component_id(item)
        for item in components
        if not isinstance(item, dict) or item.get("status") != "passed"
    ]
    add_gap(gaps, "component_status_not_passed", failed_components)


def validate_trust(summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    trust = summary.get("trust_boundary") if isinstance(summary.get("trust_boundary"), dict) else {}
    details = []
    expected = {
        "local_only": True,
        "stores_credentials": False,
        "mutates_release": False,
    }
    for key, expected_value in expected.items():
        if trust.get(key) is not expected_value:
            details.append(f"trust_boundary.{key} must be {str(expected_value).lower()}")
    if trust.get("control_plane_role") != "read_only_observer":
        details.append("trust_boundary.control_plane_role must be read_only_observer")
    add_gap(gaps, "producer_trust_boundary_drift", details)


def build_summary(producer: dict[str, Any], *, producer_path: Path) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    validate_producer(producer, gaps)
    validate_decision(producer, gaps)
    validate_rsi_boundary(producer, gaps)
    validate_components(producer, gaps)
    validate_trust(producer, gaps)
    status = "passed" if not gaps else "blocked"
    components = producer.get("components") if isinstance(producer.get("components"), list) else []
    boundary = producer.get("rsi_claim_boundary") if isinstance(producer.get("rsi_claim_boundary"), dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_path": str(producer_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "producer_recommended_next_action": producer.get("recommended_next_action"),
        "component_count": len(components),
        "operator_interpretation": {
            "bounded_governed_rsi": boundary.get("bounded_governed_rsi"),
            "full_autonomous_self_mutating_rsi": boundary.get("full_autonomous_self_mutating_rsi"),
            "release_decision": producer.get("recommended_next_action"),
            "pulse_loop": (
                "stop_repeating_readiness_evidence"
                if producer.get("continue_pulse_loop") is False
                else "continue_or_repair_readiness_evidence"
            ),
        },
        "gaps": gaps,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_release": False,
            "control_plane_approves_rsi_claims": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "publishes_claims": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--convergence-summary-json",
        required=True,
        type=Path,
        help="AO2 target/readiness-convergence/latest/summary.json",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Output readback summary JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    producer = read_json(args.convergence_summary_json)
    summary = build_summary(producer, producer_path=args.convergence_summary_json)
    write_summary(args.out_json, summary)

    print(f"control_plane_ao2_readiness_convergence_readback={summary['status']}")
    print(f"recommended_next_action={summary['producer_recommended_next_action']}")
    print(
        "full_autonomous_self_mutating_rsi="
        f"{summary['operator_interpretation']['full_autonomous_self_mutating_rsi']}"
    )
    for gap in summary["gaps"]:
        print(f"{gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
