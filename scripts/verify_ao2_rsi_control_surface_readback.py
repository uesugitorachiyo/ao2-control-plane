#!/usr/bin/env python3
"""Verify AO2 RSI control-surface readback as observer-only evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-rsi-control-surface-readback.v1"
GATE_SCHEMA_VERSION = "ao2.rsi-improvement-evidence-gate.v1"
TREND_SCHEMA_VERSION = "ao2.rsi-improvement-trend.v1"
LOOP_GOAL = "bounded_governed_rsi_control_surface_readback"
IMPROVEMENT_INTERPRETATION = "workflow_hardening_coverage_not_publication_authority"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "rsi_control_surface_blocker", "details": details})


def control_surface(summary: dict[str, Any]) -> dict[str, Any]:
    value = summary.get("control_surface_readback")
    return value if isinstance(value, dict) else {}


def trust_boundary(summary: dict[str, Any]) -> dict[str, Any]:
    value = summary.get("trust_boundary")
    return value if isinstance(value, dict) else {}


def validate_claim_publication(prefix: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    details = []
    if summary.get("claim_level") != "full_autonomous_self_mutating_rsi":
        details.append("claim_level must be full_autonomous_self_mutating_rsi")
    if summary.get("claim_publish_authority") is not False:
        details.append("claim_publish_authority must be false")
    if summary.get("claim_publish_decision") != "deny":
        details.append("claim_publish_decision must be deny")
    add_gap(gaps, f"{prefix}_claim_publication_not_denied", details)


def validate_control_surface(prefix: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    surface = control_surface(summary)
    if surface.get("loop_goal") != LOOP_GOAL:
        add_gap(gaps, f"{prefix}_control_surface_goal_mismatch", [f"loop_goal must be {LOOP_GOAL}"])

    bounded = surface.get("bounded_governed_rsi") if isinstance(surface.get("bounded_governed_rsi"), dict) else {}
    bounded_details = []
    if bounded.get("status") != "supported":
        bounded_details.append("bounded_governed_rsi.status must be supported")
    if bounded.get("evidence_state") != "passing":
        bounded_details.append("bounded_governed_rsi.evidence_state must be passing")
    if bounded.get("improvement_state") != "target_exceeded":
        bounded_details.append("bounded_governed_rsi.improvement_state must be target_exceeded")
    add_gap(gaps, f"{prefix}_control_surface_bounded_rsi_not_supported", bounded_details)

    full = (
        surface.get("full_autonomous_self_mutating_rsi")
        if isinstance(surface.get("full_autonomous_self_mutating_rsi"), dict)
        else {}
    )
    full_details = []
    if full.get("status") != "denied":
        full_details.append("full_autonomous_self_mutating_rsi.status must be denied")
    if full.get("decision") != "deny":
        full_details.append("full_autonomous_self_mutating_rsi.decision must be deny")
    if full.get("publish_authority") is not False:
        full_details.append("full_autonomous_self_mutating_rsi.publish_authority must be false")
    if full.get("boundary_state") != "enforced_by_design":
        full_details.append("full_autonomous_self_mutating_rsi.boundary_state must be enforced_by_design")
    add_gap(gaps, f"{prefix}_control_surface_full_autonomy_not_denied", full_details)

    score = surface.get("improvement_score") if isinstance(surface.get("improvement_score"), dict) else {}
    score_details = []
    if score.get("target_exceeded") is not True:
        score_details.append("improvement_score.target_exceeded must be true")
    if score.get("interpretation") != IMPROVEMENT_INTERPRETATION:
        score_details.append(f"improvement_score.interpretation must be {IMPROVEMENT_INTERPRETATION}")
    add_gap(gaps, f"{prefix}_improvement_score_interpretation_drift", score_details)


def validate_trust(prefix: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    trust = trust_boundary(summary)
    details = []
    expected = {
        "local_only": True,
        "uses_network": False,
        "stores_credentials": False,
        "requires_provider_api_key": False,
        "mutates_repositories": False,
        "approves_rsi_claims": False,
        "publishes_claims": False,
    }
    for key, expected_value in expected.items():
        if trust.get(key) is not expected_value:
            details.append(f"{key} must be {str(expected_value).lower()}")
    add_gap(gaps, f"{prefix}_trust_boundary_drift", details)


def validate_gate(gate: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    details = []
    if gate.get("schema_version") != GATE_SCHEMA_VERSION:
        details.append(f"schema_version must be {GATE_SCHEMA_VERSION}")
    if gate.get("status") != "passed":
        details.append("status must be passed")
    if gate.get("improvement_ready") is not True:
        details.append("improvement_ready must be true")
    metric = gate.get("metric") if isinstance(gate.get("metric"), dict) else {}
    if metric.get("measured_improvement_percent", 0) < metric.get("target_percent", 0):
        details.append("measured_improvement_percent must meet or exceed target_percent")
    add_gap(gaps, "gate_summary_not_passing", details)
    validate_claim_publication("gate", gate, gaps)
    validate_control_surface("gate", gate, gaps)
    validate_trust("gate", gate, gaps)


def validate_trend(trend: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    details = []
    if trend.get("schema_version") != TREND_SCHEMA_VERSION:
        details.append(f"schema_version must be {TREND_SCHEMA_VERSION}")
    if trend.get("status") != "passed":
        details.append("status must be passed")
    if trend.get("trend_ready") is not True:
        details.append("trend_ready must be true")
    if trend.get("current_measured_improvement_percent", 0) < trend.get("target_percent", 0):
        details.append("current_measured_improvement_percent must meet or exceed target_percent")
    add_gap(gaps, "trend_summary_not_passing", details)
    validate_claim_publication("trend", trend, gaps)
    validate_control_surface("trend", trend, gaps)
    validate_trust("trend", trend, gaps)


def build_summary(
    gate: dict[str, Any],
    trend: dict[str, Any],
    *,
    gate_summary_path: Path,
    trend_summary_path: Path,
) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    validate_gate(gate, gaps)
    validate_trend(trend, gaps)
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_paths": {
            "improvement_evidence_gate": str(gate_summary_path),
            "improvement_trend": str(trend_summary_path),
        },
        "producer_schema_versions": {
            "improvement_evidence_gate": gate.get("schema_version"),
            "improvement_trend": trend.get("schema_version"),
        },
        "control_surface_readback": control_surface(gate),
        "trend_control_surface_readback": control_surface(trend),
        "metrics": {
            "gate": gate.get("metric", {}),
            "trend": {
                "current_measured_improvement_percent": trend.get("current_measured_improvement_percent"),
                "previous_measured_improvement_percent": trend.get("previous_measured_improvement_percent"),
                "delta_from_previous_percent": trend.get("delta_from_previous_percent"),
                "target_percent": trend.get("target_percent"),
            },
        },
        "operator_interpretation": {
            "bounded_governed_rsi": "supported_passing_improving",
            "full_autonomous_self_mutating_rsi": "denied_boundary_enforced",
            "improvement_score": "evidence_coverage_not_publication_authority",
        },
        "gaps": gaps,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_rsi_claims": False,
            "mutates_ao_artifacts": False,
            "applies_ao_patches": False,
            "mutates_github_repositories": False,
            "mutates_observer_storage": False,
            "publishes_claims": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gate-summary-json",
        required=True,
        type=Path,
        help="AO2 target/rsi-improvement-evidence-gate/latest/summary.json",
    )
    parser.add_argument(
        "--trend-summary-json",
        required=True,
        type=Path,
        help="AO2 target/rsi-improvement-trend/latest/summary.json",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Output readback summary JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gate = read_json(args.gate_summary_json)
    trend = read_json(args.trend_summary_json)
    summary = build_summary(
        gate,
        trend,
        gate_summary_path=args.gate_summary_json,
        trend_summary_path=args.trend_summary_json,
    )
    write_summary(args.out_json, summary)

    print(f"control_plane_ao2_rsi_control_surface_readback={summary['status']}")
    print("bounded_governed_rsi=supported evidence_state=passing")
    print("full_autonomous_self_mutating_rsi=denied boundary_state=enforced_by_design")
    print(f"improvement_score=target_exceeded interpretation={IMPROVEMENT_INTERPRETATION}")
    for gap in summary["gaps"]:
        print(f"{gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
