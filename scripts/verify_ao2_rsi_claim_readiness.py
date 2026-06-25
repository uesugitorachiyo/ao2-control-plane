#!/usr/bin/env python3
"""Verify AO2 RSI claim-readiness as read-only control-plane evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-rsi-claim-readiness-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.rsi-claim-readiness-audit.v1"

REQUIRED_FULL_CLAIM_BLOCKERS = [
    "mutation_authority",
    "rollback_evidence",
    "live_self_change_evidence",
    "observer_readback",
    "covenant_claim_publish_approval",
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "rsi_claim_blocker", "details": details})


def full_claim_blocker_ids(producer: dict[str, Any]) -> list[str]:
    claims = producer.get("claims") if isinstance(producer.get("claims"), dict) else {}
    full_claim = claims.get("full_autonomous_self_mutating_rsi")
    if not isinstance(full_claim, dict):
        return []
    blockers = full_claim.get("blockers")
    if not isinstance(blockers, list):
        return []
    blocker_ids = []
    for blocker in blockers:
        if isinstance(blocker, dict) and isinstance(blocker.get("id"), str):
            blocker_ids.append(blocker["id"])
    return blocker_ids


def validate_producer_summary(producer: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if producer.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if producer.get("status") != "claim_boundary_enforced":
        add_gap(gaps, "producer_status_not_boundary_enforced", ["status must be claim_boundary_enforced"])

    claim_boundary = producer.get("claim_boundary") if isinstance(producer.get("claim_boundary"), dict) else {}
    if claim_boundary.get("bounded_governed_rsi") != "allowed":
        add_gap(
            gaps,
            "bounded_claim_boundary_not_allowed",
            ["claim_boundary.bounded_governed_rsi must be allowed"],
        )
    if claim_boundary.get("full_autonomous_self_mutating_rsi") != "denied":
        add_gap(
            gaps,
            "full_claim_boundary_not_denied",
            ["claim_boundary.full_autonomous_self_mutating_rsi must be denied"],
        )

    claims = producer.get("claims") if isinstance(producer.get("claims"), dict) else {}
    bounded = claims.get("bounded_governed_rsi") if isinstance(claims.get("bounded_governed_rsi"), dict) else {}
    full = (
        claims.get("full_autonomous_self_mutating_rsi")
        if isinstance(claims.get("full_autonomous_self_mutating_rsi"), dict)
        else {}
    )
    if bounded.get("decision") != "allowed":
        add_gap(gaps, "bounded_claim_decision_not_allowed", ["bounded_governed_rsi.decision must be allowed"])
    if bounded.get("evidence_state") != "present":
        add_gap(gaps, "bounded_claim_evidence_missing", ["bounded_governed_rsi.evidence_state must be present"])
    if full.get("decision") != "denied":
        add_gap(gaps, "full_claim_decision_not_denied", ["full_autonomous_self_mutating_rsi.decision must be denied"])
    if full.get("evidence_state") != "missing_required_evidence":
        add_gap(
            gaps,
            "full_claim_evidence_state_not_missing",
            ["full_autonomous_self_mutating_rsi.evidence_state must be missing_required_evidence"],
        )

    blocker_ids = full_claim_blocker_ids(producer)
    missing_blockers = [name for name in REQUIRED_FULL_CLAIM_BLOCKERS if name not in blocker_ids]
    add_gap(gaps, "missing_required_full_claim_blockers", missing_blockers)

    trust = producer.get("trust_boundary") if isinstance(producer.get("trust_boundary"), dict) else {}
    trust_drift = []
    if trust.get("local_only") is not True:
        trust_drift.append("local_only must be true")
    for key in [
        "uses_network",
        "stores_credentials",
        "requires_provider_api_key",
        "mutates_repositories",
        "publishes_claims",
    ]:
        if trust.get(key) is not False:
            trust_drift.append(f"{key} must be false")
    add_gap(gaps, "producer_trust_boundary_drift", trust_drift)

    return gaps


def build_summary(producer: dict[str, Any], *, claim_summary_path: Path) -> dict[str, Any]:
    gaps = validate_producer_summary(producer)
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_path": str(claim_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "claim_boundary": producer.get("claim_boundary", {}),
        "claims": producer.get("claims", {}),
        "required_full_claim_blockers": REQUIRED_FULL_CLAIM_BLOCKERS,
        "observed_full_claim_blockers": full_claim_blocker_ids(producer),
        "gaps": gaps,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_rsi_claims": False,
            "mutates_ao_artifacts": False,
            "mutates_github_repositories": False,
            "mutates_observer_storage": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO2 RSI claim-readiness audit as read-only control-plane evidence."
    )
    parser.add_argument(
        "--claim-summary-json",
        required=True,
        type=Path,
        help="AO2 rsi:claim-readiness summary.json",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Path for token-free readback summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    producer = read_json(args.claim_summary_json)
    summary = build_summary(producer, claim_summary_path=args.claim_summary_json)
    write_summary(args.out_json, summary)
    print(f"control_plane_ao2_rsi_claim_readiness_readback={summary['status']}")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
