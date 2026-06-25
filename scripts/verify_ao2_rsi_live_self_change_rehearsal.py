#!/usr/bin/env python3
"""Verify AO2 RSI live self-change rehearsal as read-only control-plane evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-rsi-live-self-change-rehearsal-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.rsi-live-self-change-rehearsal.v1"
TARGET_FILE = "scripts/rsi-claim-readiness-audit.sh"

REQUIRED_FULL_CLAIM_BLOCKERS = [
    "observer_readback",
    "covenant_claim_publish_approval",
    "retained_claim_level_evidence",
]

EXPECTED_EVIDENCE_PATHS = [
    "summary.json",
    "proposed-live-self-change.patch",
    "rollback-live-self-change.patch",
]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "rsi_claim_blocker", "details": details})


def is_relative_artifact_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def nested_metadata(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def blocker_ids(producer: dict[str, Any]) -> list[str]:
    blockers = producer.get("full_claim_blockers")
    if not isinstance(blockers, list):
        return []
    return [item for item in blockers if isinstance(item, str)]


def validate_producer_summary(producer: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if producer.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if producer.get("status") != "live_rehearsal_passed":
        add_gap(gaps, "producer_status_not_ready", ["status must be live_rehearsal_passed"])

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

    self_change = producer.get("self_change") if isinstance(producer.get("self_change"), dict) else {}
    self_change_details = []
    if self_change.get("mode") != "live_rehearsal":
        self_change_details.append("self_change.mode must be live_rehearsal")
    if self_change.get("repository") != "ao2":
        self_change_details.append("self_change.repository must be ao2")
    if self_change.get("change_class") != "verification_path_hardening":
        self_change_details.append("self_change.change_class must be verification_path_hardening")
    if self_change.get("target_files") != [TARGET_FILE]:
        self_change_details.append("self_change.target_files must be [scripts/rsi-claim-readiness-audit.sh]")

    target_before = (
        self_change.get("target_before_sha256")
        if isinstance(self_change.get("target_before_sha256"), dict)
        else {}
    )
    before_sha = target_before.get(TARGET_FILE)
    if not SHA256_RE.fullmatch(str(before_sha or "")):
        self_change_details.append(
            "self_change.target_before_sha256.scripts/rsi-claim-readiness-audit.sh must be a lowercase sha256"
        )

    mutation_sha = str(self_change.get("target_after_mutation_sha256", ""))
    if not SHA256_RE.fullmatch(mutation_sha) or mutation_sha == str(before_sha or ""):
        self_change_details.append(
            "self_change.target_after_mutation_sha256 must be a different lowercase sha256"
        )
    if self_change.get("applies_patch") is not True:
        self_change_details.append("self_change.applies_patch must be true")

    proposed_patch = nested_metadata(self_change, "proposed_patch")
    if not SHA256_RE.fullmatch(str(proposed_patch.get("sha256", ""))):
        self_change_details.append("self_change.proposed_patch.sha256 must be a lowercase sha256")
    if not is_relative_artifact_path(proposed_patch.get("path")):
        self_change_details.append("self_change.proposed_patch.path must be a relative artifact path")
    add_gap(gaps, "self_change_contract_drift", self_change_details)

    restored_details = []
    rollback_sha = str(self_change.get("target_after_rollback_sha256", ""))
    if self_change.get("repository_restored") is not True:
        restored_details.append("self_change.repository_restored must be true")
    if rollback_sha != str(before_sha or "") or not SHA256_RE.fullmatch(rollback_sha):
        restored_details.append("self_change.target_after_rollback_sha256 must match target_before_sha256")
    add_gap(gaps, "self_change_repository_not_restored", restored_details)

    rollback = producer.get("rollback") if isinstance(producer.get("rollback"), dict) else {}
    rollback_details = []
    if rollback.get("mode") != "live_rehearsal":
        rollback_details.append("rollback.mode must be live_rehearsal")
    if rollback.get("status") != "passed":
        rollback_details.append("rollback.status must be passed")
    if rollback.get("same_change_class") is not True:
        rollback_details.append("rollback.same_change_class must be true")
    rollback_patch = nested_metadata(rollback, "rollback_patch")
    if not SHA256_RE.fullmatch(str(rollback_patch.get("sha256", ""))):
        rollback_details.append("rollback.rollback_patch.sha256 must be a lowercase sha256")
    if not is_relative_artifact_path(rollback_patch.get("path")):
        rollback_details.append("rollback.rollback_patch.path must be a relative artifact path")
    add_gap(gaps, "rollback_not_passed", rollback_details)

    live_evidence = (
        producer.get("live_self_change_evidence")
        if isinstance(producer.get("live_self_change_evidence"), dict)
        else {}
    )
    evidence_details = []
    if live_evidence.get("status") != "passed":
        evidence_details.append("live_self_change_evidence.status must be passed")
    if live_evidence.get("evidence_paths") != EXPECTED_EVIDENCE_PATHS:
        evidence_details.append("live_self_change_evidence.evidence_paths must list live rehearsal artifacts")
    add_gap(gaps, "live_self_change_evidence_not_passed", evidence_details)

    observer = producer.get("observer_readback") if isinstance(producer.get("observer_readback"), dict) else {}
    observer_details = []
    if observer.get("status") != "missing":
        observer_details.append("observer_readback.status must remain missing until independent readback is published")
    if observer.get("observer") != "ao2-control-plane":
        observer_details.append("observer_readback.observer must be ao2-control-plane")
    if observer.get("evidence_paths") != []:
        observer_details.append("observer_readback.evidence_paths must be empty")
    add_gap(gaps, "observer_readback_not_missing", observer_details)

    observed_blockers = blocker_ids(producer)
    missing_blockers = [name for name in REQUIRED_FULL_CLAIM_BLOCKERS if name not in observed_blockers]
    add_gap(gaps, "missing_required_full_claim_blockers", missing_blockers)

    trust = producer.get("trust_boundary") if isinstance(producer.get("trust_boundary"), dict) else {}
    trust_drift = []
    expected_trust = {
        "local_only": True,
        "uses_network": False,
        "requires_provider_api_key": False,
        "stores_credentials": False,
        "mutates_repositories": True,
        "applies_patch": True,
        "rollback_applied": True,
        "publishes_claims": False,
    }
    for key, expected in expected_trust.items():
        if trust.get(key) is not expected:
            trust_drift.append(f"{key} must be {str(expected).lower()}")
    add_gap(gaps, "producer_trust_boundary_drift", trust_drift)

    return gaps


def build_summary(producer: dict[str, Any], *, live_rehearsal_summary_path: Path) -> dict[str, Any]:
    gaps = validate_producer_summary(producer)
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_path": str(live_rehearsal_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "claim_boundary": producer.get("claim_boundary", {}),
        "self_change": producer.get("self_change", {}),
        "rollback": producer.get("rollback", {}),
        "live_self_change_evidence": producer.get("live_self_change_evidence", {}),
        "observer_readback": producer.get("observer_readback", {}),
        "required_full_claim_blockers": REQUIRED_FULL_CLAIM_BLOCKERS,
        "observed_full_claim_blockers": blocker_ids(producer),
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
        "--live-rehearsal-summary-json",
        required=True,
        type=Path,
        help="AO2 target/rsi-live-self-change-rehearsal/latest/summary.json",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Output readback summary JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    producer = read_json(args.live_rehearsal_summary_json)
    summary = build_summary(producer, live_rehearsal_summary_path=args.live_rehearsal_summary_json)
    write_summary(args.out_json, summary)

    print(f"control_plane_ao2_rsi_live_self_change_rehearsal_readback={summary['status']}")
    print("claim_level=full_autonomous_self_mutating_rsi decision=denied")
    if summary["gaps"]:
        for gap in summary["gaps"]:
            print(f"{gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
