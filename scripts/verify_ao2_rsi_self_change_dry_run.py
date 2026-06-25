#!/usr/bin/env python3
"""Verify AO2 RSI self-change dry-run as read-only control-plane evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-rsi-self-change-dry-run-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.rsi-governed-self-change-dry-run.v1"

REQUIRED_FULL_CLAIM_BLOCKERS = [
    "mutation_authority",
    "live_self_change_evidence",
    "executed_rollback_evidence",
    "observer_readback",
    "covenant_claim_publish_approval",
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


def nested_patch_metadata(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def blocker_ids(producer: dict[str, Any]) -> list[str]:
    blockers = producer.get("full_claim_blockers")
    if not isinstance(blockers, list):
        return []
    return [item for item in blockers if isinstance(item, str)]


def validate_rollback_rehearsal(producer: dict[str, Any], target_sha: Any) -> list[str]:
    rehearsal = (
        producer.get("rollback_rehearsal")
        if isinstance(producer.get("rollback_rehearsal"), dict)
        else {}
    )
    details = []
    if rehearsal.get("mode") != "executed_in_temporary_workspace":
        details.append("rollback_rehearsal.mode must be executed_in_temporary_workspace")
    if rehearsal.get("status") != "passed":
        details.append("rollback_rehearsal.status must be passed")
    if rehearsal.get("workspace") != "rollback-rehearsal/worktree":
        details.append("rollback_rehearsal.workspace must be rollback-rehearsal/worktree")
    if rehearsal.get("target_file") != "scripts/rsi-claim-readiness-audit.sh":
        details.append("rollback_rehearsal.target_file must be scripts/rsi-claim-readiness-audit.sh")

    target_sha_text = str(target_sha or "")
    before_sha = str(rehearsal.get("target_before_sha256", ""))
    proposed_sha = str(rehearsal.get("target_after_proposed_sha256", ""))
    rollback_sha = str(rehearsal.get("target_after_rollback_sha256", ""))
    if before_sha != target_sha_text or not SHA256_RE.fullmatch(before_sha):
        details.append("rollback_rehearsal.target_before_sha256 must match self_change target sha256")
    if not SHA256_RE.fullmatch(proposed_sha) or proposed_sha == target_sha_text:
        details.append("rollback_rehearsal.target_after_proposed_sha256 must be a different lowercase sha256")
    if rollback_sha != target_sha_text or not SHA256_RE.fullmatch(rollback_sha):
        details.append("rollback_rehearsal.target_after_rollback_sha256 must match self_change target sha256")

    if rehearsal.get("proposed_patch_applied") is not True:
        details.append("rollback_rehearsal.proposed_patch_applied must be true")
    if rehearsal.get("rollback_patch_applied") is not True:
        details.append("rollback_rehearsal.rollback_patch_applied must be true")
    if rehearsal.get("same_change_class") is not True:
        details.append("rollback_rehearsal.same_change_class must be true")
    if rehearsal.get("verification") != ["bash -n scripts/rsi-claim-readiness-audit.sh"]:
        details.append(
            "rollback_rehearsal.verification must include bash -n scripts/rsi-claim-readiness-audit.sh"
        )
    return details


def validate_producer_summary(producer: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if producer.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if producer.get("status") != "dry_run_evidence_ready":
        add_gap(gaps, "producer_status_not_ready", ["status must be dry_run_evidence_ready"])

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
    if self_change.get("mode") != "dry_run":
        add_gap(gaps, "self_change_not_dry_run", ["self_change.mode must be dry_run"])
    if self_change.get("applies_patch") is not False:
        add_gap(gaps, "self_change_would_apply_patch", ["self_change.applies_patch must be false"])
    self_change_details = []
    if self_change.get("repository") != "ao2":
        self_change_details.append("self_change.repository must be ao2")
    if self_change.get("change_class") != "verification_path_hardening":
        self_change_details.append("self_change.change_class must be verification_path_hardening")
    target_files = self_change.get("target_files")
    if target_files != ["scripts/rsi-claim-readiness-audit.sh"]:
        self_change_details.append(
            "self_change.target_files must be [scripts/rsi-claim-readiness-audit.sh]"
        )
    target_before = (
        self_change.get("target_before_sha256")
        if isinstance(self_change.get("target_before_sha256"), dict)
        else {}
    )
    target_sha = target_before.get("scripts/rsi-claim-readiness-audit.sh")
    if not SHA256_RE.fullmatch(str(target_sha or "")):
        self_change_details.append(
            "self_change.target_before_sha256.scripts/rsi-claim-readiness-audit.sh must be a lowercase sha256"
        )
    proposed_patch = nested_patch_metadata(self_change, "proposed_patch")
    if not SHA256_RE.fullmatch(str(proposed_patch.get("sha256", ""))):
        self_change_details.append("self_change.proposed_patch.sha256 must be a lowercase sha256")
    if not is_relative_artifact_path(proposed_patch.get("path")):
        self_change_details.append("self_change.proposed_patch.path must be a relative artifact path")
    add_gap(gaps, "self_change_contract_drift", self_change_details)

    rollback = producer.get("rollback") if isinstance(producer.get("rollback"), dict) else {}
    rollback_details = []
    if rollback.get("mode") != "dry_run":
        rollback_details.append("rollback.mode must be dry_run")
    if rollback.get("rehearsal_status") != "planned_not_executed":
        rollback_details.append("rollback.rehearsal_status must be planned_not_executed")
    if rollback.get("same_change_class") is not True:
        rollback_details.append("rollback.same_change_class must be true")
    rollback_patch = nested_patch_metadata(rollback, "rollback_patch")
    if not SHA256_RE.fullmatch(str(rollback_patch.get("sha256", ""))):
        rollback_details.append("rollback.rollback_patch.sha256 must be a lowercase sha256")
    if not is_relative_artifact_path(rollback_patch.get("path")):
        rollback_details.append("rollback.rollback_patch.path must be a relative artifact path")
    add_gap(gaps, "rollback_not_planned_dry_run", rollback_details)
    add_gap(gaps, "rollback_rehearsal_not_executed", validate_rollback_rehearsal(producer, target_sha))

    observed_blockers = blocker_ids(producer)
    missing_blockers = [name for name in REQUIRED_FULL_CLAIM_BLOCKERS if name not in observed_blockers]
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
        "applies_patch",
        "publishes_claims",
    ]:
        if trust.get(key) is not False:
            trust_drift.append(f"{key} must be false")
    add_gap(gaps, "producer_trust_boundary_drift", trust_drift)

    return gaps


def build_summary(producer: dict[str, Any], *, self_change_summary_path: Path) -> dict[str, Any]:
    gaps = validate_producer_summary(producer)
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_path": str(self_change_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "claim_boundary": producer.get("claim_boundary", {}),
        "self_change": producer.get("self_change", {}),
        "rollback": producer.get("rollback", {}),
        "rollback_rehearsal": producer.get("rollback_rehearsal", {}),
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
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO2 RSI self-change dry-run summary as read-only control-plane evidence."
    )
    parser.add_argument(
        "--self-change-summary-json",
        required=True,
        type=Path,
        help="AO2 rsi:self-change-dry-run summary.json",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Path for token-free readback summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    producer = read_json(args.self_change_summary_json)
    summary = build_summary(producer, self_change_summary_path=args.self_change_summary_json)
    write_summary(args.out_json, summary)
    print(f"control_plane_ao2_rsi_self_change_dry_run_readback={summary['status']}")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
