#!/usr/bin/env python3
"""Verify AO2 RSI authority-packet dry-run candidate as read-only evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-ao2-rsi-authority-packet-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.rsi-governed-self-change-dry-run.v1"
AUTHORITY_PACKET_SCHEMA_VERSION = "covenant.live-self-change-authority.v1"
CLAIM_LEVEL = "full_autonomous_self_mutating_rsi"
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_producer_summary(producer: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if producer.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if producer.get("status") != "dry_run_evidence_ready":
        add_gap(gaps, "producer_status_not_ready", ["status must be dry_run_evidence_ready"])

    claim_boundary = producer.get("claim_boundary") if isinstance(producer.get("claim_boundary"), dict) else {}
    claim_boundary_details = []
    if claim_boundary.get("bounded_governed_rsi") != "allowed":
        claim_boundary_details.append("claim_boundary.bounded_governed_rsi must be allowed")
    if claim_boundary.get(CLAIM_LEVEL) != "denied":
        claim_boundary_details.append("claim_boundary.full_autonomous_self_mutating_rsi must be denied")
    add_gap(gaps, "producer_claim_boundary_drift", claim_boundary_details)

    packet = (
        producer.get("mutation_authority_packet")
        if isinstance(producer.get("mutation_authority_packet"), dict)
        else {}
    )
    packet_details = []
    if packet.get("mode") != "dry_run_candidate":
        packet_details.append("mutation_authority_packet.mode must be dry_run_candidate")
    if packet.get("schema_version") != AUTHORITY_PACKET_SCHEMA_VERSION:
        packet_details.append(
            f"mutation_authority_packet.schema_version must be {AUTHORITY_PACKET_SCHEMA_VERSION}"
        )
    if not is_relative_artifact_path(packet.get("path")):
        packet_details.append("mutation_authority_packet.path must be a relative artifact path")
    if not SHA256_RE.fullmatch(str(packet.get("sha256", ""))):
        packet_details.append("mutation_authority_packet.sha256 must be a lowercase sha256")
    add_gap(gaps, "authority_packet_contract_drift", packet_details)

    if packet.get("schema_valid_for_claim_publish") is not False:
        add_gap(
            gaps,
            "authority_packet_marked_claim_publish_valid",
            ["mutation_authority_packet.schema_valid_for_claim_publish must be false"],
        )

    trust = producer.get("trust_boundary") if isinstance(producer.get("trust_boundary"), dict) else {}
    trust_drift = []
    if trust.get("local_only") is not True:
        trust_drift.append("local_only must be true")
    if trust.get("emits_authority_packet_candidate") is not True:
        trust_drift.append("emits_authority_packet_candidate must be true")
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


def validate_packet(packet: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    contract_details = []
    if packet.get("schema_version") != AUTHORITY_PACKET_SCHEMA_VERSION:
        contract_details.append(f"schema_version must be {AUTHORITY_PACKET_SCHEMA_VERSION}")
    if packet.get("claim_level") != CLAIM_LEVEL:
        contract_details.append("claim_level must be full_autonomous_self_mutating_rsi")
    if packet.get("repository") != "ao2":
        contract_details.append("repository must be ao2")
    if packet.get("change_class") != "verification_path":
        contract_details.append("change_class must be verification_path")
    allowed_write_surface = packet.get("allowed_write_surface")
    if allowed_write_surface != ["scripts/rsi-claim-readiness-audit.sh"]:
        contract_details.append("allowed_write_surface must be [scripts/rsi-claim-readiness-audit.sh]")
    exact_digest = packet.get("exact_digest") if isinstance(packet.get("exact_digest"), dict) else {}
    if exact_digest.get("algorithm") != "sha256":
        contract_details.append("exact_digest.algorithm must be sha256")
    if not SHA256_RE.fullmatch(str(exact_digest.get("value", ""))):
        contract_details.append("exact_digest.value must be a lowercase sha256")
    add_gap(gaps, "authority_packet_contract_drift", contract_details)

    rollback = packet.get("rollback_evidence") if isinstance(packet.get("rollback_evidence"), dict) else {}
    rollback_details = []
    if rollback.get("status") != "passed":
        rollback_details.append("rollback_evidence.status must be passed")
    if rollback.get("evidence_paths") != ["summary.json"]:
        rollback_details.append("rollback_evidence.evidence_paths must be [summary.json]")
    add_gap(gaps, "authority_packet_rollback_evidence_drift", rollback_details)

    live_self_change = (
        packet.get("live_self_change_evidence")
        if isinstance(packet.get("live_self_change_evidence"), dict)
        else {}
    )
    observer_readback = (
        packet.get("observer_readback") if isinstance(packet.get("observer_readback"), dict) else {}
    )
    boundary_details = []
    if live_self_change.get("status") != "dry_run_not_live":
        boundary_details.append("live_self_change_evidence.status must be dry_run_not_live")
    if live_self_change.get("evidence_paths") != []:
        boundary_details.append("live_self_change_evidence.evidence_paths must be empty")
    if observer_readback.get("status") != "missing":
        boundary_details.append("observer_readback.status must be missing")
    if observer_readback.get("observer") != "ao2-control-plane":
        boundary_details.append("observer_readback.observer must be ao2-control-plane")
    if observer_readback.get("evidence_paths") != []:
        boundary_details.append("observer_readback.evidence_paths must be empty")
    add_gap(gaps, "authority_packet_claim_boundary_drift", boundary_details)

    return gaps


def resolve_packet_path(summary_path: Path, relative_path: str) -> Path:
    return summary_path.parent / relative_path


def build_summary(producer: dict[str, Any], *, self_change_summary_path: Path) -> dict[str, Any]:
    gaps = validate_producer_summary(producer)
    packet_meta = (
        producer.get("mutation_authority_packet")
        if isinstance(producer.get("mutation_authority_packet"), dict)
        else {}
    )
    packet_path_text = packet_meta.get("path")
    packet_path = None
    packet_sha256 = ""
    packet = {}

    if is_relative_artifact_path(packet_path_text):
        packet_path = resolve_packet_path(self_change_summary_path, str(packet_path_text))
        if packet_path.is_file():
            packet_sha256 = sha256_file(packet_path)
            expected_sha256 = str(packet_meta.get("sha256", ""))
            if packet_sha256 != expected_sha256:
                add_gap(
                    gaps,
                    "authority_packet_sha256_mismatch",
                    [f"mutation_authority_packet.sha256 must match {packet_path_text}"],
                )
            packet = read_json(packet_path)
            gaps.extend(validate_packet(packet))
        else:
            add_gap(gaps, "authority_packet_missing", [f"{packet_path_text} must exist beside summary.json"])

    status = "passed" if not gaps else "blocked"
    live_self_change = (
        packet.get("live_self_change_evidence")
        if isinstance(packet.get("live_self_change_evidence"), dict)
        else {}
    )
    observer_readback = (
        packet.get("observer_readback") if isinstance(packet.get("observer_readback"), dict) else {}
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_summary_path": str(self_change_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "claim_boundary": producer.get("claim_boundary", {}),
        "authority_packet_path": str(packet_path) if packet_path else "",
        "authority_packet_sha256": packet_sha256,
        "authority_packet": {
            "mode": packet_meta.get("mode"),
            "schema_version": packet.get("schema_version") or packet_meta.get("schema_version"),
            "schema_valid_for_claim_publish": packet_meta.get("schema_valid_for_claim_publish"),
            "claim_level": packet.get("claim_level"),
            "repository": packet.get("repository"),
            "live_self_change_status": live_self_change.get("status"),
            "observer_readback_status": observer_readback.get("status"),
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
    parser = argparse.ArgumentParser(
        description="Verify AO2 RSI authority-packet dry-run candidate as read-only control-plane evidence."
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
    print(f"control_plane_ao2_rsi_authority_packet_readback={summary['status']}")
    print(f"claim_level={CLAIM_LEVEL} decision=denied")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
