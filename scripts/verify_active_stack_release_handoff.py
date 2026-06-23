#!/usr/bin/env python3
"""Verify AO Foundry/Covenant active-stack handoff as control-plane evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-active-stack-release-handoff-readback.v1"
FOUNDRY_SCHEMA_VERSION = "ao.foundry.active-stack-readiness.v0.1"
COVENANT_SCHEMA_VERSION = "covenant.policy-spine-result.v1"

ACTIVE_REPOSITORIES = [
    "ao2",
    "ao2-control-plane",
    "ao-foundry",
    "ao-forge",
    "ao-command",
    "ao-covenant",
]

DEPRECATED_REPOSITORIES = [
    "ao-operator",
    "ao-runtime",
    "ao-control-plane",
    "ao-conductor",
    "agy-swarms",
    "codex-cron",
]

REQUIRED_RELEASE_HANDOFF_GATES = [
    "foundry-release-candidate",
    "forge-release-candidate-handoff",
    "covenant-policy-spine",
    "signed-smoke-release-gate",
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "release_blocker", "details": details})


def repository_ids(ledger: dict[str, Any]) -> list[str]:
    repositories = ledger.get("repositories")
    if not isinstance(repositories, list):
        return []
    ids = []
    for item in repositories:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.append(item["id"])
    return ids


def release_handoff_gates(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    release_handoff = ledger.get("release_handoff")
    if not isinstance(release_handoff, dict):
        return {}
    gates = release_handoff.get("gates")
    if not isinstance(gates, list):
        return {}
    by_name = {}
    for gate in gates:
        if isinstance(gate, dict) and isinstance(gate.get("name"), str):
            by_name[gate["name"]] = gate
    return by_name


def active_policy_repositories(policy_spine: dict[str, Any]) -> list[str]:
    scope = policy_spine.get("scope")
    if not isinstance(scope, dict):
        return []
    active = scope.get("active_repositories")
    if not isinstance(active, list):
        return []
    return [repo for repo in active if isinstance(repo, str)]


def validate_foundry_ledger(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if ledger.get("schema_version") != FOUNDRY_SCHEMA_VERSION:
        add_gap(gaps, "foundry_schema_mismatch", [f"schema_version must be {FOUNDRY_SCHEMA_VERSION}"])
    if ledger.get("status") != "ready":
        add_gap(gaps, "foundry_active_stack_not_ready", ["status must be ready"])

    ledger_repos = repository_ids(ledger)
    missing_active = [repo for repo in ACTIVE_REPOSITORIES if repo not in ledger_repos]
    add_gap(gaps, "missing_active_repositories", missing_active)

    deprecated_active = [repo for repo in DEPRECATED_REPOSITORIES if repo in ledger_repos]
    add_gap(gaps, "deprecated_repositories_in_active_stack", deprecated_active)

    release_handoff = ledger.get("release_handoff")
    if not isinstance(release_handoff, dict) or release_handoff.get("status") != "ready":
        add_gap(gaps, "release_handoff_not_ready", ["release_handoff.status must be ready"])

    gates = release_handoff_gates(ledger)
    missing_gates = [name for name in REQUIRED_RELEASE_HANDOFF_GATES if name not in gates]
    add_gap(gaps, "missing_required_release_handoff_gates", missing_gates)

    gate_drift = []
    for name in REQUIRED_RELEASE_HANDOFF_GATES:
        gate = gates.get(name)
        if not gate:
            continue
        if gate.get("required_before_promotion") is not True:
            gate_drift.append(f"{name}.required_before_promotion must be true")
        status = gate.get("status")
        if name == "signed-smoke-release-gate":
            if status not in {"ready", "manual_required"}:
                gate_drift.append(f"{name}.status must be ready or manual_required")
        elif status != "ready":
            gate_drift.append(f"{name}.status must be ready")
        evidence = gate.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            gate_drift.append(f"{name}.evidence must be non-empty")
    add_gap(gaps, "release_handoff_gate_drift", gate_drift)
    return gaps


def validate_policy_spine(policy_spine: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if policy_spine.get("schema_version") != COVENANT_SCHEMA_VERSION:
        add_gap(gaps, "covenant_schema_mismatch", [f"schema_version must be {COVENANT_SCHEMA_VERSION}"])
    if policy_spine.get("stack") != "ao2-first":
        add_gap(gaps, "covenant_stack_mismatch", ["stack must be ao2-first"])
    if policy_spine.get("status") != "ready":
        add_gap(gaps, "covenant_policy_spine_not_ready", ["status must be ready"])

    active = active_policy_repositories(policy_spine)
    missing_active = [repo for repo in ACTIVE_REPOSITORIES if repo not in active]
    details = [f"{repo} missing from covenant policy spine active repositories" for repo in missing_active]
    add_gap(gaps, "active_repository_scope_mismatch", details)

    deprecated_active = [repo for repo in DEPRECATED_REPOSITORIES if repo in active]
    add_gap(gaps, "deprecated_repositories_in_policy_spine", deprecated_active)

    scope = policy_spine.get("scope") if isinstance(policy_spine.get("scope"), dict) else {}
    replaced_by = scope.get("replaced_by") if isinstance(scope.get("replaced_by"), list) else []
    missing_replacements = [repo for repo in ["ao2", "ao2-control-plane"] if repo not in replaced_by]
    add_gap(gaps, "replacement_scope_mismatch", missing_replacements)

    responsibilities = policy_spine.get("responsibilities")
    if not isinstance(responsibilities, list):
        responsibilities = []
    control_plane = [
        item
        for item in responsibilities
        if isinstance(item, dict)
        and item.get("name") == "control-plane-evidence"
        and item.get("owner") == "ao2-control-plane"
    ]
    if not control_plane:
        add_gap(
            gaps,
            "control_plane_responsibility_missing",
            ["control-plane-evidence responsibility must be owned by ao2-control-plane"],
        )
    return gaps


def build_summary(ledger: dict[str, Any], policy_spine: dict[str, Any], *, ledger_path: Path, policy_path: Path) -> dict[str, Any]:
    gaps = validate_foundry_ledger(ledger) + validate_policy_spine(policy_spine)

    ledger_repos = repository_ids(ledger)
    policy_repos = active_policy_repositories(policy_spine)
    mismatch = []
    for repo in sorted(set(ledger_repos) | set(policy_repos)):
        if repo in ACTIVE_REPOSITORIES:
            continue
        if repo in ledger_repos and repo not in policy_repos:
            mismatch.append(f"{repo} present in Foundry ledger but missing from Covenant policy spine")
        if repo in policy_repos and repo not in ledger_repos:
            mismatch.append(f"{repo} present in Covenant policy spine but missing from Foundry ledger")
    add_gap(gaps, "foundry_covenant_scope_mismatch", mismatch)

    status = "passed" if not gaps else "blocked"
    gates = release_handoff_gates(ledger)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "foundry_ledger_path": str(ledger_path),
        "covenant_policy_spine_path": str(policy_path),
        "foundry_schema_version": ledger.get("schema_version"),
        "covenant_schema_version": policy_spine.get("schema_version"),
        "active_repositories": ACTIVE_REPOSITORIES,
        "deprecated_repositories": DEPRECATED_REPOSITORIES,
        "required_release_handoff_gates": REQUIRED_RELEASE_HANDOFF_GATES,
        "release_handoff": {
            "status": ledger.get("release_handoff", {}).get("status")
            if isinstance(ledger.get("release_handoff"), dict)
            else None,
            "gates": {
                name: {
                    "status": gates.get(name, {}).get("status"),
                    "required_before_promotion": gates.get(name, {}).get("required_before_promotion"),
                }
                for name in REQUIRED_RELEASE_HANDOFF_GATES
            },
        },
        "policy_spine": {
            "stack": policy_spine.get("stack"),
            "status": policy_spine.get("status"),
            "active_repositories": policy_repos,
        },
        "gaps": gaps,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_release": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "mutates_observer_storage": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO Foundry active-stack handoff and AO Covenant policy spine as read-only control-plane evidence."
    )
    parser.add_argument("--foundry-ledger", required=True, type=Path, help="AO Foundry active-stack readiness ledger")
    parser.add_argument(
        "--covenant-policy-spine",
        required=True,
        type=Path,
        help="AO Covenant policy spine JSON from `covenant policy spine --json`",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Path for token-free readback summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ledger = read_json(args.foundry_ledger)
    policy_spine = read_json(args.covenant_policy_spine)
    summary = build_summary(ledger, policy_spine, ledger_path=args.foundry_ledger, policy_path=args.covenant_policy_spine)
    write_summary(args.out_json, summary)
    print(f"control_plane_active_stack_release_handoff_readback={summary['status']}")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
