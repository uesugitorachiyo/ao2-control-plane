#!/usr/bin/env python3
"""Read back AO2 dual-repo public approval closure from the control plane."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


SCHEMA_VERSION = "ao2.cp-ao2-dual-repo-public-approval-closure-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.dual-repo-public-approval-closure.v1"
DEFAULT_REPO = "uesugitorachiyo/ao2"
DEFAULT_BRANCH = "main"
DEFAULT_WORKFLOW = "Dual Repo Public Approval Closure"
DEFAULT_ARTIFACT = "ao2-dual-repo-public-approval-closure"

REQUIRED_SOURCE_ARTIFACTS = [
    "ao2-public-release-operator-checklist-closure",
    "ao2-control-plane-public-release-pair-verification",
    "ao2-control-plane-ao2-stable-promotion-evidence-index-readback",
]

EXPECTED_SOURCE_SCHEMAS = {
    "ao2_public_release_operator_checklist_closure": "ao2.public-release-operator-checklist-closure.v1",
    "control_plane_public_release_pair_verification": "ao2.cp-public-release-pair-verification.v1",
    "control_plane_ao2_stable_promotion_evidence_index_readback": "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def gh_api(endpoint: str) -> dict[str, Any]:
    result = subprocess.run(["gh", "api", endpoint], check=True, text=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def latest_successful_run(repo: str, branch: str, workflow: str) -> dict[str, Any]:
    query = urlencode({"branch": branch, "status": "success", "per_page": "50"})
    response = gh_api(f"repos/{repo}/actions/runs?{query}")
    for run in response.get("workflow_runs", []):
        if (
            run.get("name") == workflow
            and run.get("head_branch") == branch
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
        ):
            return run
    raise SystemExit(f"no successful {workflow!r} run found on branch {branch!r}")


def run_artifact(repo: str, run_id: int, artifact_name: str) -> dict[str, Any]:
    response = gh_api(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    for artifact in response.get("artifacts", []):
        if artifact.get("name") == artifact_name:
            return artifact
    raise SystemExit(f"missing artifact {artifact_name!r} on run {run_id}")


def download_artifact(repo: str, run_id: int, artifact_name: str, work_dir: Path) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "gh",
            "run",
            "download",
            str(run_id),
            "--repo",
            repo,
            "--name",
            artifact_name,
            "--dir",
            str(work_dir),
        ],
        check=True,
    )
    summary_path = work_dir / "summary.json"
    if not summary_path.is_file():
        raise SystemExit(f"downloaded artifact {artifact_name!r} did not contain summary.json")
    return summary_path


def add_gap(gaps: list[dict[str, Any]], gap_kind: str, details: list[str]) -> None:
    if details:
        gaps.append({"gap_kind": gap_kind, "severity": "release_blocker", "details": details})


def validate_producer_summary(producer: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    if producer.get("schema_version") != PRODUCER_SCHEMA_VERSION:
        add_gap(gaps, "producer_schema_mismatch", [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"])
    if producer.get("status") != "passed":
        add_gap(gaps, "producer_status_not_passed", ["status must be passed"])
    if producer.get("dual_repo_public_approval_closure_ready") is not True:
        add_gap(gaps, "producer_not_ready", ["dual_repo_public_approval_closure_ready must be true"])
    if producer.get("release_go_no_go") != "go":
        add_gap(gaps, "producer_release_go_no_go_not_go", ["release_go_no_go must be go"])
    if producer.get("operator_decision_fields_remain_unapproved") is not True:
        add_gap(
            gaps,
            "producer_operator_decision_fields_not_unapproved",
            ["operator_decision_fields_remain_unapproved must be true"],
        )

    failures = producer.get("failures")
    if failures:
        failure_codes = []
        for item in failures:
            if isinstance(item, dict) and item.get("code"):
                failure_codes.append(str(item["code"]))
            else:
                failure_codes.append(str(item))
        add_gap(gaps, "producer_failures_present", failure_codes)

    source_artifacts = producer.get("source_artifacts")
    if not isinstance(source_artifacts, list):
        source_artifacts = []
    missing_artifacts = [name for name in REQUIRED_SOURCE_ARTIFACTS if name not in source_artifacts]
    add_gap(gaps, "missing_required_source_artifacts", missing_artifacts)

    sources = producer.get("sources") if isinstance(producer.get("sources"), dict) else {}
    source_drift = []
    for name, expected_schema in EXPECTED_SOURCE_SCHEMAS.items():
        item = sources.get(name)
        if not isinstance(item, dict):
            source_drift.append(f"{name} missing")
            continue
        if item.get("schema_version") != expected_schema:
            source_drift.append(f"{name}.schema_version must be {expected_schema}")
        if item.get("status") != "passed":
            source_drift.append(f"{name}.status must be passed")
        if name == "ao2_public_release_operator_checklist_closure" and item.get("ready") is not True:
            source_drift.append(f"{name}.ready must be true")
        if (
            name == "control_plane_ao2_stable_promotion_evidence_index_readback"
            and item.get("producer_ready") is not True
        ):
            source_drift.append(f"{name}.producer_ready must be true")
        if name == "control_plane_public_release_pair_verification" and item.get("common_platforms") != [
            "linux-x86_64",
            "macos-aarch64",
            "windows-x86_64",
        ]:
            source_drift.append(f"{name}.common_platforms must cover linux-x86_64, macos-aarch64, windows-x86_64")
    add_gap(gaps, "producer_source_drift", source_drift)

    trust = producer.get("trust_boundary") if isinstance(producer.get("trust_boundary"), dict) else {}
    trust_drift = []
    expected_false = [
        "control_plane_approves_release",
        "mutates_releases",
        "stores_credentials",
        "mutates_ao_artifacts",
        "mutates_github_releases",
        "credential_material_included",
        "provider_api_keys_allowed",
    ]
    if trust.get("local_only") is not True:
        trust_drift.append("local_only must be true")
    for key in expected_false:
        if trust.get(key) is not False:
            trust_drift.append(f"{key} must be false")
    add_gap(gaps, "producer_trust_boundary_drift", trust_drift)

    return gaps


def build_summary(
    producer: dict[str, Any],
    *,
    closure_summary_path: Path,
    downloads_github_actions_artifacts: bool,
    repo: str,
    branch: str,
    workflow: str,
    run: dict[str, Any] | None,
    artifact: dict[str, Any] | None,
) -> dict[str, Any]:
    gaps = validate_producer_summary(producer)
    status = "passed" if not gaps else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "producer_repo": repo,
        "producer_branch": branch,
        "producer_workflow": workflow,
        "producer_run_id": run.get("id") if run else None,
        "producer_run_url": run.get("html_url") if run else None,
        "producer_artifact": {
            "name": artifact.get("name"),
            "id": artifact.get("id"),
            "size_in_bytes": artifact.get("size_in_bytes"),
            "expired": artifact.get("expired") is True,
        }
        if artifact
        else None,
        "producer_summary_path": str(closure_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "producer_ready": producer.get("dual_repo_public_approval_closure_ready") is True,
        "producer_release_go_no_go": producer.get("release_go_no_go"),
        "producer_operator_decision_fields_remain_unapproved": producer.get(
            "operator_decision_fields_remain_unapproved"
        )
        is True,
        "required_source_artifacts": REQUIRED_SOURCE_ARTIFACTS,
        "producer_sources": producer.get("sources", {}),
        "producer_failures": producer.get("failures", []),
        "gaps": gaps,
        "trust_boundary": {
            "downloads_github_actions_artifacts": downloads_github_actions_artifacts,
            "control_plane_approves_release": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO2 dual-repo public approval closure as read-only control-plane evidence."
    )
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Producer GitHub repository in owner/name form")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help="Producer branch to inspect")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW, help="Producer workflow name")
    parser.add_argument("--artifact", default=DEFAULT_ARTIFACT, help="Producer artifact name")
    parser.add_argument("--run-id", type=int, help="Specific producer Actions run id to download")
    parser.add_argument(
        "--closure-summary-json",
        type=Path,
        help="Use an already-downloaded AO2 dual-repo public approval closure summary instead of downloading an artifact",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("target/ao2-dual-repo-public-approval-closure-readback/download"),
        help="Directory for downloaded producer artifact contents",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Path for the token-free readback summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run = None
    artifact = None
    downloads = args.closure_summary_json is None

    if args.closure_summary_json is not None:
        closure_summary_path = args.closure_summary_json
    else:
        run = {"id": args.run_id} if args.run_id is not None else latest_successful_run(args.repo, args.branch, args.workflow)
        artifact = run_artifact(args.repo, int(run["id"]), args.artifact)
        if artifact.get("expired") is True:
            raise SystemExit(f"artifact {args.artifact!r} on run {run['id']} is expired")
        closure_summary_path = download_artifact(args.repo, int(run["id"]), args.artifact, args.work_dir)

    producer = read_json(closure_summary_path)
    summary = build_summary(
        producer,
        closure_summary_path=closure_summary_path,
        downloads_github_actions_artifacts=downloads,
        repo=args.repo,
        branch=args.branch,
        workflow=args.workflow,
        run=run,
        artifact=artifact,
    )
    write_summary(args.out_json, summary)
    print(f"control_plane_ao2_dual_repo_public_approval_closure_readback={summary['status']}")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
