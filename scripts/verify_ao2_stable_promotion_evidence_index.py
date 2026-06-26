#!/usr/bin/env python3
"""Read back AO2 stable-promotion evidence index from the control plane."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


SCHEMA_VERSION = "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1"
PRODUCER_SCHEMA_VERSION = "ao2.stable-promotion-evidence-index.v1"
DEFAULT_REPO = "uesugitorachiyo/ao2"
DEFAULT_BRANCH = "main"
DEFAULT_WORKFLOW = "Stable Promotion Evidence Index"
DEFAULT_ARTIFACT = "ao2-stable-promotion-evidence-index"

REQUIRED_EVIDENCE = [
    "artifact_size_budget_audit",
    "post_release_verification_gate",
    "public_pair_digest_audit",
    "stable_release_evidence_packet",
]

EXPECTED_EVIDENCE_SCHEMAS = {
    "artifact_size_budget_audit": "ao2.release-artifact-size-budget-audit.v1",
    "post_release_verification_gate": "ao2.stable-promotion-evidence-gate.v1",
    "public_pair_digest_audit": "ao2.public-release-pair-digest-audit.v1",
    "stable_release_evidence_packet": "ao2.stable-release-evidence-packet.v1",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def gh_api(endpoint: str) -> dict[str, Any]:
    result = subprocess.run(["gh", "api", endpoint], check=True, text=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def workflow_id(repo: str, workflow: str) -> int:
    response = gh_api(f"repos/{repo}/actions/workflows?per_page=100")
    for item in response.get("workflows", []):
        if item.get("name") == workflow:
            return int(item["id"])
    raise SystemExit(f"workflow {workflow!r} not found in repo {repo!r}")


def latest_successful_run(repo: str, branch: str, workflow: str) -> dict[str, Any]:
    workflow = str(workflow)
    workflow_identifier = workflow_id(repo, workflow)
    query = urlencode({"branch": branch, "status": "success", "per_page": "50"})
    response = gh_api(f"repos/{repo}/actions/workflows/{workflow_identifier}/runs?{query}")
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
        add_gap(
            gaps,
            "producer_schema_mismatch",
            [f"schema_version must be {PRODUCER_SCHEMA_VERSION}"],
        )
    if producer.get("status") != "passed":
        add_gap(gaps, "producer_status_not_passed", ["status must be passed"])
    if producer.get("stable_promotion_evidence_index_ready") is not True:
        add_gap(
            gaps,
            "producer_not_ready",
            ["stable_promotion_evidence_index_ready must be true"],
        )

    blockers = producer.get("blockers")
    if blockers:
        add_gap(gaps, "producer_blockers_present", list(blockers))

    evidence = producer.get("evidence") if isinstance(producer.get("evidence"), dict) else {}
    missing = [name for name in REQUIRED_EVIDENCE if name not in evidence]
    add_gap(gaps, "missing_required_evidence", missing)

    evidence_drift = []
    for name in REQUIRED_EVIDENCE:
        item = evidence.get(name)
        if not isinstance(item, dict):
            continue
        expected_schema = EXPECTED_EVIDENCE_SCHEMAS[name]
        if item.get("schema_version") != expected_schema:
            evidence_drift.append(f"{name}.schema_version must be {expected_schema}")
        if item.get("status") != "passed":
            evidence_drift.append(f"{name}.status must be passed")
        if item.get("ready") is not True:
            evidence_drift.append(f"{name}.ready must be true")

    public_pair = evidence.get("public_pair_digest_audit")
    if isinstance(public_pair, dict) and public_pair.get("archive_parity_status") != "passed":
        evidence_drift.append("public_pair_digest_audit.archive_parity_status must be passed")

    artifact_budget = evidence.get("artifact_size_budget_audit")
    if isinstance(artifact_budget, dict) and artifact_budget.get("violations") not in ([], None):
        evidence_drift.append("artifact_size_budget_audit.violations must be empty")

    stable_packet = evidence.get("stable_release_evidence_packet")
    if isinstance(stable_packet, dict) and stable_packet.get("stable_release_evidence_ready") is not True:
        evidence_drift.append("stable_release_evidence_packet.stable_release_evidence_ready must be true")

    post_release = evidence.get("post_release_verification_gate")
    if isinstance(post_release, dict) and post_release.get("post_release_evidence_ready") is not True:
        evidence_drift.append("post_release_verification_gate.post_release_evidence_ready must be true")

    add_gap(gaps, "producer_evidence_drift", evidence_drift)

    trust = producer.get("trust_boundary") if isinstance(producer.get("trust_boundary"), dict) else {}
    trust_drift = []
    if trust.get("local_only") is not True:
        trust_drift.append("local_only must be true")
    if trust.get("control_plane_approves_release") is not False:
        trust_drift.append("control_plane_approves_release must be false")
    if trust.get("mutates_releases") is not False:
        trust_drift.append("mutates_releases must be false")
    if trust.get("stores_credentials") is not False:
        trust_drift.append("stores_credentials must be false")
    add_gap(gaps, "producer_trust_boundary_drift", trust_drift)

    return gaps


def build_summary(
    producer: dict[str, Any],
    *,
    index_summary_path: Path,
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
        "producer_summary_path": str(index_summary_path),
        "producer_schema_version": producer.get("schema_version"),
        "producer_status": producer.get("status"),
        "producer_ready": producer.get("stable_promotion_evidence_index_ready") is True,
        "required_evidence": REQUIRED_EVIDENCE,
        "producer_evidence": producer.get("evidence", {}),
        "producer_blockers": producer.get("blockers", []),
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
        description="Verify AO2 stable-promotion evidence index as read-only control-plane evidence."
    )
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Producer GitHub repository in owner/name form")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help="Producer branch to inspect")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW, help="Producer workflow name")
    parser.add_argument("--artifact", default=DEFAULT_ARTIFACT, help="Producer artifact name")
    parser.add_argument("--run-id", type=int, help="Specific producer Actions run id to download")
    parser.add_argument(
        "--index-summary-json",
        type=Path,
        help="Use an already-downloaded AO2 stable-promotion index summary instead of downloading an artifact",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("target/ao2-stable-promotion-evidence-index-readback/download"),
        help="Directory for downloaded producer artifact contents",
    )
    parser.add_argument("--out-json", required=True, type=Path, help="Path for the token-free readback summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run = None
    artifact = None
    downloads = args.index_summary_json is None

    if args.index_summary_json is not None:
        index_summary_path = args.index_summary_json
    else:
        run = {"id": args.run_id} if args.run_id is not None else latest_successful_run(args.repo, args.branch, args.workflow)
        artifact = run_artifact(args.repo, int(run["id"]), args.artifact)
        if artifact.get("expired") is True:
            raise SystemExit(f"artifact {args.artifact!r} on run {run['id']} is expired")
        index_summary_path = download_artifact(args.repo, int(run["id"]), args.artifact, args.work_dir)

    producer = read_json(index_summary_path)
    summary = build_summary(
        producer,
        index_summary_path=index_summary_path,
        downloads_github_actions_artifacts=downloads,
        repo=args.repo,
        branch=args.branch,
        workflow=args.workflow,
        run=run,
        artifact=artifact,
    )
    write_summary(args.out_json, summary)
    print(f"control_plane_ao2_stable_promotion_evidence_index_readback={summary['status']}")
    for gap in summary["gaps"]:
        print(f"{gap['severity']}: {gap['gap_kind']}: {', '.join(gap['details'])}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
