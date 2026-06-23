#!/usr/bin/env python3
"""Verify the latest successful post-release verification baseline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


SCHEMA_VERSION = "ao2.cp-post-release-verification-baseline.v1"
REQUIRED_ARTIFACTS = [
    "ao2-control-plane-post-release-verification-ubuntu",
    "ao2-control-plane-post-release-verification-macos",
    "ao2-control-plane-post-release-verification-windows",
    "ao2-control-plane-post-release-pair-verification",
    "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
    "ao2-control-plane-post-release-active-stack-release-handoff-readback",
]


def gh_api(endpoint: str) -> dict[str, Any]:
    command = ["gh", "api", endpoint]
    result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def latest_successful_run(repo: str, branch: str, workflow: str, head_sha: str | None) -> dict[str, Any]:
    query = urlencode({"branch": branch, "status": "success", "per_page": "50"})
    response = gh_api(f"repos/{repo}/actions/runs?{query}")
    for run in response.get("workflow_runs", []):
        if (
            run.get("name") == workflow
            and run.get("head_branch") == branch
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and (head_sha is None or run.get("head_sha") == head_sha)
        ):
            return run
    sha_suffix = f" at head_sha {head_sha!r}" if head_sha else ""
    raise SystemExit(f"no successful {workflow!r} run found on branch {branch!r}{sha_suffix}")


def run_artifacts(repo: str, run_id: int) -> list[dict[str, Any]]:
    response = gh_api(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    return list(response.get("artifacts", []))


def artifact_summary(artifacts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    by_name = {artifact.get("name"): artifact for artifact in artifacts}
    found = []
    missing = []
    expired = []
    for name in REQUIRED_ARTIFACTS:
        artifact = by_name.get(name)
        if artifact is None:
            missing.append(name)
            continue
        if artifact.get("expired") is True:
            expired.append(name)
        found.append(
            {
                "name": name,
                "id": artifact.get("id"),
                "size_in_bytes": artifact.get("size_in_bytes"),
                "expired": artifact.get("expired") is True,
            }
        )
    return found, missing, expired


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_summary(repo: str, branch: str, workflow: str, run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    required_artifacts, missing_artifacts, expired_artifacts = artifact_summary(artifacts)
    status = "passed" if not missing_artifacts and not expired_artifacts else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "repo": repo,
        "branch": branch,
        "workflow": workflow,
        "run_id": run.get("id"),
        "run_url": run.get("html_url"),
        "head_sha": run.get("head_sha"),
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "required_artifacts": required_artifacts,
        "missing_artifacts": missing_artifacts,
        "expired_artifacts": expired_artifacts,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_release": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify post-release baseline evidence before release promotion.")
    parser.add_argument("--repo", required=True, help="GitHub repository in owner/name form")
    parser.add_argument("--branch", default="main", help="Branch that must own the baseline run")
    parser.add_argument("--workflow", default="Post Release Verification", help="Workflow name to inspect")
    parser.add_argument("--head-sha", help="Require the baseline run to match this commit SHA")
    parser.add_argument("--out-json", required=True, type=Path, help="Path for the token-free baseline summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run = latest_successful_run(args.repo, args.branch, args.workflow, args.head_sha)
    artifacts = run_artifacts(args.repo, int(run["id"]))
    summary = build_summary(args.repo, args.branch, args.workflow, run, artifacts)
    write_summary(args.out_json, summary)
    if summary["status"] != "passed":
        for name in summary["missing_artifacts"]:
            print(f"missing required post-release artifact: {name}", file=sys.stderr)
        for name in summary["expired_artifacts"]:
            print(f"expired required post-release artifact: {name}", file=sys.stderr)
        return 1
    print(f"post_release_verification_baseline=passed run_id={summary['run_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
