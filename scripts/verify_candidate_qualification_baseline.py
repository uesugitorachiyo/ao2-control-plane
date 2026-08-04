#!/usr/bin/env python3
"""Verify exact-head CI evidence required to prepare a release candidate."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


SCHEMA_VERSION = "ao2.cp-candidate-qualification-baseline.v1"
REQUIRED_ARTIFACTS = (
    "ao2-control-plane-release-archive-linux-x86_64",
    "ao2-control-plane-release-archive-macos-aarch64",
    "ao2-control-plane-release-archive-windows-x86_64",
    "ao2-control-plane-supply-chain-linux-x86_64",
    "ao2-control-plane-supply-chain-macos-aarch64",
    "ao2-control-plane-supply-chain-windows-x86_64",
)


def gh_api(endpoint: str) -> dict[str, Any]:
    result = subprocess.run(["gh", "api", endpoint], check=True, text=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def latest_successful_run(repo: str, branch: str, workflow: str, head_sha: str) -> dict[str, Any]:
    query = urlencode({"branch": branch, "status": "success", "per_page": "50"})
    for run in gh_api(f"repos/{repo}/actions/runs?{query}").get("workflow_runs", []):
        if (
            run.get("name") == workflow
            and run.get("head_branch") == branch
            and run.get("head_sha") == head_sha
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
        ):
            return run
    raise SystemExit(f"no successful {workflow!r} run found on branch {branch!r} at head_sha {head_sha!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--workflow", default="CI")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--out-json", required=True, type=Path)
    args = parser.parse_args()

    run = latest_successful_run(args.repo, args.branch, args.workflow, args.head_sha)
    artifacts = gh_api(f"repos/{args.repo}/actions/runs/{run['id']}/artifacts?per_page=100").get("artifacts", [])
    by_name = {item.get("name"): item for item in artifacts}
    required = []
    missing = []
    expired = []
    for name in REQUIRED_ARTIFACTS:
        artifact = by_name.get(name)
        if artifact is None:
            missing.append(name)
            continue
        if artifact.get("expired") is True:
            expired.append(name)
        required.append({"name": name, "id": artifact.get("id"), "size_in_bytes": artifact.get("size_in_bytes"), "expired": artifact.get("expired") is True})
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if not missing and not expired else "blocked",
        "repo": args.repo,
        "branch": args.branch,
        "workflow": args.workflow,
        "run_id": run.get("id"),
        "run_url": run.get("html_url"),
        "head_sha": run.get("head_sha"),
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "required_artifacts": required,
        "missing_artifacts": missing,
        "expired_artifacts": expired,
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_release": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
        },
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if summary["status"] != "passed":
        raise SystemExit("candidate qualification baseline is missing or has expired required artifacts")
    print(f"candidate_qualification_baseline=passed run_id={summary['run_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
