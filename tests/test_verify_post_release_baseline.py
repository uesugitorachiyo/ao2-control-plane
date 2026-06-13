import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_post_release_baseline.py"


def write_fake_gh(tmp_path: Path, artifacts: list[dict], runs: list[dict]) -> Path:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        f"""#!/usr/bin/env python3
import json
import sys

runs = {json.dumps({"workflow_runs": runs})!r}
artifacts = {json.dumps({"artifacts": artifacts})!r}
endpoint = sys.argv[2]
if endpoint.startswith("repos/uesugitorachiyo/ao2-control-plane/actions/runs?"):
    print(runs)
elif "/actions/runs/" in endpoint and "/artifacts?" in endpoint:
    print(artifacts)
else:
    raise SystemExit(f"unexpected endpoint: {{endpoint}}")
""",
        encoding="utf-8",
    )
    fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)
    return fake_bin


def run_script(tmp_path: Path, artifacts: list[dict], runs: list[dict]) -> subprocess.CompletedProcess:
    out_json = tmp_path / "summary.json"
    fake_bin = write_fake_gh(tmp_path, artifacts, runs)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--repo",
            "uesugitorachiyo/ao2-control-plane",
            "--branch",
            "main",
            "--workflow",
            "Post Release Verification",
            "--head-sha",
            "7a55743",
            "--out-json",
            str(out_json),
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result.out_json = out_json  # type: ignore[attr-defined]
    return result


def test_post_release_baseline_verifier_accepts_latest_successful_run_with_required_artifacts(tmp_path):
    artifacts = [
        {"id": 1, "name": "ao2-control-plane-post-release-verification-ubuntu", "expired": False, "size_in_bytes": 798},
        {"id": 2, "name": "ao2-control-plane-post-release-verification-macos", "expired": False, "size_in_bytes": 798},
        {"id": 3, "name": "ao2-control-plane-post-release-verification-windows", "expired": False, "size_in_bytes": 807},
        {"id": 4, "name": "ao2-control-plane-post-release-pair-verification", "expired": False, "size_in_bytes": 1094},
        {
            "id": 5,
            "name": "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
            "expired": False,
            "size_in_bytes": 30885996,
        },
    ]
    runs = [
        {
            "id": 27458698551,
            "name": "Post Release Verification",
            "head_branch": "main",
            "head_sha": "7a55743",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/27458698551",
        }
    ]

    result = run_script(tmp_path, artifacts, runs)

    assert result.returncode == 0, result.stderr
    assert "post_release_verification_baseline=passed" in result.stdout
    summary = json.loads(result.out_json.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    assert summary["schema_version"] == "ao2.cp-post-release-verification-baseline.v1"
    assert summary["status"] == "passed"
    assert summary["run_id"] == 27458698551
    assert summary["branch"] == "main"
    assert [artifact["name"] for artifact in summary["required_artifacts"]] == [
        "ao2-control-plane-post-release-verification-ubuntu",
        "ao2-control-plane-post-release-verification-macos",
        "ao2-control-plane-post-release-verification-windows",
        "ao2-control-plane-post-release-pair-verification",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
    ]
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    }


def test_post_release_baseline_verifier_blocks_missing_required_artifact(tmp_path):
    artifacts = [
        {"id": 1, "name": "ao2-control-plane-post-release-verification-ubuntu", "expired": False, "size_in_bytes": 798},
    ]
    runs = [
        {
            "id": 27458698551,
            "name": "Post Release Verification",
            "head_branch": "main",
            "head_sha": "7a55743",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/27458698551",
        }
    ]

    result = run_script(tmp_path, artifacts, runs)

    assert result.returncode != 0
    assert "missing required post-release artifact" in result.stderr
    summary = json.loads(result.out_json.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    assert summary["status"] == "blocked"
    assert summary["missing_artifacts"] == [
        "ao2-control-plane-post-release-verification-macos",
        "ao2-control-plane-post-release-verification-windows",
        "ao2-control-plane-post-release-pair-verification",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
    ]


def test_post_release_baseline_verifier_blocks_stale_main_run(tmp_path):
    artifacts = [
        {"id": 1, "name": "ao2-control-plane-post-release-verification-ubuntu", "expired": False, "size_in_bytes": 798},
        {"id": 2, "name": "ao2-control-plane-post-release-verification-macos", "expired": False, "size_in_bytes": 798},
        {"id": 3, "name": "ao2-control-plane-post-release-verification-windows", "expired": False, "size_in_bytes": 807},
        {"id": 4, "name": "ao2-control-plane-post-release-pair-verification", "expired": False, "size_in_bytes": 1094},
        {
            "id": 5,
            "name": "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
            "expired": False,
            "size_in_bytes": 30885996,
        },
    ]
    runs = [
        {
            "id": 27458698551,
            "name": "Post Release Verification",
            "head_branch": "main",
            "head_sha": "older-sha",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/27458698551",
        }
    ]

    result = run_script(tmp_path, artifacts, runs)

    assert result.returncode != 0
    assert "no successful 'Post Release Verification' run found" in result.stderr
