import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_candidate_qualification_baseline.py"
SOURCE_SHA = "a" * 40
REQUIRED_ARTIFACTS = [
    "ao2-control-plane-release-archive-linux-x86_64",
    "ao2-control-plane-release-archive-macos-aarch64",
    "ao2-control-plane-release-archive-windows-x86_64",
    "ao2-control-plane-supply-chain-linux-x86_64",
    "ao2-control-plane-supply-chain-macos-aarch64",
    "ao2-control-plane-supply-chain-windows-x86_64",
]


def test_candidate_baseline_accepts_exact_head_ci_artifacts(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "gh").write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"runs = {{'workflow_runs': [{{'id': 12, 'name': 'CI', 'head_branch': 'main', 'head_sha': '{SOURCE_SHA}', 'status': 'completed', 'conclusion': 'success', 'html_url': 'https://example.test/run/12'}}]}}\n"
        f"artifacts = {{'artifacts': [{{'id': i + 1, 'name': name, 'expired': False, 'size_in_bytes': 100}} for i, name in enumerate({REQUIRED_ARTIFACTS!r})]}}\n"
        "print(json.dumps(runs if '/actions/runs?' in sys.argv[2] else artifacts))\n",
        encoding="utf-8",
    )
    fake_gh = fake_bin / "gh"
    fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)
    out = tmp_path / "summary.json"
    result = subprocess.run(
        [
            "python3", str(SCRIPT), "--repo", "uesugitorachiyo/ao2-control-plane",
            "--branch", "main", "--workflow", "CI", "--head-sha", SOURCE_SHA,
            "--out-json", str(out),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["schema_version"] == "ao2.cp-candidate-qualification-baseline.v1"
    assert summary["status"] == "passed"
    assert summary["head_sha"] == SOURCE_SHA
    assert [item["name"] for item in summary["required_artifacts"]] == REQUIRED_ARTIFACTS
