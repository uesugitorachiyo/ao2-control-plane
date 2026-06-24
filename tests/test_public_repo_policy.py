from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_repo_policy_scanner_is_ci_visible() -> None:
    script = REPO_ROOT / "scripts/check-public-repo-policy.sh"
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert script.exists(), "public repo policy scanner must exist"
    assert "scripts/check-license-policy.sh" in workflow
    assert "scripts/check-public-repo-policy.sh" in workflow
    assert workflow.index("scripts/check-license-policy.sh") < workflow.index(
        "scripts/check-public-repo-policy.sh"
    )


def test_public_repo_policy_scanner_passes_current_tree() -> None:
    result = subprocess.run(
        ["bash", "scripts/check-public-repo-policy.sh"],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "public repo policy check passed" in result.stdout
