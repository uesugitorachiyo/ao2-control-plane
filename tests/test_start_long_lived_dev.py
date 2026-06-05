import os
import re
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "start-long-lived-dev.sh"


def test_ci_runs_on_public_push_and_pull_request():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*workflow_dispatch:\s*$", ci)
    assert re.search(r"(?m)^\s*pull_request:\s*$", ci)
    assert re.search(r"(?m)^\s*push:\s*$", ci)
    assert re.search(r"(?m)^\s*branches:\s*\[\s*main\s*\]\s*$", ci)
    assert re.search(r"(?m)^concurrency:\s*$", ci)


def test_start_long_lived_dev_once_check_initializes_token_safely(tmp_path):
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "forbidden-openai"
    env["ANTHROPIC_API_KEY"] = "forbidden-anthropic"
    env.pop("AO2_CP_API_TOKEN", None)

    data_dir = tmp_path / "long-lived-control-plane"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--once-check",
            "--no-build",
            "--data-dir",
            str(data_dir),
            "--bind",
            "127.0.0.1:19876",
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "forbidden-openai" not in result.stdout + result.stderr
    assert "forbidden-anthropic" not in result.stdout + result.stderr
    assert "AO2_CP_API_TOKEN=" not in result.stdout
    assert "token_file=" in result.stdout
    assert "mode=600" in result.stdout
    assert "bind=127.0.0.1:19876" in result.stdout
    assert "once_check=passed" in result.stdout
    assert (data_dir / "data").is_dir()
    assert (data_dir / "logs").is_dir()
    assert (data_dir / "publishes").is_dir()
    token = data_dir / "api-token"
    assert token.is_file()
    assert stat.S_IMODE(token.stat().st_mode) == 0o600
    token_text = token.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{64}", token_text)
    assert token_text not in result.stdout
    assert token_text not in result.stderr


def test_long_lived_dev_docs_reference_bootstrap_script():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/long-lived-dev.md").read_text(encoding="utf-8")
    security = (REPO_ROOT / "docs/SECURITY.md").read_text(encoding="utf-8")

    assert "scripts/start-long-lived-dev.sh" in readme
    assert "scripts/start-long-lived-dev.sh" in runbook
    assert "pull requests and pushes to main" in security
