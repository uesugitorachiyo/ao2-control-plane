import json
import os
import re
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "start-long-lived-dev.sh"
SMOKE_SCRIPT = REPO_ROOT / "scripts" / "smoke-long-lived-dev.sh"


def test_ci_runs_on_public_push_and_pull_request():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*workflow_dispatch:\s*$", ci)
    assert re.search(r"(?m)^\s*pull_request:\s*$", ci)
    assert re.search(r"(?m)^\s*push:\s*$", ci)
    assert re.search(r"(?m)^\s*branches:\s*\[\s*main\s*\]\s*$", ci)
    assert re.search(r"(?m)^concurrency:\s*$", ci)


def test_ci_uses_node24_runtime_action_majors():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "uses: actions/checkout@v6.0.3" in ci
    assert "uses: actions/upload-artifact@v7.0.1" in ci

    assert "actions/checkout@v4" not in ci
    assert "actions/upload-artifact@v4" not in ci


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
    assert "scripts/smoke-long-lived-dev.sh" in runbook
    assert "pull requests and pushes to main" in security


def test_long_lived_dev_smoke_script_is_token_safe_and_checks_once_bootstrap(tmp_path):
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "forbidden-openai"
    env["ANTHROPIC_API_KEY"] = "forbidden-anthropic"
    env["AO2_CP_LONG_LIVED_SMOKE_ROOT"] = str(tmp_path / "smoke")

    result = subprocess.run(
        ["bash", str(SMOKE_SCRIPT)],
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
    assert "ao2.cp-long-lived-dev-hardening-smoke.v1" not in result.stdout
    assert "long_lived_dev_smoke=passed" in result.stdout

    summary = tmp_path / "smoke" / "summary.json"
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ao2.cp-long-lived-dev-hardening-smoke.v1"
    assert payload["status"] == "passed"
    assert payload["trust_boundary"]["provider_api_keys_allowed"] is False
    assert payload["trust_boundary"]["token_printed"] is False
    assert {check["status"] for check in payload["checks"]} == {"passed"}


def test_ci_runs_python_guard_tests_and_live_smoke_contract_is_documented():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = SMOKE_SCRIPT.read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/long-lived-dev.md").read_text(encoding="utf-8")

    assert "Python guard tests" in ci
    assert "PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/test_start_long_lived_dev.py -q" in ci
    assert "AO2_CP_LONG_LIVED_SMOKE_LIVE" in script
    assert "live_restart_readiness" in script
    assert "/readyz" in script
    assert "token_reused_after_restart" in script
    assert "AO2_CP_LONG_LIVED_SMOKE_LIVE=1" in runbook
    assert "restart" in runbook.lower()
