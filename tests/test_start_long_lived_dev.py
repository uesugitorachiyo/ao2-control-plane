import json
import importlib.util
import os
import subprocess
import re
import stat
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "start-long-lived-dev.sh"
SMOKE_SCRIPT = REPO_ROOT / "scripts" / "smoke-long-lived-dev.sh"
RISKY_PR_GOLDEN_BRIDGE_SMOKE = REPO_ROOT / "scripts" / "smoke-risky-pr-golden-bridge.sh"
RISKY_PR_GOLDEN_BRIDGE_SMOKE_PY = REPO_ROOT / "scripts" / "smoke-risky-pr-golden-bridge.py"
RISKY_PR_GOLDEN_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "risky-pr-golden-artifact-manifest.json"
RELEASE_TRAIN_BRIDGE_SMOKE_PY = REPO_ROOT / "scripts" / "smoke-release-train-bridge.py"
RELEASE_TRAIN_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "public-release-train-summary.json"
OPERATOR_BRIDGE_SMOKE_PY = REPO_ROOT / "scripts" / "smoke-operator-release-evidence-bridge.py"
CI_EVIDENCE_HANDLER = REPO_ROOT / "crates" / "ao2-cp-server" / "src" / "handlers" / "ci_evidence.rs"
DASHBOARD_SNAPSHOT = REPO_ROOT / "scripts" / "cp_dashboard_snapshot.py"


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


def test_release_archive_smoke_uploads_release_ready_archives_for_each_os():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for target_label in ["linux-x86_64", "macos-aarch64", "windows-x86_64"]:
        assert f"target_label: {target_label}" in ci
        assert f"dist/ao2-control-plane-0.1.13-{target_label}.tar.gz" in ci

    for needle in [
        "Upload release archive artifact",
        "name: ao2-control-plane-release-archive-${{ matrix.target_label }}",
        "${{ matrix.archive }}",
        "dist/SHA256SUMS",
        "target/release-smoke/${{ matrix.target_label }}.json",
        "if-no-files-found: error",
    ]:
        assert needle in ci


def test_readme_links_current_prerelease_and_release_archive_artifacts():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for needle in [
        "https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.13",
        "img.shields.io/github/v/release/uesugitorachiyo/ao2-control-plane",
        "https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.13",
        "gh release download v0.1.13 --repo uesugitorachiyo/ao2-control-plane",
        "ao2-control-plane-0.1.13-macos-aarch64.tar.gz",
        "https://github.com/uesugitorachiyo/ao2-control-plane/actions",
        "ao2-control-plane-release-archive-linux-x86_64",
        "ao2-control-plane-release-archive-macos-aarch64",
        "ao2-control-plane-release-archive-windows-x86_64",
        "SHA256SUMS",
    ]:
        assert needle in readme


def test_release_download_verify_checks_public_prerelease_checksums():
    script = REPO_ROOT / "scripts" / "release-download-verify.sh"
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert script.is_file()
    assert script.stat().st_mode & stat.S_IXUSR
    text = script.read_text(encoding="utf-8")

    for needle in [
        "AO2_CP_RELEASE_REPO",
        "uesugitorachiyo/ao2-control-plane",
        "AO2_CP_RELEASE_TAG",
        "v0.1.13",
        "gh release download",
        "SHA256SUMS",
        "ao2-control-plane-*.tar.gz",
        "missing release archive asset",
        "shasum -a 256 -c SHA256SUMS",
        'command -v python3',
        'command -v python',
        "control_plane_release_checksum_verify=passed",
        "control_plane_release_download_verify=passed",
    ]:
        assert needle in text

    assert "scripts/release-download-verify.sh" in readme


def test_release_download_verify_can_emit_token_free_publication_closure_summary(tmp_path):
    release_dir = tmp_path / "release-download"
    release_dir.mkdir()
    artifact = release_dir / "ao2-control-plane-0.1.13-linux-x86_64.tar.gz"
    artifact.write_text("fake archive bytes\n", encoding="utf-8")
    digest = subprocess.check_output(
        ["shasum", "-a", "256", artifact.name],
        cwd=release_dir,
        text=True,
    ).strip()
    (release_dir / "SHA256SUMS").write_text(f"{digest}\n", encoding="utf-8")
    summary = tmp_path / "summary.json"

    env = os.environ.copy()
    env["AO2_CP_RELEASE_DOWNLOAD_OFFLINE"] = "1"
    env["AO2_CP_RELEASE_DOWNLOAD_DIR"] = str(release_dir)
    env["AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON"] = str(summary)

    result = subprocess.run(
        ["bash", "scripts/release-download-verify.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "control_plane_release_publication_closure=passed" in result.stdout

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ao2.cp-release-publication-closure.v1"
    assert payload["status"] == "passed"
    assert payload["release_repo"] == "uesugitorachiyo/ao2-control-plane"
    assert payload["release_tag"] == "v0.1.13"
    assert payload["download_dir"] == str(release_dir)
    assert payload["checksum_manifest"] == str(release_dir / "SHA256SUMS")
    assert payload["checksum_verified"] is True
    assert {asset["name"] for asset in payload["assets"]} == {
        "SHA256SUMS",
        "ao2-control-plane-0.1.13-linux-x86_64.tar.gz",
    }
    for asset in payload["assets"]:
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
        assert asset["size_bytes"] > 0
    assert payload["trust_boundary"] == {
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    }


def test_release_download_verify_rejects_checksum_valid_release_without_archive(tmp_path):
    release_dir = tmp_path / "release-download"
    release_dir.mkdir()
    notes = release_dir / "release-notes.txt"
    notes.write_text("not a release archive\n", encoding="utf-8")
    digest = subprocess.check_output(
        ["shasum", "-a", "256", notes.name],
        cwd=release_dir,
        text=True,
    ).strip()
    (release_dir / "SHA256SUMS").write_text(f"{digest}\n", encoding="utf-8")
    summary = tmp_path / "summary.json"

    env = os.environ.copy()
    env["AO2_CP_RELEASE_DOWNLOAD_OFFLINE"] = "1"
    env["AO2_CP_RELEASE_DOWNLOAD_DIR"] = str(release_dir)
    env["AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON"] = str(summary)

    result = subprocess.run(
        ["bash", "scripts/release-download-verify.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert "missing release archive asset" in result.stderr
    assert not summary.exists()


def test_ci_uploads_release_publication_closure_artifact_and_docs():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    release_smoke = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    for needle in [
        "release-publication-closure:",
        "Release publication closure",
        "scripts/release-download-verify.sh",
        "GH_TOKEN: ${{ github.token }}",
        "AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON=target/release-publication-closure/summary.json",
        "target/release-publication-closure/summary.json",
        "Upload release publication closure artifact",
        "ao2-control-plane-release-publication-closure",
        "if-no-files-found: error",
    ]:
        assert needle in ci

    for needle in [
        "ao2-control-plane-release-publication-closure",
        "ao2.cp-release-publication-closure.v1",
        "scripts/release-download-verify.sh",
        "control_plane_release_publication_closure=passed",
    ]:
        assert needle in readme
        assert needle in release_smoke


def test_post_release_verification_workflow_runs_read_only_on_schedule_and_dispatch():
    workflow = (
        REPO_ROOT / ".github/workflows/post-release-verification.yml"
    ).read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    release_smoke = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(
        encoding="utf-8"
    )

    for needle in [
        "workflow_dispatch:",
        "release_tag:",
        "default: v0.1.13",
        "schedule:",
        'cron: "29 12 * * 2"',
        "contents: read",
        "cancel-in-progress: false",
        "AO2_CP_RELEASE_REPO: uesugitorachiyo/ao2-control-plane",
        "AO2_CP_RELEASE_TAG: ${{ inputs.release_tag || 'v0.1.13' }}",
        "os: ubuntu-latest",
        "os: macos-latest",
        "os: windows-latest",
        "scripts/release-download-verify.sh",
        "AO2_CP_RELEASE_CLOSURE_SUMMARY_JSON=target/post-release-verification/${{ matrix.name }}/summary.json",
        "EXPECTED_AO2_CP_RELEASE_TAG: ${{ inputs.release_tag || 'v0.1.13' }}",
        "import os",
        'assert summary["release_tag"] == os.environ["EXPECTED_AO2_CP_RELEASE_TAG"], summary',
        "ao2-control-plane-post-release-verification-${{ matrix.name }}",
        "operator-release-evidence-hosted-bridge-smoke:",
        "AO2 release evidence hosted bridge drift monitor",
        "actions: read",
        "scripts/smoke-operator-release-evidence-bridge.py",
        "--download-latest-ao2-artifact",
        "target/post-release-operator-evidence-hosted-bridge-smoke",
        "ao2.cp-operator-release-evidence-bridge-smoke.v1",
        "ao2.operator-release-evidence-bundle.v1",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
        "ao2.cp-release-publication-closure.v1",
        "checksum_verified",
        "mutates_github_releases",
        "credential_material_included",
    ]:
        assert needle in workflow

    for forbidden in [
        "gh release upload",
        "gh release edit",
        "git push origin",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ]:
        assert forbidden not in workflow

    for needle in [
        "Post Release Verification",
        ".github/workflows/post-release-verification.yml",
        "ao2-control-plane-post-release-verification-ubuntu",
        "ao2-control-plane-post-release-verification-macos",
        "ao2-control-plane-post-release-verification-windows",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
        "ao2.cp-operator-release-evidence-bridge-smoke.v1",
        "read-only",
        "ao2.cp-release-publication-closure.v1",
    ]:
        assert needle in readme
        assert needle in release_smoke


def test_production_readiness_ops_workflow_runs_branch_protection_verifier():
    workflow = (
        REPO_ROOT / ".github/workflows/production-readiness-ops.yml"
    ).read_text(encoding="utf-8")
    verifier = (REPO_ROOT / "scripts/verify-branch-protection.sh").read_text(
        encoding="utf-8"
    )
    runbook = (REPO_ROOT / "docs/runbooks/branch-protection.md").read_text(
        encoding="utf-8"
    )
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for needle in [
        "name: production-readiness-ops",
        "workflow_dispatch:",
        "schedule:",
        'cron: "23 10 * * *"',
        "contents: read",
        "GH_TOKEN: ${{ github.token }}",
        "scripts/verify-branch-protection.sh",
    ]:
        assert needle in workflow

    for needle in [
        "uesugitorachiyo/ao2-control-plane",
        "branches/$BRANCH/protection",
        "repos/$REPO/rulesets",
        "branches/$BRANCH\"",
        "mode=limited",
        "ruleset_status_checks_current",
        "rulesets_checked=true",
        "Cargo audit",
        "Cargo deny (bans + licenses + sources)",
        "Lint (fmt + clippy)",
        "Test (ubuntu-latest)",
        "Test (macos-latest)",
        "Test (windows-latest)",
        "Ingest smoke (ubuntu-x86_64)",
        "Ingest smoke (macos-aarch64)",
        "Ingest smoke (windows-x86_64)",
        "Release archive smoke (ubuntu-x86_64)",
        "Release archive smoke (macos-aarch64)",
        "Release archive smoke (windows-x86_64)",
        "branch_protection=passed",
    ]:
        assert needle in verifier

    for needle in [
        "scripts/verify-branch-protection.sh",
        ".github/workflows/production-readiness-ops.yml",
        "mode=full",
        "mode=limited",
        "active branch rulesets",
        "admin enforcement",
        "linear history",
    ]:
        assert needle in runbook
        assert needle in readme

    for forbidden in [
        "gh pr merge",
        "git push origin",
        "-X PUT",
        "-X PATCH",
        "gh repo edit",
    ]:
        assert forbidden not in workflow
        assert forbidden not in verifier


def test_branch_protection_verifier_rejects_stale_active_ruleset(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    contexts = [
        "Cargo audit",
        "Cargo deny (bans + licenses + sources)",
        "Ingest smoke (macos-aarch64)",
        "Ingest smoke (ubuntu-x86_64)",
        "Ingest smoke (windows-x86_64)",
        "Lint (fmt + clippy)",
        "Release archive smoke (macos-aarch64)",
        "Release archive smoke (ubuntu-x86_64)",
        "Release archive smoke (windows-x86_64)",
        "Test (macos-latest)",
        "Test (ubuntu-latest)",
        "Test (windows-latest)",
    ]
    protection = {
        "required_status_checks": {"strict": True, "contexts": contexts},
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }
    rulesets = [
        {
            "name": "stale default branch checks",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            {"context": "Test (macos-13)"},
                        ],
                    },
                }
            ],
        }
    ]
    fake_gh.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"protection = {protection!r}\n"
        f"rulesets = {rulesets!r}\n"
        "path = sys.argv[-1]\n"
        "if path.endswith('/protection'):\n"
        "    print(json.dumps(protection))\n"
        "elif path.endswith('/rulesets'):\n"
        "    print(json.dumps(rulesets))\n"
        "elif path.endswith('/branches/main'):\n"
        "    print(json.dumps({'protected': True, 'protection': {'required_status_checks': {'enforcement_level': 'everyone', 'contexts': protection['required_status_checks']['contexts']}}}))\n"
        "else:\n"
        "    raise SystemExit(f'unexpected gh api path: {path}')\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        ["bash", "scripts/verify-branch-protection.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "ruleset_status_checks_current" in result.stderr
    assert "Test (macos-13)" in result.stderr


def test_operator_release_evidence_bridge_accepts_additive_passed_checks(tmp_path):
    spec = importlib.util.spec_from_file_location("operator_bridge_smoke", OPERATOR_BRIDGE_SMOKE_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    summary = {
        "schema_version": "ao2.operator-release-evidence-bundle.v1",
        "status": "passed",
        "operator_release_evidence_ready": True,
        "checks": [
            {"artifact": "ao2-dual-repo-release-publication-closure-index", "status": "passed"},
            {"artifact": "post-stable-release-smoke-Linux", "status": "passed"},
            {"artifact": "post-stable-release-smoke-macOS", "status": "passed"},
            {"artifact": "post-stable-release-smoke-Windows", "status": "passed"},
            {
                "artifact": "ao2-dual-public-release-smoke",
                "status": "passed",
                "schema_version": "ao2.dual-public-release-smoke.v1",
                "task_board_readback_schema": "ao2.cp-ai-task-board-readback.v1",
                "task_board_dashboard_schema": "ao2.cp-ai-task-board-dashboard.v1",
                "auth_value_stored": False,
                "credential_material_in_urls": False,
                "control_plane_approves_release": False,
            },
            {
                "artifact": "ao2-public-release-pair-digest-audit",
                "status": "passed",
                "schema_version": "ao2.public-release-pair-digest-audit.v1",
                "summary_status": "passed",
                "archive_parity_status": "passed",
                "mutates_releases": False,
                "stores_credentials": False,
            },
            {"artifact": "ao2-control-plane-post-release-verification-ubuntu", "status": "passed"},
            {"artifact": "ao2-control-plane-post-release-verification-macos", "status": "passed"},
            {"artifact": "ao2-control-plane-post-release-verification-windows", "status": "passed"},
            {
                "artifact": "ao2-stable-promotion-evidence-index",
                "status": "passed",
                "schema_version": "ao2.stable-promotion-evidence-index.v1",
            },
        ],
        "trust_boundary": {
            "mutates_releases": False,
            "stores_credentials": False,
        },
    }
    path = tmp_path / "operator-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    loaded = module.load_operator_summary(path)

    assert len(loaded["checks"]) == 10
    assert loaded["checks"][-1]["artifact"] == "ao2-stable-promotion-evidence-index"
    script = OPERATOR_BRIDGE_SMOKE_PY.read_text(encoding="utf-8")
    assert "exactly nine checks" not in script


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


def test_risky_pr_golden_bridge_smoke_is_token_safe_and_documented():
    script = RISKY_PR_GOLDEN_BRIDGE_SMOKE.read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    release_smoke = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert RISKY_PR_GOLDEN_BRIDGE_SMOKE.is_file()
    assert RISKY_PR_GOLDEN_BRIDGE_SMOKE.stat().st_mode & stat.S_IXUSR

    for needle in [
        "ao2.cp-risky-pr-golden-bridge-smoke.v1",
        "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST",
        "target/risky-pr-golden-control-plane-bridge/artifact-manifest.json",
        "/api/v1/risky-pr/golden/artifact-manifest.json",
        "/api/v1/risky-pr/golden/artifact-manifest",
        "ao2.cp-risky-pr-golden-artifact-manifest-observer.v1",
        "read-only-observer",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "credential_material_included",
        "env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY",
        "Authorization: Bearer",
        "token not in",
    ]:
        assert needle in script

    assert "AO2_CP_API_TOKEN=" not in script
    assert "Bearer $TOKEN" not in script
    assert "scripts/smoke-risky-pr-golden-bridge.sh" in readme
    assert "scripts/smoke-risky-pr-golden-bridge.sh" in release_smoke


def test_ci_runs_cross_os_risky_pr_golden_bridge_fixture_smoke():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = RISKY_PR_GOLDEN_BRIDGE_SMOKE_PY.read_text(encoding="utf-8")
    fixture = json.loads(RISKY_PR_GOLDEN_FIXTURE.read_text(encoding="utf-8"))

    for needle in [
        "risky-pr-golden-bridge-smoke:",
        "Risky PR golden bridge smoke (${{ matrix.name }})",
        "needs: test",
        "ubuntu-x86_64",
        "macos-aarch64",
        "windows-x86_64",
        "scripts/smoke-risky-pr-golden-bridge.py",
        "tests/fixtures/risky-pr-golden-artifact-manifest.json",
        "target/risky-pr-golden-bridge-smoke/${{ matrix.name }}",
        "ao2-control-plane-risky-pr-golden-bridge-${{ matrix.name }}",
    ]:
        assert needle in ci

    for needle in [
        "ao2.cp-risky-pr-golden-bridge-smoke.v1",
        "AO2_CP_RISKY_PR_GOLDEN_ARTIFACT_MANIFEST",
        "ao2.cp-risky-pr-golden-artifact-manifest-observer.v1",
        "/api/v1/risky-pr/golden/artifact-manifest.json",
        "/api/v1/risky-pr/golden/artifact-manifest",
        "read-only-observer",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "credential_material_included",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "Authorization",
    ]:
        assert needle in script

    assert fixture["schema_version"] == "ao2.risky-pr-golden-artifact-manifest.v1"
    assert fixture["status"] == "indexed"
    assert fixture["artifact_count"] == len(fixture["artifacts"])


def test_risky_pr_golden_bridge_ci_artifact_uploads_complete_evidence_directory():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = RISKY_PR_GOLDEN_BRIDGE_SMOKE_PY.read_text(encoding="utf-8")

    assert "path: target/risky-pr-golden-bridge-smoke/${{ matrix.name }}" in ci
    assert "path: target/risky-pr-golden-bridge-smoke/${{ matrix.name }}/summary.json" not in ci

    for needle in [
        '"server_logs"',
        '"stdout"',
        '"stderr"',
        '"artifact-manifest-observer.json"',
        '"artifact-manifest.html"',
    ]:
        assert needle in script


def test_ci_runs_cross_os_release_train_bridge_fixture_smoke():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = RELEASE_TRAIN_BRIDGE_SMOKE_PY.read_text(encoding="utf-8")
    fixture = json.loads(RELEASE_TRAIN_FIXTURE.read_text(encoding="utf-8"))

    for needle in [
        "release-train-bridge-smoke:",
        "Release train bridge smoke (${{ matrix.name }})",
        "needs: test",
        "ubuntu-x86_64",
        "macos-aarch64",
        "windows-x86_64",
        "scripts/smoke-release-train-bridge.py",
        "tests/fixtures/public-release-train-summary.json",
        "target/release-train-bridge-smoke/${{ matrix.name }}",
        "ao2-control-plane-release-train-bridge-${{ matrix.name }}",
    ]:
        assert needle in ci

    for needle in [
        "ao2.cp-release-train-bridge-smoke.v1",
        "AO2_CP_RELEASE_TRAIN_SUMMARY",
        "ao2.cp-release-train-readback.v1",
        "ao2.public-release-train-drill.v1",
        "/api/v1/release/train.json",
        "/api/v1/release/train",
        "read-only-observer",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "credential_material_included",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "Authorization",
        "token not in",
    ]:
        assert needle in script

    assert fixture["schema_version"] == "ao2.public-release-train-drill.v1"
    assert fixture["status"] == "passed"
    assert fixture["release_train_manifest"]["schema_version"] == "ao2.release-train-manifest.v1"
    assert fixture["release_train_manifest"]["selected_train"] == "next_patch"
    assert fixture["release_targets"] == {
        "selected_train": "next_patch",
        "ao2": {"tag": "v0.4.81", "version": "0.4.81"},
        "ao2_control_plane": {"tag": "v0.1.14", "version": "0.1.14"},
        "promotion_confirm": "promote-stable-v0.4.81-v0.1.14",
        "public_operator_confirm": "public-release-reviewed-v0.4.81-v0.1.14",
    }
    assert fixture["release_readiness_artifact_consumer_contract"]["status"] == "passed"
    assert fixture["publish_guards"]["refuses_publish_side_effects_by_default"] is True


def test_release_train_bridge_ci_artifact_uploads_complete_evidence_directory():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = RELEASE_TRAIN_BRIDGE_SMOKE_PY.read_text(encoding="utf-8")

    assert "path: target/release-train-bridge-smoke/${{ matrix.name }}" in ci
    assert "path: target/release-train-bridge-smoke/${{ matrix.name }}/summary.json" not in ci

    for needle in [
        '"server_logs"',
        '"stdout"',
        '"stderr"',
        '"release-train-readback.json"',
        '"release-train-readback.html"',
    ]:
        assert needle in script


def test_ci_evidence_index_is_documented_and_token_safe():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    release_smoke = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")
    handler = CI_EVIDENCE_HANDLER.read_text(encoding="utf-8")

    for needle in [
        "/api/v1/ci/evidence-index",
        "/api/v1/ci/evidence-index.json",
        "ao2.cp-ci-evidence-index.v1",
        "risky-pr-golden-bridge-smoke",
        "release-train-bridge-smoke",
        "ingest-smoke",
        "release-archive-smoke",
        "backup-restore-drill",
        "read-only-observer",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "credential_material_included",
        "credential_material_in_urls",
    ]:
        assert needle in handler

    assert "Bearer secret" not in handler
    assert "/api/v1/ci/evidence-index" in readme
    assert "/api/v1/ci/evidence-index.json" in readme
    assert "ao2.cp-ci-evidence-index.v1" in readme
    assert "/api/v1/ci/evidence-index.json" in release_smoke
    assert "ao2.cp-ci-evidence-index.v1" in release_smoke


def test_dashboard_snapshot_includes_ci_evidence_index_surfaces():
    script = DASHBOARD_SNAPSHOT.read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for needle in [
        '"name": "CI Evidence Index"',
        '"endpoint": "/api/v1/ci/evidence-index"',
        '"filename": "ci-evidence-index.html"',
        '"name": "CI Evidence Index JSON"',
        '"endpoint": "/api/v1/ci/evidence-index.json"',
        '"filename": "ci-evidence-index.json"',
        "ao2.cp-dashboard-snapshot.v1",
    ]:
        assert needle in script

    assert "ci-evidence-index.html" in readme
    assert "ci-evidence-index.json" in readme


def test_ci_runs_python_guard_tests_and_live_smoke_contract_is_documented():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    script = SMOKE_SCRIPT.read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/long-lived-dev.md").read_text(encoding="utf-8")

    assert "Python guard tests" in ci
    assert "PYTHONDONTWRITEBYTECODE=1 python3 -m pytest" in ci
    assert "tests/test_start_long_lived_dev.py tests/test_release_asset_parity_audit.py tests/test_release_promotion_workflow.py tests/test_release_notes_from_checksums.py tests/test_public_release_pair_verify.py tests/test_ao2_stable_promotion_evidence_index_readback.py tests/test_ao2_dual_repo_public_approval_closure_readback.py tests/test_active_stack_release_handoff_readback.py tests/test_ao2_rsi_claim_readiness_readback.py -q" in ci
    assert "AO2_CP_LONG_LIVED_SMOKE_LIVE" in script
    assert "live_restart_readiness" in script
    assert "/readyz" in script
    assert "token_reused_after_restart" in script
    assert "AO2_CP_LONG_LIVED_SMOKE_LIVE=1" in runbook
    assert "restart" in runbook.lower()


def test_ci_uploads_python_guard_and_dr_restore_artifacts():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for needle in [
        "target/ci-artifacts/python-guards",
        "Upload Python guard artifacts",
        "ao2-control-plane-python-guards",
        "dr-restore-drill",
        "Backup/restore drill",
        "scripts/cp-dr-restore-drill.sh",
        "target/dr-restore-drill/ci/dr-restore-report.json",
        "Upload backup/restore drill artifacts",
        "ao2-control-plane-dr-restore",
    ]:
        assert needle in ci


def test_backup_restore_drill_script_is_exposed_and_documented_for_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    operations = (REPO_ROOT / "docs/runbooks/operations.md").read_text(encoding="utf-8")

    for script_name in [
        "scripts/cp_dr_restore_drill.py",
        "scripts/cp-dr-restore-drill.sh",
        "scripts/cp-dr-restore-drill.ps1",
    ]:
        script = REPO_ROOT / script_name
        assert script.is_file()

    assert (REPO_ROOT / "scripts/cp-dr-restore-drill.sh").stat().st_mode & stat.S_IXUSR
    assert "ao2.cp-dr-restore-drill.v1" in (
        REPO_ROOT / "scripts/cp_dr_restore_drill.py"
    ).read_text(encoding="utf-8")
    assert "cargo build --release -p ao2-cp-server" in ci
    assert "cp-dr-restore-drill.sh" in readme
    assert "cp-dr-restore-drill.sh" in operations


def test_backup_restore_drill_covers_negative_restore_scenarios():
    script = (REPO_ROOT / "scripts/cp_dr_restore_drill.py").read_text(encoding="utf-8")

    for needle in [
        "RESTORE_ARCHIVE_SCHEMA_VERSION",
        "ao2.cp-dr-restore-archive.v1",
        "negative_scenarios",
        "missing_archive",
        "corrupted_archive",
        "version_skew",
        "--negative-only",
        "--skip-negative-scenarios",
    ]:
        assert needle in script


def test_backup_restore_drill_negative_only_runs_without_server_binary(tmp_path):
    report_path = tmp_path / "dr-restore-negative.json"
    result = subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "cp_dr_restore_drill.py"),
            "--negative-only",
            "--work-dir",
            str(tmp_path / "work"),
            "--out",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ao2.cp-dr-restore-drill.v1"
    assert payload["status"] == "passed"
    scenarios = {item["name"]: item for item in payload["negative_scenarios"]}
    assert set(scenarios) == {
        "missing_archive",
        "corrupted_archive",
        "version_skew",
        "malformed_manifest_json",
        "missing_manifest_schema",
        "non_string_manifest_schema",
        "unsafe_path_member",
    }
    assert {item["status"] for item in scenarios.values()} == {"passed"}
    assert all(item["expected_rejection_observed"] is True for item in scenarios.values())


def test_backup_restore_drill_reports_restore_compatibility_matrix():
    script = (REPO_ROOT / "scripts/cp_dr_restore_drill.py").read_text(encoding="utf-8")

    for needle in [
        "compatibility_matrix",
        "current_manifest",
        "legacy_missing_manifest",
        "older_manifest",
        "future_manifest",
        "ao2.cp-dr-restore-archive.v0",
        "accepted_with_warning",
        "rejected",
    ]:
        assert needle in script


def test_backup_restore_drill_negative_only_includes_compatibility_matrix(tmp_path):
    report_path = tmp_path / "dr-restore-compatibility.json"
    result = subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "cp_dr_restore_drill.py"),
            "--negative-only",
            "--work-dir",
            str(tmp_path / "work"),
            "--out",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    matrix = {item["name"]: item for item in payload["compatibility_matrix"]}
    assert set(matrix) == {
        "current_manifest",
        "legacy_missing_manifest",
        "older_manifest",
        "future_manifest",
    }
    assert matrix["current_manifest"]["decision"] == "accepted"
    assert matrix["legacy_missing_manifest"]["decision"] == "accepted_with_warning"
    assert matrix["older_manifest"]["decision"] == "accepted_with_warning"
    assert matrix["future_manifest"]["decision"] == "rejected"
    assert payload["status"] == "passed"


def test_backup_restore_drill_negative_only_includes_malformed_restore_corpus(tmp_path):
    script = (REPO_ROOT / "scripts/cp_dr_restore_drill.py").read_text(encoding="utf-8")

    for needle in [
        "malformed_manifest_json",
        "missing_manifest_schema",
        "non_string_manifest_schema",
        "unsafe_path_member",
        "malformed_restore_corpus",
        "manifest_json_invalid",
        "manifest_schema_missing",
        "manifest_schema_not_string",
        "unsafe archive member",
    ]:
        assert needle in script

    report_path = tmp_path / "dr-restore-malformed-corpus.json"
    result = subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "cp_dr_restore_drill.py"),
            "--negative-only",
            "--work-dir",
            str(tmp_path / "work"),
            "--out",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    scenarios = {item["name"]: item for item in payload["negative_scenarios"]}
    for name in [
        "malformed_manifest_json",
        "missing_manifest_schema",
        "non_string_manifest_schema",
        "unsafe_path_member",
    ]:
        assert scenarios[name]["status"] == "passed"
        assert scenarios[name]["expected_rejection_observed"] is True
    assert payload["malformed_restore_corpus"]["status"] == "passed"
    assert set(payload["malformed_restore_corpus"]["scenario_names"]) == {
        "malformed_manifest_json",
        "missing_manifest_schema",
        "non_string_manifest_schema",
        "unsafe_path_member",
    }
