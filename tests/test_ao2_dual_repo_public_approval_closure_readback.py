import json
import os
import stat
import subprocess
import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_dual_repo_public_approval_closure.py"


def load_script_module():
    spec = importlib.util.spec_from_file_location("dual_repo_approval_readback", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def approval_closure_summary(**overrides):
    payload = {
        "schema_version": "ao2.dual-repo-public-approval-closure.v1",
        "status": "passed",
        "dual_repo_public_approval_closure_ready": True,
        "release_go_no_go": "go",
        "operator_decision_fields_remain_unapproved": True,
        "source_artifacts": [
            "ao2-public-release-operator-checklist-closure",
            "ao2-control-plane-public-release-pair-verification",
            "ao2-control-plane-ao2-stable-promotion-evidence-index-readback",
        ],
        "sources": {
            "ao2_public_release_operator_checklist_closure": {
                "schema_version": "ao2.public-release-operator-checklist-closure.v1",
                "status": "passed",
                "ready": True,
            },
            "control_plane_public_release_pair_verification": {
                "schema_version": "ao2.cp-public-release-pair-verification.v1",
                "status": "passed",
                "common_platforms": ["linux-x86_64", "macos-aarch64", "windows-x86_64"],
            },
            "control_plane_ao2_stable_promotion_evidence_index_readback": {
                "schema_version": "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1",
                "status": "passed",
                "producer_ready": True,
                "required_evidence": [
                    "artifact_size_budget_audit",
                    "post_release_verification_gate",
                    "public_pair_digest_audit",
                    "stable_release_evidence_packet",
                ],
            },
        },
        "failures": [],
        "trust_boundary": {
            "local_only": True,
            "control_plane_approves_release": False,
            "mutates_releases": False,
            "stores_credentials": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, closure_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    closure_path = tmp_path / "dual-repo-public-approval-closure.json"
    out_json = tmp_path / "readback-summary.json"
    closure_path.write_text(
        json.dumps(closure_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--closure-summary-json",
            str(closure_path),
            "--out-json",
            str(out_json),
        ],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    parsed = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else {}
    return result, parsed


def test_ao2_dual_repo_public_approval_closure_readback_accepts_complete_closure(tmp_path):
    result, summary = run_script(tmp_path, approval_closure_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_dual_repo_public_approval_closure_readback=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-dual-repo-public-approval-closure-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.dual-repo-public-approval-closure.v1"
    assert summary["producer_status"] == "passed"
    assert summary["producer_ready"] is True
    assert summary["producer_release_go_no_go"] == "go"
    assert summary["producer_operator_decision_fields_remain_unapproved"] is True
    assert summary["required_source_artifacts"] == [
        "ao2-public-release-operator-checklist-closure",
        "ao2-control-plane-public-release-pair-verification",
        "ao2-control-plane-ao2-stable-promotion-evidence-index-readback",
    ]
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_dual_repo_public_approval_closure_readback_blocks_gaps_and_missing_sources(tmp_path):
    payload = approval_closure_summary(
        release_go_no_go="no_go",
        dual_repo_public_approval_closure_ready=False,
        failures=[{"code": "control_plane_public_release_pair_gaps_present"}],
    )
    payload["source_artifacts"].remove("ao2-control-plane-public-release-pair-verification")

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_dual_repo_public_approval_closure_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_not_ready",
            "severity": "release_blocker",
            "details": ["dual_repo_public_approval_closure_ready must be true"],
        },
        {
            "gap_kind": "producer_release_go_no_go_not_go",
            "severity": "release_blocker",
            "details": ["release_go_no_go must be go"],
        },
        {
            "gap_kind": "producer_failures_present",
            "severity": "release_blocker",
            "details": ["control_plane_public_release_pair_gaps_present"],
        },
        {
            "gap_kind": "missing_required_source_artifacts",
            "severity": "release_blocker",
            "details": ["ao2-control-plane-public-release-pair-verification"],
        },
    ]


def test_ao2_dual_repo_public_approval_closure_readback_blocks_trust_boundary_drift(tmp_path):
    payload = approval_closure_summary()
    payload["trust_boundary"]["mutates_github_releases"] = True

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_trust_boundary_drift",
            "severity": "release_blocker",
            "details": ["mutates_github_releases must be false"],
        }
    ]


def test_latest_successful_run_queries_workflow_specific_runs(monkeypatch):
    module = load_script_module()
    endpoints = []

    def fake_gh_api(endpoint: str):
        endpoints.append(endpoint)
        if endpoint == "repos/uesugitorachiyo/ao2/actions/workflows?per_page=100":
            return {
                "workflows": [
                    {"id": 123, "name": "Dual Repo Public Approval Closure"},
                    {"id": 456, "name": "Unrelated CI"},
                ]
            }
        if endpoint.startswith("repos/uesugitorachiyo/ao2/actions/workflows/123/runs?"):
            return {
                "workflow_runs": [
                    {
                        "id": 789,
                        "name": "Dual Repo Public Approval Closure",
                        "head_branch": "main",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    monkeypatch.setattr(module, "gh_api", fake_gh_api)

    run = module.latest_successful_run(
        "uesugitorachiyo/ao2",
        "main",
        "Dual Repo Public Approval Closure",
    )

    assert run["id"] == 789
    assert endpoints == [
        "repos/uesugitorachiyo/ao2/actions/workflows?per_page=100",
        "repos/uesugitorachiyo/ao2/actions/workflows/123/runs?branch=main&status=success&per_page=50",
    ]


def test_ao2_dual_repo_public_approval_closure_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-dual-repo-public-approval-closure-readback.v1",
        "ao2.dual-repo-public-approval-closure.v1",
        "ao2-dual-repo-public-approval-closure",
        "ao2-public-release-operator-checklist-closure",
        "ao2-control-plane-public-release-pair-verification",
        "ao2-control-plane-ao2-stable-promotion-evidence-index-readback",
        "control_plane_approves_release",
        "mutates_github_releases",
        "provider_api_keys_allowed",
    ]:
        assert needle in script

    for forbidden in [
        "gh release upload",
        "gh release edit",
        "git push origin",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ]:
        assert forbidden not in script

    for needle in [
        "scripts/verify_ao2_dual_repo_public_approval_closure.py",
        "ao2.cp-ao2-dual-repo-public-approval-closure-readback.v1",
        "control_plane_ao2_dual_repo_public_approval_closure_readback=passed",
        "tests/test_ao2_dual_repo_public_approval_closure_readback.py",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
