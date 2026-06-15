import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_stable_promotion_evidence_index.py"


def stable_index_summary(**overrides):
    payload = {
        "schema_version": "ao2.stable-promotion-evidence-index.v1",
        "status": "passed",
        "stable_promotion_evidence_index_ready": True,
        "blockers": [],
        "evidence": {
            "artifact_size_budget_audit": {
                "schema_version": "ao2.release-artifact-size-budget-audit.v1",
                "status": "passed",
                "ready": True,
                "violations": [],
            },
            "post_release_verification_gate": {
                "schema_version": "ao2.stable-promotion-evidence-gate.v1",
                "status": "passed",
                "ready": True,
                "post_release_evidence_ready": True,
            },
            "public_pair_digest_audit": {
                "schema_version": "ao2.public-release-pair-digest-audit.v1",
                "status": "passed",
                "ready": True,
                "archive_parity_status": "passed",
            },
            "stable_release_evidence_packet": {
                "schema_version": "ao2.stable-release-evidence-packet.v1",
                "status": "passed",
                "ready": True,
                "stable_release_evidence_ready": True,
            },
        },
        "trust_boundary": {
            "local_only": True,
            "control_plane_approves_release": False,
            "mutates_releases": False,
            "stores_credentials": False,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, index_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    index_path = tmp_path / "ao2-stable-index-summary.json"
    out_json = tmp_path / "readback-summary.json"
    index_path.write_text(json.dumps(index_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--index-summary-json",
            str(index_path),
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


def test_ao2_stable_promotion_evidence_index_readback_accepts_complete_passed_index(tmp_path):
    result, summary = run_script(tmp_path, stable_index_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_stable_promotion_evidence_index_readback=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.stable-promotion-evidence-index.v1"
    assert summary["producer_status"] == "passed"
    assert summary["producer_ready"] is True
    assert summary["gaps"] == []
    assert summary["required_evidence"] == [
        "artifact_size_budget_audit",
        "post_release_verification_gate",
        "public_pair_digest_audit",
        "stable_release_evidence_packet",
    ]
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_stable_promotion_evidence_index_readback_blocks_partial_or_blocked_index(tmp_path):
    payload = stable_index_summary(blockers=["public pair digest audit missing"])
    payload["evidence"].pop("public_pair_digest_audit")

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_stable_promotion_evidence_index_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_blockers_present",
            "severity": "release_blocker",
            "details": ["public pair digest audit missing"],
        },
        {
            "gap_kind": "missing_required_evidence",
            "severity": "release_blocker",
            "details": ["public_pair_digest_audit"],
        },
    ]


def test_ao2_stable_promotion_evidence_index_readback_blocks_trust_boundary_drift(tmp_path):
    payload = stable_index_summary()
    payload["trust_boundary"]["mutates_releases"] = True

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_trust_boundary_drift",
            "severity": "release_blocker",
            "details": ["mutates_releases must be false"],
        }
    ]


def test_ao2_stable_promotion_evidence_index_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1",
        "ao2.stable-promotion-evidence-index.v1",
        "ao2-stable-promotion-evidence-index",
        "public_pair_digest_audit",
        "artifact_size_budget_audit",
        "stable_release_evidence_packet",
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
        "scripts/verify_ao2_stable_promotion_evidence_index.py",
        "ao2.cp-ao2-stable-promotion-evidence-index-readback.v1",
        "control_plane_ao2_stable_promotion_evidence_index_readback=passed",
        "tests/test_ao2_stable_promotion_evidence_index_readback.py",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
