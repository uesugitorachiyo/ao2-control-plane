import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_rsi_self_change_dry_run.py"


def self_change_dry_run_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-governed-self-change-dry-run.v1",
        "status": "dry_run_evidence_ready",
        "claim_boundary": {
            "bounded_governed_rsi": "allowed",
            "full_autonomous_self_mutating_rsi": "denied",
        },
        "self_change": {
            "mode": "dry_run",
            "applies_patch": False,
            "repository": "ao2",
            "change_class": "verification_path_hardening",
            "target_files": ["scripts/rsi-claim-readiness-audit.sh"],
            "target_before_sha256": {"scripts/rsi-claim-readiness-audit.sh": "a" * 64},
            "proposed_patch": {
                "path": "proposed-self-change.patch",
                "sha256": "b" * 64,
            },
        },
        "rollback": {
            "mode": "dry_run",
            "rehearsal_status": "planned_not_executed",
            "same_change_class": True,
            "rollback_patch": {
                "path": "rollback-self-change.patch",
                "sha256": "c" * 64,
            },
        },
        "rollback_rehearsal": {
            "mode": "executed_in_temporary_workspace",
            "status": "passed",
            "workspace": "rollback-rehearsal/worktree",
            "target_file": "scripts/rsi-claim-readiness-audit.sh",
            "target_before_sha256": "a" * 64,
            "target_after_proposed_sha256": "d" * 64,
            "target_after_rollback_sha256": "a" * 64,
            "proposed_patch_applied": True,
            "rollback_patch_applied": True,
            "same_change_class": True,
            "verification": ["bash -n scripts/rsi-claim-readiness-audit.sh"],
        },
        "full_claim_blockers": [
            "mutation_authority",
            "live_self_change_evidence",
            "executed_rollback_evidence",
            "observer_readback",
            "covenant_claim_publish_approval",
        ],
        "trust_boundary": {
            "local_only": True,
            "uses_network": False,
            "stores_credentials": False,
            "requires_provider_api_key": False,
            "mutates_repositories": False,
            "applies_patch": False,
            "publishes_claims": False,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, producer_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    producer_path = tmp_path / "self-change-dry-run-summary.json"
    out_json = tmp_path / "readback-summary.json"
    producer_path.write_text(json.dumps(producer_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--self-change-summary-json",
            str(producer_path),
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


def test_ao2_rsi_self_change_dry_run_readback_accepts_bounded_dry_run(tmp_path):
    result, summary = run_script(tmp_path, self_change_dry_run_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_rsi_self_change_dry_run_readback=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-rsi-self-change-dry-run-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.rsi-governed-self-change-dry-run.v1"
    assert summary["producer_status"] == "dry_run_evidence_ready"
    assert summary["self_change"]["mode"] == "dry_run"
    assert summary["self_change"]["applies_patch"] is False
    assert summary["rollback"]["mode"] == "dry_run"
    assert summary["rollback"]["rehearsal_status"] == "planned_not_executed"
    assert summary["rollback"]["same_change_class"] is True
    assert summary["rollback_rehearsal"] == {
        "mode": "executed_in_temporary_workspace",
        "status": "passed",
        "workspace": "rollback-rehearsal/worktree",
        "target_file": "scripts/rsi-claim-readiness-audit.sh",
        "target_before_sha256": "a" * 64,
        "target_after_proposed_sha256": "d" * 64,
        "target_after_rollback_sha256": "a" * 64,
        "proposed_patch_applied": True,
        "rollback_patch_applied": True,
        "same_change_class": True,
        "verification": ["bash -n scripts/rsi-claim-readiness-audit.sh"],
    }
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_rsi_claims": False,
        "mutates_ao_artifacts": False,
        "applies_ao_patches": False,
        "mutates_github_repositories": False,
        "mutates_observer_storage": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_rsi_self_change_dry_run_readback_blocks_live_mutation_claim(tmp_path):
    payload = self_change_dry_run_summary()
    payload["claim_boundary"]["full_autonomous_self_mutating_rsi"] = "allowed"
    payload["self_change"]["mode"] = "live"
    payload["self_change"]["applies_patch"] = True
    payload["rollback"]["rehearsal_status"] = "executed"
    payload["full_claim_blockers"] = [
        blocker for blocker in payload["full_claim_blockers"] if blocker != "executed_rollback_evidence"
    ]

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_self_change_dry_run_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "full_claim_boundary_not_denied",
            "severity": "rsi_claim_blocker",
            "details": ["claim_boundary.full_autonomous_self_mutating_rsi must be denied"],
        },
        {
            "gap_kind": "self_change_not_dry_run",
            "severity": "rsi_claim_blocker",
            "details": ["self_change.mode must be dry_run"],
        },
        {
            "gap_kind": "self_change_would_apply_patch",
            "severity": "rsi_claim_blocker",
            "details": ["self_change.applies_patch must be false"],
        },
        {
            "gap_kind": "rollback_not_planned_dry_run",
            "severity": "rsi_claim_blocker",
            "details": ["rollback.rehearsal_status must be planned_not_executed"],
        },
        {
            "gap_kind": "missing_required_full_claim_blockers",
            "severity": "rsi_claim_blocker",
            "details": ["executed_rollback_evidence"],
        },
    ]


def test_ao2_rsi_self_change_dry_run_readback_blocks_trust_boundary_drift(tmp_path):
    payload = self_change_dry_run_summary()
    payload["trust_boundary"]["uses_network"] = True
    payload["trust_boundary"]["applies_patch"] = True

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_trust_boundary_drift",
            "severity": "rsi_claim_blocker",
            "details": ["uses_network must be false", "applies_patch must be false"],
        }
    ]


def test_ao2_rsi_self_change_dry_run_readback_blocks_missing_rollback_rehearsal(tmp_path):
    payload = self_change_dry_run_summary()
    del payload["rollback_rehearsal"]

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_self_change_dry_run_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "rollback_rehearsal_not_executed",
            "severity": "rsi_claim_blocker",
            "details": [
                "rollback_rehearsal.mode must be executed_in_temporary_workspace",
                "rollback_rehearsal.status must be passed",
                "rollback_rehearsal.workspace must be rollback-rehearsal/worktree",
                "rollback_rehearsal.target_file must be scripts/rsi-claim-readiness-audit.sh",
                "rollback_rehearsal.target_before_sha256 must match self_change target sha256",
                "rollback_rehearsal.target_after_proposed_sha256 must be a different lowercase sha256",
                "rollback_rehearsal.target_after_rollback_sha256 must match self_change target sha256",
                "rollback_rehearsal.proposed_patch_applied must be true",
                "rollback_rehearsal.rollback_patch_applied must be true",
                "rollback_rehearsal.same_change_class must be true",
                "rollback_rehearsal.verification must include bash -n scripts/rsi-claim-readiness-audit.sh",
            ],
        }
    ]


def test_ao2_rsi_self_change_dry_run_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-rsi-self-change-dry-run-readback.v1",
        "ao2.rsi-governed-self-change-dry-run.v1",
        "dry_run_evidence_ready",
        "verification_path_hardening",
        "planned_not_executed",
        "executed_in_temporary_workspace",
        "rollback_rehearsal",
        "executed_rollback_evidence",
        "applies_ao_patches",
        "provider_api_keys_allowed",
    ]:
        assert needle in script

    for forbidden in [
        "gh release upload",
        "gh release edit",
        "git push origin",
        "git apply",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ]:
        assert forbidden not in script

    for needle in [
        "scripts/verify_ao2_rsi_self_change_dry_run.py",
        "ao2.cp-ao2-rsi-self-change-dry-run-readback.v1",
        "control_plane_ao2_rsi_self_change_dry_run_readback=passed",
        "tests/test_ao2_rsi_self_change_dry_run_readback.py",
        "Checkout AO2",
        "npm run rsi:self-change-dry-run",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
