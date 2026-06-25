import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_rsi_live_self_change_rehearsal.py"


def live_self_change_rehearsal_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-live-self-change-rehearsal.v1",
        "status": "live_rehearsal_passed",
        "claim_boundary": {
            "bounded_governed_rsi": "allowed",
            "full_autonomous_self_mutating_rsi": "denied",
        },
        "self_change": {
            "mode": "live_rehearsal",
            "repository": "ao2",
            "change_class": "verification_path_hardening",
            "target_files": ["scripts/rsi-claim-readiness-audit.sh"],
            "target_before_sha256": {"scripts/rsi-claim-readiness-audit.sh": "a" * 64},
            "target_after_mutation_sha256": "b" * 64,
            "target_after_rollback_sha256": "a" * 64,
            "applies_patch": True,
            "repository_restored": True,
            "proposed_patch": {
                "path": "proposed-live-self-change.patch",
                "sha256": "c" * 64,
            },
        },
        "rollback": {
            "mode": "live_rehearsal",
            "status": "passed",
            "same_change_class": True,
            "rollback_patch": {
                "path": "rollback-live-self-change.patch",
                "sha256": "d" * 64,
            },
        },
        "live_self_change_evidence": {
            "status": "passed",
            "evidence_paths": [
                "summary.json",
                "proposed-live-self-change.patch",
                "rollback-live-self-change.patch",
            ],
        },
        "observer_readback": {
            "status": "missing",
            "observer": "ao2-control-plane",
            "evidence_paths": [],
        },
        "full_claim_blockers": [
            "observer_readback",
            "covenant_claim_publish_approval",
            "retained_claim_level_evidence",
        ],
        "trust_boundary": {
            "local_only": True,
            "uses_network": False,
            "requires_provider_api_key": False,
            "stores_credentials": False,
            "mutates_repositories": True,
            "applies_patch": True,
            "rollback_applied": True,
            "publishes_claims": False,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, producer_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    producer_path = tmp_path / "live-self-change-rehearsal-summary.json"
    out_json = tmp_path / "readback-summary.json"
    producer_path.write_text(json.dumps(producer_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--live-rehearsal-summary-json",
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


def test_ao2_rsi_live_self_change_rehearsal_readback_accepts_restored_live_rehearsal(tmp_path):
    result, summary = run_script(tmp_path, live_self_change_rehearsal_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_rsi_live_self_change_rehearsal_readback=passed" in result.stdout
    assert "claim_level=full_autonomous_self_mutating_rsi decision=denied" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-rsi-live-self-change-rehearsal-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.rsi-live-self-change-rehearsal.v1"
    assert summary["producer_status"] == "live_rehearsal_passed"
    assert summary["claim_boundary"] == {
        "bounded_governed_rsi": "allowed",
        "full_autonomous_self_mutating_rsi": "denied",
    }
    assert summary["self_change"]["mode"] == "live_rehearsal"
    assert summary["self_change"]["applies_patch"] is True
    assert summary["self_change"]["repository_restored"] is True
    assert summary["self_change"]["target_after_mutation_sha256"] == "b" * 64
    assert summary["self_change"]["target_after_rollback_sha256"] == "a" * 64
    assert summary["rollback"] == {
        "mode": "live_rehearsal",
        "status": "passed",
        "same_change_class": True,
        "rollback_patch": {
            "path": "rollback-live-self-change.patch",
            "sha256": "d" * 64,
        },
    }
    assert summary["live_self_change_evidence"] == {
        "status": "passed",
        "evidence_paths": [
            "summary.json",
            "proposed-live-self-change.patch",
            "rollback-live-self-change.patch",
        ],
    }
    assert summary["observer_readback"] == {
        "status": "missing",
        "observer": "ao2-control-plane",
        "evidence_paths": [],
    }
    assert summary["observed_full_claim_blockers"] == [
        "observer_readback",
        "covenant_claim_publish_approval",
        "retained_claim_level_evidence",
    ]
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_rsi_claims": False,
        "mutates_ao_artifacts": False,
        "applies_ao_patches": False,
        "mutates_github_repositories": False,
        "mutates_observer_storage": False,
        "publishes_claims": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_rsi_live_self_change_rehearsal_readback_blocks_unrestored_repository(tmp_path):
    payload = live_self_change_rehearsal_summary()
    payload["claim_boundary"]["full_autonomous_self_mutating_rsi"] = "allowed"
    payload["self_change"]["repository_restored"] = False
    payload["self_change"]["target_after_rollback_sha256"] = "e" * 64
    payload["rollback"]["status"] = "failed"
    payload["observer_readback"] = {
        "status": "passed",
        "observer": "ao2-control-plane",
        "evidence_paths": ["readback.json"],
    }

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_live_self_change_rehearsal_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "full_claim_boundary_not_denied",
            "severity": "rsi_claim_blocker",
            "details": ["claim_boundary.full_autonomous_self_mutating_rsi must be denied"],
        },
        {
            "gap_kind": "self_change_repository_not_restored",
            "severity": "rsi_claim_blocker",
            "details": [
                "self_change.repository_restored must be true",
                "self_change.target_after_rollback_sha256 must match target_before_sha256",
            ],
        },
        {
            "gap_kind": "rollback_not_passed",
            "severity": "rsi_claim_blocker",
            "details": ["rollback.status must be passed"],
        },
        {
            "gap_kind": "observer_readback_not_missing",
            "severity": "rsi_claim_blocker",
            "details": [
                "observer_readback.status must remain missing until independent readback is published",
                "observer_readback.evidence_paths must be empty",
            ],
        },
    ]


def test_ao2_rsi_live_self_change_rehearsal_readback_blocks_trust_boundary_drift(tmp_path):
    payload = live_self_change_rehearsal_summary()
    payload["trust_boundary"]["uses_network"] = True
    payload["trust_boundary"]["publishes_claims"] = True

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_trust_boundary_drift",
            "severity": "rsi_claim_blocker",
            "details": ["uses_network must be false", "publishes_claims must be false"],
        }
    ]


def test_ao2_rsi_live_self_change_rehearsal_readback_blocks_unsafe_artifact_paths(tmp_path):
    payload = live_self_change_rehearsal_summary()
    payload["self_change"]["proposed_patch"]["path"] = "../proposed-live-self-change.patch"
    payload["rollback"]["rollback_patch"]["path"] = "/tmp/rollback-live-self-change.patch"

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "self_change_contract_drift",
            "severity": "rsi_claim_blocker",
            "details": ["self_change.proposed_patch.path must be a relative artifact path"],
        },
        {
            "gap_kind": "rollback_not_passed",
            "severity": "rsi_claim_blocker",
            "details": ["rollback.rollback_patch.path must be a relative artifact path"],
        },
    ]


def test_ao2_rsi_live_self_change_rehearsal_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-rsi-live-self-change-rehearsal-readback.v1",
        "ao2.rsi-live-self-change-rehearsal.v1",
        "live_rehearsal_passed",
        "verification_path_hardening",
        "repository_restored",
        "rollback_applied",
        "observer_readback",
        "retained_claim_level_evidence",
        "control_plane_approves_rsi_claims",
        "publishes_claims",
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
        "scripts/verify_ao2_rsi_live_self_change_rehearsal.py",
        "ao2.cp-ao2-rsi-live-self-change-rehearsal-readback.v1",
        "control_plane_ao2_rsi_live_self_change_rehearsal_readback=passed",
        "tests/test_ao2_rsi_live_self_change_rehearsal_readback.py",
        "Checkout AO2",
        "AO2_RSI_LIVE_SELF_CHANGE_REHEARSAL=1 npm run rsi:live-self-change-rehearsal",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
