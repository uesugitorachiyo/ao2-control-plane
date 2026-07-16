import json
import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_month4_controlled_self_improvement_observation.py"
FIXTURE = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "controlled-self-improvement"
    / "dry-run-evidence-pack.v0.1.json"
)


def run_script(tmp_path: Path, fixture: Path = FIXTURE):
    out_json = tmp_path / "controlled-self-improvement-observation.json"
    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--dry-run-evidence-json",
            str(fixture),
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


def test_month4_controlled_self_improvement_observation_accepts_ao2_fixture(tmp_path):
    result, summary = run_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "control_plane_month4_controlled_self_improvement_observation=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-month4-controlled-self-improvement-observation.v0.1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.controlled-self-improvement-dry-run-evidence-pack.v0.1"
    assert summary["producer_status"] == "dry_run_passed"
    assert summary["observation"] == {
        "dry_run_only": True,
        "rollback_verified": True,
        "approval_required": True,
        "provider_execution": False,
        "rsi_authorized": False,
        "promotion_requested": False,
    }
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "control_plane_approves_self_change": False,
        "mutates_ao_artifacts": False,
        "applies_ao_patches": False,
        "mutates_github_repositories": False,
        "provider_api_keys_allowed": False,
        "credential_material_included": False,
    }


def test_month4_controlled_self_improvement_observation_blocks_live_authority(tmp_path):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["authority"]["dry_run_only"] = False
    payload["authority"]["live_self_modification_authorized"] = True
    payload["authority"]["provider_execution_performed"] = True
    payload["authority"]["rsi_authorized"] = True
    payload["authority"]["promotion_requested"] = True
    payload["rollback"]["rollback_verified"] = False
    unsafe = tmp_path / "unsafe.json"
    unsafe.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result, summary = run_script(tmp_path, unsafe)

    assert result.returncode != 0
    assert "control_plane_month4_controlled_self_improvement_observation=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "authority_boundary_drift",
            "severity": "month4_gate_blocker",
            "details": [
                "authority.dry_run_only must be true",
                "authority.live_self_modification_authorized must be false",
                "authority.provider_execution_performed must be false",
                "authority.rsi_authorized must be false",
                "authority.promotion_requested must be false",
            ],
        },
        {
            "gap_kind": "rollback_not_verified",
            "severity": "month4_gate_blocker",
            "details": ["rollback_verified must be true"],
        },
    ]
