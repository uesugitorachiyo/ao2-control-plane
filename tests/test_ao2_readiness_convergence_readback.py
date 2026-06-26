import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_readiness_convergence.py"


def convergence_summary(**overrides):
    payload = {
        "schema_version": "ao2.readiness-convergence-gate.v1",
        "status": "passed",
        "readiness_converged": True,
        "continue_pulse_loop": False,
        "recommended_next_action": "operator_release_decision_required",
        "rsi_claim_boundary": {
            "bounded_governed_rsi": "supported",
            "full_autonomous_self_mutating_rsi": "denied",
            "claim_publish_authority": False,
        },
        "decision": {
            "operator_release_decision_required": True,
            "release_mutation_authority": False,
            "control_plane_observer_only": True,
        },
        "components": [
            {"component_id": "risky_pr_product_readiness", "status": "passed"},
            {"component_id": "release_evidence_closure", "status": "passed"},
            {"component_id": "release_readiness_static", "status": "passed"},
            {"component_id": "release_readiness_regression", "status": "passed"},
            {"component_id": "release_asset_publication_readiness", "status": "passed"},
            {"component_id": "public_ship_dry_run", "status": "passed"},
            {"component_id": "release_cutover_readiness_lock", "status": "passed"},
            {"component_id": "pulse_terminal_eval_loop_schema_compatibility", "status": "passed"},
            {"component_id": "pulse_auto_advance_integration_gate", "status": "passed"},
            {"component_id": "pulse_resume_dry_run", "status": "passed"},
            {"component_id": "pulse_daemon_status", "status": "passed"},
        ],
        "blocking_next_actions": [],
        "trust_boundary": {
            "local_only": True,
            "stores_credentials": False,
            "mutates_release": False,
            "control_plane_role": "read_only_observer",
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    convergence_path = tmp_path / "readiness-convergence-summary.json"
    out_json = tmp_path / "readback-summary.json"
    convergence_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--convergence-summary-json",
            str(convergence_path),
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


def test_ao2_readiness_convergence_readback_accepts_operator_decision_boundary(tmp_path):
    result, summary = run_script(tmp_path, convergence_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_readiness_convergence_readback=passed" in result.stdout
    assert "recommended_next_action=operator_release_decision_required" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-readiness-convergence-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.readiness-convergence-gate.v1"
    assert summary["operator_interpretation"] == {
        "bounded_governed_rsi": "supported",
        "full_autonomous_self_mutating_rsi": "denied",
        "release_decision": "operator_release_decision_required",
        "pulse_loop": "stop_repeating_readiness_evidence",
    }
    assert summary["component_count"] == 11
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_release": False,
        "control_plane_approves_rsi_claims": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "publishes_claims": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_readiness_convergence_readback_blocks_authority_drift(tmp_path):
    payload = convergence_summary(
        continue_pulse_loop=True,
        recommended_next_action="continue_pulse_loop",
    )
    payload["decision"]["release_mutation_authority"] = True
    payload["decision"]["control_plane_observer_only"] = False
    payload["rsi_claim_boundary"]["claim_publish_authority"] = True
    payload["rsi_claim_boundary"]["full_autonomous_self_mutating_rsi"] = "approved"

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_readiness_convergence_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "convergence_decision_drift",
            "severity": "readiness_convergence_blocker",
            "details": [
                "continue_pulse_loop must be false",
                "recommended_next_action must be operator_release_decision_required",
                "decision.release_mutation_authority must be false",
                "decision.control_plane_observer_only must be true",
            ],
        },
        {
            "gap_kind": "rsi_claim_boundary_drift",
            "severity": "readiness_convergence_blocker",
            "details": [
                "rsi_claim_boundary.full_autonomous_self_mutating_rsi must be denied",
                "rsi_claim_boundary.claim_publish_authority must be false",
            ],
        },
    ]


def test_ao2_readiness_convergence_readback_blocks_missing_or_failed_components(tmp_path):
    payload = convergence_summary()
    payload["components"][3]["status"] = "failed"
    payload["blocking_next_actions"] = [
        {"component_id": "release_readiness_regression", "action": "repair"}
    ]

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_blockers_present",
            "severity": "readiness_convergence_blocker",
            "details": ["release_readiness_regression"],
        },
        {
            "gap_kind": "component_status_not_passed",
            "severity": "readiness_convergence_blocker",
            "details": ["release_readiness_regression"],
        },
    ]


def test_ao2_readiness_convergence_readback_is_documented_and_executable():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-readiness-convergence-readback.v1",
        "ao2.readiness-convergence-gate.v1",
        "operator_release_decision_required",
        "full_autonomous_self_mutating_rsi",
        "control_plane_approves_release",
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
        "scripts/verify_ao2_readiness_convergence.py",
        "ao2.cp-ao2-readiness-convergence-readback.v1",
        "control_plane_ao2_readiness_convergence_readback=passed",
        "tests/test_ao2_readiness_convergence_readback.py",
    ]:
        assert needle in readme
        assert needle in runbook
