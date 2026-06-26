import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_rsi_control_surface_readback.py"


def control_surface_readback():
    return {
        "loop_goal": "bounded_governed_rsi_control_surface_readback",
        "bounded_governed_rsi": {
            "status": "supported",
            "evidence_state": "passing",
            "improvement_state": "target_exceeded",
        },
        "full_autonomous_self_mutating_rsi": {
            "status": "denied",
            "decision": "deny",
            "publish_authority": False,
            "boundary_state": "enforced_by_design",
        },
        "improvement_score": {
            "target_exceeded": True,
            "interpretation": "workflow_hardening_coverage_not_publication_authority",
        },
    }


def improvement_gate_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-improvement-evidence-gate.v1",
        "status": "passed",
        "improvement_ready": True,
        "claim_level": "full_autonomous_self_mutating_rsi",
        "claim_publish_authority": False,
        "claim_publish_decision": "deny",
        "metric": {
            "baseline_check_count": 6,
            "observed_check_count": 9,
            "measured_improvement_percent": 50.0,
            "target_percent": 5.0,
            "unit": "enforced_rsi_evidence_checks",
        },
        "control_surface_readback": control_surface_readback(),
        "trust_boundary": {
            "local_only": True,
            "uses_network": False,
            "stores_credentials": False,
            "requires_provider_api_key": False,
            "mutates_repositories": False,
            "approves_rsi_claims": False,
            "publishes_claims": False,
        },
    }
    payload.update(overrides)
    return payload


def improvement_trend_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-improvement-trend.v1",
        "status": "passed",
        "trend_ready": True,
        "claim_level": "full_autonomous_self_mutating_rsi",
        "claim_publish_authority": False,
        "claim_publish_decision": "deny",
        "current_measured_improvement_percent": 50.0,
        "previous_measured_improvement_percent": 50.0,
        "delta_from_previous_percent": 0.0,
        "target_percent": 5.0,
        "control_surface_readback": control_surface_readback(),
        "latest_record": {
            "schema_version": "ao2.rsi-improvement-trend-record.v1",
            "measured_improvement_percent": 50.0,
            "target_percent": 5.0,
            "baseline_check_count": 6,
            "observed_check_count": 9,
            "claim_publish_authority": False,
            "claim_publish_decision": "deny",
            "control_surface_readback": control_surface_readback(),
        },
        "trust_boundary": {
            "local_only": True,
            "uses_network": False,
            "stores_credentials": False,
            "requires_provider_api_key": False,
            "mutates_repositories": False,
            "approves_rsi_claims": False,
            "publishes_claims": False,
            "writes_local_history": True,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, gate_summary: dict, trend_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    gate_path = tmp_path / "rsi-improvement-evidence-gate-summary.json"
    trend_path = tmp_path / "rsi-improvement-trend-summary.json"
    out_json = tmp_path / "readback-summary.json"
    gate_path.write_text(json.dumps(gate_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trend_path.write_text(json.dumps(trend_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--gate-summary-json",
            str(gate_path),
            "--trend-summary-json",
            str(trend_path),
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


def test_ao2_rsi_control_surface_readback_accepts_bounded_governed_improvement(tmp_path):
    result, summary = run_script(tmp_path, improvement_gate_summary(), improvement_trend_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_rsi_control_surface_readback=passed" in result.stdout
    assert "bounded_governed_rsi=supported evidence_state=passing" in result.stdout
    assert "full_autonomous_self_mutating_rsi=denied boundary_state=enforced_by_design" in result.stdout
    assert "improvement_score=target_exceeded interpretation=workflow_hardening_coverage_not_publication_authority" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-rsi-control-surface-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_versions"] == {
        "improvement_evidence_gate": "ao2.rsi-improvement-evidence-gate.v1",
        "improvement_trend": "ao2.rsi-improvement-trend.v1",
    }
    assert summary["control_surface_readback"] == control_surface_readback()
    assert summary["operator_interpretation"] == {
        "bounded_governed_rsi": "supported_passing_improving",
        "full_autonomous_self_mutating_rsi": "denied_boundary_enforced",
        "improvement_score": "evidence_coverage_not_publication_authority",
    }
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


def test_ao2_rsi_control_surface_readback_blocks_target_exceeded_as_publish_authority(tmp_path):
    gate = improvement_gate_summary(claim_publish_authority=True, claim_publish_decision="allow")
    gate["control_surface_readback"]["full_autonomous_self_mutating_rsi"]["publish_authority"] = True
    gate["control_surface_readback"]["full_autonomous_self_mutating_rsi"]["decision"] = "allow"
    trend = improvement_trend_summary(claim_publish_authority=True, claim_publish_decision="allow")
    trend["control_surface_readback"]["full_autonomous_self_mutating_rsi"]["publish_authority"] = True
    trend["control_surface_readback"]["improvement_score"]["interpretation"] = "publication_authority"

    result, summary = run_script(tmp_path, gate, trend)

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_control_surface_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "gate_claim_publication_not_denied",
            "severity": "rsi_control_surface_blocker",
            "details": [
                "claim_publish_authority must be false",
                "claim_publish_decision must be deny",
            ],
        },
        {
            "gap_kind": "gate_control_surface_full_autonomy_not_denied",
            "severity": "rsi_control_surface_blocker",
            "details": [
                "full_autonomous_self_mutating_rsi.decision must be deny",
                "full_autonomous_self_mutating_rsi.publish_authority must be false",
            ],
        },
        {
            "gap_kind": "trend_claim_publication_not_denied",
            "severity": "rsi_control_surface_blocker",
            "details": [
                "claim_publish_authority must be false",
                "claim_publish_decision must be deny",
            ],
        },
        {
            "gap_kind": "trend_control_surface_full_autonomy_not_denied",
            "severity": "rsi_control_surface_blocker",
            "details": ["full_autonomous_self_mutating_rsi.publish_authority must be false"],
        },
        {
            "gap_kind": "trend_improvement_score_interpretation_drift",
            "severity": "rsi_control_surface_blocker",
            "details": [
                "improvement_score.interpretation must be workflow_hardening_coverage_not_publication_authority"
            ],
        },
    ]


def test_ao2_rsi_control_surface_readback_blocks_observer_authority_drift(tmp_path):
    gate = improvement_gate_summary()
    gate["trust_boundary"]["approves_rsi_claims"] = True
    trend = improvement_trend_summary()
    trend["trust_boundary"]["mutates_repositories"] = True

    result, summary = run_script(tmp_path, gate, trend)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "gate_trust_boundary_drift",
            "severity": "rsi_control_surface_blocker",
            "details": ["approves_rsi_claims must be false"],
        },
        {
            "gap_kind": "trend_trust_boundary_drift",
            "severity": "rsi_control_surface_blocker",
            "details": ["mutates_repositories must be false"],
        },
    ]


def test_ao2_rsi_control_surface_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-rsi-control-surface-readback.v1",
        "ao2.rsi-improvement-evidence-gate.v1",
        "ao2.rsi-improvement-trend.v1",
        "bounded_governed_rsi_control_surface_readback",
        "workflow_hardening_coverage_not_publication_authority",
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
        "scripts/verify_ao2_rsi_control_surface_readback.py",
        "ao2.cp-ao2-rsi-control-surface-readback.v1",
        "control_plane_ao2_rsi_control_surface_readback=passed",
        "tests/test_ao2_rsi_control_surface_readback.py",
        "Checkout AO2",
        "Checkout AO Covenant",
        "npm run rsi:cross-repo-e2e",
        "npm run rsi:improvement-evidence-gate",
        "npm run rsi:improvement-trend",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
