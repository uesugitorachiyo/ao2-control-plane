import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao_stack_rsi_chain_binding_readback.py"


def blueprint_authorization(**overrides):
    payload = {
        "schema": "ao.blueprint.build-authorization.v0.1",
        "project_id": "ao-blueprint-self",
        "status": "ready",
        "score": 100,
        "approved_by_user": True,
        "next_allowed_action": "ao-foundry",
        "blueprint_pack_digest": "sha256:blueprint",
        "requirements_digest": "sha256:requirements",
        "traceability_digest": "sha256:traceability",
        "sdd_plan_digest": "sha256:sdd",
    }
    payload.update(overrides)
    return payload


def foundry_chain(**overrides):
    payload = {
        "schema_version": "ao.forge.goal-run-retained-evidence.v0.1",
        "goal_id": "ao2-weekend-hardening",
        "iteration": "20260619T180000Z-verification",
        "phase": "verification",
        "summary": "Retained bounded, governed RSI evidence chain.",
        "captured_outputs": [
            {
                "label": "ao-foundry-rsi-candidate",
                "command": "foundry pulse run",
                "schema_version": "ao.foundry.rsi-candidate.v0.1",
                "status": "ready",
                "generated_by": "foundry pulse run",
                "baseline_score": 90,
                "candidate_score": 100,
                "mutates_repositories": False,
            },
            {
                "label": "ao-foundry-rsi-improvement-gate",
                "command": "foundry pulse run",
                "schema_version": "ao.foundry.rsi-improvement-gate.v0.1",
                "status": "passed",
                "baseline_score": 90,
                "candidate_score": 100,
                "required_improvement_percent": 5,
                "actual_improvement_percent": 10,
                "autonomous_claim": "measured_local_improvement",
                "mutates_repositories": False,
            },
            {
                "label": "ao-foundry-rsi-next-improvement-task",
                "command": "foundry pulse run",
                "schema_version": "ao.foundry.rsi-next-improvement-task.v0.1",
                "status": "ready",
                "required_improvement_percent": 5,
                "actual_improvement_percent": 10,
                "autonomous_claim": "derived_local_next_improvement",
                "mutates_repositories": False,
            },
        ],
        "retention_policy": {
            "temporary_paths_allowed": False,
            "minimum_retention_days_after_terminal_phase": 90,
        },
        "retention_metadata": {
            "retention_class": "loop_evidence",
            "retain_while_goal_active": True,
            "deletion_requires_review": True,
        },
    }
    payload.update(overrides)
    return payload


def forge_goal_run(**overrides):
    payload = {
        "schema_version": "ao.forge.goal-run.v0.1",
        "goal_id": "ao2-weekend-hardening",
        "repo": "ao2",
        "objective": "Harden AO2 toward production readiness without broadening mutation authority.",
        "acceptance_criteria": [
            "Every iteration leaves the repository with passing focused tests for touched behavior.",
            "Changes stay inside AO2 hardening scope and preserve existing release controls.",
        ],
        "allowed_scope": [
            "AO2 policy, evidence, adapter, and verification hardening.",
            "Read-only inspection and test additions needed to prove hardening behavior.",
        ],
        "stop_conditions": [
            "The next task would require release mutation or credential access.",
            "The diff exceeds the declared AO2 hardening scope.",
        ],
        "current_phase": "implementation",
        "next_task": "Implement the smallest verified AO2 hardening task.",
        "loop_owner": {
            "state_owner": "ao-forge",
            "executor": "ao2-pulse",
            "scheduler": "external-scheduler",
        },
        "next_action_guard": {
            "must_read_latest_goal_run": True,
            "must_match_allowed_scope": True,
            "must_satisfy_acceptance_criteria": True,
            "on_mismatch": "backoff_or_stop",
        },
        "last_iteration": {
            "status": "passed",
            "evidence": [
                {
                    "label": "bounded-rsi-improvement-chain-retention-proof.json",
                    "path": "docs/evidence/goals/ao2-weekend-hardening/20260619T180000Z-verification/bounded-rsi-improvement-chain-retention-proof.json",
                    "sha256": "82cb13938f4ce05cc43e58b2e508de2a1f6e5004c6233f72045d215ea49c53d3",
                }
            ],
        },
    }
    payload.update(overrides)
    return payload


def ao2_cross_repo_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-cross-repo-e2e.v1",
        "status": "passed",
        "claim_level": "full_autonomous_self_mutating_rsi",
        "claim_publish_decision": "deny",
        "claim_publish_authority": False,
        "claim_publish_resource": "full-autonomous-self-mutating-rsi",
        "checks": [
            {"name": "live_self_change_rehearsal", "status": "passed"},
            {"name": "control_plane_readback", "status": "passed"},
            {"name": "readback_index", "status": "passed"},
            {"name": "claim_readiness", "status": "passed"},
            {"name": "blueprint_authorization", "status": "passed"},
            {"name": "covenant_claim_publish_gate", "status": "passed"},
            {"name": "improvement_evidence_gate", "status": "passed"},
            {"name": "improvement_trend", "status": "passed"},
        ],
        "blueprint_authorization": {
            "schema_version": "ao2.rsi-blueprint-authorization-gate.v1",
            "status": "passed",
            "gate_model": "tiered",
            "blueprint_authorization_ready": True,
            "self_authorized_by_rsi": False,
            "authorizes_ao_blueprint_self_change": False,
            "authorizes_claim_publication": False,
        },
        "observed_evidence": {
            "covenant_gate_schema_version": "covenant.rsi-claim-publish-gate.v1",
            "covenant_gate_status": "denied",
            "control_plane_readback_status": "passed",
            "readback_index_status": "passed",
            "claim_readiness_status": "claim_boundary_enforced",
            "improvement_gate_status": "passed",
            "improvement_trend_status": "passed",
            "measured_improvement_percent": 50.0,
        },
        "trust_boundary": {
            "approves_rsi_claims": False,
            "local_only": True,
            "publishes_claims": False,
            "requires_provider_api_key": False,
            "stores_credentials": False,
            "uses_network": False,
        },
    }
    payload.update(overrides)
    return payload


def control_surface_readback(**overrides):
    payload = {
        "schema_version": "ao2.cp-ao2-rsi-control-surface-readback.v1",
        "status": "passed",
        "control_surface_readback": {
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
        },
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_rsi_claims": False,
            "mutates_ao_artifacts": False,
            "applies_ao_patches": False,
            "mutates_github_repositories": False,
            "mutates_observer_storage": False,
            "publishes_claims": False,
            "credential_material_included": False,
            "provider_api_keys_allowed": False,
        },
    }
    payload.update(overrides)
    return payload


def foundry_control_surface_packet(**overrides):
    payload = {
        "schema_version": "ao.foundry.rsi-control-surface-packet.v0.1",
        "status": "ready",
        "generated_by": "foundry portfolio readback",
        "goal_id": "bounded-governed-rsi-control-surface-readback",
        "loop_goal": "bounded_governed_rsi_control_surface_readback",
        "chain": [
            "ao-blueprint",
            "ao-foundry",
            "ao-forge",
            "ao-covenant",
            "ao2",
            "ao2-control-plane",
        ],
        "claim_boundaries": {
            "bounded_governed_rsi": {
                "decision": "allowed",
                "status": "supported",
                "reason": "bounded governed RSI evidence is linked",
            },
            "full_autonomous_self_mutating_rsi": {
                "decision": "denied",
                "status": "boundary_enforced",
                "publish_authority": False,
                "reason": "full autonomous RSI remains denied",
            },
            "improvement_score": {
                "interpretation": "evidence_coverage_not_publication_authority",
                "target_exceeded": True,
            },
        },
        "evidence_links": [
            {
                "label": "blueprint_build_authorization",
                "repo": "ao-blueprint",
                "path": "../ao-blueprint/examples/blueprints/valid/bounded-governed-rsi-control-surface-readback/build-authorization.json",
                "schema_version": "ao.blueprint.build-authorization.v0.1",
                "status": "ready",
                "sha256": "5dd0d6576377ed500cfbd32a76efe0a159c9ff426cf810659d8b43e31a0f66a1",
                "role": "authorization",
            },
            {
                "label": "forge_retained_chain_binding_readback",
                "repo": "ao-forge",
                "path": "../ao-forge/docs/evidence/goals/ao2-weekend-hardening/20260619T180000Z-verification/ao-stack-rsi-chain-binding-readback-retention-proof.json",
                "schema_version": "ao.forge.goal-run-retained-evidence.v0.1",
                "status": "retained",
                "sha256": "a39a334b375b8ccd96a1173c24588854fcde9e7a9a5f48ab01668670e46527b2",
                "role": "retained_proof",
            },
            {
                "label": "ao2_improvement_evidence_gate",
                "repo": "ao2",
                "path": "../ao2/target/rsi-improvement-evidence-gate/latest/summary.json",
                "schema_version": "ao2.rsi-improvement-evidence-gate.v1",
                "status": "passed",
                "sha256": "ba7a755f1b5fbfaf22d4d5bef6a6a3751ca2c3448bf4e4503bee774ccb643d7c",
                "role": "execution_evidence",
            },
            {
                "label": "ao2_improvement_trend",
                "repo": "ao2",
                "path": "../ao2/target/rsi-improvement-trend/latest/summary.json",
                "schema_version": "ao2.rsi-improvement-trend.v1",
                "status": "passed",
                "sha256": "aec2c426a02b508508ffa099411e93f6dde9d7c0a76a7a81d875a3092b0ca29d",
                "role": "execution_evidence",
            },
            {
                "label": "control_plane_control_surface_readback",
                "repo": "ao2-control-plane",
                "path": "../ao2-control-plane/target/ao-stack-rsi-chain-binding-readback/producers/control-surface-readback.json",
                "schema_version": "ao2.cp-ao2-rsi-control-surface-readback.v1",
                "status": "passed",
                "sha256": "114c23ea1b77e7183fd9076e396ddf4a41344cbb262fb17a5e01717e175b10f8",
                "role": "observer_readback",
            },
        ],
        "trust_boundary": {
            "foundry_mutates_repositories": False,
            "foundry_approves_claims": False,
            "control_plane_observer_only": True,
            "provider_credentials_allowed": False,
            "publishes_full_autonomous_rsi_claim": False,
        },
        "next_actions": [
            "retain this packet as the Foundry portfolio readback for the bounded governed RSI loop",
        ],
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, **overrides) -> tuple[subprocess.CompletedProcess, dict]:
    inputs = {
        "blueprint": overrides.get("blueprint", blueprint_authorization()),
        "foundry": overrides.get("foundry", foundry_chain()),
        "forge": overrides.get("forge", forge_goal_run()),
        "ao2": overrides.get("ao2", ao2_cross_repo_summary()),
        "control": overrides.get("control", control_surface_readback()),
    }
    paths = {}
    for name, payload in inputs.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths[name] = path
    out_json = tmp_path / "chain-readback-summary.json"

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--blueprint-authorization-json",
            str(paths["blueprint"]),
            "--foundry-chain-json",
            str(paths["foundry"]),
            "--forge-goal-run-json",
            str(paths["forge"]),
            "--ao2-cross-repo-summary-json",
            str(paths["ao2"]),
            "--control-surface-readback-json",
            str(paths["control"]),
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


def run_script_with_foundry_packet(tmp_path: Path, packet: dict) -> tuple[subprocess.CompletedProcess, dict]:
    packet_path = tmp_path / "foundry-control-surface-packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inputs = {
        "blueprint": blueprint_authorization(),
        "foundry": foundry_chain(),
        "forge": forge_goal_run(),
        "ao2": ao2_cross_repo_summary(),
        "control": control_surface_readback(),
    }
    paths = {}
    for name, payload in inputs.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths[name] = path
    out_json = tmp_path / "chain-readback-summary.json"

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--blueprint-authorization-json",
            str(paths["blueprint"]),
            "--foundry-chain-json",
            str(paths["foundry"]),
            "--foundry-control-surface-packet-json",
            str(packet_path),
            "--forge-goal-run-json",
            str(paths["forge"]),
            "--ao2-cross-repo-summary-json",
            str(paths["ao2"]),
            "--control-surface-readback-json",
            str(paths["control"]),
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


def test_ao_stack_rsi_chain_binding_readback_accepts_observer_only_chain(tmp_path):
    result, summary = run_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao_stack_rsi_chain_binding_readback=passed" in result.stdout
    assert "chain=blueprint->foundry->forge->covenant->ao2->control-plane" in result.stdout
    assert "full_autonomous_self_mutating_rsi=denied boundary_state=enforced_by_design" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao-stack-rsi-chain-binding-readback.v1"
    assert summary["status"] == "passed"
    assert [stage["stage"] for stage in summary["chain_binding"]] == [
        "blueprint_authorization",
        "foundry_candidate_gate",
        "forge_goal_run",
        "covenant_claim_decision",
        "ao2_execution_evidence",
        "control_plane_readback",
    ]
    assert summary["operator_interpretation"] == {
        "bounded_governed_rsi": "supported_by_bound_chain",
        "full_autonomous_self_mutating_rsi": "denied_by_covenant_and_control_surface",
        "control_plane_role": "observer_readback_only",
    }
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "control_plane_approves_rsi_claims": False,
        "control_plane_executes_ao_work": False,
        "control_plane_mutates_repositories": False,
        "control_plane_publishes_claims": False,
        "control_plane_authorizes_blueprint_self_change": False,
        "provider_api_keys_allowed": False,
        "credential_material_included": False,
    }


def test_ao_stack_rsi_chain_binding_readback_consumes_foundry_control_surface_packet(tmp_path):
    result, summary = run_script_with_foundry_packet(tmp_path, foundry_control_surface_packet())

    assert result.returncode == 0, result.stderr
    assert summary["status"] == "passed"
    assert summary["producer_schema_versions"]["foundry_control_surface_packet"] == "ao.foundry.rsi-control-surface-packet.v0.1"
    stages = {stage["stage"]: stage for stage in summary["chain_binding"]}
    assert stages["foundry_control_surface_packet"] == {
        "stage": "foundry_control_surface_packet",
        "source": "ao-foundry",
        "schema_version": "ao.foundry.rsi-control-surface-packet.v0.1",
        "status": "ready",
        "loop_goal": "bounded_governed_rsi_control_surface_readback",
        "bounded_governed_rsi": "supported",
        "full_autonomous_self_mutating_rsi": "denied",
        "publishes_full_autonomous_rsi_claim": False,
        "control_plane_observer_only": True,
    }


def test_ao_stack_rsi_chain_binding_readback_blocks_foundry_control_surface_packet_authority_drift(tmp_path):
    packet = foundry_control_surface_packet()
    packet["claim_boundaries"]["full_autonomous_self_mutating_rsi"]["decision"] = "allowed"
    packet["trust_boundary"]["publishes_full_autonomous_rsi_claim"] = True

    result, summary = run_script_with_foundry_packet(tmp_path, packet)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert {
        "gap_kind": "foundry_control_surface_packet_authority_drift",
        "severity": "rsi_chain_binding_blocker",
        "details": [
            "full_autonomous_self_mutating_rsi.decision must be denied",
            "trust_boundary.publishes_full_autonomous_rsi_claim must be false",
        ],
    } in summary["gaps"]


def test_ao_stack_rsi_chain_binding_readback_blocks_blueprint_authority_drift(tmp_path):
    blueprint = blueprint_authorization(status="blocked", score=80, next_allowed_action="ao2")
    ao2 = ao2_cross_repo_summary()
    ao2["blueprint_authorization"]["self_authorized_by_rsi"] = True

    result, summary = run_script(tmp_path, blueprint=blueprint, ao2=ao2)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "blueprint_authorization_not_ready",
            "severity": "rsi_chain_binding_blocker",
            "details": [
                "status must be ready",
                "score must be 100",
                "next_allowed_action must be ao-foundry",
            ],
        },
        {
            "gap_kind": "ao2_blueprint_gate_authority_drift",
            "severity": "rsi_chain_binding_blocker",
            "details": ["self_authorized_by_rsi must be false"],
        },
    ]


def test_ao_stack_rsi_chain_binding_readback_blocks_foundry_or_covenant_authority_drift(tmp_path):
    foundry = foundry_chain()
    foundry["captured_outputs"][1]["mutates_repositories"] = True
    foundry["captured_outputs"][1]["autonomous_claim"] = "full_autonomous_self_mutating_rsi"
    ao2 = ao2_cross_repo_summary(claim_publish_decision="allow", claim_publish_authority=True)
    ao2["observed_evidence"]["covenant_gate_status"] = "allowed"

    result, summary = run_script(tmp_path, foundry=foundry, ao2=ao2)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "foundry_candidate_gate_authority_drift",
            "severity": "rsi_chain_binding_blocker",
            "details": [
                "ao-foundry-rsi-improvement-gate.mutates_repositories must be false",
                "ao-foundry-rsi-improvement-gate.autonomous_claim must not be full_autonomous_self_mutating_rsi",
            ],
        },
        {
            "gap_kind": "covenant_claim_decision_not_denied",
            "severity": "rsi_chain_binding_blocker",
            "details": [
                "claim_publish_decision must be deny",
                "claim_publish_authority must be false",
                "observed_evidence.covenant_gate_status must be denied",
            ],
        },
    ]


def test_ao_stack_rsi_chain_binding_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao-stack-rsi-chain-binding-readback.v1",
        "ao.blueprint.build-authorization.v0.1",
        "ao.forge.goal-run-retained-evidence.v0.1",
        "ao.forge.goal-run.v0.1",
        "ao2.rsi-cross-repo-e2e.v1",
        "ao2.cp-ao2-rsi-control-surface-readback.v1",
        "ao.foundry.rsi-control-surface-packet.v0.1",
        "foundry_control_surface_packet",
        "full_autonomous_self_mutating_rsi",
        "control_plane_approves_rsi_claims",
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
        "scripts/verify_ao_stack_rsi_chain_binding_readback.py",
        "ao2.cp-ao-stack-rsi-chain-binding-readback.v1",
        "control_plane_ao_stack_rsi_chain_binding_readback=passed",
        "tests/test_ao_stack_rsi_chain_binding_readback.py",
        "Checkout AO Blueprint",
        "Checkout AO Foundry",
        "Checkout AO Forge",
        "Checkout AO Covenant",
        "npm run rsi:cross-repo-e2e",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook

    for needle in [
        "Setup Go for AO Covenant",
        "go-version-file: ao-covenant/go.mod",
    ]:
        assert needle in ci
