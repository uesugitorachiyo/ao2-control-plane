import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_active_stack_release_handoff.py"


ACTIVE_REPOS = [
    "ao2",
    "ao2-control-plane",
    "ao-foundry",
    "ao-forge",
    "ao-command",
    "ao-covenant",
]


def foundry_ledger(**overrides):
    payload = {
        "schema_version": "ao.foundry.active-stack-readiness.v0.1",
        "registry_id": "local-ao-stack",
        "generated_from_registry": "examples/registry/local-ao-stack.foundry-registry.json",
        "last_sweep_date": "2026-06-23",
        "status": "ready",
        "repositories": [
            {
                "id": repo,
                "name": repo,
                "role": "evidence-observer" if repo == "ao2-control-plane" else "active",
                "status": "ready",
                "verification_evidence": ["verified"],
            }
            for repo in ACTIVE_REPOS
        ],
        "release_handoff": {
            "status": "ready",
            "gates": [
                {
                    "name": "foundry-release-candidate",
                    "status": "ready",
                    "required_before_promotion": True,
                    "evidence": ["foundry candidate"],
                },
                {
                    "name": "forge-release-candidate-handoff",
                    "status": "ready",
                    "required_before_promotion": True,
                    "evidence": ["forge handoff"],
                },
                {
                    "name": "covenant-policy-spine",
                    "status": "ready",
                    "required_before_promotion": True,
                    "evidence": ["covenant.policy-spine-result.v1"],
                },
                {
                    "name": "signed-smoke-release-gate",
                    "status": "manual_required",
                    "required_before_promotion": True,
                    "evidence": ["release_safe=true"],
                },
            ],
        },
        "next_actions": ["run signed smoke before promotion"],
    }
    payload.update(overrides)
    return payload


def covenant_policy_spine(**overrides):
    payload = {
        "schema_version": "covenant.policy-spine-result.v1",
        "stack": "ao2-first",
        "status": "ready",
        "scope": {
            "active_repositories": list(ACTIVE_REPOS),
            "replaced_by": ["ao2", "ao2-control-plane"],
        },
        "responsibilities": [
            {
                "name": "control-plane-evidence",
                "owner": "ao2-control-plane",
                "gates": ["schema-backed publication", "readiness status exposure"],
            },
            {
                "name": "policy-decision",
                "owner": "ao-covenant",
                "gates": ["contract schema validation"],
            },
        ],
        "out_of_bounds": [
            "does not publish or store control-plane evidence",
            "does not replace release orchestration",
        ],
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, ledger: dict, policy_spine: dict) -> tuple[subprocess.CompletedProcess, dict]:
    ledger_path = tmp_path / "active-stack-readiness.ledger.json"
    policy_path = tmp_path / "policy-spine.json"
    out_json = tmp_path / "readback-summary.json"
    ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    policy_path.write_text(json.dumps(policy_spine, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--foundry-ledger",
            str(ledger_path),
            "--covenant-policy-spine",
            str(policy_path),
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


def test_active_stack_release_handoff_readback_accepts_foundry_and_covenant_evidence(tmp_path):
    result, summary = run_script(tmp_path, foundry_ledger(), covenant_policy_spine())

    assert result.returncode == 0, result.stderr
    assert "control_plane_active_stack_release_handoff_readback=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-active-stack-release-handoff-readback.v1"
    assert summary["status"] == "passed"
    assert summary["foundry_schema_version"] == "ao.foundry.active-stack-readiness.v0.1"
    assert summary["covenant_schema_version"] == "covenant.policy-spine-result.v1"
    assert summary["active_repositories"] == ACTIVE_REPOS
    assert summary["required_release_handoff_gates"] == [
        "foundry-release-candidate",
        "forge-release-candidate-handoff",
        "covenant-policy-spine",
        "signed-smoke-release-gate",
    ]
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "mutates_observer_storage": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_active_stack_release_handoff_readback_blocks_missing_required_handoff_gate(tmp_path):
    ledger = foundry_ledger()
    ledger["release_handoff"]["gates"] = [
        gate for gate in ledger["release_handoff"]["gates"] if gate["name"] != "covenant-policy-spine"
    ]

    result, summary = run_script(tmp_path, ledger, covenant_policy_spine())

    assert result.returncode != 0
    assert "control_plane_active_stack_release_handoff_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "missing_required_release_handoff_gates",
            "severity": "release_blocker",
            "details": ["covenant-policy-spine"],
        }
    ]


def test_active_stack_release_handoff_readback_blocks_policy_spine_scope_drift(tmp_path):
    policy = covenant_policy_spine()
    policy["scope"]["active_repositories"].remove("ao2-control-plane")

    result, summary = run_script(tmp_path, foundry_ledger(), policy)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "active_repository_scope_mismatch",
            "severity": "release_blocker",
            "details": ["ao2-control-plane missing from covenant policy spine active repositories"],
        }
    ]


def test_active_stack_release_handoff_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-active-stack-release-handoff-readback.v1",
        "ao.foundry.active-stack-readiness.v0.1",
        "covenant.policy-spine-result.v1",
        "foundry-release-candidate",
        "covenant-policy-spine",
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
        "scripts/verify_active_stack_release_handoff.py",
        "ao2.cp-active-stack-release-handoff-readback.v1",
        "control_plane_active_stack_release_handoff_readback=passed",
        "tests/test_active_stack_release_handoff_readback.py",
        "Checkout AO Foundry",
        "Checkout AO Covenant",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook


def test_current_public_docs_do_not_use_deprecated_ao_product_names():
    checked_docs = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs/runbooks/release-smoke.md",
        REPO_ROOT / "docs/DEPLOYMENT.md",
        REPO_ROOT / "docs/SECURITY.md",
    ]
    forbidden = ["AO Operator", "AO Control Plane", "ao-operator", "ao-control-plane", "ao-runtime"]
    for path in checked_docs:
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{path.relative_to(REPO_ROOT)} still contains {needle!r}"
