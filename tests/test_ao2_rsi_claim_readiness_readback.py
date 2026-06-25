import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_rsi_claim_readiness.py"


REQUIRED_BLOCKERS = [
    "mutation_authority",
    "rollback_evidence",
    "live_self_change_evidence",
    "observer_readback",
    "covenant_claim_publish_approval",
]


def rsi_claim_readiness_summary(**overrides):
    payload = {
        "schema_version": "ao2.rsi-claim-readiness-audit.v1",
        "status": "claim_boundary_enforced",
        "claim_boundary": {
            "bounded_governed_rsi": "allowed",
            "full_autonomous_self_mutating_rsi": "denied",
        },
        "claims": {
            "bounded_governed_rsi": {
                "decision": "allowed",
                "evidence_state": "present",
                "evidence": [
                    "scripts/pulse-auto-advance.sh",
                    "scripts/pulse-generate-next.sh",
                    "scripts/pulse-real-execute-containment.sh",
                    "scripts/pulse-resume.sh",
                    "tests/test_public_stabilization.py",
                    "docs/VERIFICATION.md",
                ],
                "missing_evidence": [],
            },
            "full_autonomous_self_mutating_rsi": {
                "decision": "denied",
                "evidence_state": "missing_required_evidence",
                "blockers": [
                    {"id": blocker, "evidence_state": "missing", "required_evidence": blocker}
                    for blocker in REQUIRED_BLOCKERS
                ],
            },
        },
        "trust_boundary": {
            "local_only": True,
            "uses_network": False,
            "stores_credentials": False,
            "requires_provider_api_key": False,
            "mutates_repositories": False,
            "publishes_claims": False,
        },
    }
    payload.update(overrides)
    return payload


def run_script(tmp_path: Path, claim_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    claim_path = tmp_path / "rsi-claim-readiness-summary.json"
    out_json = tmp_path / "readback-summary.json"
    claim_path.write_text(json.dumps(claim_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--claim-summary-json",
            str(claim_path),
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


def test_ao2_rsi_claim_readiness_readback_accepts_boundary_enforced_summary(tmp_path):
    result, summary = run_script(tmp_path, rsi_claim_readiness_summary())

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_rsi_claim_readiness_readback=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-rsi-claim-readiness-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.rsi-claim-readiness-audit.v1"
    assert summary["producer_status"] == "claim_boundary_enforced"
    assert summary["claim_boundary"] == {
        "bounded_governed_rsi": "allowed",
        "full_autonomous_self_mutating_rsi": "denied",
    }
    assert summary["required_full_claim_blockers"] == REQUIRED_BLOCKERS
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "downloads_github_actions_artifacts": False,
        "control_plane_approves_rsi_claims": False,
        "mutates_ao_artifacts": False,
        "mutates_github_repositories": False,
        "mutates_observer_storage": False,
        "credential_material_included": False,
        "provider_api_keys_allowed": False,
    }


def test_ao2_rsi_claim_readiness_readback_blocks_full_claim_or_missing_blocker(tmp_path):
    payload = rsi_claim_readiness_summary()
    payload["claim_boundary"]["full_autonomous_self_mutating_rsi"] = "allowed"
    payload["claims"]["full_autonomous_self_mutating_rsi"]["decision"] = "allowed"
    payload["claims"]["full_autonomous_self_mutating_rsi"]["blockers"] = [
        blocker
        for blocker in payload["claims"]["full_autonomous_self_mutating_rsi"]["blockers"]
        if blocker["id"] != "rollback_evidence"
    ]

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_claim_readiness_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "full_claim_boundary_not_denied",
            "severity": "rsi_claim_blocker",
            "details": ["claim_boundary.full_autonomous_self_mutating_rsi must be denied"],
        },
        {
            "gap_kind": "full_claim_decision_not_denied",
            "severity": "rsi_claim_blocker",
            "details": ["full_autonomous_self_mutating_rsi.decision must be denied"],
        },
        {
            "gap_kind": "missing_required_full_claim_blockers",
            "severity": "rsi_claim_blocker",
            "details": ["rollback_evidence"],
        },
    ]


def test_ao2_rsi_claim_readiness_readback_blocks_trust_boundary_drift(tmp_path):
    payload = rsi_claim_readiness_summary()
    payload["trust_boundary"]["mutates_repositories"] = True

    result, summary = run_script(tmp_path, payload)

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "producer_trust_boundary_drift",
            "severity": "rsi_claim_blocker",
            "details": ["mutates_repositories must be false"],
        }
    ]


def test_ao2_rsi_claim_readiness_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-rsi-claim-readiness-readback.v1",
        "ao2.rsi-claim-readiness-audit.v1",
        "bounded_governed_rsi",
        "full_autonomous_self_mutating_rsi",
        "mutation_authority",
        "rollback_evidence",
        "live_self_change_evidence",
        "control_plane_approves_rsi_claims",
        "mutates_github_repositories",
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
        "scripts/verify_ao2_rsi_claim_readiness.py",
        "ao2.cp-ao2-rsi-claim-readiness-readback.v1",
        "control_plane_ao2_rsi_claim_readiness_readback=passed",
        "tests/test_ao2_rsi_claim_readiness_readback.py",
        "Checkout AO2",
        "npm run rsi:claim-readiness",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
