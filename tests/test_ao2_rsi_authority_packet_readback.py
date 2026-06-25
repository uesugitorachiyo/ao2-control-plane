import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_ao2_rsi_authority_packet.py"


def authority_packet(**overrides):
    payload = {
        "schema_version": "covenant.live-self-change-authority.v1",
        "authority_id": "ao2-rsi-self-change-dry-run-authority",
        "approval_identity": "ao-operator",
        "approval_ticket_id": "ticket-ao2-rsi-dry-run-authority",
        "repository": "ao2",
        "branch": "codex/live-self-change-rehearsal",
        "change_class": "verification_path",
        "allowed_write_surface": ["scripts/rsi-claim-readiness-audit.sh"],
        "exact_digest": {
            "algorithm": "sha256",
            "covers": ["proposed-self-change.patch", "rollback-self-change.patch", "summary.json"],
            "value": "a" * 64,
        },
        "rollback_evidence": {
            "status": "passed",
            "evidence_paths": ["summary.json"],
        },
        "live_self_change_evidence": {
            "status": "dry_run_not_live",
            "evidence_paths": [],
        },
        "observer_readback": {
            "observer": "ao2-control-plane",
            "status": "missing",
            "evidence_paths": [],
        },
        "claim_level": "full_autonomous_self_mutating_rsi",
        "claim_publish_resource": "full-autonomous-self-mutating-rsi",
        "expires_at_utc": "2026-07-02T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def self_change_dry_run_summary(packet_sha256: str, **overrides):
    payload = {
        "schema_version": "ao2.rsi-governed-self-change-dry-run.v1",
        "status": "dry_run_evidence_ready",
        "claim_boundary": {
            "bounded_governed_rsi": "allowed",
            "full_autonomous_self_mutating_rsi": "denied",
        },
        "mutation_authority_packet": {
            "mode": "dry_run_candidate",
            "schema_version": "covenant.live-self-change-authority.v1",
            "schema_valid_for_claim_publish": False,
            "path": "live-self-change-authority.packet.json",
            "sha256": packet_sha256,
            "reason": "live self-change execution and observer readback are not present in dry-run evidence",
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
            "emits_authority_packet_candidate": True,
        },
    }
    payload.update(overrides)
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_packet_fixture(tmp_path: Path, packet: dict) -> tuple[Path, str]:
    packet_path = tmp_path / "live-self-change-authority.packet.json"
    write_json(packet_path, packet)
    digest = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    return packet_path, digest


def run_script(tmp_path: Path, producer_summary: dict) -> tuple[subprocess.CompletedProcess, dict]:
    producer_path = tmp_path / "summary.json"
    out_json = tmp_path / "readback-summary.json"
    write_json(producer_path, producer_summary)

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


def test_ao2_rsi_authority_packet_readback_accepts_dry_run_candidate_without_upgrading_claim(tmp_path):
    packet_path, packet_sha256 = write_packet_fixture(tmp_path, authority_packet())
    result, summary = run_script(tmp_path, self_change_dry_run_summary(packet_sha256))

    assert result.returncode == 0, result.stderr
    assert "control_plane_ao2_rsi_authority_packet_readback=passed" in result.stdout
    assert "claim_level=full_autonomous_self_mutating_rsi decision=denied" in result.stdout
    assert summary["schema_version"] == "ao2.cp-ao2-rsi-authority-packet-readback.v1"
    assert summary["status"] == "passed"
    assert summary["producer_schema_version"] == "ao2.rsi-governed-self-change-dry-run.v1"
    assert summary["producer_status"] == "dry_run_evidence_ready"
    assert summary["authority_packet_path"] == str(packet_path)
    assert summary["authority_packet_sha256"] == packet_sha256
    assert summary["authority_packet"] == {
        "mode": "dry_run_candidate",
        "schema_version": "covenant.live-self-change-authority.v1",
        "schema_valid_for_claim_publish": False,
        "claim_level": "full_autonomous_self_mutating_rsi",
        "repository": "ao2",
        "live_self_change_status": "dry_run_not_live",
        "observer_readback_status": "missing",
    }
    assert summary["claim_boundary"] == {
        "bounded_governed_rsi": "allowed",
        "full_autonomous_self_mutating_rsi": "denied",
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


def test_ao2_rsi_authority_packet_readback_blocks_hash_or_publishability_drift(tmp_path):
    write_packet_fixture(
        tmp_path,
        authority_packet(
            live_self_change_evidence={"status": "passed", "evidence_paths": ["live.json"]},
            observer_readback={
                "observer": "ao2-control-plane",
                "status": "passed",
                "evidence_paths": ["readback.json"],
            },
        ),
    )
    result, summary = run_script(
        tmp_path,
        self_change_dry_run_summary(
            "f" * 64,
            mutation_authority_packet={
                "mode": "dry_run_candidate",
                "schema_version": "covenant.live-self-change-authority.v1",
                "schema_valid_for_claim_publish": True,
                "path": "live-self-change-authority.packet.json",
                "sha256": "f" * 64,
                "reason": "tampered",
            },
        ),
    )

    assert result.returncode != 0
    assert "control_plane_ao2_rsi_authority_packet_readback=blocked" in result.stdout
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "authority_packet_marked_claim_publish_valid",
            "severity": "rsi_claim_blocker",
            "details": ["mutation_authority_packet.schema_valid_for_claim_publish must be false"],
        },
        {
            "gap_kind": "authority_packet_sha256_mismatch",
            "severity": "rsi_claim_blocker",
            "details": ["mutation_authority_packet.sha256 must match live-self-change-authority.packet.json"],
        },
        {
            "gap_kind": "authority_packet_claim_boundary_drift",
            "severity": "rsi_claim_blocker",
            "details": [
                "live_self_change_evidence.status must be dry_run_not_live",
                "live_self_change_evidence.evidence_paths must be empty",
                "observer_readback.status must be missing",
                "observer_readback.evidence_paths must be empty",
            ],
        },
    ]


def test_ao2_rsi_authority_packet_readback_blocks_unsafe_packet_path(tmp_path):
    result, summary = run_script(
        tmp_path,
        self_change_dry_run_summary(
            "a" * 64,
            mutation_authority_packet={
                "mode": "dry_run_candidate",
                "schema_version": "covenant.live-self-change-authority.v1",
                "schema_valid_for_claim_publish": False,
                "path": "../live-self-change-authority.packet.json",
                "sha256": "a" * 64,
                "reason": "unsafe path",
            },
        ),
    )

    assert result.returncode != 0
    assert summary["status"] == "blocked"
    assert summary["gaps"] == [
        {
            "gap_kind": "authority_packet_contract_drift",
            "severity": "rsi_claim_blocker",
            "details": ["mutation_authority_packet.path must be a relative artifact path"],
        }
    ]


def test_ao2_rsi_authority_packet_readback_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-ao2-rsi-authority-packet-readback.v1",
        "ao2.rsi-governed-self-change-dry-run.v1",
        "covenant.live-self-change-authority.v1",
        "dry_run_candidate",
        "schema_valid_for_claim_publish",
        "dry_run_not_live",
        "observer_readback",
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
        "scripts/verify_ao2_rsi_authority_packet.py",
        "ao2.cp-ao2-rsi-authority-packet-readback.v1",
        "control_plane_ao2_rsi_authority_packet_readback=passed",
        "tests/test_ao2_rsi_authority_packet_readback.py",
        "Checkout AO2",
        "npm run rsi:self-change-dry-run",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook
