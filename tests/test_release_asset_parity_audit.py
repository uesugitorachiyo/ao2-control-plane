import json
import os
import re
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "release-asset-parity-audit.sh"


def write_release_view(path, asset_names):
    path.write_text(
        json.dumps(
            {
                "tagName": "v0.1.12",
                "name": "ao2-control-plane v0.1.12 stable",
                "isDraft": False,
                "isPrerelease": False,
                "publishedAt": "2026-06-10T18:45:22Z",
                "assets": [
                    {
                        "name": name,
                        "size": 17,
                        "digest": f"sha256:{idx:064x}",
                        "state": "uploaded",
                    }
                    for idx, name in enumerate(asset_names, start=1)
                ],
                "url": "https://github.com/uesugitorachiyo/ao2-control-plane/releases/tag/v0.1.12",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def write_checksums(path, asset_names):
    path.write_text(
        "".join(f"{idx:064x}  {name}\n" for idx, name in enumerate(asset_names, start=1)),
        encoding="utf-8",
    )


def run_audit(tmp_path, release_assets, checksum_assets, strict=False):
    release_view = tmp_path / "release-view.json"
    checksums = tmp_path / "SHA256SUMS"
    summary = tmp_path / "summary.json"
    write_release_view(release_view, release_assets)
    write_checksums(checksums, checksum_assets)

    env = os.environ.copy()
    env["AO2_CP_RELEASE_ASSET_PARITY_RELEASE_VIEW_JSON"] = str(release_view)
    env["AO2_CP_RELEASE_ASSET_PARITY_CHECKSUMS"] = str(checksums)
    env["AO2_CP_RELEASE_ASSET_PARITY_SUMMARY_JSON"] = str(summary)
    if strict:
        env["AO2_CP_RELEASE_ASSET_PARITY_STRICT"] = "1"

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result, json.loads(summary.read_text(encoding="utf-8"))


def expected_release_assets():
    return [
        "SHA256SUMS",
        "ao2-control-plane-0.1.12-linux-x86_64.tar.gz",
        "ao2-control-plane-0.1.12-macos-aarch64.tar.gz",
        "ao2-control-plane-0.1.12-windows-x86_64.tar.gz",
        "ao2-control-plane-release-support-fixture-parity-summary.json",
        "ao2-control-plane-release-train-bridge-macos-summary.json",
        "ao2-control-plane-release-train-bridge-ubuntu-summary.json",
        "ao2-control-plane-release-train-bridge-windows-summary.json",
    ]


def test_release_asset_parity_audit_script_is_read_only_documented_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    text = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "AO2_CP_RELEASE_ASSET_PARITY_STRICT",
        "ao2.cp-release-asset-parity-audit.v1",
        "linux-x86_64",
        "macos-aarch64",
        "windows-x86_64",
        "mutates_github_releases",
        "credential_material_included",
    ]:
        assert needle in text

    for forbidden in [
        "gh release upload",
        "gh release edit",
        "git push origin",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ]:
        assert forbidden not in text

    for needle in [
        "Release asset parity audit",
        "scripts/release-asset-parity-audit.sh",
        "ao2-control-plane-release-asset-parity-audit",
        "ao2.cp-release-asset-parity-audit.v1",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook


def test_release_asset_parity_audit_passes_complete_three_os_stable_release(tmp_path):
    assets = expected_release_assets()
    result, summary = run_audit(tmp_path, assets, assets)

    assert result.returncode == 0, result.stderr
    assert "control_plane_release_asset_parity=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-release-asset-parity-audit.v1"
    assert summary["status"] == "passed"
    assert summary["release_tag"] == "v0.1.12"
    assert summary["stable_release"] is True
    assert summary["expected_platform_archives"] == [
        "ao2-control-plane-0.1.12-linux-x86_64.tar.gz",
        "ao2-control-plane-0.1.12-macos-aarch64.tar.gz",
        "ao2-control-plane-0.1.12-windows-x86_64.tar.gz",
    ]
    assert summary["missing_platform_archives"] == []
    assert summary["missing_checksum_entries"] == []
    assert summary["release_notes_archive_drift"] == []
    assert summary["trust_boundary"] == {
        "control_plane_approves_release": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    }


def test_release_asset_parity_audit_reports_partial_public_release_without_secret_leaks(tmp_path):
    partial_assets = [
        "SHA256SUMS",
        "ao2-control-plane-0.1.12-macos-aarch64.tar.gz",
        "ao2-control-plane-release-support-fixture-parity-summary.json",
        "ao2-control-plane-release-train-bridge-macos-summary.json",
        "ao2-control-plane-release-train-bridge-ubuntu-summary.json",
        "ao2-control-plane-release-train-bridge-windows-summary.json",
    ]
    result, summary = run_audit(tmp_path, partial_assets, partial_assets)

    assert result.returncode == 0, result.stderr
    assert "control_plane_release_asset_parity=attention" in result.stdout
    assert summary["status"] == "attention"
    assert summary["strict"] is False
    assert summary["missing_platform_archives"] == [
        "ao2-control-plane-0.1.12-linux-x86_64.tar.gz",
        "ao2-control-plane-0.1.12-windows-x86_64.tar.gz",
    ]
    assert summary["missing_checksum_entries"] == [
        "ao2-control-plane-0.1.12-linux-x86_64.tar.gz",
        "ao2-control-plane-0.1.12-windows-x86_64.tar.gz",
    ]
    assert re.fullmatch(r"[0-9a-f]{64}", summary["release_view_sha256"])
    assert "Bearer " not in result.stdout
    assert "Bearer " not in result.stderr


def test_release_asset_parity_audit_strict_mode_fails_on_missing_platform_assets(tmp_path):
    partial_assets = [
        "SHA256SUMS",
        "ao2-control-plane-0.1.12-macos-aarch64.tar.gz",
        "ao2-control-plane-release-support-fixture-parity-summary.json",
        "ao2-control-plane-release-train-bridge-macos-summary.json",
        "ao2-control-plane-release-train-bridge-ubuntu-summary.json",
        "ao2-control-plane-release-train-bridge-windows-summary.json",
    ]
    result, summary = run_audit(tmp_path, partial_assets, partial_assets, strict=True)

    assert result.returncode != 0
    assert "control_plane_release_asset_parity=attention" in result.stdout
    assert summary["status"] == "attention"
    assert summary["strict"] is True
