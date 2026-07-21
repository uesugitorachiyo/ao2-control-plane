import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "public_release_pair_verify.py"


def write_release_view(path, repo, tag, name, assets):
    path.write_text(
        json.dumps(
            {
                "tagName": tag,
                "name": name,
                "isDraft": False,
                "isPrerelease": False,
                "publishedAt": "2026-06-12T12:34:56Z",
                "url": f"https://github.com/{repo}/releases/tag/{tag}",
                "assets": [
                    {
                        "name": asset,
                        "size": idx + 100,
                        "digest": f"sha256:{idx:064x}",
                        "state": "uploaded",
                    }
                    for idx, asset in enumerate(assets, start=1)
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def write_checksums(path, assets):
    path.write_text(
        "".join(f"{idx:064x}  {asset}\n" for idx, asset in enumerate(assets, start=1)),
        encoding="utf-8",
    )


def ao2_assets():
    version = "0.5.2"
    archives = [
        f"ao2-{version}-linux-aarch64.tar.gz",
        f"ao2-{version}-linux-x86_64.tar.gz",
        f"ao2-{version}-macos-aarch64.tar.gz",
        f"ao2-{version}-windows-x86_64.tar.gz",
    ]
    sidecars = [sidecar for archive in archives for sidecar in (f"{archive}.sha256", f"{archive}.sig")]
    return archives + sidecars + [
        "SHA256SUMS",
        "ao2-release-artifact-closure-index.json",
        "ao2-release-provenance.json",
        "ao2-release-provenance.json.sig",
        "ao2-release-readiness-summary.json",
        "ao2-release-signing-public.pem",
        "ao2-release-train-control-plane-bridge-summary.json",
    ]


def control_plane_assets():
    version = "0.1.17"
    return [
        "SHA256SUMS",
        f"ao2-control-plane-{version}-linux-x86_64.tar.gz",
        f"ao2-control-plane-{version}-macos-aarch64.tar.gz",
        f"ao2-control-plane-{version}-windows-x86_64.tar.gz",
        "summary.json",
    ]


def test_public_release_pair_verify_defaults_follow_release_train_manifest():
    manifest_path = REPO_ROOT / "docs" / "release" / "release-train.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "ao2.release-train-manifest.v1"
    assert manifest["stable"]["ao2"] == {"tag": "v0.5.2", "version": "0.5.2"}
    assert manifest["stable"]["ao2_control_plane"] == {
        "tag": "v0.1.17",
        "version": "0.1.17",
    }
    assert manifest["next_patch"]["ao2"] == {"tag": "v0.5.3", "version": "0.5.3"}
    assert manifest["next_patch"]["ao2_control_plane"] == {
        "tag": "v0.1.18",
        "version": "0.1.18",
    }

    spec = importlib.util.spec_from_file_location("public_release_pair_verify", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.RELEASE_TRAIN_MANIFEST == manifest_path
    assert module.DEFAULT_AO2_TAG == manifest["stable"]["ao2"]["tag"]
    assert module.DEFAULT_CONTROL_PLANE_TAG == manifest["stable"]["ao2_control_plane"]["tag"]

    script = SCRIPT.read_text(encoding="utf-8")
    assert "load_release_train_manifest" in script
    assert "docs/release/release-train.json" in script


def run_pair_verify(tmp_path, *, ao2_release_assets=None, cp_checksum_assets=None, strict=False):
    ao2_release_assets = ao2_release_assets or ao2_assets()
    cp_release_assets = control_plane_assets()
    cp_checksum_assets = cp_checksum_assets or cp_release_assets

    ao2_view = tmp_path / "ao2-release-view.json"
    ao2_checksums = tmp_path / "ao2-SHA256SUMS"
    cp_view = tmp_path / "control-plane-release-view.json"
    cp_checksums = tmp_path / "control-plane-SHA256SUMS"
    summary = tmp_path / "summary.json"

    write_release_view(ao2_view, "uesugitorachiyo/ao2", "v0.5.2", "AO2 v0.5.2 stable", ao2_release_assets)
    write_checksums(ao2_checksums, ao2_release_assets)
    write_release_view(
        cp_view,
        "uesugitorachiyo/ao2-control-plane",
        "v0.1.17",
        "ao2-control-plane v0.1.17",
        cp_release_assets,
    )
    write_checksums(cp_checksums, cp_checksum_assets)

    args = [
        "python3",
        str(SCRIPT),
        "--ao2-release-view-json",
        str(ao2_view),
        "--ao2-checksums",
        str(ao2_checksums),
        "--control-plane-release-view-json",
        str(cp_view),
        "--control-plane-checksums",
        str(cp_checksums),
        "--summary-json",
        str(summary),
    ]
    if strict:
        args.append("--strict")

    result = subprocess.run(
        args,
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    parsed_summary = json.loads(summary.read_text(encoding="utf-8")) if summary.exists() else {}
    return result, parsed_summary


def test_public_release_pair_verify_passes_complete_ao2_and_control_plane_releases(tmp_path):
    result, summary = run_pair_verify(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "control_plane_public_release_pair_verification=passed" in result.stdout
    assert summary["schema_version"] == "ao2.cp-public-release-pair-verification.v1"
    assert summary["status"] == "passed"
    assert summary["ao2"]["release_tag"] == "v0.5.2"
    assert summary["control_plane"]["release_tag"] == "v0.1.17"
    assert summary["common_platforms"] == ["linux-x86_64", "macos-aarch64", "windows-x86_64"]
    assert summary["ao2"]["extra_platforms"] == ["linux-aarch64"]
    assert summary["gaps"] == []
    assert summary["trust_boundary"] == {
        "control_plane_approves_release": False,
        "downloads_archives": False,
        "mutates_ao_artifacts": False,
        "mutates_github_releases": False,
        "credential_material_included": False,
    }


def test_public_release_pair_verify_reports_missing_ao2_provenance_gap(tmp_path):
    assets = [asset for asset in ao2_assets() if asset != "ao2-release-provenance.json.sig"]

    result, summary = run_pair_verify(tmp_path, ao2_release_assets=assets, strict=True)

    assert result.returncode != 0
    assert "control_plane_public_release_pair_verification=attention" in result.stdout
    assert summary["status"] == "attention"
    assert summary["gaps"] == [
        {
            "gap_kind": "ao2_missing_required_assets",
            "severity": "release_blocker",
            "assets": ["ao2-release-provenance.json.sig"],
        }
    ]


def test_public_release_pair_verify_requires_control_plane_summary_checksum_entry(tmp_path):
    cp_checksum_assets = [asset for asset in control_plane_assets() if asset != "summary.json"]

    result, summary = run_pair_verify(tmp_path, cp_checksum_assets=cp_checksum_assets, strict=True)

    assert result.returncode != 0
    assert "control_plane_public_release_pair_verification=attention" in result.stdout
    assert summary["status"] == "attention"
    assert "summary.json" in summary["control_plane"]["published_assets"]
    assert "summary.json" not in summary["control_plane"]["checksum_entries"]
    assert summary["gaps"] == [
        {
            "gap_kind": "control_plane_missing_checksum_entries",
            "severity": "release_blocker",
            "assets": ["summary.json"],
        }
    ]


def test_public_release_pair_verify_is_documented_executable_and_in_ci():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    post_release = (REPO_ROOT / ".github/workflows/post-release-verification.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    assert SCRIPT.is_file()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR

    script = SCRIPT.read_text(encoding="utf-8")
    for needle in [
        "ao2.cp-public-release-pair-verification.v1",
        "ao2-release-provenance.json.sig",
        "ao2-control-plane-0.1.17-windows-x86_64.tar.gz",
        "control_plane_approves_release",
        "mutates_github_releases",
        "credential_material_included",
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
        "scripts/public_release_pair_verify.py",
        "ao2.cp-public-release-pair-verification.v1",
        "control_plane_public_release_pair_verification=passed",
        "tests/test_public_release_pair_verify.py",
    ]:
        assert needle in ci
        assert needle in readme
        assert needle in runbook

    for needle in [
        "public-release-pair-verification",
        "scripts/public_release_pair_verify.py",
        "--strict",
        "ao2-control-plane-post-release-pair-verification",
        "control_plane_public_release_pair_verification=passed",
        "ao2.cp-public-release-pair-verification.v1",
    ]:
        assert needle in post_release
