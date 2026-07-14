from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-promotion.yml"


def workflow_text():
    assert WORKFLOW.is_file(), "missing release-promotion workflow"
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_promotion_workflow_requires_explicit_version_and_tag_and_defaults_to_dry_run():
    workflow = workflow_text()

    for needle in [
        "name: Release Promotion",
        "workflow_dispatch:",
        "version:",
        "description: ao2-control-plane package version to promote.",
        "tag:",
        "description: GitHub release tag to prepare or publish.",
        "required: true",
        "dry_run:",
        "default: true",
        "permissions:",
        "contents: write",
        "actions/download-artifact@v8.0.1",
        "cancel-in-progress: false",
        "ao2-control-plane-release-promotion-${{ inputs.tag }}",
    ]:
        assert needle in workflow

    version_input = workflow.split("      version:\n", 1)[1].split("      tag:\n", 1)[0]
    tag_input = workflow.split("      tag:\n", 1)[1].split("      dry_run:\n", 1)[0]
    assert "default:" not in version_input
    assert "default:" not in tag_input
    assert "actions/download-artifact@v7.0.1" not in workflow


def test_release_promotion_refuses_version_that_does_not_match_workspace_package():
    workflow = workflow_text()

    for needle in [
        "Verify requested version matches workspace metadata",
        "workspace_version",
        "release promotion version mismatch",
        "Cargo.toml",
        "input_version = \"${{ inputs.version }}\"",
    ]:
        assert needle in workflow


def test_release_promotion_builds_and_smokes_three_target_archives():
    workflow = workflow_text()

    for target_label, runner, binary in [
        ("linux-x86_64", "ubuntu-latest", "target/release/ao2-cp-server"),
        ("macos-aarch64", "macos-latest", "target/release/ao2-cp-server"),
        ("windows-x86_64", "windows-latest", "target/release/ao2-cp-server.exe"),
    ]:
        assert f"os: {runner}" in workflow
        assert f"target_label: {target_label}" in workflow
        assert f"binary: {binary}" in workflow
        assert f"ao2-control-plane-${{{{ inputs.version }}}}-{target_label}.tar.gz" in workflow

    for needle in [
        "cargo build --release -p ao2-cp-server",
        "--version \"${{ inputs.version }}\"",
        "--target-label \"${{ matrix.target_label }}\"",
        "scripts/smoke-release-archive.sh",
        "./scripts/smoke-release-archive.ps1",
        "ao2-control-plane-release-candidate-${{ inputs.tag }}-${{ matrix.target_label }}",
        "dist/SHA256SUMS",
        "target/release-smoke/${{ matrix.target_label }}.json",
        "if-no-files-found: error",
    ]:
        assert needle in workflow


def test_release_promotion_assembles_token_free_plan_and_trust_boundary():
    workflow = workflow_text()

    for needle in [
        "needs: post-release-verification-baseline",
        "assemble-release-promotion-plan:",
        "ao2.cp-release-promotion-plan.v1",
        "target/release-promotion/${{ inputs.tag }}/summary.json",
        "target/release-promotion/${{ inputs.tag }}/SHA256SUMS",
        '"status": "prepared"',
        '"source_commit": os.environ["GITHUB_SHA"]',
        '"source_ref": os.environ["GITHUB_REF_NAME"]',
        '"control_plane_approves_release": False',
        '"mutates_ao_artifacts": False',
        '"credential_material_included": False',
        '"release_acceptance_owner": "factory-v3 evaluator-closer"',
        '"github_release_mutation_requested": dry_run is False',
        'summary_sha256 = hashlib.sha256(summary_bytes).hexdigest()',
        'checksum_lines.append(f"{summary_sha256}  summary.json\\n")',
        '"evidence_assets": evidence_assets',
        "ao2-control-plane-release-promotion-plan-${{ inputs.tag }}",
    ]:
        assert needle in workflow

    for forbidden in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "provider_api_key",
        "mutates_ao_artifacts\": True",
        "control_plane_approves_release\": True",
    ]:
        assert forbidden not in workflow


def test_release_promotion_requires_successful_post_release_baseline_artifacts():
    workflow = workflow_text()

    for needle in [
        "actions: read",
        "post-release-verification-baseline:",
        "Require successful post-release verification baseline",
        "scripts/verify_post_release_baseline.py",
        "--repo uesugitorachiyo/ao2-control-plane",
        "--branch main",
        "--workflow \"Post Release Verification\"",
        "--head-sha \"${{ github.sha }}\"",
        "--out-json target/release-promotion/${{ inputs.tag }}/post-release-baseline.json",
        "ao2.cp-post-release-verification-baseline.v1",
        "ao2-control-plane-post-release-verification-ubuntu",
        "ao2-control-plane-post-release-verification-macos",
        "ao2-control-plane-post-release-verification-windows",
        "ao2-control-plane-post-release-pair-verification",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
        "ao2-control-plane-post-release-active-stack-release-handoff-readback",
        '"post_release_verification_baseline": post_release_baseline',
        '"required_post_release_artifacts": required_post_release_artifacts',
        "control_plane_approves_release",
        "mutates_ao_artifacts",
        "credential_material_included",
    ]:
        assert needle in workflow


def test_release_promotion_publish_step_is_explicitly_guarded():
    workflow = workflow_text()

    for needle in [
        "if: ${{ inputs.dry_run == 'false' }}",
        "GH_TOKEN: ${{ github.token }}",
        "gh release view \"${{ inputs.tag }}\"",
        "gh release edit \"${{ inputs.tag }}\"",
        "gh release create \"${{ inputs.tag }}\"",
        "--target \"$GITHUB_SHA\"",
        "--latest",
        "gh release upload \"${{ inputs.tag }}\"",
        "target/release-promotion/${{ inputs.tag }}/release-notes.md",
        '"$root/post-release-baseline.json"',
    ]:
        assert needle in workflow


def test_release_promotion_is_documented_and_guarded_in_ci():
    workflow = workflow_text()
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for needle in [
        "tests/test_release_promotion_workflow.py",
        "PYTHONDONTWRITEBYTECODE=1 python3 -m pytest",
    ]:
        assert needle in ci

    for needle in [
        "Release Promotion",
        ".github/workflows/release-promotion.yml",
        "ao2-control-plane-release-promotion-plan",
        "ao2.cp-release-promotion-plan.v1",
        "dry_run",
        "explicit version and tag inputs",
        "Linux x86_64, macOS aarch64, and Windows x86_64",
        "Post Release Verification",
        "ao2.cp-post-release-verification-baseline.v1",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
        "ao2-control-plane-post-release-active-stack-release-handoff-readback",
    ]:
        assert needle in readme
        assert needle in workflow or needle in ci or needle in readme
