import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "generate_release_notes_from_checksums.py"


def write_checksums(path, rows):
    path.write_text(
        "".join(f"{sha}  {name}\n" for name, sha in rows),
        encoding="utf-8",
    )


def run_generator(tmp_path, rows, *extra_args):
    checksums = tmp_path / "SHA256SUMS"
    output = tmp_path / "release-notes.md"
    write_checksums(checksums, rows)
    result = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--version",
            "0.1.13",
            "--tag",
            "v0.1.13",
            "--checksums",
            str(checksums),
            "--output",
            str(output),
            "--released",
            "2026-06-12",
            "--release-workflow",
            "Release Promotion",
            *extra_args,
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result, output


def complete_rows():
    return [
        (
            "ao2-control-plane-0.1.13-windows-x86_64.tar.gz",
            "0" * 63 + "3",
        ),
        (
            "ao2-control-plane-0.1.13-linux-x86_64.tar.gz",
            "0" * 63 + "1",
        ),
        (
            "ao2-control-plane-0.1.13-macos-aarch64.tar.gz",
            "0" * 63 + "2",
        ),
    ]


def test_release_notes_generator_writes_deterministic_three_os_table(tmp_path):
    result, output = run_generator(
        tmp_path,
        complete_rows(),
        "--source-commit",
        "abc123def456",
    )

    assert result.returncode == 0, result.stderr
    assert "control_plane_release_notes_generated=" in result.stdout
    notes = output.read_text(encoding="utf-8")
    assert notes == "\n".join(
        [
            "# ao2-control-plane v0.1.13 release notes",
            "",
            "**Released:** 2026-06-12",
            "**Release workflow:** `Release Promotion`",
            "**Source commit:** `abc123def456`",
            "",
            "## Archives",
            "",
            "| OS | File | SHA-256 |",
            "|---|---|---|",
            "| Linux x86_64 | `ao2-control-plane-0.1.13-linux-x86_64.tar.gz` | `0000000000000000000000000000000000000000000000000000000000000001` |",
            "| macOS aarch64 | `ao2-control-plane-0.1.13-macos-aarch64.tar.gz` | `0000000000000000000000000000000000000000000000000000000000000002` |",
            "| Windows x86_64 | `ao2-control-plane-0.1.13-windows-x86_64.tar.gz` | `0000000000000000000000000000000000000000000000000000000000000003` |",
            "",
            "## Production-readiness changes",
            "",
            "- Release notes were generated from `SHA256SUMS` to avoid manual hash drift.",
            "- Keeps AO2 release acceptance outside the control plane; the control plane remains an observer and release asset publisher for its own binaries.",
            "",
        ]
    )


def test_release_notes_generator_fails_when_platform_archive_checksum_is_missing(tmp_path):
    rows = [
        row
        for row in complete_rows()
        if not row[0].endswith("windows-x86_64.tar.gz")
    ]
    result, output = run_generator(tmp_path, rows)

    assert result.returncode != 0
    assert not output.exists()
    assert "missing checksum entries" in result.stderr
    assert "ao2-control-plane-0.1.13-windows-x86_64.tar.gz" in result.stderr


def test_release_notes_generator_is_wired_into_release_promotion_and_docs():
    workflow = (REPO_ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs/runbooks/release-smoke.md").read_text(encoding="utf-8")

    for needle in [
        "scripts/generate_release_notes_from_checksums.py",
        "--checksums",
        "target/release-promotion/${{ inputs.tag }}/SHA256SUMS",
        "target/release-promotion/${{ inputs.tag }}/release-notes.md",
    ]:
        assert needle in workflow

    for needle in [
        "generate_release_notes_from_checksums.py",
        "generated from `SHA256SUMS`",
    ]:
        assert needle in readme
        assert needle in runbook
