#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def readme_from_shell_script() -> str:
    text = (ROOT / "scripts/package-local.sh").read_text(encoding="utf-8")
    marker = "cat > \"$STAGE/README.txt\" <<'TXT'\n"
    start = text.index(marker) + len(marker)
    end = text.index("\nTXT\n", start)
    return text[start:end] + "\n"


def copy(src: pathlib.Path, dst: pathlib.Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def manifest(
    version: str,
    target_label: str,
    binary_name: str,
    binary_sha: str,
    gc_binary_name: str,
    gc_binary_sha: str,
    py_verifier_sha: str,
    ps_verifier_sha: str,
    fetch_handoff_sha: str,
    ps_fetch_handoff_sha: str,
    sbom_sha: str,
) -> dict:
    return {
        "schema_version": "ao2-control-plane.release-manifest.v1",
        "name": "ao2-control-plane",
        "version": version,
        "target": target_label,
        "binary": binary_name,
        "binary_path": f"bin/{binary_name}",
        "binary_sha256": binary_sha,
        "legal_files": ["LICENSE", "NOTICE"],
        "server": "ao2-cp-server",
        "sbom": {
            "path": "ao2-control-plane.cdx.json",
            "format": "CycloneDX",
            "spec_version": "1.5",
            "sha256": sbom_sha,
            "source": "Cargo.lock",
        },
        "lifecycle": {
            "receipt_schema": "ao2-control-plane.install-receipt.v1",
            "scripts": {
                "install.sh": "install.sh",
                "install.ps1": "install.ps1",
                "rollback.sh": "rollback.sh",
                "rollback.ps1": "rollback.ps1",
                "uninstall.sh": "uninstall.sh",
                "uninstall.ps1": "uninstall.ps1",
            },
            "transaction_scope": ["ao2-cp-server", "ao2-cp-gc"],
            "uninstall_preserves_data_and_config_by_default": True,
        },
        "operator_tools": {
            "gc": {
                "binary": gc_binary_name,
                "binary_path": f"bin/{gc_binary_name}",
                "binary_sha256": gc_binary_sha,
                "purpose": "operator-facing count-based retention pruner",
                "trust_boundary": "deletes content-addressed observer evidence on per-kind LRU; never approves AO2 digests, closes AO2 runs, or executes provider plugins",
                "usage_dry_run": f"bin/{gc_binary_name} --data-dir <path> --keep-latest <N> --dry-run",
                "usage_apply": f"bin/{gc_binary_name} --data-dir <path> --keep-latest <N> --apply",
            }
        },
        "trust_boundary": "read-only observer; never starts providers or approves AO2 runs",
        "support_bundle_trust_boundary": "offline verification only; no bearer tokens, provider keys, AO2 artifact mutation, or release approval",
        "offline_support_bundle_verifiers": {
            "python": {
                "path": "verify_release_support_bundle.py",
                "sha256": py_verifier_sha,
                "command": "python3 verify_release_support_bundle.py release-support-bundle.json",
            },
            "powershell": {
                "path": "Verify-ReleaseSupportBundle.ps1",
                "sha256": ps_verifier_sha,
                "command": "pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-support-bundle.json",
            },
        },
        "release_support_handoff_fetcher": {
            "path": "fetch_release_support_handoff.py",
            "sha256": fetch_handoff_sha,
            "command": "AO2_CP_AUTH_VALUE='<authorization-header>' python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir release-handoff",
            "powershell_path": "Fetch-ReleaseSupportHandoff.ps1",
            "powershell_sha256": ps_fetch_handoff_sha,
            "powershell_command": "$env:AO2_CP_AUTH_VALUE='<authorization-header>'; pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir release-handoff",
            "auth_value_stored": False,
            "outputs": [
                "release-support-verifier-handoff.json",
                "release-support-bundle.json",
                "SHA256SUMS",
                "release-support-bundle-verify.json",
                "release-support-bundle-manifest.json",
                "fetch-summary.json",
            ],
            "phase1_portable_handoff": {
                "flag": "--include-phase1-portable",
                "command": "AO2_CP_AUTH_VALUE='<authorization-header>' python3 fetch_release_support_handoff.py --base-url http://127.0.0.1:8744 --out-dir phase1-handoff --include-phase1-portable",
                "powershell_flag": "-IncludePhase1Portable",
                "powershell_command": "$env:AO2_CP_AUTH_VALUE='<authorization-header>'; pwsh -File Fetch-ReleaseSupportHandoff.ps1 -BaseUrl http://127.0.0.1:8744 -OutDir phase1-handoff -IncludePhase1Portable",
                "verification_upload": "phase1-portable-manifest-verify-upload.json",
                "verification_result": "phase1-portable-manifest-verification.json",
                "outputs": [
                    "phase1-portable-manifest.json",
                    "ao2-phase1-operator-support-bundle.json",
                    "ao2-phase1-gap-report.json",
                    "phase1-SHA256SUMS",
                    "phase1-portable-manifest-verify-upload.json",
                    "phase1-portable-manifest-verification.json",
                    "fetch-summary.json",
                ],
                "auth_value_stored": False,
                "trust_boundary": "read-only observer; no bearer tokens, provider keys, AO2 artifact mutation, or release approval",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default=str(ROOT / "dist"))
    parser.add_argument("--version", default="0.1.17")
    parser.add_argument("--binary", default=str(ROOT / "target/release/ao2-cp-server"))
    parser.add_argument("--target-label", default="")
    args = parser.parse_args()

    binary = pathlib.Path(args.binary)
    if not binary.is_file():
        raise SystemExit(f"missing ao2-control-plane binary: {binary}")
    compiled_version = subprocess.run(
        [str(binary), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()
    expected_version = f"ao2-cp-server {args.version}"
    if compiled_version != expected_version:
        raise SystemExit(
            f"compiled binary version '{compiled_version}' does not match requested package version '{expected_version}'"
        )

    target_label = args.target_label or f"{os.name}-unknown"
    windows = "windows" in target_label
    binary_name = "ao2-cp-server.exe" if windows else "ao2-cp-server"
    gc_source_name = "ao2-cp-gc.exe" if binary.name.endswith(".exe") else "ao2-cp-gc"
    gc_binary = binary.with_name(gc_source_name)
    if not gc_binary.is_file():
        raise SystemExit(f"missing ao2-cp-gc binary alongside server binary: {gc_binary}")
    gc_binary_name = "ao2-cp-gc.exe" if windows else "ao2-cp-gc"

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = pathlib.Path(tmp)
        copy(binary, stage / "bin" / binary_name)
        copy(gc_binary, stage / "bin" / gc_binary_name)
        for source, dest in [
            ("scripts/verify_release_support_bundle.py", "verify_release_support_bundle.py"),
            ("scripts/Verify-ReleaseSupportBundle.ps1", "Verify-ReleaseSupportBundle.ps1"),
            ("scripts/fetch_release_support_handoff.py", "fetch_release_support_handoff.py"),
            ("scripts/Fetch-ReleaseSupportHandoff.ps1", "Fetch-ReleaseSupportHandoff.ps1"),
            ("scripts/release/install.sh", "install.sh"),
            ("scripts/release/install.ps1", "install.ps1"),
            ("scripts/release/rollback.sh", "rollback.sh"),
            ("scripts/release/rollback.ps1", "rollback.ps1"),
            ("scripts/release/uninstall.sh", "uninstall.sh"),
            ("scripts/release/uninstall.ps1", "uninstall.ps1"),
            ("LICENSE", "LICENSE"),
            ("NOTICE", "NOTICE"),
        ]:
            copy(ROOT / source, stage / dest)

        subprocess.run(
            [
                "python3" if shutil.which("python3") else "python",
                str(ROOT / "scripts/generate_cargo_lock_sbom.py"),
                "--lockfile",
                str(ROOT / "Cargo.lock"),
                "--output",
                str(stage / "ao2-control-plane.cdx.json"),
            ],
            check=True,
        )

        checksums = {
            "binary": sha256_file(stage / "bin" / binary_name),
            "gc": sha256_file(stage / "bin" / gc_binary_name),
            "py_verifier": sha256_file(stage / "verify_release_support_bundle.py"),
            "ps_verifier": sha256_file(stage / "Verify-ReleaseSupportBundle.ps1"),
            "fetch": sha256_file(stage / "fetch_release_support_handoff.py"),
            "ps_fetch": sha256_file(stage / "Fetch-ReleaseSupportHandoff.ps1"),
            "sbom": sha256_file(stage / "ao2-control-plane.cdx.json"),
        }
        (stage / "RELEASE-MANIFEST.json").write_text(
            json.dumps(
                manifest(
                    args.version,
                    target_label,
                    binary_name,
                    checksums["binary"],
                    gc_binary_name,
                    checksums["gc"],
                    checksums["py_verifier"],
                    checksums["ps_verifier"],
                    checksums["fetch"],
                    checksums["ps_fetch"],
                    checksums["sbom"],
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (stage / "README.txt").write_text(readme_from_shell_script(), encoding="utf-8")

        files = sorted(path for path in stage.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
        (stage / "SHA256SUMS").write_text(
            "".join(f"{sha256_file(path)}  {path.relative_to(stage).as_posix()}\n" for path in files),
            encoding="utf-8",
        )

        archive = out_dir / f"ao2-control-plane-{args.version}-{target_label}.tar.gz"
        entry_names = [
            "bin",
            "install.sh",
            "install.ps1",
            "rollback.sh",
            "rollback.ps1",
            "uninstall.sh",
            "uninstall.ps1",
            "ao2-control-plane.cdx.json",
            "verify_release_support_bundle.py",
            "Verify-ReleaseSupportBundle.ps1",
            "fetch_release_support_handoff.py",
            "Fetch-ReleaseSupportHandoff.ps1",
            "SHA256SUMS",
            "RELEASE-MANIFEST.json",
            "README.txt",
            "LICENSE",
            "NOTICE",
        ]
        with tarfile.open(archive, "w:gz") as tar:
            for name in entry_names:
                tar.add(stage / name, arcname=name)

    archive_sha = sha256_file(archive)
    with (out_dir / "SHA256SUMS").open("a", encoding="utf-8") as handle:
        handle.write(f"{archive_sha}  {archive.name}\n")
    print("ao2_control_plane_package=passed")
    print(f"archive={archive}")
    print(f"sha256={archive_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
