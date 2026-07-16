import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCRIPT = REPO_ROOT / "scripts" / "package-local.sh"
SBOM_SCRIPT = REPO_ROOT / "scripts" / "generate_cargo_lock_sbom.py"
TEST_RUNNER = REPO_ROOT / "scripts" / "run-workspace-tests.py"
ARCHIVE_SMOKE = REPO_ROOT / "scripts" / "smoke-release-archive.sh"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_payloads(directory: Path, marker: str) -> Path:
    directory.mkdir(parents=True)
    server = directory / "ao2-cp-server"
    gc = directory / "ao2-cp-gc"
    server.write_text(
        f"#!/bin/sh\nprintf 'ao2-cp-server {marker}\\n'\n", encoding="utf-8"
    )
    gc.write_text(f"#!/bin/sh\nprintf 'gc-{marker}\\n'\n", encoding="utf-8")
    server.chmod(0o755)
    gc.chmod(0o755)
    return server


def package(tmp_path: Path, marker: str) -> Path:
    binary = write_payloads(tmp_path / f"build-{marker}", marker)
    out_dir = tmp_path / f"dist-{marker}"
    subprocess.run(
        [
            "sh",
            str(PACKAGE_SCRIPT),
            "--out-dir",
            str(out_dir),
            "--version",
            marker,
            "--binary",
            str(binary),
            "--target-label",
            "linux-x86_64",
        ],
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return out_dir / f"ao2-control-plane-{marker}-linux-x86_64.tar.gz"


def extract(archive: Path, destination: Path) -> Path:
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(destination)
    return destination


def run_lifecycle(script: Path, install_dir: Path):
    env = os.environ.copy()
    env["AO2_CP_INSTALL_DIR"] = str(install_dir)
    return subprocess.run(
        ["sh", str(script)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def parse_checksums(text: str):
    rows = {}
    for line in text.splitlines():
        digest, name = line.split(maxsplit=1)
        rows[name] = digest
    return rows


def test_stable_release_train_points_to_published_patch():
    workspace = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    lockfile = (REPO_ROOT / "Cargo.lock").read_text(encoding="utf-8")
    package_script = PACKAGE_SCRIPT.read_text(encoding="utf-8")
    release_train = (REPO_ROOT / "docs/release/release-train.json").read_text(
        encoding="utf-8"
    )

    assert 'version = "0.1.16"' in workspace
    for crate in ("ao2-cp-schema", "ao2-cp-server", "ao2-cp-storage"):
        block = lockfile.split(f'name = "{crate}"', 1)[1].split("[[package]]", 1)[0]
        assert 'version = "0.1.16"' in block
    assert 'VERSION="0.1.16"' in package_script
    release_train_json = json.loads(release_train)
    assert release_train_json["stable"]["ao2_control_plane"] == {
        "tag": "v0.1.16",
        "version": "0.1.16",
    }
    assert release_train_json["next_patch"]["ao2_control_plane"] == {
        "tag": "v0.1.16",
        "version": "0.1.16",
    }


def test_package_rejects_version_substitution(tmp_path):
    binary = write_payloads(tmp_path / "build-actual", "0.1.16")
    result = subprocess.run(
        [
            "sh",
            str(PACKAGE_SCRIPT),
            "--out-dir",
            str(tmp_path / "dist"),
            "--version",
            "9.9.9-substituted",
            "--binary",
            str(binary),
            "--target-label",
            "linux-x86_64",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "does not match requested package version" in result.stderr


def test_workspace_test_runner_raises_posix_limit_and_leaves_windows_unchanged():
    runner = load_module(TEST_RUNNER, "run_workspace_tests")

    class FakeResource:
        RLIMIT_NOFILE = 7

        def __init__(self, limits):
            self.limits = limits
            self.set_calls = []

        def getrlimit(self, resource):
            assert resource == self.RLIMIT_NOFILE
            return self.limits

        def setrlimit(self, resource, limits):
            self.set_calls.append((resource, limits))

    posix = FakeResource((256, 8192))
    runner.prepare_nofile_limit("posix", posix)
    assert posix.set_calls == [(posix.RLIMIT_NOFILE, (4096, 8192))]

    windows = FakeResource((256, 256))
    runner.prepare_nofile_limit("nt", windows)
    assert windows.set_calls == []
    assert runner.CARGO_TEST_COMMAND == [
        "cargo",
        "test",
        "--workspace",
        "--all-targets",
    ]


def test_workspace_test_runner_rejects_insufficient_posix_hard_limit():
    runner = load_module(TEST_RUNNER, "run_workspace_tests_hard_limit")

    class FakeResource:
        RLIMIT_NOFILE = 7

        @staticmethod
        def getrlimit(_resource):
            return (256, 2048)

    try:
        runner.prepare_nofile_limit("posix", FakeResource())
    except RuntimeError as error:
        message = str(error)
    else:
        raise AssertionError("hard limit below 4096 must fail")

    assert "2048" in message
    assert "4096" in message
    assert "hard limit" in message.lower()


def test_archive_smoke_canonicalizes_install_root_before_installer_changes_directory():
    smoke = ARCHIVE_SMOKE.read_text(encoding="utf-8")
    mkdir = smoke.index('mkdir -p "$AO2_CP_SMOKE_ROOT"')
    canonical = smoke.index(
        'AO2_CP_SMOKE_ROOT="$(cd "$AO2_CP_SMOKE_ROOT" && pwd)"'
    )
    install = smoke.index('AO2_CP_INSTALL_DIR="$install_dir" sh "$extract/install.sh"')

    assert mkdir < canonical < install


def test_cargo_lock_sbom_is_deterministic_cyclonedx_1_5(tmp_path):
    first = tmp_path / "first.cdx.json"
    second = tmp_path / "second.cdx.json"
    command = [
        "python3",
        str(SBOM_SCRIPT),
        "--lockfile",
        str(REPO_ROOT / "Cargo.lock"),
        "--output",
    ]
    subprocess.run(command + [str(first)], check=True, cwd=REPO_ROOT)
    subprocess.run(command + [str(second)], check=True, cwd=REPO_ROOT)

    assert first.read_bytes() == second.read_bytes()
    sbom = json.loads(first.read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["version"] == "0.1.16"
    assert len(sbom["components"]) > 50
    assert any(component["name"] == "ao2-cp-server" for component in sbom["components"])


def test_package_checksums_cover_full_closure_and_manifest_contract(tmp_path):
    archive = package(tmp_path, "9.9.9-contract")
    with tarfile.open(archive, "r:gz") as bundle:
        files = {member.name for member in bundle.getmembers() if member.isfile()}
        checksums = parse_checksums(
            bundle.extractfile("SHA256SUMS").read().decode("utf-8")
        )
        manifest = json.load(bundle.extractfile("RELEASE-MANIFEST.json"))
        sbom_bytes = bundle.extractfile("ao2-control-plane.cdx.json").read()

    assert set(checksums) == files - {"SHA256SUMS"}
    assert checksums["ao2-control-plane.cdx.json"] == hashlib.sha256(
        sbom_bytes
    ).hexdigest()
    assert manifest["sbom"]["format"] == "CycloneDX"
    assert manifest["sbom"]["spec_version"] == "1.5"
    assert manifest["lifecycle"]["receipt_schema"] == (
        "ao2-control-plane.install-receipt.v1"
    )
    for script in ("install.sh", "install.ps1", "rollback.sh", "rollback.ps1", "uninstall.sh", "uninstall.ps1"):
        assert script in files
        assert script in manifest["lifecycle"]["scripts"]


def test_unix_install_update_and_rollback_is_transactional(tmp_path):
    old_bundle = extract(package(tmp_path, "1.0.0-old"), tmp_path / "old")
    new_bundle = extract(package(tmp_path, "1.0.1-new"), tmp_path / "new")
    install_dir = tmp_path / "install"

    first = run_lifecycle(old_bundle / "install.sh", install_dir)
    assert first.returncode == 0, first.stderr
    update = run_lifecycle(new_bundle / "install.sh", install_dir)
    assert update.returncode == 0, update.stderr
    assert "ao2-cp-server 1.0.1-new" in (install_dir / "ao2-cp-server").read_text()
    assert "gc-1.0.1-new" in (install_dir / "ao2-cp-gc").read_text()

    receipt = json.loads(
        (install_dir / "ao2-control-plane.install-receipt.json").read_text()
    )
    assert receipt["schema_version"] == "ao2-control-plane.install-receipt.v1"
    assert receipt["operation"] == "install"
    assert all(item["prior_present"] for item in receipt["binaries"])

    rollback = run_lifecycle(new_bundle / "rollback.sh", install_dir)
    assert rollback.returncode == 0, rollback.stderr
    assert "ao2-cp-server 1.0.0-old" in (install_dir / "ao2-cp-server").read_text()
    assert "gc-1.0.0-old" in (install_dir / "ao2-cp-gc").read_text()


def test_unix_install_verifies_both_payloads_before_writing(tmp_path):
    old_bundle = extract(package(tmp_path, "2.0.0-old"), tmp_path / "old")
    new_bundle = extract(package(tmp_path, "2.0.1-new"), tmp_path / "new")
    install_dir = tmp_path / "install"
    assert run_lifecycle(old_bundle / "install.sh", install_dir).returncode == 0
    before = {
        name: (install_dir / name).read_bytes()
        for name in ("ao2-cp-server", "ao2-cp-gc")
    }
    (new_bundle / "bin" / "ao2-cp-gc").write_text("tampered", encoding="utf-8")

    failed = run_lifecycle(new_bundle / "install.sh", install_dir)

    assert failed.returncode != 0
    assert "checksum mismatch" in failed.stderr.lower()
    assert before == {
        name: (install_dir / name).read_bytes()
        for name in ("ao2-cp-server", "ao2-cp-gc")
    }
