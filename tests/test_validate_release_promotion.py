import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_release_promotion.py"
SOURCE_SHA = "a" * 40
VERSION = "9.9.9"
TAG = "v9.9.9"


def make_plan(tmp_path: Path):
    root = tmp_path / "plan"
    downloaded = root / "downloaded"
    assets = []
    checksum_rows = []
    for target in ("linux-x86_64", "macos-aarch64", "windows-x86_64"):
        name = f"ao2-control-plane-{VERSION}-{target}.tar.gz"
        path = downloaded / target / "dist" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"archive:{target}".encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assets.append(
            {
                "name": name,
                "path": f"downloaded/{target}/dist/{name}",
                "sha256": digest,
                "size_bytes": path.stat().st_size,
                "target_label": target,
            }
        )
        checksum_rows.append(f"{digest}  {name}\n")

    baseline = root / "post-release-baseline.json"
    required_artifact_names = [
        "ao2-control-plane-post-release-verification-ubuntu",
        "ao2-control-plane-post-release-verification-macos",
        "ao2-control-plane-post-release-verification-windows",
        "ao2-control-plane-post-release-pair-verification",
        "ao2-control-plane-post-release-operator-evidence-hosted-bridge-smoke",
        "ao2-control-plane-post-release-active-stack-release-handoff-readback",
    ]
    baseline_payload = {
        "schema_version": "ao2.cp-post-release-verification-baseline.v1",
        "status": "passed",
        "repo": "uesugitorachiyo/ao2-control-plane",
        "branch": "main",
        "workflow": "Post Release Verification",
        "run_id": 123,
        "run_url": "https://github.com/uesugitorachiyo/ao2-control-plane/actions/runs/123",
        "head_sha": SOURCE_SHA,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "required_artifacts": [
            {"name": name, "id": index + 1, "size_in_bytes": 100, "expired": False}
            for index, name in enumerate(required_artifact_names)
        ],
        "missing_artifacts": [],
        "expired_artifacts": [],
        "trust_boundary": {
            "downloads_github_actions_artifacts": False,
            "control_plane_approves_release": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
        },
    }
    baseline.write_text(
        json.dumps(baseline_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    notes = root / "release-notes.md"
    notes.write_text("release notes\n", encoding="utf-8")
    summary = {
        "schema_version": "ao2.cp-release-promotion-plan.v1",
        "status": "prepared",
        "version": VERSION,
        "tag": TAG,
        "dry_run": True,
        "source_commit": SOURCE_SHA,
        "archive_assets": assets,
        "release_notes_sha256": hashlib.sha256(notes.read_bytes()).hexdigest(),
        "post_release_verification_baseline": baseline_payload,
        "required_post_release_artifacts": required_artifact_names,
    }
    summary_path = root / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_rows.extend(
        [
            f"{hashlib.sha256(summary_path.read_bytes()).hexdigest()}  summary.json\n",
            f"{hashlib.sha256(baseline.read_bytes()).hexdigest()}  post-release-baseline.json\n",
            f"{hashlib.sha256(notes.read_bytes()).hexdigest()}  release-notes.md\n",
        ]
    )
    (root / "SHA256SUMS").write_text("".join(checksum_rows), encoding="utf-8")
    return root, hashlib.sha256(summary_path.read_bytes()).hexdigest()


def validate(root: Path, digest: str, **overrides):
    values = {
        "source_sha": SOURCE_SHA,
        "version": VERSION,
        "tag": TAG,
        "plan_sha256": digest,
        "confirmation": f"publish {TAG} from {SOURCE_SHA} with plan {digest}",
        "event_sha": SOURCE_SHA,
    }
    values.update(overrides)
    command = ["python3", str(VALIDATOR), "--root", str(root)]
    for name, value in values.items():
        command.extend([f"--{name.replace('_', '-')}", value])
    return subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True)


def test_valid_immutable_release_promotion_plan_passes(tmp_path):
    root, digest = make_plan(tmp_path)

    result = validate(root, digest)

    assert result.returncode == 0, result.stderr
    assert "release_promotion_validation=passed" in result.stdout


def test_release_promotion_rejects_identity_and_confirmation_mismatches(tmp_path):
    root, digest = make_plan(tmp_path)
    cases = [
        {"plan_sha256": "b" * 64},
        {"source_sha": "b" * 40},
        {"event_sha": "b" * 40},
        {"version": "9.9.8"},
        {"tag": "v9.9.8"},
        {"confirmation": "publish something else"},
    ]

    for overrides in cases:
        result = validate(root, digest, **overrides)
        assert result.returncode != 0, overrides


def test_release_promotion_rejects_tampered_or_unsafe_archive_contract(tmp_path):
    root, digest = make_plan(tmp_path)
    archive = next((root / "downloaded").glob("**/*linux-x86_64.tar.gz"))
    archive.write_bytes(b"tampered")
    assert validate(root, digest).returncode != 0

    root, _ = make_plan(tmp_path / "unsafe")
    summary_path = root / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["archive_assets"][0]["path"] = "../outside.tar.gz"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    unsafe_digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    assert validate(root, unsafe_digest).returncode != 0


def test_release_promotion_rejects_tampered_release_notes(tmp_path):
    root, digest = make_plan(tmp_path)
    (root / "release-notes.md").write_text("altered notes\n", encoding="utf-8")

    assert validate(root, digest).returncode != 0


def test_release_promotion_rejects_unsafe_or_mismatched_baseline(tmp_path):
    for field, value in (
        ("status", "blocked"),
        ("head_sha", "b" * 40),
        ("missing_artifacts", ["missing"]),
    ):
        root, digest = make_plan(tmp_path / field)
        baseline_path = root / "post-release-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline[field] = value
        baseline_path.write_text(
            json.dumps(baseline, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert validate(root, digest).returncode != 0

    root, _ = make_plan(tmp_path / "embedded")
    summary_path = root / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["post_release_verification_baseline"]["status"] = "blocked"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    changed_digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    assert validate(root, changed_digest).returncode != 0


def test_release_promotion_rejects_malformed_or_stale_baseline_metadata(tmp_path):
    cases = (
        ("run_id", None),
        ("run_url", 123),
        ("checked_at_utc", "not-a-timestamp"),
        ("checked_at_utc", "2000-01-01T00:00:00+00:00"),
    )
    for index, (field, value) in enumerate(cases):
        root, digest = make_plan(tmp_path / f"metadata-{index}")
        baseline_path = root / "post-release-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline[field] = value
        baseline_path.write_text(
            json.dumps(baseline, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert validate(root, digest).returncode != 0

    root, digest = make_plan(tmp_path / "extra-field")
    baseline_path = root / "post-release-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["undeclared"] = True
    baseline_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert validate(root, digest).returncode != 0
