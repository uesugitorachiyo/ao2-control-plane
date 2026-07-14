#!/usr/bin/env python3
"""Verify the public AO2/control-plane release pair without release mutation."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


DEFAULT_AO2_REPO = "uesugitorachiyo/ao2"
DEFAULT_CONTROL_PLANE_REPO = "uesugitorachiyo/ao2-control-plane"
REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_TRAIN_MANIFEST = REPO_ROOT / "docs/release/release-train.json"
DEFAULT_OUTPUT_ROOT = Path("target/public-release-pair-verification")
PLATFORM_ORDER = ["linux-x86_64", "linux-aarch64", "macos-aarch64", "windows-x86_64"]
# Current default control-plane Windows archive contract:
# ao2-control-plane-0.1.15-windows-x86_64.tar.gz


def load_release_train_manifest(path: Path = RELEASE_TRAIN_MANIFEST) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "ao2.release-train-manifest.v1":
        raise SystemExit(f"unexpected release train manifest schema: {manifest.get('schema_version')}")
    for train_name in ("stable", "next_patch"):
        train = manifest.get(train_name)
        if not isinstance(train, dict):
            raise SystemExit(f"missing release train: {train_name}")
        for component in ("ao2", "ao2_control_plane"):
            target = train.get(component)
            if not isinstance(target, dict) or not target.get("tag") or not target.get("version"):
                raise SystemExit(f"invalid release train target: {train_name}.{component}")
    return manifest


RELEASE_TRAIN_DEFAULTS = load_release_train_manifest()
DEFAULT_AO2_TAG = RELEASE_TRAIN_DEFAULTS["stable"]["ao2"]["tag"]
DEFAULT_CONTROL_PLANE_TAG = RELEASE_TRAIN_DEFAULTS["stable"]["ao2_control_plane"]["tag"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify AO2 and ao2-control-plane public release metadata/checksums as one read-only pair."
    )
    parser.add_argument("--ao2-repo", default=DEFAULT_AO2_REPO)
    parser.add_argument("--ao2-tag", default=DEFAULT_AO2_TAG)
    parser.add_argument("--ao2-release-view-json", type=Path)
    parser.add_argument("--ao2-checksums", type=Path)
    parser.add_argument("--control-plane-repo", default=DEFAULT_CONTROL_PLANE_REPO)
    parser.add_argument("--control-plane-tag", default=DEFAULT_CONTROL_PLANE_TAG)
    parser.add_argument("--control-plane-release-view-json", type=Path)
    parser.add_argument("--control-plane-checksums", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--summary-json", type=Path)
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args()


def version_from_tag(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def run_gh_json(repo: str, tag: str) -> dict:
    if not shutil.which("gh"):
        raise SystemExit("missing gh CLI: pass --*-release-view-json and --*-checksums for offline verification")
    result = subprocess.run(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            repo,
            "--json",
            "tagName,name,isDraft,isPrerelease,publishedAt,assets,url",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def download_checksums(repo: str, tag: str, output_dir: Path) -> Path:
    if not shutil.which("gh"):
        raise SystemExit("missing gh CLI: pass --*-checksums for offline verification")
    output_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "gh",
            "release",
            "download",
            tag,
            "--repo",
            repo,
            "--pattern",
            "SHA256SUMS",
            "--dir",
            str(output_dir),
            "--clobber",
        ],
        check=True,
    )
    return output_dir / "SHA256SUMS"


def read_release_view(path: Path | None, repo: str, tag: str) -> tuple[dict, str]:
    if path:
        return json.loads(path.read_text(encoding="utf-8")), str(path)
    return run_gh_json(repo, tag), "gh release view"


def read_checksums(path: Path | None, repo: str, tag: str, output_dir: Path) -> tuple[dict[str, str], str]:
    checksum_path = path or download_checksums(repo, tag, output_dir)
    if not checksum_path.is_file():
        raise SystemExit(f"missing release checksum manifest: {checksum_path}")

    entries: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            entries[parts[-1].lstrip("*")] = parts[0].lower()
    return entries, str(checksum_path)


def ao2_required_assets(version: str) -> list[str]:
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


def control_plane_required_assets(version: str) -> list[str]:
    return [
        "SHA256SUMS",
        f"ao2-control-plane-{version}-linux-x86_64.tar.gz",
        f"ao2-control-plane-{version}-macos-aarch64.tar.gz",
        f"ao2-control-plane-{version}-windows-x86_64.tar.gz",
        "summary.json",
    ]


def control_plane_checksum_required_assets(version: str) -> list[str]:
    return [
        f"ao2-control-plane-{version}-linux-x86_64.tar.gz",
        f"ao2-control-plane-{version}-macos-aarch64.tar.gz",
        f"ao2-control-plane-{version}-windows-x86_64.tar.gz",
        "summary.json",
    ]


def platform_labels(asset_names: list[str], prefix: str, version: str) -> list[str]:
    pattern = re.compile(rf"^{re.escape(prefix)}-{re.escape(version)}-(.+)\.tar\.gz$")
    labels = {match.group(1) for name in asset_names if (match := pattern.match(name))}
    return [label for label in PLATFORM_ORDER if label in labels]


def asset_names(release_view: dict) -> list[str]:
    return sorted(asset.get("name", "") for asset in release_view.get("assets", []) if asset.get("name"))


def append_release_gaps(
    gaps: list[dict],
    *,
    repo_label: str,
    release_view: dict,
    required_assets: list[str],
    checksum_required_assets: list[str],
    checksums: dict[str, str],
) -> None:
    names = set(asset_names(release_view))
    required = set(required_assets)
    checksum_required = set(checksum_required_assets)

    if release_view.get("isDraft") or release_view.get("isPrerelease"):
        gaps.append(
            {
                "gap_kind": f"{repo_label}_release_not_stable",
                "severity": "release_blocker",
                "is_draft": bool(release_view.get("isDraft")),
                "is_prerelease": bool(release_view.get("isPrerelease")),
            }
        )

    missing_assets = sorted(required - names)
    if missing_assets:
        gaps.append(
            {
                "gap_kind": f"{repo_label}_missing_required_assets",
                "severity": "release_blocker",
                "assets": missing_assets,
            }
        )

    missing_checksums = sorted(asset for asset in checksum_required if asset in names and asset not in checksums)
    if missing_checksums:
        gaps.append(
            {
                "gap_kind": f"{repo_label}_missing_checksum_entries",
                "severity": "release_blocker",
                "assets": missing_checksums,
            }
        )


def release_summary(
    *,
    repo: str,
    tag: str,
    release_view: dict,
    release_view_source: str,
    checksums: dict[str, str],
    checksum_source: str,
    required_assets: list[str],
    platforms: list[str],
    extra_platforms: list[str],
) -> dict:
    names = asset_names(release_view)
    return {
        "release_repo": repo,
        "release_tag": tag,
        "release_name": release_view.get("name", ""),
        "release_url": release_view.get("url", ""),
        "published_at": release_view.get("publishedAt", ""),
        "stable_release": not bool(release_view.get("isDraft")) and not bool(release_view.get("isPrerelease")),
        "release_view_source": release_view_source,
        "checksum_manifest": checksum_source,
        "required_assets": required_assets,
        "published_assets": names,
        "checksum_entries": sorted(checksums),
        "platforms": platforms,
        "extra_platforms": extra_platforms,
    }


def main() -> int:
    args = parse_args()
    output_root = args.output_root
    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = args.summary_json or output_root / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    ao2_version = version_from_tag(args.ao2_tag)
    cp_version = version_from_tag(args.control_plane_tag)

    ao2_release, ao2_release_source = read_release_view(args.ao2_release_view_json, args.ao2_repo, args.ao2_tag)
    cp_release, cp_release_source = read_release_view(
        args.control_plane_release_view_json,
        args.control_plane_repo,
        args.control_plane_tag,
    )
    ao2_checksums, ao2_checksum_source = read_checksums(
        args.ao2_checksums,
        args.ao2_repo,
        args.ao2_tag,
        output_root / "ao2",
    )
    cp_checksums, cp_checksum_source = read_checksums(
        args.control_plane_checksums,
        args.control_plane_repo,
        args.control_plane_tag,
        output_root / "control-plane",
    )

    ao2_required = ao2_required_assets(ao2_version)
    cp_required = control_plane_required_assets(cp_version)
    ao2_checksum_required = [asset for asset in ao2_required if asset != "SHA256SUMS"]
    cp_checksum_required = control_plane_checksum_required_assets(cp_version)
    ao2_platforms = platform_labels(asset_names(ao2_release), "ao2", ao2_version)
    cp_platforms = platform_labels(asset_names(cp_release), "ao2-control-plane", cp_version)
    common_platforms = [label for label in PLATFORM_ORDER if label in set(ao2_platforms) & set(cp_platforms)]
    ao2_extra_platforms = [label for label in ao2_platforms if label not in set(cp_platforms)]
    cp_extra_platforms = [label for label in cp_platforms if label not in set(ao2_platforms)]

    gaps: list[dict] = []
    append_release_gaps(
        gaps,
        repo_label="ao2",
        release_view=ao2_release,
        required_assets=ao2_required,
        checksum_required_assets=ao2_checksum_required,
        checksums=ao2_checksums,
    )
    append_release_gaps(
        gaps,
        repo_label="control_plane",
        release_view=cp_release,
        required_assets=cp_required,
        checksum_required_assets=cp_checksum_required,
        checksums=cp_checksums,
    )

    if common_platforms != ["linux-x86_64", "macos-aarch64", "windows-x86_64"]:
        gaps.append(
            {
                "gap_kind": "missing_common_platforms",
                "severity": "release_blocker",
                "common_platforms": common_platforms,
                "required_common_platforms": ["linux-x86_64", "macos-aarch64", "windows-x86_64"],
            }
        )

    status = "attention" if gaps else "passed"
    selected_train = (
        "stable"
        if args.ao2_tag == DEFAULT_AO2_TAG and args.control_plane_tag == DEFAULT_CONTROL_PLANE_TAG
        else "custom"
    )
    if selected_train == "stable":
        selected_targets = RELEASE_TRAIN_DEFAULTS["stable"]
    else:
        selected_targets = {
            "ao2": {"tag": args.ao2_tag, "version": version_from_tag(args.ao2_tag)},
            "ao2_control_plane": {
                "tag": args.control_plane_tag,
                "version": version_from_tag(args.control_plane_tag),
            },
            "promotion_confirm": "",
            "public_operator_confirm": "",
        }
    release_train_manifest = {
        "schema_version": RELEASE_TRAIN_DEFAULTS["schema_version"],
        "source": str(RELEASE_TRAIN_MANIFEST),
        "selected_train": selected_train,
        "stable": RELEASE_TRAIN_DEFAULTS["stable"],
        "next_patch": RELEASE_TRAIN_DEFAULTS["next_patch"],
    }
    release_targets = {
        "selected_train": selected_train,
        "ao2": selected_targets["ao2"],
        "ao2_control_plane": selected_targets["ao2_control_plane"],
        "promotion_confirm": selected_targets["promotion_confirm"],
        "public_operator_confirm": selected_targets["public_operator_confirm"],
    }
    summary = {
        "schema_version": "ao2.cp-public-release-pair-verification.v1",
        "status": status,
        "strict": args.strict,
        "release_train_manifest": release_train_manifest,
        "release_targets": release_targets,
        "ao2": release_summary(
            repo=args.ao2_repo,
            tag=args.ao2_tag,
            release_view=ao2_release,
            release_view_source=ao2_release_source,
            checksums=ao2_checksums,
            checksum_source=ao2_checksum_source,
            required_assets=ao2_required,
            platforms=ao2_platforms,
            extra_platforms=ao2_extra_platforms,
        ),
        "control_plane": release_summary(
            repo=args.control_plane_repo,
            tag=args.control_plane_tag,
            release_view=cp_release,
            release_view_source=cp_release_source,
            checksums=cp_checksums,
            checksum_source=cp_checksum_source,
            required_assets=cp_required,
            platforms=cp_platforms,
            extra_platforms=cp_extra_platforms,
        ),
        "common_platforms": common_platforms,
        "gaps": gaps,
        "trust_boundary": {
            "control_plane_approves_release": False,
            "downloads_archives": False,
            "mutates_ao_artifacts": False,
            "mutates_github_releases": False,
            "credential_material_included": False,
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"control_plane_public_release_pair_verification={status}")
    print(f"control_plane_public_release_pair_verification_summary={summary_path}")
    if status != "passed" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
