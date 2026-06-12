#!/usr/bin/env python3
"""Generate control-plane release notes from a SHA256SUMS manifest."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path


TARGETS = [
    ("linux-x86_64", "Linux x86_64"),
    ("macos-aarch64", "macOS aarch64"),
    ("windows-x86_64", "Windows x86_64"),
]


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        digest = parts[0].lower()
        name = parts[-1].lstrip("*")
        if re.fullmatch(r"[0-9a-f]{64}", digest):
            checksums[name] = digest
    return checksums


def build_notes(
    *,
    version: str,
    tag: str,
    checksums: dict[str, str],
    released: str,
    release_workflow: str,
    source_commit: str,
) -> str:
    expected = [
        (f"ao2-control-plane-{version}-{target}.tar.gz", label)
        for target, label in TARGETS
    ]
    missing = [name for name, _label in expected if name not in checksums]
    if missing:
        raise ValueError("missing checksum entries: " + ", ".join(missing))

    lines = [
        f"# ao2-control-plane {tag} release notes",
        "",
        f"**Released:** {released}",
        f"**Release workflow:** `{release_workflow}`",
    ]
    if source_commit:
        lines.append(f"**Source commit:** `{source_commit}`")
    lines.extend(
        [
            "",
            "## Archives",
            "",
            "| OS | File | SHA-256 |",
            "|---|---|---|",
        ]
    )
    for name, label in expected:
        lines.append(f"| {label} | `{name}` | `{checksums[name]}` |")
    lines.extend(
        [
            "",
            "## Production-readiness changes",
            "",
            "- Release notes were generated from `SHA256SUMS` to avoid manual hash drift.",
            "- Keeps AO2 release acceptance outside the control plane; the control plane remains an observer and release asset publisher for its own binaries.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate ao2-control-plane release notes from SHA256SUMS."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--released", default=date.today().isoformat())
    parser.add_argument("--release-workflow", default="Release Promotion")
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()

    try:
        checksums = parse_checksums(args.checksums)
        notes = build_notes(
            version=args.version,
            tag=args.tag,
            checksums=checksums,
            released=args.released,
            release_workflow=args.release_workflow,
            source_commit=args.source_commit,
        )
    except Exception as exc:
        print(f"control_plane_release_notes_generation=failed: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(notes, encoding="utf-8")
    print(f"control_plane_release_notes_generated={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
