#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM directly from Cargo.lock."""

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote
import uuid


QUOTED_VALUE = re.compile(r'^([a-z]+) = ("(?:[^"\\]|\\.)*")$')


def parse_lockfile(path):
    packages = []
    current = None
    in_dependencies = False
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if current:
                packages.append(current)
            current = {"dependencies": []}
            in_dependencies = False
            continue
        if current is None:
            continue
        if line == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies:
            if line == "]":
                in_dependencies = False
            elif line:
                current["dependencies"].append(json.loads(line.rstrip(",")))
            continue
        match = QUOTED_VALUE.match(line)
        if match and match.group(1) in {"name", "version", "source", "checksum"}:
            current[match.group(1)] = json.loads(match.group(2))
    if current:
        packages.append(current)
    return packages


def package_ref(package):
    source = package.get("source", "workspace")
    qualifier = quote(source, safe="")
    return f"pkg:cargo/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}?source={qualifier}"


def dependency_candidates(specification, packages):
    match = re.match(r"^([^ ]+)(?: ([^ ]+))?(?: \((.+)\))?$", specification)
    if not match:
        return []
    name, version, source = match.groups()
    matches = [package for package in packages if package["name"] == name]
    if version:
        matches = [package for package in matches if package["version"] == version]
    if source:
        matches = [package for package in matches if package.get("source") == source]
    return sorted(package_ref(package) for package in matches)


def make_sbom(lockfile):
    lockfile = Path(lockfile)
    lock_bytes = lockfile.read_bytes()
    packages = parse_lockfile(lockfile)
    components = []
    dependency_rows = []
    for package in sorted(packages, key=package_ref):
        reference = package_ref(package)
        component = {
            "bom-ref": reference,
            "name": package["name"],
            "purl": reference,
            "type": "library",
            "version": package["version"],
        }
        if "checksum" in package:
            component["hashes"] = [
                {"alg": "SHA-256", "content": package["checksum"]}
            ]
        components.append(component)
        dependencies = set()
        for specification in package["dependencies"]:
            dependencies.update(dependency_candidates(specification, packages))
        dependency_rows.append({"ref": reference, "dependsOn": sorted(dependencies)})

    primary = next(package for package in packages if package["name"] == "ao2-cp-server")
    primary_ref = package_ref(primary)
    application_ref = f"pkg:cargo/ao2-control-plane@{primary['version']}"
    dependency_rows.append({"ref": application_ref, "dependsOn": [primary_ref]})
    dependency_rows.sort(key=lambda row: row["ref"])
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": dependency_rows,
        "metadata": {
            "component": {
                "bom-ref": application_ref,
                "name": "ao2-control-plane",
                "purl": application_ref,
                "type": "application",
                "version": primary["version"],
            },
            "tools": {
                "components": [
                    {
                        "name": "generate_cargo_lock_sbom.py",
                        "type": "application",
                        "version": "1",
                    }
                ]
            },
        },
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(lock_bytes).hexdigest())}",
        "specVersion": "1.5",
        "version": 1,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = make_sbom(args.lockfile)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
