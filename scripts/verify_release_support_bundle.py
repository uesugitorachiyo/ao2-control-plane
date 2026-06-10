#!/usr/bin/env python3
"""Verify AO2 Control Plane release support-bundle embedded surface digests.

Usage:
  python3 scripts/verify_release_support_bundle.py release-support-bundle.json
  python3 scripts/verify_release_support_bundle.py --json release-support-bundle.json
  python3 scripts/verify_release_support_bundle.py --checksums SHA256SUMS release-support-bundle.json
  python3 scripts/verify_release_support_bundle.py --compare-against OTHER.json release-support-bundle.json

This is an offline, read-only verifier. It never contacts the control plane and
never mutates AO2/factory-v3 artifacts. The optional --json mode emits a stable
machine-readable summary for scheduler/control-plane ingestion. The optional
--checksums flag verifies that the canonical bundle digest is also present in a
downloaded SHA256SUMS file, so macOS/Ubuntu/Windows operators can validate the
portable handoff without relying on platform-specific sha256sum tooling. The
optional --compare-against flag (Lane NN) diffs aggregate verdicts and per-
surface candidate_correlation status across two release-candidate bundles so
operators can surface verdict drift between candidates without re-navigating
each bundle's HTML surfaces.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

SURFACE_PATHS = {
    "ci_evidence_index": ["ci_evidence_index"],
    "release_assembly": ["release_assembly"],
    "release_readiness": ["readiness"],
    "release_candidate_handoff": ["handoff"],
    "release_cockpit": ["cockpit"],
    "release_evaluator_decision": ["evaluator_decision"],
    "install_verification": ["install_verification"],
    "hosted_release_smoke": ["hosted_release_smoke"],
    "storage_support_bundle": ["storage_support"],
}

EXPECTED_JSON_PATHS = {
    "ci_evidence_index": "$.ci_evidence_index",
    "release_assembly": "$.release_assembly",
    "release_readiness": "$.readiness",
    "release_candidate_handoff": "$.handoff",
    "release_cockpit": "$.cockpit",
    "release_evaluator_decision": "$.evaluator_decision",
    "install_verification": "$.install_verification",
    "hosted_release_smoke": "$.hosted_release_smoke",
    "storage_support_bundle": "$.storage_support",
}

REQUIRED_SURFACE_IDS = tuple(EXPECTED_JSON_PATHS.keys())
EXPECTED_MANIFEST_SCHEMA = "ao2.cp-release-support-bundle-manifest.v1"
REQUIRED_CI_EVIDENCE_FAMILY_IDS = (
    "risky-pr-golden-bridge-smoke",
    "release-train-bridge-smoke",
    "ingest-smoke",
    "release-archive-smoke",
    "backup-restore-drill",
)
# Operator-visible candidate-correlation field MUST be present at the top of
# every embedded surface that exposes cross-evidence triage to the operator.
# A downgraded server dropping the field would silently mask release/three_os/
# evaluator/codex/claude divergence, so the offline verifier hard-fails the
# bundle here as a defense-in-depth gate.
#
# Each entry maps surface_id -> field name on that surface that holds the full
# candidate_correlation object. release_assembly uses candidate_correlation_detail
# because its top-level candidate_correlation is the status string consumed by
# the cross-OS smoke scripts (changing that would break operator contracts).
CANDIDATE_CORRELATION_REQUIRED_SURFACES = (
    ("release_cockpit", "candidate_correlation"),
    ("release_candidate_handoff", "candidate_correlation"),
    ("release_readiness", "candidate_correlation"),
    ("release_assembly", "candidate_correlation_detail"),
)
class CliArgs(NamedTuple):
    json_mode: bool
    checksums_path: Path | None
    compare_against_path: Path | None
    bundle_path: Path


# Lane NN: cross-bundle byte-identity comparison.
# Operators compare two release-candidate bundles to surface verdict drift
# between candidates. The compare-against flow extracts the verdicts and
# correlation-status fields from both bundles and emits a structural diff
# WITHOUT contacting either control plane. Verdict drift on any of these
# fields is operator-actionable and fails the primary bundle's exit code so
# automation pipelines surface the drift without parsing the JSON summary.
COMPARISON_PARITY_VERDICTS = (
    "candidate_correlation_parity",
    "surface_content_hash_parity",
)
COMPARISON_PARITY_SURFACES = (
    "release_cockpit",
    "release_candidate_handoff",
    "release_readiness",
)
COMPARISON_CORRELATION_STATUS_SURFACES = (
    ("release_cockpit", "candidate_correlation"),
    ("release_candidate_handoff", "candidate_correlation"),
    ("release_readiness", "candidate_correlation"),
    ("release_assembly", "candidate_correlation_detail"),
)
# Lane ZZ: rejected_smoke_audit is rendered identically on cockpit, handoff,
# and readiness JSON by construction (the same rejected_smoke_audit_summary()
# reader is embedded by all three handlers). A tampered offline bundle could
# alter one surface's audit object without touching the others — Lane XX's
# server-side pass-through proves the property holds at render time; the
# offline verifier audits it at bundle-acceptance time. Cross-bundle drift
# in the rotation-budget fields is also operator-actionable: two bundles
# collected at different rotation states will show different size/count
# even when verdicts agree, so the comparison view surfaces it as a
# distinct drift signal that is NOT a verdict failure.
REJECTED_SMOKE_AUDIT_SURFACES = (
    "release_cockpit",
    "release_candidate_handoff",
    "release_readiness",
)
REJECTED_SMOKE_AUDIT_BUDGET_FIELDS = (
    "count",
    "audit_log_size_bytes",
    "audit_log_cap_bytes",
)


SECRET_MARKERS = {
    "authorization_bearer_header": re.compile(r"authorization\s*[:=]\s*bearer\s+[^\s\"']+", re.IGNORECASE),
    "ao2_cp_api_token_assignment": re.compile(r"AO2_CP_API_TOKEN\s*=", re.IGNORECASE),
    "openai_api_key_assignment": re.compile(r"OPENAI_API_KEY\s*=", re.IGNORECASE),
    "anthropic_api_key_assignment": re.compile(r"ANTHROPIC_API_KEY\s*=", re.IGNORECASE),
    "json_api_token_field": re.compile(r"\"(?:api_token|access_token|refresh_token)\"\s*:\s*\"[^\"]+\"", re.IGNORECASE),
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_canonical(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def get_surface(bundle: dict[str, Any], surface_id: str) -> Any:
    value: Any = bundle
    for part in SURFACE_PATHS.get(surface_id, []):
        if not isinstance(value, dict) or part not in value:
            raise KeyError(surface_id)
        value = value[part]
    return value


def secret_marker_failures(raw: str) -> list[str]:
    failures: list[str] = []
    for marker, pattern in SECRET_MARKERS.items():
        if pattern.search(raw):
            failures.append(f"secret hygiene: forbidden marker {marker} present in support bundle")
    return failures


def emit_result(
    failures: list[str],
    surfaces: list[Any],
    bundle: dict[str, Any],
    json_mode: bool,
    checksum_verified: bool | None,
    comparison_against: dict[str, Any] | None = None,
) -> int:
    status = "failed" if failures else "passed"
    result = {
        "status": status,
        "surface_count": len(surfaces),
        "bundle_sha256": sha256_canonical(bundle) if isinstance(bundle, dict) else "missing",
        "checksum_verified": checksum_verified,
        "trust_boundary": "read_only_observer",
        "control_plane_role": "read_only_observer",
        "release_acceptance_owner": "factory-v3 evaluator-closer",
        "verification_scope": "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval",
        "failures": failures,
        "comparison_against": comparison_against,
    }
    if json_mode:
        print(json.dumps(result, sort_keys=True))
    elif failures:
        print("FAILED release support-bundle verification")
        for failure in failures:
            print(f"- {failure}")
    else:
        summary = {
            "status": result["status"],
            "surface_count": result["surface_count"],
            "bundle_sha256": result["bundle_sha256"],
            "checksum_verified": result["checksum_verified"],
            "trust_boundary": result["trust_boundary"],
        }
        if comparison_against is not None:
            summary["comparison_against"] = comparison_against
        print(json.dumps(summary, sort_keys=True))
    return 1 if failures else 0


def parse_args(argv: list[str]) -> CliArgs | None:
    json_mode = False
    checksums_path: Path | None = None
    compare_against_path: Path | None = None
    args = argv[1:]
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--json":
            json_mode = True
        elif flag == "--checksums" and args:
            checksums_path = Path(args.pop(0))
        elif flag == "--compare-against" and args:
            compare_against_path = Path(args.pop(0))
        else:
            return None
    if len(args) != 1:
        return None
    return CliArgs(
        json_mode=json_mode,
        checksums_path=checksums_path,
        compare_against_path=compare_against_path,
        bundle_path=Path(args[0]),
    )


def collect_comparison_view(bundle: Any) -> dict[str, Any]:
    """Extract the verdict + correlation-status fields used for cross-bundle diff."""
    view: dict[str, Any] = {
        "schema_version": bundle.get("schema_version") if isinstance(bundle, dict) else None,
        "release_candidate_version": bundle.get("release_candidate_version") if isinstance(bundle, dict) else None,
        "verdicts": {},
        "correlation_status": {},
        "rejected_smoke_audit": {},
    }
    for surface_id in COMPARISON_PARITY_SURFACES:
        try:
            surface = get_surface(bundle, surface_id) if isinstance(bundle, dict) else None
        except KeyError:
            continue
        if not isinstance(surface, dict):
            continue
        for verdict_field in COMPARISON_PARITY_VERDICTS:
            value = surface.get(verdict_field)
            if isinstance(value, str):
                view["verdicts"].setdefault(verdict_field, {})[surface_id] = value
    for surface_id, field_name in COMPARISON_CORRELATION_STATUS_SURFACES:
        try:
            surface = get_surface(bundle, surface_id) if isinstance(bundle, dict) else None
        except KeyError:
            continue
        if not isinstance(surface, dict):
            continue
        correlation = surface.get(field_name)
        if isinstance(correlation, dict):
            status = correlation.get("status")
            if isinstance(status, str):
                view["correlation_status"][surface_id] = status
    # Lane ZZ: collect rejected_smoke_audit rotation-budget fields from each
    # operator-triage surface so the cross-bundle diff can surface drift.
    # Two bundles captured at different rotation states will show different
    # size/count even when verdicts match — that's still operator-actionable
    # because it signals one of: (a) bundles were captured across rotation,
    # (b) a tampering burst between captures, or (c) tampering of the audit
    # log itself. The drift is surfaced as a distinct signal, never folded
    # into the verdict-parity boolean.
    for surface_id in REJECTED_SMOKE_AUDIT_SURFACES:
        try:
            surface = get_surface(bundle, surface_id) if isinstance(bundle, dict) else None
        except KeyError:
            continue
        if not isinstance(surface, dict):
            continue
        audit = surface.get("rejected_smoke_audit")
        if not isinstance(audit, dict):
            continue
        captured: dict[str, Any] = {}
        for field_name in REJECTED_SMOKE_AUDIT_BUDGET_FIELDS:
            value = audit.get(field_name)
            if isinstance(value, int) and not isinstance(value, bool):
                captured[field_name] = value
        if captured:
            view["rejected_smoke_audit"][surface_id] = captured
    return view


def comparison_diff(
    primary_view: dict[str, Any],
    compare_view: dict[str, Any],
    primary_sha256: str,
    compare_sha256: str,
) -> tuple[dict[str, Any], list[str]]:
    """Build the comparison report and any operator-actionable drift failures."""
    failures: list[str] = []
    verdict_diffs: list[dict[str, Any]] = []
    for verdict_field in COMPARISON_PARITY_VERDICTS:
        primary_map = primary_view["verdicts"].get(verdict_field, {})
        compare_map = compare_view["verdicts"].get(verdict_field, {})
        for surface_id in COMPARISON_PARITY_SURFACES:
            primary_value = primary_map.get(surface_id)
            compare_value = compare_map.get(surface_id)
            if primary_value != compare_value:
                verdict_diffs.append(
                    {
                        "surface": surface_id,
                        "field": verdict_field,
                        "primary": primary_value,
                        "compare": compare_value,
                    }
                )
                failures.append(
                    f"comparison_verdict_drift: {surface_id}.{verdict_field} "
                    f"differs across bundles (primary={primary_value!r}, compare={compare_value!r})"
                )
    correlation_status_diffs: list[dict[str, Any]] = []
    for surface_id, _ in COMPARISON_CORRELATION_STATUS_SURFACES:
        primary_value = primary_view["correlation_status"].get(surface_id)
        compare_value = compare_view["correlation_status"].get(surface_id)
        if primary_value != compare_value:
            correlation_status_diffs.append(
                {
                    "surface": surface_id,
                    "primary": primary_value,
                    "compare": compare_value,
                }
            )
            failures.append(
                f"comparison_correlation_status_drift: {surface_id} "
                f"candidate_correlation.status differs across bundles "
                f"(primary={primary_value!r}, compare={compare_value!r})"
            )
    # Lane ZZ: cross-bundle rotation-budget drift. The audit-budget signal is
    # explicitly NOT folded into verdict_parity — two bundles captured at
    # different times legitimately have different rotation states. The diff
    # surfaces the drift so operators can decide whether it's expected
    # (between-captures activity) or suspicious (audit-log tampering, or
    # rotation cap drift indicating a server-side cap change).
    audit_budget_diffs: list[dict[str, Any]] = []
    primary_audit = primary_view.get("rejected_smoke_audit", {}) or {}
    compare_audit = compare_view.get("rejected_smoke_audit", {}) or {}
    for surface_id in REJECTED_SMOKE_AUDIT_SURFACES:
        primary_entry = primary_audit.get(surface_id, {}) or {}
        compare_entry = compare_audit.get(surface_id, {}) or {}
        for field_name in REJECTED_SMOKE_AUDIT_BUDGET_FIELDS:
            primary_value = primary_entry.get(field_name)
            compare_value = compare_entry.get(field_name)
            if primary_value != compare_value:
                audit_budget_diffs.append(
                    {
                        "surface": surface_id,
                        "field": field_name,
                        "primary": primary_value,
                        "compare": compare_value,
                    }
                )
                failures.append(
                    f"comparison_audit_log_rotation_budget_drift: "
                    f"{surface_id}.rejected_smoke_audit.{field_name} "
                    f"differs across bundles (primary={primary_value!r}, "
                    f"compare={compare_value!r})"
                )
    schema_match = primary_view["schema_version"] == compare_view["schema_version"]
    if not schema_match:
        failures.append(
            f"comparison_schema_version_drift: primary={primary_view['schema_version']!r} "
            f"vs compare={compare_view['schema_version']!r}; bundles are not the same schema generation"
        )
    report: dict[str, Any] = {
        "primary_bundle_sha256": primary_sha256,
        "compare_bundle_sha256": compare_sha256,
        "bundle_sha256_match": primary_sha256 == compare_sha256,
        "schema_version_match": schema_match,
        "primary_schema_version": primary_view["schema_version"],
        "compare_schema_version": compare_view["schema_version"],
        "primary_release_candidate_version": primary_view["release_candidate_version"],
        "compare_release_candidate_version": compare_view["release_candidate_version"],
        "verdict_diffs": verdict_diffs,
        "correlation_status_diffs": correlation_status_diffs,
        "audit_budget_diffs": audit_budget_diffs,
        "verdict_parity": not verdict_diffs and not correlation_status_diffs,
    }
    return report, failures


def checksum_failures(checksums_path: Path, bundle_filename: str, bundle_sha256: str) -> list[str]:
    failures: list[str] = []
    try:
        text = checksums_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"checksums: unable to read {checksums_path}: {exc}"]

    candidates: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            failures.append(f"checksums: malformed line {raw_line!r}")
            continue
        digest, path = parts[0].lower(), parts[1].lstrip("*")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            failures.append(f"checksums: malformed sha256 digest for {path}")
            continue
        candidates.append((digest, path))

    matching_paths = [path for digest, path in candidates if digest == bundle_sha256]
    if not matching_paths:
        failures.append(
            "checksums: canonical bundle digest not present in SHA256SUMS; "
            f"expected {bundle_sha256} for {bundle_filename}"
        )
    elif not any(
        path == bundle_filename
        or path.endswith(f"/{bundle_filename}")
        or (path.startswith("ao2-release-support-bundle-") and path.endswith(".json"))
        for path in matching_paths
    ):
        failures.append(
            "checksums: canonical bundle digest present but not associated with "
            f"{bundle_filename}; matched {matching_paths}"
        )
    return failures


def ci_evidence_index_semantic_failures(surface: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(surface, dict):
        return ["ci_evidence_index: expected object"]
    if surface.get("schema_version") != "ao2.cp-ci-evidence-index.v1":
        failures.append(
            "ci_evidence_index.schema_version: expected ao2.cp-ci-evidence-index.v1"
        )
    if surface.get("control_plane_role") != "read-only-observer":
        failures.append(
            "ci_evidence_index.control_plane_role: expected read-only-observer"
        )
    for field_name in (
        "mutates_ao_artifacts",
        "mutates_observer_storage",
        "control_plane_approves_release",
    ):
        if surface.get(field_name) is not False:
            failures.append(f"ci_evidence_index.{field_name}: expected false")
    auth = surface.get("auth")
    if not isinstance(auth, dict):
        failures.append("ci_evidence_index.auth: expected object")
    else:
        if auth.get("required") is not True:
            failures.append("ci_evidence_index.auth.required: expected true")
        if auth.get("scheme") != "bearer":
            failures.append("ci_evidence_index.auth.scheme: expected bearer")
        for field_name in ("credential_material_included", "credential_material_in_urls"):
            if auth.get(field_name) is not False:
                failures.append(f"ci_evidence_index.auth.{field_name}: expected false")
    endpoints = surface.get("endpoints")
    if not isinstance(endpoints, dict):
        failures.append("ci_evidence_index.endpoints: expected object")
    else:
        if endpoints.get("html") != "/api/v1/ci/evidence-index":
            failures.append("ci_evidence_index.endpoints.html: unexpected path")
        if endpoints.get("json") != "/api/v1/ci/evidence-index.json":
            failures.append("ci_evidence_index.endpoints.json: unexpected path")
    families = surface.get("evidence_families")
    if not isinstance(families, list):
        failures.append("ci_evidence_index.evidence_families: expected array")
        return failures
    family_by_id = {
        family.get("id"): family for family in families if isinstance(family, dict)
    }
    for family_id in REQUIRED_CI_EVIDENCE_FAMILY_IDS:
        family = family_by_id.get(family_id)
        if family is None:
            failures.append(f"ci_evidence_index.evidence_families: missing {family_id}")
            continue
        if family.get("operator_action") != "download-ci-artifact":
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.operator_action: expected download-ci-artifact"
            )
        schema_versions = family.get("schema_versions")
        if not isinstance(schema_versions, list) or not schema_versions:
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.schema_versions: expected non-empty array"
            )
        artifact_pattern = family.get("artifact_name_pattern")
        if not isinstance(artifact_pattern, str) or "ao2-control-plane" not in artifact_pattern:
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.artifact_name_pattern: expected ao2-control-plane artifact pattern"
            )
        provenance = family.get("ci_artifact_provenance")
        if not isinstance(provenance, dict):
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance: expected object"
            )
        else:
            if provenance.get("provider") != "github-actions":
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.provider: expected github-actions"
                )
            if provenance.get("workflow_file") != ".github/workflows/ci.yml":
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.workflow_file: expected .github/workflows/ci.yml"
                )
            if provenance.get("workflow_name") != "CI":
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.workflow_name: expected CI"
                )
            if provenance.get("run_id_source") != "github_actions_run_id":
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.run_id_source: expected github_actions_run_id"
                )
            if provenance.get("token_free") is not True:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.token_free: expected true"
                )
            job_names = provenance.get("job_names")
            if not isinstance(job_names, list) or not job_names:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.job_names: expected non-empty array"
                )
            artifact_names = provenance.get("artifact_names")
            if not isinstance(artifact_names, list) or not artifact_names:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.artifact_names: expected non-empty array"
                )
            elif not all(isinstance(name, str) and "ao2-control-plane" in name for name in artifact_names):
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.artifact_names: expected ao2-control-plane artifact names"
                )
            run_url_template = provenance.get("run_url_template")
            if not isinstance(run_url_template, str) or "/actions/runs/<run_id>" not in run_url_template:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.run_url_template: expected GitHub Actions run template"
                )
            artifact_url_template = provenance.get("artifact_download_url_template")
            if not isinstance(artifact_url_template, str) or "/actions/runs/<run_id>/artifacts" not in artifact_url_template:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.artifact_download_url_template: expected GitHub Actions artifact template"
                )
            digest_reference = provenance.get("digest_reference")
            if not isinstance(digest_reference, str) or "summary" not in digest_reference:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.ci_artifact_provenance.digest_reference: expected summary digest reference"
                )
        trust_boundary = family.get("trust_boundary")
        if not isinstance(trust_boundary, dict):
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.trust_boundary: expected object"
            )
            continue
        if trust_boundary.get("read_only") is not True:
            failures.append(
                f"ci_evidence_index.evidence_families.{family_id}.trust_boundary.read_only: expected true"
            )
        for field_name in ("approves_release", "mutates_ao_artifacts"):
            if trust_boundary.get(field_name) is not False:
                failures.append(
                    f"ci_evidence_index.evidence_families.{family_id}.trust_boundary.{field_name}: expected false"
                )
    return failures


def hosted_release_smoke_semantic_failures(surface: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(surface, dict):
        return ["hosted_release_smoke: expected object"]
    if surface.get("schema_version") != "ao2.release-archive-hosted-smoke.v1":
        failures.append(
            "hosted_release_smoke.schema_version: expected ao2.release-archive-hosted-smoke.v1"
        )
    if surface.get("status") != "passed":
        failures.append("hosted_release_smoke.status: expected passed")
    if surface.get("install_verification_schema") != "ao2.install-verification-evidence.v1":
        failures.append(
            "hosted_release_smoke.install_verification_schema: expected ao2.install-verification-evidence.v1"
        )
    if not isinstance(surface.get("install_verification_evidence"), str) or not surface.get(
        "install_verification_evidence"
    ):
        failures.append(
            "hosted_release_smoke.install_verification_evidence: expected non-empty string"
        )
    for field_name in (
        "provider_api_keys_required",
        "control_plane_approves_release",
        "mutates_ao_artifacts",
    ):
        if surface.get(field_name) is not False:
            failures.append(f"hosted_release_smoke.{field_name}: expected false")
    if surface.get("release_acceptance_owner") != "factory-v3 evaluator-closer":
        failures.append(
            "hosted_release_smoke.release_acceptance_owner: expected factory-v3 evaluator-closer"
        )
    return failures


def main(argv: list[str]) -> int:
    parsed = parse_args(argv)
    if parsed is None:
        print(
            "usage: verify_release_support_bundle.py [--json] [--checksums SHA256SUMS] "
            "[--compare-against OTHER.json] release-support-bundle.json",
            file=sys.stderr,
        )
        return 2

    json_mode, checksums_path, compare_against_path, bundle_path = parsed
    raw_bundle = bundle_path.read_text(encoding="utf-8")
    bundle = json.loads(raw_bundle)
    manifest = bundle.get("portable_bundle_manifest", {})
    integrity = manifest.get("integrity", {})
    expected_sha = integrity.get("surface_sha256", {})
    surfaces = manifest.get("included_surfaces", [])

    bundle_sha256 = sha256_canonical(bundle)
    failures: list[str] = secret_marker_failures(raw_bundle)
    checksum_verified: bool | None = None
    if checksums_path is not None:
        checksum_check_failures = checksum_failures(checksums_path, bundle_path.name, bundle_sha256)
        failures.extend(checksum_check_failures)
        checksum_verified = not checksum_check_failures
    if bundle.get("schema_version") != "ao2.cp-release-support-bundle.v1":
        failures.append(
            "schema_version: expected ao2.cp-release-support-bundle.v1, "
            f"found {bundle.get('schema_version', 'missing')}"
        )
    if not isinstance(surfaces, list):
        failures.append("portable_bundle_manifest.included_surfaces: expected array")
        surfaces = []
    if not isinstance(expected_sha, dict):
        failures.append("integrity.surface_sha256: expected object")
        expected_sha = {}
    if manifest.get("schema_version") != EXPECTED_MANIFEST_SCHEMA:
        failures.append(
            f"portable_bundle_manifest.schema_version: expected {EXPECTED_MANIFEST_SCHEMA}, "
            f"found {manifest.get('schema_version', 'missing')}"
        )

    surface_ids = [surface.get("id", "missing") if isinstance(surface, dict) else "missing" for surface in surfaces]
    unknown_ids = sorted(set(surface_ids) - set(REQUIRED_SURFACE_IDS))
    missing_ids = [surface_id for surface_id in REQUIRED_SURFACE_IDS if surface_id not in surface_ids]
    duplicate_ids = sorted({surface_id for surface_id in surface_ids if surface_ids.count(surface_id) > 1})
    if len(surfaces) != len(REQUIRED_SURFACE_IDS):
        failures.append(
            f"portable_bundle_manifest.included_surfaces: expected {len(REQUIRED_SURFACE_IDS)} surfaces, found {len(surfaces)}"
        )
    for surface_id in missing_ids:
        failures.append(f"{surface_id}: missing required support-bundle surface")
    for surface_id in unknown_ids:
        failures.append(f"{surface_id}: unknown support-bundle surface id")
    for surface_id in duplicate_ids:
        failures.append(f"{surface_id}: duplicate support-bundle surface id")
    for surface_id in REQUIRED_SURFACE_IDS:
        if surface_id not in expected_sha:
            failures.append(f"{surface_id}: missing required integrity.surface_sha256 entry")
    verification_plan = integrity.get("verification_plan", {}) if isinstance(integrity, dict) else {}
    if verification_plan.get("surface_count") != len(REQUIRED_SURFACE_IDS):
        failures.append(
            f"verification_plan.surface_count: expected {len(REQUIRED_SURFACE_IDS)}, found {verification_plan.get('surface_count', 'missing')}"
        )

    for surface in surfaces:
        if not isinstance(surface, dict):
            failures.append(f"included_surfaces entry: expected object, found {type(surface).__name__}")
            continue
        surface_id = surface.get("id", "missing")
        declared_path = surface.get("path", "missing")
        expected_path = EXPECTED_JSON_PATHS.get(surface_id, "missing")
        manifest_sha = surface.get("sha256", "missing")
        integrity_sha = expected_sha.get(surface_id, "missing")
        try:
            embedded = get_surface(bundle, surface_id)
            recomputed_sha = sha256_canonical(embedded)
            embedded_schema = embedded.get("schema_version", "missing") if isinstance(embedded, dict) else "missing"
        except Exception as exc:  # noqa: BLE001 - command-line verifier should report all failures compactly.
            recomputed_sha = f"error:{exc}"
            embedded_schema = "missing"
        declared_schema = surface.get("schema_version", "missing")
        if not (
            declared_path == expected_path
            and manifest_sha != "missing"
            and integrity_sha != "missing"
            and manifest_sha == integrity_sha == recomputed_sha
            and declared_schema == embedded_schema
        ):
            failures.append(
                f"{surface_id}: path={declared_path!r}/{expected_path!r} "
                f"manifest={manifest_sha} integrity={integrity_sha} recomputed={recomputed_sha} "
                f"schema={declared_schema!r}/{embedded_schema!r}"
            )
        if surface_id == "ci_evidence_index":
            try:
                failures.extend(ci_evidence_index_semantic_failures(get_surface(bundle, surface_id)))
            except Exception as exc:  # noqa: BLE001 - keep verifier fail-closed and compact.
                failures.append(f"ci_evidence_index.semantic_validation: error {exc}")
        if surface_id == "hosted_release_smoke":
            try:
                failures.extend(hosted_release_smoke_semantic_failures(get_surface(bundle, surface_id)))
            except Exception as exc:  # noqa: BLE001 - keep verifier fail-closed and compact.
                failures.append(f"hosted_release_smoke.semantic_validation: error {exc}")

    trust = bundle.get("trust_boundary", {})
    if trust.get("role") != "read_only_observer" or trust.get("mutates_ao_artifacts") is not False:
        failures.append("trust_boundary: expected read_only_observer and mutates_ao_artifacts=false")

    correlation_hashes: dict[str, str] = {}
    for surface_id, field_name in CANDIDATE_CORRELATION_REQUIRED_SURFACES:
        try:
            embedded = get_surface(bundle, surface_id)
        except KeyError:
            continue
        if not isinstance(embedded, dict):
            failures.append(
                f"{surface_id}: {field_name} missing because surface is not an object"
            )
            continue
        correlation = embedded.get(field_name)
        if not isinstance(correlation, dict):
            failures.append(
                f"{surface_id}: {field_name} missing or not an object; "
                "operator triage requires this field on cockpit, handoff, readiness, and assembly surfaces"
            )
            continue
        status = correlation.get("status")
        if status not in ("matched", "mismatched"):
            failures.append(
                f"{surface_id}.{field_name}.status: expected matched|mismatched, found {status!r}"
            )
        if not isinstance(correlation.get("blockers"), list):
            failures.append(
                f"{surface_id}.{field_name}.blockers: expected array"
            )
        correlation_hashes[surface_id] = sha256_canonical(correlation)

    # Lane FF: cross-surface candidate_correlation byte-identity audit.
    # All four operator-triage surfaces (cockpit, handoff, readiness,
    # assembly_detail) embed the SAME candidate_correlation object by
    # construction — every render path calls candidate_correlation_value()
    # with the same underlying artifact evidence. A tampered offline bundle
    # could embed inconsistent objects across surfaces (e.g., cockpit shows
    # status=matched, readiness shows status=mismatched). The legacy per-
    # surface validation passes both individually because each is "valid"
    # in shape. The byte-identity check catches the cross-surface drift.
    if len(correlation_hashes) >= 2:
        distinct_hashes = sorted(set(correlation_hashes.values()))
        if len(distinct_hashes) > 1:
            buckets = ", ".join(
                f"{surface_id}={sha[:12]}"
                for surface_id, sha in sorted(correlation_hashes.items())
            )
            failures.append(
                "candidate_correlation_cross_surface_byte_identity: the four "
                "operator-triage surfaces (cockpit, handoff, readiness, "
                "assembly_detail) MUST embed byte-identical candidate_correlation "
                f"objects; found {len(distinct_hashes)} distinct canonical hashes "
                f"({buckets})"
            )

    # Lane HH: cross-surface byte-identity audit for the aggregate parity
    # verdicts. The control plane recomputes candidate_correlation_parity
    # (Lane W) and aggregates surface_content_hash_parity (Lane CC) from
    # the same underlying three-OS smoke evidence and then surfaces both
    # verdicts on cockpit, handoff, and readiness by construction. A
    # tampered offline bundle could expose "matched" on cockpit while
    # readiness/handoff still show "drift", visually misleading the
    # operator. The legacy per-surface validation passes individually
    # because each verdict is a valid enum string in isolation. The
    # cross-surface verdict audit catches the drift. Markers are listed
    # literally so the cross-script parity test can grep them.
    for verdict_field, marker in (
        (
            "candidate_correlation_parity",
            "candidate_correlation_parity_cross_surface_byte_identity",
        ),
        (
            "surface_content_hash_parity",
            "surface_content_hash_parity_cross_surface_byte_identity",
        ),
    ):
        verdicts: dict[str, str] = {}
        for surface_id in (
            "release_cockpit",
            "release_candidate_handoff",
            "release_readiness",
        ):
            try:
                surface = get_surface(bundle, surface_id)
            except KeyError:
                continue
            if not isinstance(surface, dict):
                continue
            value = surface.get(verdict_field)
            if isinstance(value, str):
                verdicts[surface_id] = value
        if len(verdicts) >= 2:
            distinct = sorted(set(verdicts.values()))
            if len(distinct) > 1:
                buckets = ", ".join(
                    f"{surface_id}={value!r}"
                    for surface_id, value in sorted(verdicts.items())
                )
                failures.append(
                    f"{marker}: the three operator-triage surfaces (cockpit, handoff, readiness) "
                    f"MUST agree on the aggregate {verdict_field} verdict; "
                    f"found {len(distinct)} distinct values ({buckets})"
                )

    # Lane ZZ: cross-surface rejected_smoke_audit byte-identity audit.
    # cockpit/handoff/readiness JSON each embed the same audit summary by
    # construction (the rejected_smoke_audit_summary reader is invoked once
    # per render and serialized into all three surfaces). A tampered offline
    # bundle could alter one surface's audit object — for instance bumping
    # cockpit's count to mask rejected tampering attempts on operator
    # surfaces while leaving readiness untouched. The per-surface shape
    # check would still pass (each is a valid object). The byte-identity
    # hash catches the cross-surface drift, paralleling Lane FF/HH for the
    # rotation-budget surface introduced in Lane XX.
    audit_hashes: dict[str, str] = {}
    for surface_id in REJECTED_SMOKE_AUDIT_SURFACES:
        try:
            surface = get_surface(bundle, surface_id)
        except KeyError:
            continue
        if not isinstance(surface, dict):
            continue
        audit = surface.get("rejected_smoke_audit")
        if not isinstance(audit, dict):
            continue
        audit_hashes[surface_id] = sha256_canonical(audit)
    if len(audit_hashes) >= 2:
        distinct_audit_hashes = sorted(set(audit_hashes.values()))
        if len(distinct_audit_hashes) > 1:
            buckets = ", ".join(
                f"{surface_id}={sha[:12]}"
                for surface_id, sha in sorted(audit_hashes.items())
            )
            failures.append(
                "rejected_smoke_audit_cross_surface_byte_identity: the three "
                "operator-triage surfaces (cockpit, handoff, readiness) MUST embed "
                "byte-identical rejected_smoke_audit objects; "
                f"found {len(distinct_audit_hashes)} distinct canonical hashes "
                f"({buckets})"
            )

    comparison_against: dict[str, Any] | None = None
    if compare_against_path is not None:
        try:
            raw_compare = compare_against_path.read_text(encoding="utf-8")
            compare_bundle = json.loads(raw_compare)
        except (OSError, json.JSONDecodeError) as exc:
            comparison_against = {
                "bundle_path": str(compare_against_path),
                "load_error": f"failed to load compare-against bundle: {exc}",
                "verdict_parity": False,
            }
            failures.append(
                f"comparison_against: failed to load {compare_against_path}: {exc}"
            )
        else:
            # Run secret-marker hygiene on the compare bundle too — a tampered
            # compare bundle leaking a bearer header is still operator-relevant
            # even though it's not the primary verification target.
            compare_secret_failures = secret_marker_failures(raw_compare)
            if compare_secret_failures:
                failures.extend(
                    f"comparison_against: {fail}"
                    for fail in compare_secret_failures
                )
            primary_view = collect_comparison_view(bundle)
            compare_view = collect_comparison_view(compare_bundle)
            compare_sha256 = sha256_canonical(compare_bundle)
            report, comparison_failures = comparison_diff(
                primary_view, compare_view, bundle_sha256, compare_sha256
            )
            report["bundle_path"] = str(compare_against_path)
            comparison_against = report
            failures.extend(comparison_failures)

    return emit_result(
        failures, surfaces, bundle, json_mode, checksum_verified, comparison_against
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
