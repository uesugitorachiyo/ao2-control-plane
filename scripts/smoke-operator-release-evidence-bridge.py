#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import signal
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER_SCHEMA = "ao2.cp-operator-release-evidence-readback.v1"
OPERATOR_EVIDENCE_SCHEMA = "ao2.operator-release-evidence-bundle.v1"
SUMMARY_SCHEMA = "ao2.cp-operator-release-evidence-bridge-smoke.v1"
SUMMARY_ENV = "AO2_CP_OPERATOR_RELEASE_EVIDENCE_SUMMARY"
AO2_REPO = "uesugitorachiyo/ao2"
AO2_WORKFLOW = "Operator Release Evidence Audit"
AO2_ARTIFACT = "ao2-operator-release-evidence-bundle"
DUAL_PUBLIC_SMOKE_ARTIFACT = "ao2-dual-public-release-smoke"
PUBLIC_PAIR_DIGEST_ARTIFACT = "ao2-public-release-pair-digest-audit"
PROVIDER_KEY_ENVS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
ABSOLUTE_PATH_CANARIES = ("/private/ao2", "/Users/local")
REQUIRED_OPERATOR_EVIDENCE_ARTIFACTS = (
    "ao2-dual-repo-release-publication-closure-index",
    "post-stable-release-smoke-Linux",
    "post-stable-release-smoke-macOS",
    "post-stable-release-smoke-Windows",
    DUAL_PUBLIC_SMOKE_ARTIFACT,
    PUBLIC_PAIR_DIGEST_ARTIFACT,
    "ao2-control-plane-post-release-verification-ubuntu",
    "ao2-control-plane-post-release-verification-macos",
    "ao2-control-plane-post-release-verification-windows",
)


def default_server_bin() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return ROOT / "target" / "release" / f"ao2-cp-server{suffix}"


def parse_args() -> argparse.Namespace:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser = argparse.ArgumentParser(
        description=(
            "Start ao2-cp-server against an AO2 operator release evidence "
            "summary and verify the authenticated JSON/HTML readback surfaces "
            "without printing bearer material."
        )
    )
    parser.add_argument(
        "--summary",
        default=str(
            ROOT
            / "crates"
            / "ao2-cp-server"
            / "tests"
            / "fixtures"
            / "operator-release-evidence-bundle-summary.json"
        ),
        help="AO2 operator release evidence summary path.",
    )
    parser.add_argument(
        "--download-latest-ao2-artifact",
        action="store_true",
        help=(
            "Download the latest successful AO2 Operator Release Evidence Audit "
            "artifact and use its summary.json instead of --summary."
        ),
    )
    parser.add_argument(
        "--server-bin",
        default=str(default_server_bin()),
        help="ao2-cp-server binary path.",
    )
    parser.add_argument(
        "--out-root",
        default=str(ROOT / "target" / "operator-release-evidence-bridge-smoke" / stamp),
        help="Evidence output directory.",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("AO2_CP_OPERATOR_RELEASE_EVIDENCE_BRIDGE_SMOKE_BIND", "127.0.0.1:19881"),
        help="Host:port bind address.",
    )
    return parser.parse_args()


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def download_latest_ao2_artifact(out_root: Path) -> Path:
    artifact_dir = out_root / "downloaded-ao2-operator-release-evidence"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    runs = run_command(
        [
            "gh",
            "run",
            "list",
            "--repo",
            AO2_REPO,
            "--branch",
            "main",
            "--workflow",
            AO2_WORKFLOW,
            "--status",
            "success",
            "--limit",
            "10",
            "--json",
            "databaseId",
            "--jq",
            ".[].databaseId",
        ],
        ROOT,
    ).stdout.splitlines()

    last_error = ""
    for run_id in runs:
        if not run_id.strip():
            continue
        shutil.rmtree(artifact_dir, ignore_errors=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [
                "gh",
                "run",
                "download",
                run_id.strip(),
                "--repo",
                AO2_REPO,
                "--name",
                AO2_ARTIFACT,
                "--dir",
                str(artifact_dir),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0:
            (artifact_dir / "run-id.txt").write_text(run_id.strip() + "\n", encoding="utf-8")
            summary = artifact_dir / "summary.json"
            if summary.is_file():
                return summary
            last_error = f"downloaded {AO2_ARTIFACT} from run {run_id}, but summary.json was missing"
        else:
            last_error = result.stderr.strip()

    raise SystemExit(f"unable to download latest {AO2_ARTIFACT}: {last_error}")


def load_operator_summary(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != OPERATOR_EVIDENCE_SCHEMA:
        raise SystemExit(f"unexpected operator evidence schema: {payload.get('schema_version')}")
    if payload.get("status") != "passed":
        raise SystemExit(f"operator evidence summary is not passed: {payload.get('status')}")
    if payload.get("operator_release_evidence_ready") is not True:
        raise SystemExit("operator evidence summary is not release-ready")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise SystemExit("operator evidence summary must contain checks")
    present_artifacts = {check.get("artifact") for check in checks if isinstance(check, dict)}
    missing_artifacts = [
        artifact for artifact in REQUIRED_OPERATOR_EVIDENCE_ARTIFACTS if artifact not in present_artifacts
    ]
    if missing_artifacts:
        raise SystemExit(
            "operator evidence summary missing required checks: " + ", ".join(missing_artifacts)
        )
    dual_public = next(
        (check for check in checks if check.get("artifact") == DUAL_PUBLIC_SMOKE_ARTIFACT),
        None,
    )
    if dual_public is None:
        raise SystemExit(f"operator evidence summary missing {DUAL_PUBLIC_SMOKE_ARTIFACT}")
    if (
        dual_public.get("schema_version") != "ao2.dual-public-release-smoke.v1"
        or dual_public.get("task_board_readback_schema") != "ao2.cp-ai-task-board-readback.v1"
        or dual_public.get("task_board_dashboard_schema") != "ao2.cp-ai-task-board-dashboard.v1"
        or dual_public.get("auth_value_stored") is not False
        or dual_public.get("credential_material_in_urls") is not False
        or dual_public.get("control_plane_approves_release") is not False
    ):
        raise SystemExit("operator evidence dual public smoke check is not read-only and schema-complete")
    public_pair_digest = next(
        (check for check in checks if check.get("artifact") == PUBLIC_PAIR_DIGEST_ARTIFACT),
        None,
    )
    if public_pair_digest is None:
        raise SystemExit(f"operator evidence summary missing {PUBLIC_PAIR_DIGEST_ARTIFACT}")
    if (
        public_pair_digest.get("schema_version") != "ao2.public-release-pair-digest-audit.v1"
        or public_pair_digest.get("summary_status") != "passed"
        or public_pair_digest.get("archive_parity_status") != "passed"
        or public_pair_digest.get("mutates_releases") is not False
        or public_pair_digest.get("stores_credentials") is not False
    ):
        raise SystemExit("operator evidence public pair digest audit check is not read-only and archive-complete")
    if any(check.get("status") != "passed" for check in checks):
        raise SystemExit("operator evidence summary contains a non-passing check")
    trust = payload.get("trust_boundary")
    if not isinstance(trust, dict):
        raise SystemExit("operator evidence summary missing trust boundary")
    if trust.get("mutates_releases") is not False or trust.get("stores_credentials") is not False:
        raise SystemExit("operator evidence summary trust boundary is not read-only")
    return payload


def request_text(url: str, token: str, timeout: float = 5.0) -> str:
    request = urllib.request.Request(url)
    request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def wait_for_healthz(base_url: str, timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=1.0) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.2)
    raise RuntimeError(f"healthz did not become ready: {last_error}")


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    args = parse_args()
    out_root = Path(args.out_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    summary_source_path = (
        download_latest_ao2_artifact(out_root)
        if args.download_latest_ao2_artifact
        else Path(args.summary).resolve()
    )
    server_bin = Path(args.server_bin).resolve()
    data_root = out_root / "data"
    logs_root = out_root / "logs"
    summary_path = out_root / "summary.json"
    json_path = out_root / "operator-release-evidence-readback.json"
    html_path = out_root / "operator-release-evidence-readback.html"
    stdout_path = logs_root / "server.out"
    stderr_path = logs_root / "server.err"

    if not summary_source_path.is_file():
        raise SystemExit(f"missing AO2 operator release evidence summary: {summary_source_path}")
    if not server_bin.is_file():
        raise SystemExit(f"missing ao2-cp-server binary: {server_bin}")

    source_summary = load_operator_summary(summary_source_path)
    data_root.mkdir(parents=True, exist_ok=True)
    logs_root.mkdir(parents=True, exist_ok=True)

    token = secrets.token_hex(32)
    env = os.environ.copy()
    for provider_key in PROVIDER_KEY_ENVS:
        env.pop(provider_key, None)
    env.update(
        {
            "AO2_CP_API_TOKEN": token,
            "AO2_CP_BIND": args.bind,
            "AO2_CP_DATA_DIR": str(data_root),
            SUMMARY_ENV: str(summary_source_path),
        }
    )

    process = None
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        try:
            process = subprocess.Popen(
                [str(server_bin)],
                cwd=str(ROOT),
                env=env,
                stdout=stdout,
                stderr=stderr,
                text=True,
            )
            base_url = f"http://{args.bind}"
            wait_for_healthz(base_url)
            observer_text = request_text(f"{base_url}/api/v1/release/operator-evidence.json", token)
            html = request_text(f"{base_url}/api/v1/release/operator-evidence", token)
        finally:
            if process is not None:
                terminate_process(process)

    json_path.write_text(observer_text, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    start_output = stdout_path.read_text(encoding="utf-8") + stderr_path.read_text(encoding="utf-8")
    observer = json.loads(observer_text)
    operator_evidence = observer.get("operator_release_evidence", {})

    checks = []

    def add_check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"detail": detail, "name": name, "status": "passed" if passed else "failed"})

    add_check("observer_schema", observer.get("schema_version") == OBSERVER_SCHEMA)
    add_check("operator_evidence_schema", operator_evidence.get("schema_version") == OPERATOR_EVIDENCE_SCHEMA)
    add_check("operator_evidence_status", operator_evidence.get("status") == "passed")
    add_check("operator_evidence_ready", operator_evidence.get("operator_release_evidence_ready") is True)
    present_artifacts = {
        check.get("artifact")
        for check in operator_evidence.get("checks", [])
        if isinstance(check, dict)
    }
    missing_artifacts = [
        artifact for artifact in REQUIRED_OPERATOR_EVIDENCE_ARTIFACTS if artifact not in present_artifacts
    ]
    add_check(
        "operator_evidence_required_artifacts",
        not missing_artifacts,
        ", ".join(missing_artifacts),
    )
    observer_dual_public = next(
        (
            check
            for check in operator_evidence.get("checks", [])
            if check.get("artifact") == DUAL_PUBLIC_SMOKE_ARTIFACT
        ),
        {},
    )
    add_check("dual_public_smoke_present", bool(observer_dual_public))
    add_check(
        "dual_public_readback_schema",
        observer_dual_public.get("task_board_readback_schema")
        == "ao2.cp-ai-task-board-readback.v1",
    )
    add_check(
        "dual_public_dashboard_schema",
        observer_dual_public.get("task_board_dashboard_schema")
        == "ao2.cp-ai-task-board-dashboard.v1",
    )
    add_check("dual_public_auth_value_not_stored", observer_dual_public.get("auth_value_stored") is False)
    add_check(
        "dual_public_credential_material_not_in_urls",
        observer_dual_public.get("credential_material_in_urls") is False,
    )
    add_check(
        "dual_public_control_plane_does_not_approve_release",
        observer_dual_public.get("control_plane_approves_release") is False,
    )
    observer_public_pair_digest = next(
        (
            check
            for check in operator_evidence.get("checks", [])
            if check.get("artifact") == PUBLIC_PAIR_DIGEST_ARTIFACT
        ),
        {},
    )
    add_check("public_pair_digest_present", bool(observer_public_pair_digest))
    add_check(
        "public_pair_digest_schema",
        observer_public_pair_digest.get("schema_version")
        == "ao2.public-release-pair-digest-audit.v1",
    )
    add_check(
        "public_pair_digest_archive_parity",
        observer_public_pair_digest.get("archive_parity_status") == "passed",
    )
    add_check(
        "public_pair_digest_does_not_mutate_releases",
        observer_public_pair_digest.get("mutates_releases") is False,
    )
    add_check(
        "public_pair_digest_stores_no_credentials",
        observer_public_pair_digest.get("stores_credentials") is False,
    )
    add_check("operator_evidence_matches_source", operator_evidence.get("status") == source_summary.get("status"))
    add_check("control_plane_role", observer.get("control_plane_role") == "read-only-observer")
    add_check("release_approval_deferred", observer.get("control_plane_approves_release") is False)
    add_check("mutates_ao_artifacts", observer.get("mutates_ao_artifacts") is False)
    add_check("mutates_observer_storage", observer.get("mutates_observer_storage") is False)
    add_check("credential_material_included", observer.get("auth", {}).get("credential_material_included") is False)
    add_check("credential_material_in_urls", observer.get("auth", {}).get("credential_material_in_urls") is False)
    add_check("configured_env", observer.get("source", {}).get("configured_env") == SUMMARY_ENV)
    add_check("html_title", "AO2 Operator Release Evidence" in html)
    add_check("html_role", "read-only-observer" in html)
    add_check("html_operator_evidence_schema", OPERATOR_EVIDENCE_SCHEMA in html)
    add_check("html_dual_public_smoke", DUAL_PUBLIC_SMOKE_ARTIFACT in html)
    add_check("html_dual_public_readback_schema", "ao2.cp-ai-task-board-readback.v1" in html)
    add_check("html_dual_public_trust_boundary", "control_plane_approves_release=false" in html)
    add_check("html_public_pair_digest", PUBLIC_PAIR_DIGEST_ARTIFACT in html)
    add_check(
        "html_public_pair_digest_archive_parity",
        "archive_parity_status=passed" in html,
    )
    add_check("html_public_pair_digest_read_only", "mutates_releases=false" in html)
    add_check("token not in json", token not in observer_text)
    add_check("token not in html", token not in html)
    add_check("token not in start_output", token not in start_output)
    add_check(
        "local_path_redacted_json",
        all(canary not in observer_text for canary in ABSOLUTE_PATH_CANARIES),
    )
    add_check(
        "local_path_redacted_html",
        all(canary not in html for canary in ABSOLUTE_PATH_CANARIES),
    )
    add_check(
        "provider_keys_absent",
        all(provider_key not in observer_text for provider_key in PROVIDER_KEY_ENVS)
        and all(provider_key not in html for provider_key in PROVIDER_KEY_ENVS)
        and all(provider_key not in start_output for provider_key in PROVIDER_KEY_ENVS),
    )

    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    summary = {
        "bind": args.bind,
        "checks": checks,
        "downloaded_latest_ao2_artifact": bool(args.download_latest_ao2_artifact),
        "evidence_files": {
            "html_observer_name": "operator-release-evidence-readback.html",
            "json_observer_name": "operator-release-evidence-readback.json",
            "summary_name": "summary.json",
        },
        "html_observer": str(html_path),
        "json_observer": str(json_path),
        "operator_release_evidence": {
            "configured_env": SUMMARY_ENV,
            "path_redacted": True,
            "schema_version": operator_evidence.get("schema_version"),
            "status": operator_evidence.get("status"),
            "operator_release_evidence_ready": operator_evidence.get("operator_release_evidence_ready"),
        },
        "schema_version": SUMMARY_SCHEMA,
        "server_logs": {
            "stderr": str(stderr_path),
            "stdout": str(stdout_path),
        },
        "status": status,
        "summary_source": str(summary_source_path),
        "trust_boundary": {
            "control_plane_approves_release": False,
            "control_plane_role": "read-only-observer",
            "credential_material_in_urls": False,
            "credential_material_included": False,
            "downloads_github_actions_artifacts": bool(args.download_latest_ao2_artifact),
            "mutates_ao_artifacts": False,
            "mutates_observer_storage": False,
            "provider_api_keys_allowed": False,
            "token_printed": False,
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if status != "passed":
        for check in checks:
            if check["status"] != "passed":
                print(f"failed={check['name']} {check.get('detail', '')}", file=sys.stderr)
        return 1

    print(f"operator_release_evidence_bridge_smoke_root={out_root}")
    print(f"operator_release_evidence_bridge_smoke_summary={summary_path}")
    print("operator_release_evidence_bridge_smoke=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
