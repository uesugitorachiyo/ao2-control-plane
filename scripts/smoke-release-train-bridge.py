#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER_SCHEMA = "ao2.cp-release-train-readback.v1"
RELEASE_TRAIN_SCHEMA = "ao2.public-release-train-drill.v1"
SUMMARY_SCHEMA = "ao2.cp-release-train-bridge-smoke.v1"
SUMMARY_ENV = "AO2_CP_RELEASE_TRAIN_SUMMARY"
PROVIDER_KEY_ENVS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
ABSOLUTE_PATH_CANARY = "/tmp/ao2-release-train-fixture"


def default_server_bin() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return ROOT / "target" / "release" / f"ao2-cp-server{suffix}"


def parse_args() -> argparse.Namespace:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser = argparse.ArgumentParser(
        description=(
            "Start ao2-cp-server against an AO2 public release-train summary "
            "fixture and verify JSON/HTML observer surfaces without printing "
            "bearer material."
        )
    )
    parser.add_argument(
        "--summary",
        default=str(ROOT / "tests" / "fixtures" / "public-release-train-summary.json"),
        help="AO2 public release-train drill summary path.",
    )
    parser.add_argument(
        "--server-bin",
        default=str(default_server_bin()),
        help="ao2-cp-server binary path.",
    )
    parser.add_argument(
        "--out-root",
        default=str(ROOT / "target" / "release-train-bridge-smoke" / stamp),
        help="Evidence output directory.",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("AO2_CP_RELEASE_TRAIN_BRIDGE_SMOKE_BIND", "127.0.0.1:19880"),
        help="Host:port bind address.",
    )
    return parser.parse_args()


def load_summary(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != RELEASE_TRAIN_SCHEMA:
        raise SystemExit(f"unexpected release-train schema: {payload.get('schema_version')}")
    if payload.get("status") != "passed":
        raise SystemExit(f"release-train fixture is not passed: {payload.get('status')}")
    contract = payload.get("release_readiness_artifact_consumer_contract")
    if not isinstance(contract, dict) or contract.get("status") != "passed":
        raise SystemExit("release-train fixture consumer contract is not passed")
    guards = payload.get("publish_guards")
    if not isinstance(guards, dict) or guards.get("refuses_publish_side_effects_by_default") is not True:
        raise SystemExit("release-train fixture publish guard is not strict")
    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        raise SystemExit("release-train fixture checks must be a non-empty list")
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
    summary_source_path = Path(args.summary).resolve()
    server_bin = Path(args.server_bin).resolve()
    out_root = Path(args.out_root).resolve()
    data_root = out_root / "data"
    logs_root = out_root / "logs"
    summary_path = out_root / "summary.json"
    json_path = out_root / "release-train-readback.json"
    html_path = out_root / "release-train-readback.html"
    stdout_path = logs_root / "server.out"
    stderr_path = logs_root / "server.err"

    if not summary_source_path.is_file():
        raise SystemExit(f"missing AO2 release-train summary: {summary_source_path}")
    if not server_bin.is_file():
        raise SystemExit(f"missing ao2-cp-server binary: {server_bin}")

    source_summary = load_summary(summary_source_path)
    out_root.mkdir(parents=True, exist_ok=True)
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
            observer_text = request_text(f"{base_url}/api/v1/release/train.json", token)
            html = request_text(f"{base_url}/api/v1/release/train", token)
        finally:
            if process is not None:
                terminate_process(process)

    json_path.write_text(observer_text, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    start_output = stdout_path.read_text(encoding="utf-8") + stderr_path.read_text(encoding="utf-8")
    observer = json.loads(observer_text)
    release_train = observer.get("release_train", {})

    checks = []

    def add_check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"detail": detail, "name": name, "status": "passed" if passed else "failed"})

    add_check("observer_schema", observer.get("schema_version") == OBSERVER_SCHEMA)
    add_check("release_train_schema", release_train.get("schema_version") == RELEASE_TRAIN_SCHEMA)
    add_check("release_train_status", release_train.get("status") == "passed")
    add_check(
        "consumer_contract_status",
        release_train.get("release_readiness_artifact_consumer_contract", {}).get("status") == "passed",
    )
    add_check(
        "publish_guard",
        release_train.get("publish_guards", {}).get("refuses_publish_side_effects_by_default") is True,
    )
    add_check("control_plane_role", observer.get("control_plane_role") == "read-only-observer")
    add_check("release_approval_deferred", observer.get("control_plane_approves_release") is False)
    add_check("mutates_ao_artifacts", observer.get("mutates_ao_artifacts") is False)
    add_check("mutates_observer_storage", observer.get("mutates_observer_storage") is False)
    add_check("credential_material_included", observer.get("auth", {}).get("credential_material_included") is False)
    add_check("credential_material_in_urls", observer.get("auth", {}).get("credential_material_in_urls") is False)
    add_check("configured_env", observer.get("source", {}).get("configured_env") == SUMMARY_ENV)
    add_check("source_status_preserved", release_train.get("status") == source_summary.get("status"))
    add_check("html_title", "AO2 Release Train Readback" in html)
    add_check("html_role", "read-only-observer" in html)
    add_check("html_release_train_schema", RELEASE_TRAIN_SCHEMA in html)
    add_check("token not in json", token not in observer_text)
    add_check("token not in html", token not in html)
    add_check("token not in start_output", token not in start_output)
    add_check("local_path_redacted_json", ABSOLUTE_PATH_CANARY not in observer_text)
    add_check("local_path_redacted_html", ABSOLUTE_PATH_CANARY not in html)
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
        "evidence_files": {
            "html_observer_name": "release-train-readback.html",
            "json_observer_name": "release-train-readback.json",
            "summary_name": "summary.json",
        },
        "html_observer": str(html_path),
        "json_observer": str(json_path),
        "release_train": {
            "configured_env": SUMMARY_ENV,
            "path_redacted": True,
            "schema_version": release_train.get("schema_version"),
            "status": release_train.get("status"),
        },
        "schema_version": SUMMARY_SCHEMA,
        "server_logs": {
            "stderr": str(stderr_path),
            "stdout": str(stdout_path),
        },
        "status": status,
        "trust_boundary": {
            "control_plane_approves_release": False,
            "control_plane_role": "read-only-observer",
            "credential_material_in_urls": False,
            "credential_material_included": False,
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

    print(f"release_train_bridge_smoke_root={out_root}")
    print(f"release_train_bridge_smoke_summary={summary_path}")
    print("release_train_bridge_smoke=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
