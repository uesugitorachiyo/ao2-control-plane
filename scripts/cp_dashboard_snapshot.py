#!/usr/bin/env python3
"""Fetch token-safe local AO2 Control Plane dashboard snapshots.

The helper reads the bearer value from an environment variable, sends it only
as an HTTP Authorization header, and writes local HTML/JSON snapshots plus a
sanitized manifest. It never puts bearer tokens in URLs, stdout, stderr, or the
generated files.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ao2.cp-dashboard-snapshot.v1"

DEFAULT_SURFACES = [
    {
        "name": "Phase 1 Promotion",
        "endpoint": "/api/v1/phase1/promotion/dashboard",
        "filename": "phase1-promotion-dashboard.html",
    },
    {
        "name": "Storage",
        "endpoint": "/api/v1/storage/dashboard",
        "filename": "storage-dashboard.html",
    },
    {
        "name": "Audit Log",
        "endpoint": "/api/v1/audit-log/dashboard",
        "filename": "audit-log-dashboard.html",
    },
    {
        "name": "Signed Evidence",
        "endpoint": "/api/v1/evidence-pack/dashboard",
        "filename": "evidence-pack-dashboard.html",
    },
    {
        "name": "Route Index",
        "endpoint": "/api/v1/control-plane/routes.json",
        "filename": "routes.json",
    },
    {
        "name": "CI Evidence Index",
        "endpoint": "/api/v1/ci/evidence-index",
        "filename": "ci-evidence-index.html",
    },
    {
        "name": "CI Evidence Index JSON",
        "endpoint": "/api/v1/ci/evidence-index.json",
        "filename": "ci-evidence-index.json",
    },
    {
        "name": "Status",
        "endpoint": "/api/v1/status",
        "filename": "status.json",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_url(base_url: str, endpoint: str) -> str:
    return f"{base_url.rstrip('/')}{endpoint}"


def require_token(api_token_env: str) -> str:
    token = os.environ.get(api_token_env, "")
    if not token:
        raise ValueError(
            f"missing {api_token_env}; export the control-plane token in an environment variable"
        )
    return token


def fetch_surface(base_url: str, endpoint: str, token: str, timeout: float) -> tuple[bytes, str, int]:
    request = urllib.request.Request(
        build_url(base_url, endpoint),
        headers={
            "Accept": "text/html,application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: operator-provided local/private CP URL
        return response.read(), response.headers.get("content-type", ""), response.status


def assert_token_safe(raw: bytes, token: str, label: str) -> None:
    text = raw.decode("utf-8", errors="replace")
    forbidden = [
        token,
        f"Bearer {token}",
        f"token={token}",
        f"api_token={token}",
    ]
    for marker in forbidden:
        if marker and marker in text:
            raise ValueError(f"{label} contained a bearer-token value; refusing to write snapshots")


def write_index(out_dir: Path, manifest: dict[str, Any]) -> Path:
    rows = []
    for surface in manifest["surfaces"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(surface['name'])}</td>"
            f"<td><a href=\"{html.escape(surface['filename'])}\">{html.escape(surface['filename'])}</a></td>"
            f"<td><code>{html.escape(surface['endpoint'])}</code></td>"
            f"<td>{surface['status_code']}</td>"
            f"<td><code>{surface['sha256']}</code></td>"
            "</tr>"
        )
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AO2 Control Plane Dashboard Snapshots</title>
  <style>
    body {{ margin: 2rem; max-width: 76rem; font-family: ui-serif, Georgia, Cambria, "Times New Roman", serif; color: #17201b; background: #f7f8f5; }}
    h1 {{ margin-bottom: .25rem; font-size: clamp(2rem, 4vw, 3.5rem); line-height: 1; }}
    p {{ max-width: 52rem; color: #56635d; line-height: 1.55; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cfd8d3; }}
    th, td {{ padding: .7rem; border-bottom: 1px solid #cfd8d3; text-align: left; vertical-align: top; }}
    th {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; color: #56635d; }}
    code {{ overflow-wrap: anywhere; }}
    a {{ color: #0b6b4f; font-weight: 700; }}
    .notice {{ border-left: 4px solid #8a4b00; padding-left: 1rem; }}
  </style>
</head>
<body>
  <main>
    <h1>AO2 Control Plane Dashboard Snapshots</h1>
    <p>Generated at {html.escape(manifest['generated_at_utc'])} from {html.escape(manifest['base_url'])}. These files are local read-only snapshots fetched with an Authorization header.</p>
    <p class="notice">Do not put bearer tokens in browser URLs. This snapshot intentionally stores no bearer-token value and does not approve releases, start providers, or mutate AO artifacts.</p>
    <table>
      <thead><tr><th>Surface</th><th>Local File</th><th>Source Endpoint</th><th>Status</th><th>SHA-256</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    <p><a href="manifest.json">Manifest JSON</a></p>
  </main>
</body>
</html>
"""
    path = out_dir / "index.html"
    path.write_text(body, encoding="utf-8")
    return path


def build_snapshots(args: argparse.Namespace) -> dict[str, Any]:
    token = require_token(args.api_token_env)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    surfaces = []
    for surface in DEFAULT_SURFACES:
        raw, content_type, status_code = fetch_surface(
            args.base_url, surface["endpoint"], token, args.timeout_seconds
        )
        assert_token_safe(raw, token, surface["endpoint"])
        path = out_dir / surface["filename"]
        path.write_bytes(raw)
        surfaces.append(
            {
                "name": surface["name"],
                "endpoint": surface["endpoint"],
                "filename": surface["filename"],
                "status_code": status_code,
                "content_type": content_type,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            }
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "base_url": args.base_url.rstrip("/"),
        "api_token_env": args.api_token_env,
        "token_in_output": False,
        "trust_boundary": {
            "control_plane_role": "read_only_observer",
            "mutates_ao_artifacts": False,
            "control_plane_approves_release": False,
            "release_acceptance_owner": "factory-v3 evaluator-closer",
        },
        "surfaces": surfaces,
    }
    manifest_raw = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    assert_token_safe(manifest_raw, token, "manifest")
    (out_dir / "manifest.json").write_bytes(manifest_raw)
    index_path = write_index(out_dir, manifest)
    assert_token_safe(index_path.read_bytes(), token, "index")
    if args.open:
        webbrowser.open(index_path.resolve().as_uri())
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "out_dir": str(out_dir),
        "index": str(index_path),
        "manifest": str(out_dir / "manifest.json"),
        "surface_count": len(surfaces),
        "token_in_output": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8744")
    parser.add_argument("--api-token-env", default="AO2_CP_API_TOKEN")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--open", action="store_true", help="Open the generated local index in the default browser.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        summary = build_snapshots(args)
    except urllib.error.HTTPError as exc:
        print(f"cp-dashboard-snapshot: HTTP {exc.code} while fetching {exc.url}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"cp-dashboard-snapshot: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
