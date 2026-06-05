import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cp_dashboard_snapshot.py"


class DashboardHandler(BaseHTTPRequestHandler):
    seen_paths = []
    seen_authorizations = []

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        if self.path.startswith("/api/v1/"):
            auth = self.headers.get("Authorization", "")
            self.__class__.seen_paths.append(self.path)
            self.__class__.seen_authorizations.append(auth)
            if auth != "Bearer unit-token":
                self.send_response(401)
                self.end_headers()
                return
        if self.path.endswith(".json") or self.path == "/api/v1/status":
            body = b'{"schema_version":"test.v1","ok":true}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = (
            "<!doctype html><title>Dashboard</title>"
            f"<main>snapshot source {self.path}</main>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DashboardSnapshotTests(unittest.TestCase):
    def setUp(self):
        DashboardHandler.seen_paths = []
        DashboardHandler.seen_authorizations = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_helper(self, out_dir, env):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--base-url",
                self.base_url,
                "--out-dir",
                str(out_dir),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_fetches_dashboard_snapshots_with_header_and_writes_sanitized_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AO2_CP_API_TOKEN"] = "unit-token"
            result = self.run_helper(Path(tmp), env)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("unit-token", result.stdout)
            self.assertNotIn("unit-token", result.stderr)
            self.assertIn("/api/v1/phase1/promotion/dashboard", DashboardHandler.seen_paths)
            self.assertIn("/api/v1/storage/dashboard", DashboardHandler.seen_paths)
            self.assertTrue(DashboardHandler.seen_authorizations)
            self.assertTrue(
                all(value == "Bearer unit-token" for value in DashboardHandler.seen_authorizations)
            )

            out_dir = Path(tmp)
            manifest = (out_dir / "manifest.json").read_text()
            index = (out_dir / "index.html").read_text()
            self.assertIn("ao2.cp-dashboard-snapshot.v1", manifest)
            self.assertIn("Phase 1 Promotion", index)
            self.assertIn("Do not put bearer tokens in browser URLs", index)
            self.assertNotIn("unit-token", manifest)
            self.assertNotIn("Bearer unit-token", index)

            for path in out_dir.iterdir():
                if path.is_file():
                    text = path.read_text(errors="replace")
                    self.assertNotIn("unit-token", text, path)
                    self.assertNotIn("Bearer unit-token", text, path)

    def test_missing_token_env_fails_without_leaking_secret_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.pop("AO2_CP_API_TOKEN", None)
            result = self.run_helper(Path(tmp), env)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("AO2_CP_API_TOKEN", result.stderr)
            self.assertNotIn("Bearer ", result.stderr)
            self.assertFalse((Path(tmp) / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
