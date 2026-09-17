import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SERVER_PATH = Path(__file__).resolve().parents[1] / "web" / "server.py"
SPEC = importlib.util.spec_from_file_location("santet_web", SERVER_PATH)
assert SPEC and SPEC.loader
WEB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WEB
SPEC.loader.exec_module(WEB)


class OverviewTests(unittest.TestCase):
    def test_overview_summarizes_local_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "artifacts" / "security"
            report.mkdir(parents=True)
            (report / "scan.sarif").write_text(json.dumps({
                "runs": [{
                    "tool": {"driver": {"rules": [{
                        "id": "unsafe",
                        "properties": {"security-severity": "8.1"},
                    }]}},
                    "results": [{"ruleId": "unsafe", "level": "error"}],
                }],
            }), encoding="utf-8")
            (report / "sbom.cdx.json").write_text(
                json.dumps({"components": [{"name": "one"}, {"name": "two"}]}),
                encoding="utf-8",
            )

            result = WEB.overview(root)
            self.assertEqual(result["findings"]["high"], 1)
            self.assertEqual(result["components"], 2)
            self.assertEqual(result["artifactCount"], 2)
            self.assertEqual(result["posture"], "attention")


class CommandContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = WEB.JobManager(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_arbitrary_command(self):
        with self.assertRaisesRegex(ValueError, "not available"):
            self.manager._build_command({"command": "shell"})

    def test_rejects_image_shell_characters(self):
        with self.assertRaisesRegex(ValueError, "valid"):
            self.manager._build_command({"command": "image-scan", "image": "app:latest;id"})

    def test_builds_bounded_cloud_command(self):
        command, argv, env = self.manager._build_command({
            "command": "cloud-inventory",
            "provider": "gcp",
            "target": "sandbox",
        })
        self.assertEqual(command, "cloud-inventory")
        self.assertEqual(argv[-2:], ["cloud-inventory", "gcp"])
        self.assertEqual(env["SANTET_CLOUD_TARGET"], "sandbox")

    def test_cluster_read_requires_exact_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.manager._build_command({
                "command": "kubearmor-status",
                "context": "dev-cluster",
                "allowClusterRead": False,
            })


class HTTPContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = WEB.SantetHTTPServer(("127.0.0.1", 0), Path(self.temp.name))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def json_get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=3) as response:
            return response, json.loads(response.read())

    def test_health_and_static_dashboard(self):
        response, health = self.json_get("/api/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(health["mode"], "local-rnd")
        self.assertTrue(health["csrfToken"])
        with urllib.request.urlopen(self.base + "/", timeout=3) as response:
            body = response.read().decode()
        self.assertIn("Local Security Console", body)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_post_requires_local_request_token(self):
        request = urllib.request.Request(
            self.base + "/api/jobs",
            method="POST",
            data=b'{"command":"doctor"}',
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(context.exception.code, 403)
        context.exception.close()

    def test_non_local_host_header_is_rejected(self):
        request = urllib.request.Request(
            self.base + "/api/health",
            headers={"Host": "dashboard.example.test"},
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(context.exception.code, 403)
        context.exception.close()

    def test_artifact_traversal_is_blocked(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(self.base + "/api/artifacts/../../README.md", timeout=3)
        self.assertIn(context.exception.code, {403, 404})
        context.exception.close()


if __name__ == "__main__":
    unittest.main()
