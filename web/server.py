#!/usr/bin/env python3
"""Local-only Web UI backend for Santet DevSecOps.

The UI is intentionally dependency-free and delegates all security work to the
existing Santet CLI. It does not expose a shell or cluster-changing commands.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import secrets
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


TOOL_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = Path(__file__).resolve().parent / "static"
POLICY_PATH = TOOL_ROOT / ".santet" / "policy.env"
PROVIDERS = {"aws", "azure", "gcp", "alibabacloud", "all"}
CATALOGS = {"checks", "services", "compliance", "categories"}
SAFE_COMMANDS = {
    "doctor",
    "scan",
    "secrets",
    "sast",
    "dependencies",
    "filesystem",
    "kube-lint",
    "sbom",
    "image-scan",
    "cloud-validate",
    "cloud-doctor",
    "cloud-inventory",
    "cloud-scan",
    "cloud-list",
    "cluster-doctor",
    "kubearmor-status",
    "kubearmor-probe",
    "kubearmor-policy-check",
}
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CONTEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,191}$")
MAX_BODY = 32 * 1024
MAX_LOG_CHARS = 600_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_version() -> str:
    try:
        for line in POLICY_PATH.read_text(encoding="utf-8").splitlines():
            if line.startswith("SANTET_VERSION="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "development"


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def sarif_counts(path: Path) -> dict[str, int]:
    data = read_json(path)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    if not isinstance(data, dict):
        return counts
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        rules: dict[str, str] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []) if isinstance(driver, dict) else []:
            if not isinstance(rule, dict):
                continue
            severity = str(rule.get("properties", {}).get("security-severity", ""))
            level = str(rule.get("defaultConfiguration", {}).get("level", ""))
            try:
                score = float(severity)
            except ValueError:
                score = -1
            category = (
                "critical" if score >= 9 else
                "high" if score >= 7 else
                "medium" if score >= 4 else
                "low" if score >= 0 else
                "high" if level == "error" else
                "medium" if level == "warning" else
                "low" if level == "note" else "unknown"
            )
            rules[str(rule.get("id", ""))] = category
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            category = rules.get(str(result.get("ruleId", "")))
            if not category:
                level = str(result.get("level", ""))
                category = {"error": "high", "warning": "medium", "note": "low"}.get(level, "unknown")
            counts[category] += 1
    return counts


def recursive_vulnerability_ids(value: Any, found: set[str]) -> None:
    if isinstance(value, dict):
        vulnerabilities = value.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:
                if isinstance(item, dict):
                    identifier = item.get("id") or item.get("aliases") or item.get("summary")
                    found.add(json.dumps(identifier, sort_keys=True))
                else:
                    found.add(str(item))
        for child in value.values():
            recursive_vulnerability_ids(child, found)
    elif isinstance(value, list):
        for child in value:
            recursive_vulnerability_ids(child, found)


def artifact_inventory(report_root: Path) -> list[dict[str, Any]]:
    if not report_root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    resolved_root = report_root.resolve()
    for path in report_root.rglob("*"):
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            path.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        relative = path.relative_to(report_root).as_posix()
        stat = path.stat()
        items.append({
            "name": path.name,
            "path": relative,
            "kind": path.suffix.lower().lstrip(".") or "file",
            "size": stat.st_size,
            "updatedAt": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return sorted(items, key=lambda item: item["updatedAt"], reverse=True)


def overview(target_root: Path) -> dict[str, Any]:
    report_root = target_root / "artifacts" / "security"
    sarif_total = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for path in report_root.rglob("*.sarif") if report_root.is_dir() else []:
        for severity, count in sarif_counts(path).items():
            sarif_total[severity] += count

    osv_ids: set[str] = set()
    osv = read_json(report_root / "osv.json")
    if osv is not None:
        recursive_vulnerability_ids(osv, osv_ids)

    kube_data = read_json(report_root / "kube-linter.json")
    kube_findings = 0
    if isinstance(kube_data, dict):
        reports = kube_data.get("Reports", [])
        kube_findings = len(reports) if isinstance(reports, list) else 0

    sbom_data = read_json(report_root / "sbom.cdx.json")
    components = 0
    if isinstance(sbom_data, dict) and isinstance(sbom_data.get("components"), list):
        components = len(sbom_data["components"])

    artifacts = artifact_inventory(report_root)
    latest = artifacts[0]["updatedAt"] if artifacts else None
    blocking = sarif_total["critical"] + sarif_total["high"] + len(osv_ids)
    posture = "attention" if blocking else "clear" if artifacts else "not-scanned"
    return {
        "version": read_version(),
        "target": str(target_root),
        "posture": posture,
        "findings": sarif_total,
        "dependencyVulnerabilities": len(osv_ids),
        "kubernetesFindings": kube_findings,
        "components": components,
        "artifactCount": len(artifacts),
        "latestEvidenceAt": latest,
        "artifacts": artifacts[:8],
        "providers": ["AWS", "Azure", "Google Cloud", "Alibaba Cloud"],
    }


@dataclass
class Job:
    id: str
    command: str
    argv: list[str]
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    log: str = ""
    process: subprocess.Popen[str] | None = field(default=None, repr=False)

    def public(self, include_log: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.id,
            "command": self.command,
            "argv": self.argv,
            "status": self.status,
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "exitCode": self.exit_code,
        }
        if include_log:
            value["log"] = self.log
        return value


class JobManager:
    def __init__(self, target_root: Path):
        self.target_root = target_root
        self.jobs: dict[str, Job] = {}
        self.lock = threading.RLock()
        self.execution_lock = threading.Lock()

    def list(self) -> list[dict[str, Any]]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda job: job.created_at, reverse=True)
            return [job.public(include_log=False) for job in jobs[:20]]

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def active(self) -> Job | None:
        with self.lock:
            return next((job for job in self.jobs.values() if job.status in {"queued", "running"}), None)

    def create(self, payload: dict[str, Any]) -> Job:
        command, argv, env = self._build_command(payload)
        with self.lock:
            if next((item for item in self.jobs.values() if item.status in {"queued", "running"}), None):
                raise RuntimeError("Another security job is already running. Wait or cancel it first.")
            job = Job(id=secrets.token_hex(6), command=command, argv=argv)
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, env), daemon=True).start()
        return job

    def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        if not job:
            raise KeyError(job_id)
        with self.lock:
            if job.status not in {"queued", "running"}:
                return job
            process = job.process
            job.status = "cancelling"
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        return job

    def _append(self, job: Job, text: str) -> None:
        with self.lock:
            job.log = (job.log + text)[-MAX_LOG_CHARS:]

    def _run(self, job: Job, env: dict[str, str]) -> None:
        with self.execution_lock:
            with self.lock:
                if job.status == "cancelling":
                    job.status = "cancelled"
                    job.finished_at = utc_now()
                    return
                job.status = "running"
                job.started_at = utc_now()
            self._append(job, f"$ {' '.join(job.argv)}\n\n")
            try:
                process = subprocess.Popen(
                    job.argv,
                    cwd=self.target_root,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                with self.lock:
                    job.process = process
                assert process.stdout is not None
                for line in process.stdout:
                    self._append(job, line)
                return_code = process.wait()
                with self.lock:
                    job.exit_code = return_code
                    if job.status == "cancelling":
                        job.status = "cancelled"
                    else:
                        job.status = "succeeded" if return_code == 0 else "failed"
            except OSError as exc:
                self._append(job, f"Unable to start Santet: {exc}\n")
                with self.lock:
                    job.exit_code = 127
                    job.status = "failed"
            finally:
                with self.lock:
                    job.process = None
                    job.finished_at = utc_now()

    def _build_command(self, payload: dict[str, Any]) -> tuple[str, list[str], dict[str, str]]:
        command = str(payload.get("command", "")).strip()
        if command not in SAFE_COMMANDS:
            raise ValueError("Command is not available in the local Web UI.")
        argv = [str(TOOL_ROOT / "santet"), command]
        env = os.environ.copy()
        env["SANTET_TARGET_DIR"] = str(self.target_root)

        if command.startswith("cloud-") and command != "cloud-validate":
            provider = str(payload.get("provider", "aws")).strip().lower()
            if provider not in PROVIDERS:
                raise ValueError("Unsupported cloud provider.")
            if command == "cloud-list" and provider == "all":
                raise ValueError("Catalog listing requires one provider.")
            argv.append(provider)
            if command == "cloud-list":
                catalog = str(payload.get("catalog", "checks")).strip().lower()
                if catalog not in CATALOGS:
                    raise ValueError("Unsupported cloud catalog.")
                argv.append(catalog)
            target = str(payload.get("target", "local-rnd")).strip()
            if not LABEL_RE.fullmatch(target):
                raise ValueError("Cloud target must be a safe label.")
            env["SANTET_CLOUD_TARGET"] = target

        if command == "image-scan":
            image = str(payload.get("image", "")).strip()
            if not IMAGE_RE.fullmatch(image):
                raise ValueError("Enter a valid local or registry image reference.")
            env["IMAGE"] = image

        if command in {"kubearmor-status", "kubearmor-probe", "kubearmor-policy-check"}:
            context = str(payload.get("context", "")).strip()
            if not CONTEXT_RE.fullmatch(context):
                raise ValueError("An exact Kubernetes context is required.")
            if payload.get("allowClusterRead") is not True:
                raise ValueError("Explicit read-only cluster confirmation is required.")
            env["SANTET_CONTEXT"] = context
            env["ALLOW_CLUSTER_READ"] = "true"

        return command, argv, env


class SantetHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], target_root: Path):
        super().__init__(address, SantetHandler)
        self.target_root = target_root
        self.report_root = target_root / "artifacts" / "security"
        self.csrf_token = secrets.token_urlsafe(24)
        self.jobs = JobManager(target_root)


class SantetHandler(SimpleHTTPRequestHandler):
    server: SantetHTTPServer

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if not self._valid_local_host():
            self._json({"error": "This R&D UI accepts localhost requests only."}, HTTPStatus.FORBIDDEN)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({
                "ok": True,
                "mode": "local-rnd",
                "version": read_version(),
                "target": str(self.server.target_root),
                "csrfToken": self.server.csrf_token,
            })
        elif parsed.path == "/api/overview":
            self._json(overview(self.server.target_root))
        elif parsed.path == "/api/artifacts":
            self._json({"artifacts": artifact_inventory(self.server.report_root)})
        elif parsed.path.startswith("/api/artifacts/"):
            self._serve_artifact(unquote(parsed.path.removeprefix("/api/artifacts/")))
        elif parsed.path == "/api/jobs":
            self._json({"jobs": self.server.jobs.list()})
        elif parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.removeprefix("/api/jobs/").split("/", 1)[0]
            job = self.server.jobs.get(job_id)
            self._json(job.public() if job else {"error": "Job not found."}, HTTPStatus.OK if job else HTTPStatus.NOT_FOUND)
        elif parsed.path.startswith("/api/"):
            self._json({"error": "Endpoint not found."}, HTTPStatus.NOT_FOUND)
        else:
            self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        if not self._valid_local_host():
            self._json({"error": "This R&D UI accepts localhost requests only."}, HTTPStatus.FORBIDDEN)
            return
        parsed = urlparse(self.path)
        if self.headers.get("X-Santet-Token") != self.server.csrf_token:
            self._json({"error": "Invalid local request token."}, HTTPStatus.FORBIDDEN)
            return
        try:
            payload = self._payload()
        except ValueError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        try:
            if parsed.path == "/api/jobs":
                job = self.server.jobs.create(payload)
                self._json(job.public(), HTTPStatus.ACCEPTED)
                return
            if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/cancel"):
                job_id = parsed.path.removeprefix("/api/jobs/").removesuffix("/cancel").strip("/")
                self._json(self.server.jobs.cancel(job_id).public())
                return
        except ValueError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except RuntimeError as exc:
            self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
            return
        except KeyError:
            self._json({"error": "Job not found."}, HTTPStatus.NOT_FOUND)
            return
        self._json({"error": "Endpoint not found."}, HTTPStatus.NOT_FOUND)

    def _valid_local_host(self) -> bool:
        host = self.headers.get("Host", "").strip().lower()
        if host.startswith("["):
            hostname = host[1:].split("]", 1)[0]
        else:
            hostname = host.split(":", 1)[0]
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _payload(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length.") from exc
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Request body is empty or too large.")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _serve_artifact(self, relative: str) -> None:
        if not relative or Path(relative).name.startswith("."):
            self._json({"error": "Artifact not found."}, HTTPStatus.NOT_FOUND)
            return
        root = self.server.report_root.resolve()
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            self._json({"error": "Artifact path is outside the evidence directory."}, HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            self._json({"error": "Artifact not found."}, HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(candidate.stat().st_size))
        self.send_header("Content-Disposition", f'attachment; filename="{candidate.name}"')
        self.end_headers()
        with candidate.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                self.wfile.write(chunk)

    def _serve_static(self, request_path: str) -> None:
        relative = "index.html" if request_path in {"", "/"} else unquote(request_path.lstrip("/"))
        root = STATIC_ROOT.resolve()
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            candidate = root / "index.html"
        content = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        content = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local Santet DevSecOps Web UI")
    parser.add_argument("--host", default=os.environ.get("SANTET_UI_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SANTET_UI_PORT", "7777")))
    parser.add_argument("--target", default=os.environ.get("SANTET_UI_TARGET", os.getcwd()))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing a non-loopback bind; this R&D UI has no authentication.")
    target_root = Path(args.target).expanduser().resolve()
    if not target_root.is_dir():
        raise SystemExit(f"Target directory does not exist: {target_root}")
    server = SantetHTTPServer((args.host, args.port), target_root)
    host, port = server.server_address[:2]
    print(f"Santet DevSecOps Web UI {read_version()}")
    print(f"Target: {target_root}")
    print(f"Open: http://{host}:{port}")
    print("Local R&D mode: authentication is disabled; loopback binding is enforced.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping Santet Web UI.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
