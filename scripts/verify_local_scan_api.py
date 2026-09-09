"""Exercise the local HTTP job, transport, immutable result, and shell routes."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.admission_policy import ScanAdmissionGate  # noqa: E402
from scanner.api_contract import API_VERSION, BUNDLE_VERSION, validate_job, validate_viewer_bundle  # noqa: E402
from scanner.local_scan_api import LocalScanJobService, build_server  # noqa: E402


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    outgoing = Request(base_url + path, data=body, method=method, headers=headers or {})
    try:
        with urlopen(outgoing, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers), error.read()


def json_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    value: object | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    body = None if value is None else json.dumps(value).encode("utf-8")
    headers = {} if body is None else {"Content-Type": "application/json"}
    status, response_headers, payload = request(
        base_url,
        path,
        method=method,
        body=body,
        headers=headers,
    )
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise AssertionError("API response was not a JSON object")
    return status, response_headers, parsed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fixture_bundle(name: str) -> dict[str, object]:
    bundle: dict[str, object] = {
        "bundleVersion": BUNDLE_VERSION,
        "record": json.loads((ROOT / "fixtures" / "scan" / f"{name}.json").read_text()),
        "scene": json.loads((ROOT / "fixtures" / "scene-manifest" / f"{name}.json").read_text()),
        "result": json.loads((ROOT / "fixtures" / "result-manifest" / f"{name}.json").read_text()),
        "runtime": json.loads((ROOT / "fixtures" / "viewer-runtime" / f"{name}.json").read_text()),
        "mapping": json.loads((ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json").read_text()),
    }
    validate_viewer_bundle(bundle)
    return bundle


def wait_for_terminal(service: LocalScanJobService, job_id: str) -> dict[str, object]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = service.get_job(job_id)
        if job is None:
            raise AssertionError("job disappeared")
        if job["state"] not in {"queued", "running"}:
            return job
        time.sleep(0.02)
    raise AssertionError("job did not reach a terminal state")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="dom-xray-api-shell-") as temporary:
        static_root = Path(temporary)
        (static_root / "index.html").write_text(
            "<!doctype html><title>DOM X-Ray shell</title>",
            encoding="utf-8",
        )
        service = LocalScanJobService()
        server = build_server("127.0.0.1", 0, service, static_root=static_root)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            status, headers, health = json_request(base_url, "/api/health")
            require(status == 200 and health["apiVersion"] == API_VERSION, "health route failed")
            require(health["arbitraryPublicScanning"] is False, "health overstated scanner mode")
            require(headers.get("Cache-Control") == "no-store", "health response is cacheable")

            status, _headers, malformed = request(
                base_url,
                "/api/scans",
                method="POST",
                body=b"not-json",
                headers={"Content-Type": "application/json"},
            )
            require(status == 400, "malformed JSON was not rejected")
            validate_job(json.loads(malformed))

            status, _headers, oversized = request(
                base_url,
                "/api/scans",
                method="POST",
                body=b"x" * 2_049,
                headers={"Content-Type": "application/json"},
            )
            require(status == 413, "oversized body was not rejected")
            validate_job(json.loads(oversized))

            status, _headers, disabled = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://www.example.org/"},
            )
            require(status == 503 and disabled["state"] == "rejected", "public scanner was not disabled")
            require(disabled["error"]["code"] == "scanner-disabled", "disabled reason drifted")
            validate_job(disabled)

            status, headers, job = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://gallery.example/"},
            )
            require(status == 202, "seeded scan was not accepted")
            require(headers.get("Location") == f"/api/scans/{job['jobId']}", "job location drifted")
            validate_job(job)

            deadline = time.monotonic() + 8
            observed_states = {job["state"]}
            while job["state"] in {"queued", "running"} and time.monotonic() < deadline:
                time.sleep(0.05)
                status, poll_headers, job = json_request(base_url, f"/api/scans/{job['jobId']}")
                require(status == 200, "job poll failed")
                require(poll_headers.get("Cache-Control") == "no-store", "job response is cacheable")
                validate_job(job)
                observed_states.add(job["state"])
            require(job["state"] == "ready", f"seeded scan did not become ready: {job}")
            result = job["result"]
            require(isinstance(result, dict), "ready job has no result")

            status, bundle_headers, bundle_payload = request(base_url, result["bundleUrl"])
            require(status == 200, "immutable bundle route failed")
            require("immutable" in bundle_headers.get("Cache-Control", ""), "bundle is not immutable")
            etag = bundle_headers.get("ETag")
            require(bool(etag), "bundle has no ETag")
            bundle = json.loads(bundle_payload)
            validate_viewer_bundle(bundle)
            require(bundle["record"]["requestedUrl"] == "https://gallery.example/", "record was relabeled")

            status, etag_headers, etag_payload = request(
                base_url,
                result["bundleUrl"],
                headers={"If-None-Match": etag},
            )
            require(status == 304 and not etag_payload, "bundle conditional request failed")
            require(etag_headers.get("ETag") == etag, "bundle ETag drifted")

            status, shell_headers, shell = request(base_url, result["resultPath"])
            require(status == 200 and b"DOM X-Ray shell" in shell, "stable result shell failed")
            require("default-src 'self'" in shell_headers.get("Content-Security-Policy", ""), "shell CSP missing")

            status, _headers, reused = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://gallery.example/"},
            )
            require(status == 200 and reused["state"] == "ready", "exact result was not reused")
            require(reused["result"]["resultId"] == result["resultId"], "reuse changed result identity")
            validate_job(reused)

            status, _headers, missing = json_request(base_url, "/api/scans/j_00000000000000000000000000000000")
            require(status == 404 and missing == {"error": "not-found"}, "unknown job leaked data")
        finally:
            server.shutdown()
            server.server_close()
            service.shutdown()
            thread.join(timeout=2)

    class WrongTargetExecutor:
        def supports(self, _target_url: str) -> bool:
            return True

        def execute(self, _target_url: str, progress) -> dict[str, object]:
            progress("capturing")
            return fixture_bundle("image-heavy")

    wrong_service = LocalScanJobService(WrongTargetExecutor(), max_workers=1)
    try:
        wrong_job, status, _retry = wrong_service.submit("https://clean.example/")
        require(status == 202, "wrong-target executor did not enter the job boundary")
        wrong_terminal = wait_for_terminal(wrong_service, wrong_job["jobId"])
        require(
            wrong_terminal["state"] == "failed"
            and wrong_terminal["error"]["code"] == "internal-error",
            "executor target mismatch crossed publication",
        )
    finally:
        wrong_service.shutdown()

    class BlockingExecutor:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def supports(self, target_url: str) -> bool:
            return target_url in {"https://gallery.example/", "https://clean.example/"}

        def execute(self, target_url: str, progress) -> dict[str, object]:
            progress("capturing")
            self.started.set()
            if not self.release.wait(5):
                raise AssertionError("blocking executor timed out")
            name = "image-heavy" if target_url == "https://gallery.example/" else "clean"
            return fixture_bundle(name)

    clock = [100.0]
    blocker = BlockingExecutor()
    bounded_service = LocalScanJobService(
        blocker,
        max_workers=1,
        max_active_jobs=1,
        admission_gate=ScanAdmissionGate(
            duplicate_window_seconds=10,
            origin_cooling_seconds=1,
            clock=lambda: clock[0],
        ),
    )
    try:
        first, status, _retry = bounded_service.submit("https://gallery.example/")
        require(status == 202 and blocker.started.wait(2), "blocking scan did not start")
        duplicate, status, retry = bounded_service.submit("https://gallery.example/")
        require(
            status == 429
            and duplicate["error"]["code"] == "rate-limited"
            and retry == 10,
            "in-flight duplicate was not rate limited",
        )
        overflow, status, retry = bounded_service.submit("https://clean.example/")
        require(
            status == 429
            and overflow["error"]["code"] == "queue-full"
            and retry == 1,
            "active-job limit was not enforced",
        )
        blocker.release.set()
        require(wait_for_terminal(bounded_service, first["jobId"])["state"] == "ready", "first bounded scan failed")
        clock[0] += 1.1
        retried, status, _retry = bounded_service.submit("https://clean.example/")
        require(status == 202, "queue-full reservation was not released after cooling")
        require(wait_for_terminal(bounded_service, retried["jobId"])["state"] == "ready", "retried scan failed")
    finally:
        blocker.release.set()
        bounded_service.shutdown()

    print(
        "Verified local no-login HTTP health, bounded submissions, seeded transport admission, "
        f"job polling ({sorted(observed_states)}), immutable ETag results, stable result shell, "
        "exact reuse, target correlation, admission cooling, active-job bounds, and content-free "
        "misses; arbitrary public scanning stayed disabled."
    )


if __name__ == "__main__":
    main()
