"""Exercise the local HTTP job, transport, immutable result, and shell routes."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.admission_policy import ScanAdmissionGate  # noqa: E402
from scanner.api_contract import (  # noqa: E402
    API_VERSION,
    BUNDLE_VERSION,
    validate_job,
    validate_viewer_bundle,
)
from scanner.local_scan_api import FixtureScanExecutor, LocalScanJobService, build_server  # noqa: E402
from scanner.result_store import FilesystemResultStore, MemoryResultStore, ResultStoreError  # noqa: E402
from scanner.video_renderer import VideoRenderError  # noqa: E402


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
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    body = None if value is None else json.dumps(value).encode("utf-8")
    outgoing_headers = dict(headers or {})
    if body is not None:
        outgoing_headers["Content-Type"] = "application/json"
    status, response_headers, payload = request(
        base_url,
        path,
        method=method,
        body=body,
        headers=outgoing_headers,
    )
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise AssertionError("API response was not a JSON object")
    return status, response_headers, parsed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify_artifact_route(
    base_url: str,
    path: str,
    descriptor: dict[str, object],
    *,
    label: str,
    media_type: str,
    signature: bytes,
) -> tuple[bytes, str]:
    status, headers, payload = request(base_url, path)
    require(status == 200, f"{label} artifact route failed")
    artifact = descriptor["artifact"]
    sha256 = hashlib.sha256(payload).hexdigest()
    require(payload.startswith(signature), f"{label} route returned the wrong media bytes")
    require(descriptor["eligible"] is True, f"{label} was not eligible")
    require(descriptor["state"] == "ready", f"{label} was not ready")
    require(
        isinstance(artifact, dict)
        and artifact["sha256"] == sha256
        and artifact["byteLength"] == len(payload)
        and artifact["byteLength"] == int(headers["Content-Length"]),
        f"{label} manifest descriptor did not match exact route bytes",
    )
    require(headers.get("Content-Type") == media_type, f"{label} content type drifted")
    require(
        headers.get("Cache-Control") == "no-store",
        f"{label} artifact was cacheable without a purge path",
    )
    require(
        headers.get("X-Content-Type-Options") == "nosniff",
        f"{label} artifact omitted nosniff",
    )
    etag = headers.get("ETag")
    require(
        etag == f'"{sha256}"' and not etag.startswith("W/"),
        f"{label} artifact did not use a strong content ETag",
    )

    status, head_headers, head_payload = request(base_url, path, method="HEAD")
    require(status == 200 and not head_payload, f"{label} HEAD was not bodyless")
    for header_name in (
        "Content-Type",
        "Content-Length",
        "Cache-Control",
        "ETag",
        "X-Content-Type-Options",
    ):
        require(
            head_headers.get(header_name) == headers.get(header_name),
            f"{label} HEAD {header_name} did not match GET",
        )

    status, conditional_headers, conditional_payload = request(
        base_url,
        path,
        headers={"If-None-Match": etag},
    )
    require(status == 304 and not conditional_payload, f"{label} conditional request failed")
    require(conditional_headers.get("ETag") == etag, f"{label} conditional ETag drifted")
    require(
        conditional_headers.get("Cache-Control") == "no-store"
        and conditional_headers.get("X-Content-Type-Options") == "nosniff",
        f"{label} 304 response omitted cache/security headers",
    )

    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        status, upload_headers, upload_payload = request(
            base_url,
            path,
            method=method,
            body=b"raw-upload-attempt",
            headers={"Content-Type": "application/octet-stream"},
        )
        require(
            status == 405
            and not upload_payload
            and upload_headers.get("Allow") == "GET, HEAD"
            and upload_headers.get("Cache-Control") == "no-store",
            f"{label} {method} upload was not rejected as an empty 405",
        )
    status, _headers, unchanged_payload = request(base_url, path)
    require(
        status == 200 and unchanged_payload == payload,
        f"raw {label} upload attempt altered the immutable artifact",
    )
    return payload, etag


def deletion_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def submission_headers(token: str) -> dict[str, str]:
    return {"X-Deletion-Token-Digest": f"sha256={deletion_digest(token)}"}


def stable_result_files(root: Path) -> bytes:
    return b"".join(
        path.read_bytes()
        for path in root.iterdir()
        if path.is_file() and not path.is_symlink()
    )


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
    duplicate_backend = MemoryResultStore(keys=(b"B" * 32,))
    try:
        LocalScanJobService(
            result_backend=duplicate_backend,
            result_store=duplicate_backend,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("job service accepted two result authorities")
    with tempfile.TemporaryDirectory(prefix="dom-xray-api-shell-") as temporary:
        static_root = Path(temporary)
        (static_root / "index.html").write_text(
            "<!doctype html><title>DOM X-Ray shell</title>",
            encoding="utf-8",
        )
        result_root = static_root / "stored-results"
        store_key = b"L" * 32
        delete_token = f"dxrd_{'a' * 64}"
        reused_token = f"dxrd_{'b' * 64}"
        service = LocalScanJobService(
            result_store=FilesystemResultStore(result_root, keys=(store_key,))
        )
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

            status, _headers, missing_digest = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://gallery.example/"},
            )
            require(status == 400, "missing deletion-token digest was not rejected")
            validate_job(missing_digest)

            status, _headers, disabled = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://www.example.org/"},
                headers=submission_headers(delete_token),
            )
            require(status == 503 and disabled["state"] == "rejected", "public scanner was not disabled")
            require(disabled["error"]["code"] == "scanner-disabled", "disabled reason drifted")
            validate_job(disabled)

            status, headers, job = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://gallery.example/"},
                headers=submission_headers(delete_token),
            )
            require(status == 202, "seeded scan was not accepted")
            require(headers.get("Location") == f"/api/scans/{job['jobId']}", "job location drifted")
            validate_job(job)

            # The seeded executor crosses the supervised transport boundary and
            # renders the eligible poster in controlled Chromium. Keep this
            # bounded, but allow enough time for a cold browser process.
            deadline = time.monotonic() + 45
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
            require(
                bundle_headers.get("Cache-Control") == "no-store",
                "deletable bundle was cacheable without a purge path",
            )
            etag = bundle_headers.get("ETag")
            require(bool(etag), "bundle has no ETag")
            bundle = json.loads(bundle_payload)
            validate_viewer_bundle(bundle)
            require(bundle["record"]["requestedUrl"] == "https://gallery.example/", "record was relabeled")

            poster_path = f"/api/results/{result['resultId']}/poster.png"
            poster_descriptor = bundle["result"]["exports"]["poster"]
            poster_payload, poster_etag = verify_artifact_route(
                base_url,
                poster_path,
                poster_descriptor,
                label="poster",
                media_type="image/png",
                signature=b"\x89PNG\r\n\x1a\n",
            )
            video_path = f"/api/results/{result['resultId']}/video.mp4"
            video_descriptor = bundle["result"]["exports"]["video"]
            video_payload, video_etag = verify_artifact_route(
                base_url,
                video_path,
                video_descriptor,
                label="video",
                media_type="video/mp4",
                signature=b"\x00\x00",
            )
            require(
                video_payload[4:8] == b"ftyp"
                and video_descriptor["durationMs"] == 5_000,
                "video artifact did not preserve the exact MP4 contract",
            )

            for artifact_name in ("poster.png", "video.mp4"):
                for miss_path in (
                    f"/api/results/r_{'0' * 32}/{artifact_name}",
                    f"/api/results/r_{'0' * 32}%2F{artifact_name}",
                ):
                    status, _headers, miss_payload = request(base_url, miss_path)
                    require(status == 404, "wrong or unsafe artifact result ID was accepted")
                    require(
                        not miss_payload or json.loads(miss_payload) == {"error": "not-found"},
                        "artifact miss leaked data",
                    )

            require(delete_token.encode("ascii") not in stable_result_files(result_root), "token reached disk")
            require(
                deletion_digest(delete_token).encode("ascii") not in stable_result_files(result_root),
                "public token digest reached disk",
            )

            status, etag_headers, etag_payload = request(
                base_url,
                result["bundleUrl"],
                headers={"If-None-Match": etag},
            )
            require(status == 304 and not etag_payload, "bundle conditional request failed")
            require(
                etag_headers.get("ETag") == etag
                and etag_headers.get("Cache-Control") == "no-store"
                and etag_headers.get("X-Content-Type-Options") == "nosniff",
                "bundle 304 omitted identity, cache, or security headers",
            )

            status, shell_headers, shell = request(base_url, result["resultPath"])
            require(status == 200 and b"DOM X-Ray shell" in shell, "stable result shell failed")
            shell_csp = shell_headers.get("Content-Security-Policy", "")
            require("default-src 'self'" in shell_csp, "shell CSP missing")
            require("img-src 'self' data: blob:" in shell_csp, "shell CSP blocks verified poster previews")
            require("media-src 'self' blob:" in shell_csp, "shell CSP blocks verified video playback")

            status, _headers, reused = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://gallery.example/"},
                headers=submission_headers(reused_token),
            )
            require(status == 200 and reused["state"] == "ready", "exact result was not reused")
            require(reused["result"]["resultId"] == result["resultId"], "reuse changed result identity")
            validate_job(reused)
            status, _headers, reused_delete = request(
                base_url,
                result["bundleUrl"],
                method="DELETE",
                headers={"X-Deletion-Token": reused_token},
            )
            require(status == 403 and not reused_delete, "reused submission inherited deletion authority")

            status, _headers, clean_submission = json_request(
                base_url,
                "/api/scans",
                method="POST",
                value={"apiVersion": API_VERSION, "url": "https://clean.example/"},
                headers=submission_headers(reused_token),
            )
            require(status == 202, "neutral clean scan was not accepted")
            clean_deadline = time.monotonic() + 30
            while clean_submission["state"] in {"queued", "running"} and time.monotonic() < clean_deadline:
                time.sleep(0.05)
                status, _poll_headers, clean_submission = json_request(
                    base_url,
                    f"/api/scans/{clean_submission['jobId']}",
                )
                require(status == 200, "clean job poll failed")
                validate_job(clean_submission)
            require(clean_submission["state"] == "ready", "neutral clean scan did not become ready")
            clean_result = clean_submission["result"]
            require(isinstance(clean_result, dict), "clean ready job has no result")
            status, _headers, clean_bundle_payload = request(base_url, clean_result["bundleUrl"])
            require(status == 200, "neutral clean bundle route failed")
            clean_bundle = json.loads(clean_bundle_payload)
            validate_viewer_bundle(clean_bundle)
            clean_poster = clean_bundle["result"]["exports"]["poster"]
            clean_video = clean_bundle["result"]["exports"]["video"]
            require(
                clean_poster["eligible"] is False
                and clean_poster["state"] == "ineligible"
                and clean_poster["artifact"] is None,
                "neutral clean result unexpectedly became poster-eligible",
            )
            require(
                clean_video["eligible"] is False
                and clean_video["state"] == "ineligible"
                and clean_video["artifact"] is None,
                "neutral clean result unexpectedly became video-eligible",
            )
            clean_poster_path = f"/api/results/{clean_result['resultId']}/poster.png"
            status, _headers, clean_poster_payload = request(base_url, clean_poster_path)
            require(status == 404 and not clean_poster_payload, "neutral clean result exposed a poster")
            clean_video_path = f"/api/results/{clean_result['resultId']}/video.mp4"
            status, _headers, clean_video_payload = request(base_url, clean_video_path)
            require(status == 404 and not clean_video_payload, "neutral clean result exposed a video")

            status, _headers, missing = json_request(base_url, "/api/scans/j_00000000000000000000000000000000")
            require(status == 404 and missing == {"error": "not-found"}, "unknown job leaked data")
        finally:
            server.shutdown()
            server.server_close()
            service.shutdown()
            thread.join(timeout=2)

        restarted_service = LocalScanJobService(
            result_store=FilesystemResultStore(result_root, keys=(store_key,))
        )
        restarted_server = build_server(
            "127.0.0.1",
            0,
            restarted_service,
            static_root=static_root,
        )
        restarted_thread = threading.Thread(target=restarted_server.serve_forever, daemon=True)
        restarted_thread.start()
        restarted_url = f"http://127.0.0.1:{restarted_server.server_port}"
        try:
            status, restarted_headers, restarted_payload = request(
                restarted_url,
                result["bundleUrl"],
            )
            require(status == 200, "durable result did not survive API restart")
            require(restarted_payload == bundle_payload, "restart changed immutable bundle bytes")
            require(restarted_headers.get("ETag") == etag, "restart changed immutable ETag")

            status, restarted_poster_headers, restarted_poster_payload = request(
                restarted_url,
                poster_path,
            )
            require(
                status == 200
                and restarted_poster_payload == poster_payload
                and restarted_poster_headers.get("ETag") == poster_etag
                and restarted_poster_headers.get("Content-Length") == str(len(poster_payload)),
                "durable poster did not survive API restart byte-for-byte",
            )
            require(
                restarted_poster_headers.get("Cache-Control") == "no-store"
                and restarted_poster_headers.get("X-Content-Type-Options") == "nosniff",
                "restarted poster omitted cache/security headers",
            )
            status, restarted_video_headers, restarted_video_payload = request(
                restarted_url,
                video_path,
            )
            require(
                status == 200
                and restarted_video_payload == video_payload
                and restarted_video_headers.get("ETag") == video_etag
                and restarted_video_headers.get("Content-Length") == str(len(video_payload)),
                "durable video did not survive API restart byte-for-byte",
            )
            require(
                restarted_video_headers.get("Cache-Control") == "no-store"
                and restarted_video_headers.get("X-Content-Type-Options") == "nosniff",
                "restarted video omitted cache/security headers",
            )

            status, malformed_headers, malformed_delete = request(
                restarted_url,
                result["bundleUrl"],
                method="DELETE",
                headers={"X-Deletion-Token": "weak"},
            )
            require(status == 400 and not malformed_delete, "malformed deletion token was accepted")
            require(
                malformed_headers.get("Cache-Control") == "no-store",
                "deletion rejection was cacheable",
            )
            status, _headers, wrong_delete = request(
                restarted_url,
                result["bundleUrl"],
                method="DELETE",
                headers={"X-Deletion-Token": f"dxrd_{'0' * 64}"},
            )
            require(status == 403 and not wrong_delete, "wrong deletion token was accepted")
        finally:
            restarted_server.shutdown()
            restarted_server.server_close()
            restarted_service.shutdown()
            restarted_thread.join(timeout=2)

        deletion_service = LocalScanJobService(
            result_store=FilesystemResultStore(result_root, keys=(store_key,))
        )
        deletion_server = build_server(
            "127.0.0.1",
            0,
            deletion_service,
            static_root=static_root,
        )
        deletion_thread = threading.Thread(target=deletion_server.serve_forever, daemon=True)
        deletion_thread.start()
        deletion_url = f"http://127.0.0.1:{deletion_server.server_port}"
        try:
            status, deleted_headers, deleted_payload = request(
                deletion_url,
                result["bundleUrl"],
                method="DELETE",
                headers={"X-Deletion-Token": delete_token},
            )
            require(status == 204 and not deleted_payload, "owner could not delete after restart")
            require(deleted_headers.get("Cache-Control") == "no-store", "deletion was cacheable")
            status, missing_headers, missing_payload = request(
                deletion_url,
                result["bundleUrl"],
                headers={"If-None-Match": etag},
            )
            require(status == 404, "deleted result remained reachable")
            require(json.loads(missing_payload) == {"error": "not-found"}, "deleted result leaked data")
            require(
                missing_headers.get("Cache-Control") == "no-store",
                "deleted bundle miss was cacheable",
            )
            status, missing_poster_headers, missing_poster_payload = request(
                deletion_url,
                poster_path,
                headers={"If-None-Match": poster_etag},
            )
            require(
                status == 404 and not missing_poster_payload,
                "deleted result poster remained reachable with a stale ETag",
            )
            require(
                missing_poster_headers.get("Cache-Control") == "no-store",
                "deleted poster miss was cacheable",
            )
            status, missing_video_headers, missing_video_payload = request(
                deletion_url,
                video_path,
                headers={"If-None-Match": video_etag},
            )
            require(
                status == 404 and not missing_video_payload,
                "deleted result video remained reachable with a stale ETag",
            )
            require(
                missing_video_headers.get("Cache-Control") == "no-store",
                "deleted video miss was cacheable",
            )
        finally:
            deletion_server.shutdown()
            deletion_server.server_close()
            deletion_service.shutdown()
            deletion_thread.join(timeout=2)

    def unavailable_video(_bundle: dict[str, object]) -> bytes:
        raise VideoRenderError("injected video failure")

    fallback_result_id = "r_" + "d" * 32
    fallback_executor = FixtureScanExecutor(
        result_id_factory=lambda: fallback_result_id,
        poster_renderer=lambda _bundle: poster_payload,
        video_renderer=unavailable_video,
    )
    fallback_service = LocalScanJobService(fallback_executor, max_workers=1)
    fallback_server = build_server("127.0.0.1", 0, fallback_service, static_root=None)
    fallback_thread = threading.Thread(target=fallback_server.serve_forever, daemon=True)
    fallback_thread.start()
    fallback_url = f"http://127.0.0.1:{fallback_server.server_port}"
    try:
        fallback_job, status, _retry = fallback_service.submit(
            "https://gallery.example/",
            deletion_digest(delete_token),
        )
        require(status == 202, "video fallback scan was not accepted")
        fallback_terminal = wait_for_terminal(fallback_service, fallback_job["jobId"])
        require(fallback_terminal["state"] == "ready", "video failure discarded the poster result")
        fallback_result = fallback_terminal["result"]
        assert isinstance(fallback_result, dict)
        fallback_bundle_bytes = fallback_service.get_bundle(fallback_result_id)
        require(fallback_bundle_bytes is not None, "poster-only fallback bundle was not published")
        fallback_bundle = json.loads(fallback_bundle_bytes[0])
        require(
            fallback_bundle["result"]["exports"]["poster"]["state"] == "ready"
            and fallback_bundle["result"]["exports"]["video"]["state"] == "not-generated",
            "video renderer failure did not produce the intended poster-only manifest",
        )
        require(
            fallback_service.get_artifact(fallback_result_id, "poster") is not None
            and fallback_service.get_artifact(fallback_result_id, "video") is None,
            "poster-only fallback registered the wrong artifact set",
        )
        status, _headers, fallback_poster = request(
            fallback_url,
            f"/api/results/{fallback_result_id}/poster.png",
        )
        require(
            status == 200 and fallback_poster == poster_payload,
            "poster-only fallback did not expose its verified poster",
        )
        status, _headers, fallback_video = request(
            fallback_url,
            f"/api/results/{fallback_result_id}/video.mp4",
        )
        require(status == 404 and not fallback_video, "poster-only fallback exposed a video route")
    finally:
        fallback_server.shutdown()
        fallback_server.server_close()
        fallback_service.shutdown()
        fallback_thread.join(timeout=2)

    def unavailable_poster(_bundle: dict[str, object]) -> bytes:
        raise RuntimeError("injected poster failure")

    poster_failure_executor = FixtureScanExecutor(poster_renderer=unavailable_poster)
    try:
        poster_failure_executor.execute("https://gallery.example/", lambda _progress: None)
    except RuntimeError as error:
        require(str(error) == "injected poster failure", "poster failure identity drifted")
    else:
        raise AssertionError("poster renderer failure was silently downgraded")

    class WrongTargetExecutor:
        def supports(self, _target_url: str) -> bool:
            return True

        def execute(self, _target_url: str, progress) -> dict[str, object]:
            progress("capturing")
            return fixture_bundle("image-heavy")

    wrong_service = LocalScanJobService(WrongTargetExecutor(), max_workers=1)
    try:
        wrong_job, status, _retry = wrong_service.submit(
            "https://clean.example/",
            deletion_digest(delete_token),
        )
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
        first, status, _retry = bounded_service.submit(
            "https://gallery.example/",
            deletion_digest(delete_token),
        )
        require(status == 202 and blocker.started.wait(2), "blocking scan did not start")
        duplicate, status, retry = bounded_service.submit(
            "https://gallery.example/",
            deletion_digest(reused_token),
        )
        require(
            status == 429
            and duplicate["error"]["code"] == "rate-limited"
            and retry == 10,
            "in-flight duplicate was not rate limited",
        )
        overflow, status, retry = bounded_service.submit(
            "https://clean.example/",
            deletion_digest(reused_token),
        )
        require(
            status == 429
            and overflow["error"]["code"] == "queue-full"
            and retry == 1,
            "active-job limit was not enforced",
        )
        blocker.release.set()
        require(wait_for_terminal(bounded_service, first["jobId"])["state"] == "ready", "first bounded scan failed")
        clock[0] += 1.1
        retried, status, _retry = bounded_service.submit(
            "https://clean.example/",
            deletion_digest(reused_token),
        )
        require(status == 202, "queue-full reservation was not released after cooling")
        require(wait_for_terminal(bounded_service, retried["jobId"])["state"] == "ready", "retried scan failed")
    finally:
        blocker.release.set()
        bounded_service.shutdown()

    admission_now = [300.0]
    retention_now = [datetime(2026, 9, 10, 12, tzinfo=UTC)]
    expiring_service = LocalScanJobService(
        admission_gate=ScanAdmissionGate(
            duplicate_window_seconds=10,
            origin_cooling_seconds=1,
            clock=lambda: admission_now[0],
        ),
        result_store=MemoryResultStore(
            keys=(b"E" * 32,),
            retention_seconds=1,
            clock=lambda: retention_now[0],
        ),
    )
    try:
        first_expiring, status, _retry = expiring_service.submit(
            "https://clean.example/",
            deletion_digest(delete_token),
        )
        require(status == 202, "retention test scan was not accepted")
        require(
            wait_for_terminal(expiring_service, first_expiring["jobId"])["state"] == "ready",
            "retention test scan did not complete",
        )
        admission_now[0] += 2
        retention_now[0] += timedelta(seconds=2)
        recovered_submission, status, _retry = expiring_service.submit(
            "https://clean.example/",
            deletion_digest(reused_token),
        )
        require(status == 202, "expired dedup mapping did not recover into a fresh scan")
        require(
            wait_for_terminal(expiring_service, recovered_submission["jobId"])["state"] == "ready",
            "fresh scan after expiry did not complete",
        )
    finally:
        expiring_service.shutdown()

    rate_store = MemoryResultStore(keys=(b"R" * 32,))
    rate_token = f"dxrd_{'c' * 64}"
    rate_publication = rate_store.publish(fixture_bundle("clean"), deletion_digest(rate_token))
    rate_service = LocalScanJobService(result_backend=rate_store)
    try:
        for _index in range(4):
            outcome, retry_after = rate_service.delete_result(
                rate_publication.result_id,
                f"dxrd_{'0' * 64}",
            )
            require(outcome == "forbidden" and retry_after is None, "wrong-token response drifted")
        outcome, retry_after = rate_service.delete_result(
            rate_publication.result_id,
            f"dxrd_{'0' * 64}",
        )
        require(
            outcome == "rate-limited" and isinstance(retry_after, int) and retry_after > 0,
            "deletion-token guessing was not throttled",
        )
        outcome, retry_after = rate_service.delete_result(rate_publication.result_id, rate_token)
        require(
            outcome == "deleted" and retry_after is None,
            "guess throttling blocked the legitimate owner",
        )
    finally:
        rate_service.shutdown()

    class DeleteOutcomeBackend:
        def __init__(self) -> None:
            self.outcome: str | Exception = "pending"

        def delete(self, _result_id: str, _deletion_token: str) -> str:
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome

    delete_backend = DeleteOutcomeBackend()
    delete_service = LocalScanJobService(result_backend=delete_backend)  # type: ignore[arg-type]
    delete_server = build_server("127.0.0.1", 0, delete_service, static_root=None)
    delete_thread = threading.Thread(target=delete_server.serve_forever, daemon=True)
    delete_thread.start()
    delete_url = f"http://127.0.0.1:{delete_server.server_port}"
    delete_path = f"/api/results/{'r_' + 'e' * 32}"
    try:
        status, headers, payload = request(delete_url, delete_path, method="DELETE")
        require(
            status == 202
            and not payload
            and headers.get("Retry-After") == "5"
            and headers.get("Cache-Control") == "no-store",
            "pending deletion did not return a cache-free 202 with Retry-After",
        )
        delete_backend.outcome = "retryable"
        status, headers, payload = request(delete_url, delete_path, method="DELETE")
        require(
            status == 503
            and not payload
            and headers.get("Retry-After") == "5"
            and headers.get("Cache-Control") == "no-store",
            "retryable deletion did not return a cache-free 503 with Retry-After",
        )
        delete_backend.outcome = ResultStoreError("transient provider outage", retryable=True)
        status, headers, payload = request(delete_url, delete_path, method="DELETE")
        require(
            status == 503 and not payload and headers.get("Retry-After") == "5",
            "retryable storage exception did not preserve retry semantics",
        )
        delete_backend.outcome = ResultStoreError("stored identity is corrupt")
        status, headers, payload = request(delete_url, delete_path, method="DELETE")
        require(
            status == 404 and not payload and headers.get("Retry-After") is None,
            "nonretryable storage corruption did not remain a content-free 404",
        )
    finally:
        delete_server.shutdown()
        delete_server.server_close()
        delete_service.shutdown()
        delete_thread.join(timeout=2)

    class ReadFailureBackend:
        def __init__(self) -> None:
            self.error = ResultStoreError("transient provider outage", retryable=True)

        def get(self, _result_id: str):
            raise self.error

        def get_artifact(self, _result_id: str, _kind: str):
            raise self.error

    read_backend = ReadFailureBackend()
    read_service = LocalScanJobService(result_backend=read_backend)  # type: ignore[arg-type]
    read_server = build_server("127.0.0.1", 0, read_service, static_root=None)
    read_thread = threading.Thread(target=read_server.serve_forever, daemon=True)
    read_thread.start()
    read_url = f"http://127.0.0.1:{read_server.server_port}"
    read_result_id = "r_" + "f" * 32
    try:
        for path in (
            f"/api/results/{read_result_id}",
            f"/api/results/{read_result_id}/poster.png",
        ):
            for method in ("GET", "HEAD"):
                status, headers, payload = request(read_url, path, method=method)
                require(
                    status == 503
                    and not payload
                    and headers.get("Cache-Control") == "no-store"
                    and headers.get("Retry-After") == "5",
                    "retryable result read did not return a cache-free 503",
                )
        read_backend.error = ResultStoreError("stored identity is corrupt")
        status, headers, payload = request(
            read_url,
            f"/api/results/{read_result_id}",
        )
        require(
            status == 404
            and json.loads(payload) == {"error": "not-found"}
            and headers.get("Cache-Control") == "no-store",
            "nonretryable bundle failure did not remain a cache-free miss",
        )
    finally:
        read_server.shutdown()
        read_server.server_close()
        read_service.shutdown()
        read_thread.join(timeout=2)

    print(
        "Verified local no-login HTTP health, bounded submissions, seeded transport admission, "
        f"job polling ({sorted(observed_states)}), browser-held owner capability, no-store ETag "
        "results and server-rendered poster/video artifacts, poster-only video-failure fallback, "
        "byte-identical restart recovery, HMAC deletion after "
        "restart, stale-ETag denial, binary GET/HEAD parity, raw-upload refusal, "
        "exact reuse without ownership transfer, expiry recovery, owner-safe guessing throttles, "
        "target correlation, retryable read availability, "
        "admission cooling, active-job bounds, and content-free misses; arbitrary public scanning "
        "stayed disabled."
    )


if __name__ == "__main__":
    main()
