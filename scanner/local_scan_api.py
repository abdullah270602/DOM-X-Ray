"""Local same-origin scan API proving jobs, transport admission, and results.

This server deliberately accepts only the three seeded fixture targets. It uses
the real transport supervisor and deterministic mapping pipeline, but it is not
the production public-egress boundary described by ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import argparse
import json
import logging
import mimetypes
import re
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import unquote, urlsplit, urlunsplit

from jsonschema import Draft202012Validator, FormatChecker

from scanner.admission_policy import ScanAdmissionGate
from scanner.api_contract import (
    API_VERSION,
    BUNDLE_VERSION,
    ApiContractError,
    stable_json_bytes,
    validate_job,
    validate_submission,
    validate_viewer_bundle,
)
from scanner.destination_policy import DestinationPolicy, DestinationPolicyError
from scanner.poster_renderer import render_poster_png
from scanner.result_manifest import build_result_manifest
from scanner.result_store import (
    ArtifactKind,
    FilesystemResultStore,
    MemoryResultStore,
    ResultBackend,
    ResultStoreError,
    load_or_create_store_key,
)
from scanner.scan_transport import PublicScanGrant, WorkerLaunch, run_public_scan_transport
from scanner.scene_manifest import build_scene_manifest
from scanner.video_renderer import VideoRenderError, render_video_mp4
from scanner.viewer_runtime import build_viewer_runtime
from scripts.validate_fixtures import validate_semantics


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_WORKER = ROOT / "fixtures" / "worker" / "scan_transport_worker_fixture.py"
FIXTURE_DIR = ROOT / "fixtures" / "scan"
SCAN_SCHEMA = json.loads((ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8"))
MAPPING = json.loads((ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json").read_text(encoding="utf-8"))
LOGGER = logging.getLogger(__name__)

MAX_REQUEST_BODY_BYTES = 2_048
DEFAULT_POLL_AFTER_MS = 350
MAX_DELETION_FAILURES = 5
DELETION_FAILURE_WINDOW_SECONDS = 60
DELETION_DIGEST_HEADER_PATTERN = re.compile(r"^sha256=([0-9a-f]{64})$")
ARTIFACT_ROUTE_PATTERN = re.compile(
    r"^/api/results/(r_[0-9a-f]{32})/(poster\.png|video\.mp4)$"
)
ARTIFACT_ROUTES: dict[str, tuple[ArtifactKind, str]] = {
    "poster.png": ("poster", "image/png"),
    "video.mp4": ("video", "video/mp4"),
}
PUBLIC_FIXTURE_ADDRESS = "93.184.216.34"
SEEDED_TARGETS = {
    "https://clean.example/": "clean",
    "https://gallery.example/": "image-heavy",
    "https://newsroom.example/": "third-party-heavy",
}

PUBLIC_ERRORS: dict[str, tuple[str, bool]] = {
    "invalid-target": ("Enter a supported public HTTP or HTTPS URL.", False),
    "rate-limited": ("That target was submitted recently. Try again shortly.", True),
    "queue-full": ("The scanner queue is full. Try again shortly.", True),
    "scanner-disabled": ("Public scanning is disabled in this local safety proof.", False),
    "scan-timeout": ("The scan reached its time limit.", True),
    "worker-crashed": ("The isolated scanner stopped before producing a result.", True),
    "invalid-result": ("The scanner produced a result that could not be admitted.", True),
    "capture-failed": ("The page could not be captured safely.", True),
    "internal-error": ("The scan could not be completed.", True),
}


class ScanExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        if code not in PUBLIC_ERRORS:
            raise ValueError("unknown public scan error code")
        self.code = code
        super().__init__(code)


class ScanExecutor(Protocol):
    def supports(self, target_url: str) -> bool: ...

    def execute(
        self,
        target_url: str,
        progress: Callable[[str], None],
    ) -> ScanExecution: ...


@dataclass(frozen=True)
class ScanExecution:
    bundle: dict[str, Any]
    artifacts: dict[str, bytes]


def _canonical_target(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target is not an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("target contains forbidden authority or data")
    host = parsed.hostname.lower()
    default_port = 80 if parsed.scheme == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path or "/", "", ""))


class FixtureScanExecutor:
    """Seed-only executor that still crosses the real supervised transport seam."""

    def __init__(
        self,
        result_id_factory: Callable[[], str] | None = None,
        poster_renderer: Callable[[dict[str, Any]], bytes] = render_poster_png,
        video_renderer: Callable[[dict[str, Any]], bytes] = render_video_mp4,
    ) -> None:
        self._schema_validator = Draft202012Validator(
            SCAN_SCHEMA,
            format_checker=FormatChecker(),
        )
        self._result_id_factory = result_id_factory or (lambda: f"r_{secrets.token_hex(16)}")
        self._poster_renderer = poster_renderer
        self._video_renderer = video_renderer

    def _fixture_name(self, target_url: str) -> str | None:
        try:
            return SEEDED_TARGETS.get(_canonical_target(target_url))
        except (ValueError, TypeError):
            return None

    def supports(self, target_url: str) -> bool:
        return self._fixture_name(target_url) is not None

    def _validate_schema(self, record: dict[str, Any]) -> None:
        errors = sorted(self._schema_validator.iter_errors(record), key=lambda error: list(error.path))
        if errors:
            raise ValueError("scan record failed schema validation")

    def _validate_semantics(self, record: dict[str, Any]) -> None:
        validate_semantics(record, "local API scan record", self._schema_validator)

    def execute(
        self,
        target_url: str,
        progress: Callable[[str], None],
    ) -> ScanExecution:
        fixture_name = self._fixture_name(target_url)
        if fixture_name is None:
            raise ScanExecutionError("scanner-disabled")
        record_path = FIXTURE_DIR / f"{fixture_name}.json"

        def resolver(hostname: str, _port: int) -> list[str]:
            if hostname not in {"clean.example", "gallery.example", "newsroom.example"}:
                raise RuntimeError("seed resolver refused an unknown host")
            return [PUBLIC_FIXTURE_ADDRESS]

        def launch_worker(_grant: PublicScanGrant, result_path: Path) -> WorkerLaunch:
            return WorkerLaunch(
                command=(
                    sys.executable,
                    str(FIXTURE_WORKER),
                    "valid",
                    str(record_path),
                    str(result_path),
                ),
                cwd=ROOT,
            )

        progress("capturing")
        try:
            transport = run_public_scan_transport(
                target_url,
                policy=DestinationPolicy(resolver),
                launch_worker=launch_worker,
                schema_validator=self._validate_schema,
                semantic_validator=self._validate_semantics,
                deadline_seconds=3,
            )
        except DestinationPolicyError as error:
            raise ScanExecutionError("invalid-target") from error
        if not transport.admitted or transport.record is None:
            outcome_codes = {
                "worker-timeout": "scan-timeout",
                "worker-crashed": "worker-crashed",
                "worker-invalid-result": "invalid-result",
                "launch-failed": "capture-failed",
                "supervisor-failed": "capture-failed",
                "invalid-envelope": "invalid-result",
                "invalid-record": "invalid-result",
            }
            raise ScanExecutionError(outcome_codes.get(transport.outcome, "internal-error"))

        progress("mapping")
        record = transport.record
        scene = build_scene_manifest(record, MAPPING)
        result = build_result_manifest(
            record,
            result_id=self._result_id_factory(),
            scene_manifest=scene,
            mapping_registry=MAPPING,
        )
        runtime = build_viewer_runtime(record, scene, result, MAPPING)
        bundle = {
            "bundleVersion": BUNDLE_VERSION,
            "record": record,
            "scene": scene,
            "result": result,
            "runtime": runtime,
            "mapping": MAPPING,
        }
        validate_viewer_bundle(bundle)
        artifacts: dict[str, bytes] = {}
        progress("publishing")
        if result["exports"]["poster"]["eligible"]:
            poster = self._poster_renderer(bundle)
            result = build_result_manifest(
                record,
                result_id=result["resultId"],
                scene_manifest=scene,
                mapping_registry=MAPPING,
                artifact_payloads={"poster": poster},
            )
            runtime = build_viewer_runtime(record, scene, result, MAPPING)
            bundle = {
                "bundleVersion": BUNDLE_VERSION,
                "record": record,
                "scene": scene,
                "result": result,
                "runtime": runtime,
                "mapping": MAPPING,
            }
            validate_viewer_bundle(bundle)
            artifacts["poster"] = poster
        if result["exports"]["video"]["eligible"]:
            try:
                video = self._video_renderer(bundle)
            except VideoRenderError as error:
                # A result remains useful and shareable as a verified poster if
                # the optional video runtime is unavailable or fails closed.
                LOGGER.info("trusted video render fell back to poster: %s", error)
            else:
                artifacts["video"] = video
                result = build_result_manifest(
                    record,
                    result_id=result["resultId"],
                    scene_manifest=scene,
                    mapping_registry=MAPPING,
                    artifact_payloads=artifacts,
                )
                runtime = build_viewer_runtime(record, scene, result, MAPPING)
                bundle = {
                    "bundleVersion": BUNDLE_VERSION,
                    "record": record,
                    "scene": scene,
                    "result": result,
                    "runtime": runtime,
                    "mapping": MAPPING,
                }
                validate_viewer_bundle(bundle)
        return ScanExecution(bundle=bundle, artifacts=artifacts)


@dataclass
class _Job:
    job_id: str
    state: str
    progress: str
    submitted_at: str
    updated_at: str
    scan_status: str | None = None
    result: dict[str, str] | None = None
    error: dict[str, object] | None = None
    poll_after_ms: int | None = DEFAULT_POLL_AFTER_MS
    target_url: str | None = None
    deletion_token_digest: str | None = None


class LocalScanJobService:
    """Bounded in-process orchestration proof; not a distributed queue."""

    def __init__(
        self,
        scan_executor: ScanExecutor | None = None,
        *,
        max_workers: int = 2,
        max_active_jobs: int = 8,
        admission_gate: ScanAdmissionGate | None = None,
        result_backend: ResultBackend | None = None,
        result_store: ResultBackend | None = None,
    ) -> None:
        if max_workers <= 0 or max_active_jobs <= 0:
            raise ValueError("job service limits must be positive")
        if result_backend is not None and result_store is not None:
            raise ValueError("configure one result backend")
        self._scan_executor = scan_executor or FixtureScanExecutor()
        self._max_active_jobs = max_active_jobs
        self._admission = admission_gate or ScanAdmissionGate(
            duplicate_window_seconds=60,
            origin_cooling_seconds=10,
        )
        self._result_backend = result_backend or result_store or MemoryResultStore()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dom-xray-scan")
        self._jobs: dict[str, _Job] = {}
        self._deletion_failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    @staticmethod
    def _new_job_id() -> str:
        return f"j_{secrets.token_hex(16)}"

    @staticmethod
    def _error(code: str) -> dict[str, object]:
        message, retryable = PUBLIC_ERRORS[code]
        return {"code": code, "message": message, "retryable": retryable}

    def _snapshot(self, job: _Job) -> dict[str, Any]:
        value = {
            "apiVersion": API_VERSION,
            "jobId": job.job_id,
            "state": job.state,
            "progress": job.progress,
            "submittedAt": job.submitted_at,
            "updatedAt": job.updated_at,
            "scanStatus": job.scan_status,
            "result": job.result,
            "error": job.error,
            "pollAfterMs": job.poll_after_ms,
        }
        validate_job(value)
        return value

    def _terminal_job(self, state: str, code: str) -> _Job:
        now = self._now()
        return _Job(
            job_id=self._new_job_id(),
            state=state,
            progress=state,
            submitted_at=now,
            updated_at=now,
            error=self._error(code),
            poll_after_ms=None,
        )

    def reject_submission(self) -> dict[str, Any]:
        job = self._terminal_job("rejected", "invalid-target")
        with self._lock:
            self._jobs[job.job_id] = job
            return self._snapshot(job)

    def submit(
        self,
        target_url: str,
        deletion_token_digest: str,
    ) -> tuple[dict[str, Any], int, int | None]:
        if re.fullmatch(r"[0-9a-f]{64}", deletion_token_digest) is None:
            raise ValueError("invalid deletion token digest")
        if not self._scan_executor.supports(target_url):
            job = self._terminal_job("rejected", "scanner-disabled")
            with self._lock:
                self._jobs[job.job_id] = job
                return self._snapshot(job), HTTPStatus.SERVICE_UNAVAILABLE, None
        try:
            admission = self._admission.reserve(target_url)
        except (TypeError, ValueError):
            job = self._terminal_job("rejected", "invalid-target")
            with self._lock:
                self._jobs[job.job_id] = job
                return self._snapshot(job), HTTPStatus.FORBIDDEN, None

        if admission.action == "reuse":
            assert admission.reusable_result_id is not None
            result_id = admission.reusable_result_id
            with self._lock:
                try:
                    stored = self._result_backend.get(result_id)
                except (ValueError, ResultStoreError):
                    stored = None
                if stored is None:
                    job = None
                else:
                    bundle = json.loads(stored.payload)
                    now = self._now()
                    job = _Job(
                        job_id=self._new_job_id(),
                        state="ready",
                        progress="complete",
                        submitted_at=now,
                        updated_at=now,
                        scan_status=bundle["record"]["status"],
                        result={
                            "resultId": result_id,
                            "resultPath": bundle["result"]["resultPath"],
                            "bundleUrl": f"/api/results/{result_id}",
                        },
                        poll_after_ms=None,
                        target_url=target_url,
                    )
                    self._jobs[job.job_id] = job
                    snapshot = self._snapshot(job)
            if stored is None:
                self._admission.forget_result(result_id)
                return self.submit(target_url, deletion_token_digest)
            return snapshot, HTTPStatus.OK, None

        if admission.action == "reject":
            job = self._terminal_job("rejected", "rate-limited")
            with self._lock:
                self._jobs[job.job_id] = job
                return (
                    self._snapshot(job),
                    HTTPStatus.TOO_MANY_REQUESTS,
                    admission.retry_after_seconds,
                )

        with self._lock:
            active_count = sum(job.state in {"queued", "running"} for job in self._jobs.values())
            if active_count >= self._max_active_jobs:
                self._admission.abandon(target_url)
                job = self._terminal_job("rejected", "queue-full")
                self._jobs[job.job_id] = job
                return self._snapshot(job), HTTPStatus.TOO_MANY_REQUESTS, 1
            now = self._now()
            job = _Job(
                job_id=self._new_job_id(),
                state="queued",
                progress="queued",
                submitted_at=now,
                updated_at=now,
                target_url=target_url,
                deletion_token_digest=deletion_token_digest,
            )
            self._jobs[job.job_id] = job
            snapshot = self._snapshot(job)
        self._pool.submit(self._run, job.job_id, target_url)
        return snapshot, HTTPStatus.ACCEPTED, None

    def _set_progress(self, job_id: str, progress: str) -> None:
        if progress not in {"capturing", "mapping", "publishing"}:
            raise ValueError("unknown job progress")
        with self._lock:
            job = self._jobs[job_id]
            if job.state not in {"queued", "running"}:
                return
            job.state = "running"
            job.progress = progress
            job.updated_at = self._now()

    def _run(self, job_id: str, target_url: str) -> None:
        try:
            executed = self._scan_executor.execute(
                target_url,
                lambda progress: self._set_progress(job_id, progress),
            )
            # Preserve the narrow fake-executor seam used by existing contract
            # tests while requiring ready artifacts at the storage boundary.
            execution = (
                executed
                if isinstance(executed, ScanExecution)
                else ScanExecution(bundle=executed, artifacts={})
            )
            bundle = execution.bundle
            validate_viewer_bundle(bundle)
            if _canonical_target(bundle["record"]["requestedUrl"]) != _canonical_target(target_url):
                raise ApiContractError("executor result does not match its requested target")
            result_id = bundle["result"]["resultId"]
            with self._lock:
                deletion_token_digest = self._jobs[job_id].deletion_token_digest
            if deletion_token_digest is None:
                raise ResultStoreError("queued scan has no deletion token digest")
            self._result_backend.publish(
                bundle,
                deletion_token_digest,
                execution.artifacts,
            )
            self._admission.complete(target_url, result_id)
            with self._lock:
                job = self._jobs[job_id]
                job.state = "ready"
                job.progress = "complete"
                job.updated_at = self._now()
                job.scan_status = bundle["record"]["status"]
                job.result = {
                    "resultId": result_id,
                    "resultPath": bundle["result"]["resultPath"],
                    "bundleUrl": f"/api/results/{result_id}",
                }
                job.deletion_token_digest = None
                job.poll_after_ms = None
                self._snapshot(job)
        except ScanExecutionError as error:
            self._fail(job_id, error.code)
        except Exception:
            self._fail(job_id, "internal-error")

    def _fail(self, job_id: str, code: str) -> None:
        target_url: str | None = None
        with self._lock:
            job = self._jobs[job_id]
            if job.state not in {"queued", "running"}:
                return
            job.state = "failed"
            job.progress = "failed"
            job.updated_at = self._now()
            job.error = self._error(code)
            job.poll_after_ms = None
            job.deletion_token_digest = None
            target_url = job.target_url
            self._snapshot(job)
        if target_url is not None:
            self._admission.abandon(target_url)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return None if job is None else self._snapshot(job)

    def get_bundle(self, result_id: str) -> tuple[bytes, str] | None:
        try:
            stored = self._result_backend.get(result_id)
        except (ValueError, ResultStoreError):
            return None
        return None if stored is None else (stored.payload, stored.etag)

    def get_artifact(
        self,
        result_id: str,
        kind: ArtifactKind = "poster",
    ) -> tuple[bytes, str] | None:
        try:
            stored = self._result_backend.get_artifact(result_id, kind)
        except (ValueError, ResultStoreError):
            return None
        return None if stored is None else (stored.payload, stored.etag)

    def delete_result(self, result_id: str, deletion_token: str) -> tuple[str, int | None]:
        now = time.monotonic()
        with self._lock:
            try:
                outcome = self._result_backend.delete(result_id, deletion_token)
            except ResultStoreError:
                return "not-found", None
            if outcome == "forbidden":
                failures = [
                    attempted_at
                    for attempted_at in self._deletion_failures.get(result_id, [])
                    if now - attempted_at < DELETION_FAILURE_WINDOW_SECONDS
                ]
                failures.append(now)
                self._deletion_failures[result_id] = failures
                if len(failures) >= MAX_DELETION_FAILURES:
                    retry_after = max(
                        1,
                        int(DELETION_FAILURE_WINDOW_SECONDS - (now - failures[0]) + 0.999),
                    )
                    return "rate-limited", retry_after
            elif outcome == "deleted":
                self._deletion_failures.pop(result_id, None)
        if outcome == "deleted":
            self._admission.forget_result(result_id)
        return outcome, None

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)


class LocalScanHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        service: LocalScanJobService,
        *,
        static_root: Path | None,
        verbose: bool = False,
    ) -> None:
        self.service = service
        self.static_root = static_root.resolve() if static_root is not None else None
        self.verbose = verbose
        super().__init__(server_address, LocalScanRequestHandler)


class LocalScanRequestHandler(BaseHTTPRequestHandler):
    server: LocalScanHttpServer

    def log_message(self, format: str, *args: object) -> None:
        if self.server.verbose:
            super().log_message(format, *args)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_json(
        self,
        status: int,
        value: object,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._send_bytes(
            status,
            stable_json_bytes(value),
            "application/json; charset=utf-8",
            headers=headers,
        )

    def _send_empty(
        self,
        status: int,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Length", "0")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def _rejected_body(self, status: int) -> None:
        job = self.server.service.reject_submission()
        self._send_json(status, job, headers={"Cache-Control": "no-store"})

    def _drain_bounded_request_body(self) -> bool:
        if self.headers.get("Transfer-Encoding") is not None:
            return False
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return True
        try:
            content_length = int(raw_length)
        except ValueError:
            return False
        if content_length < 0 or content_length > MAX_REQUEST_BODY_BYTES:
            return False
        try:
            return len(self.rfile.read(content_length)) == content_length
        except OSError:
            return False

    def _reject_artifact_method(self, path: str) -> bool:
        if ARTIFACT_ROUTE_PATTERN.fullmatch(path) is None:
            return False
        drained = self._drain_bounded_request_body()
        headers = {"Allow": "GET, HEAD", "Cache-Control": "no-store"}
        if not drained:
            self.close_connection = True
            headers["Connection"] = "close"
        self._send_empty(
            HTTPStatus.METHOD_NOT_ALLOWED,
            headers=headers,
        )
        return True

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if self._reject_artifact_method(path):
            return
        if path != "/api/scans":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self._rejected_body(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._rejected_body(HTTPStatus.BAD_REQUEST)
            return
        if content_length < 0 or content_length > MAX_REQUEST_BODY_BYTES:
            self._rejected_body(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            raw = self.rfile.read(content_length)
            body = json.loads(raw.decode("utf-8"))
            target_url = validate_submission(body)
        except (UnicodeError, json.JSONDecodeError, ApiContractError):
            self._rejected_body(HTTPStatus.BAD_REQUEST)
            return
        digest_header = self.headers.get("X-Deletion-Token-Digest", "")
        digest_match = DELETION_DIGEST_HEADER_PATTERN.fullmatch(digest_header)
        if digest_match is None:
            self._rejected_body(HTTPStatus.BAD_REQUEST)
            return
        job, status, retry_after = self.server.service.submit(
            target_url,
            digest_match.group(1),
        )
        headers = {"Cache-Control": "no-store", "Location": f"/api/scans/{job['jobId']}"}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)
        self._send_json(status, job, headers=headers)

    def do_PUT(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if self._reject_artifact_method(path):
            return
        self._send_empty(HTTPStatus.NOT_FOUND, headers={"Cache-Control": "no-store"})

    def do_PATCH(self) -> None:  # noqa: N802
        self.do_PUT()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.do_PUT()

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if self._reject_artifact_method(path):
            return
        match = re.fullmatch(r"/api/results/(r_[0-9a-f]{32})", path)
        if match is None:
            self._send_empty(HTTPStatus.NOT_FOUND, headers={"Cache-Control": "no-store"})
            return
        token = self.headers.get("X-Deletion-Token", "")
        outcome, retry_after = self.server.service.delete_result(match.group(1), token)
        if outcome == "deleted":
            self._send_empty(HTTPStatus.NO_CONTENT, headers={"Cache-Control": "no-store"})
        elif outcome == "malformed":
            self._send_empty(HTTPStatus.BAD_REQUEST, headers={"Cache-Control": "no-store"})
        elif outcome == "forbidden":
            self._send_empty(HTTPStatus.FORBIDDEN, headers={"Cache-Control": "no-store"})
        elif outcome == "rate-limited":
            self._send_empty(
                HTTPStatus.TOO_MANY_REQUESTS,
                headers={"Cache-Control": "no-store", "Retry-After": str(retry_after)},
            )
        else:
            self._send_empty(HTTPStatus.NOT_FOUND, headers={"Cache-Control": "no-store"})

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_get()

    def do_GET(self) -> None:  # noqa: N802
        self._handle_get()

    def _handle_get(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "apiVersion": API_VERSION,
                    "status": "ok",
                    "mode": "seeded-fixture-only",
                    "arbitraryPublicScanning": False,
                },
                headers={"Cache-Control": "no-store"},
            )
            return
        if path.startswith("/api/scans/"):
            job_id = path.removeprefix("/api/scans/")
            job = self.server.service.get_job(job_id)
            if job is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            else:
                self._send_json(HTTPStatus.OK, job, headers={"Cache-Control": "no-store"})
            return
        artifact_match = ARTIFACT_ROUTE_PATTERN.fullmatch(path)
        if artifact_match is not None:
            kind, content_type = ARTIFACT_ROUTES[artifact_match.group(2)]
            found = self.server.service.get_artifact(artifact_match.group(1), kind)
            if found is None:
                self._send_empty(
                    HTTPStatus.NOT_FOUND,
                    headers={"Cache-Control": "no-store"},
                )
                return
            payload, etag = found
            if self.headers.get("If-None-Match") == etag:
                self.send_response(HTTPStatus.NOT_MODIFIED)
                self._security_headers()
                self.send_header("Cache-Control", "no-store")
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self._send_bytes(
                HTTPStatus.OK,
                payload,
                content_type,
                headers={"Cache-Control": "no-store", "ETag": etag},
            )
            return
        if path.startswith("/api/results/"):
            result_id = path.removeprefix("/api/results/")
            found = self.server.service.get_bundle(result_id)
            if found is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
                return
            payload, etag = found
            if self.headers.get("If-None-Match") == etag:
                self.send_response(HTTPStatus.NOT_MODIFIED)
                self._security_headers()
                self.send_header("Cache-Control", "no-store")
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self._send_bytes(
                HTTPStatus.OK,
                payload,
                "application/json; charset=utf-8",
                headers={
                    "Cache-Control": "no-store",
                    "ETag": etag,
                },
            )
            return
        self._serve_static(path)

    def _serve_static(self, path: str) -> None:
        static_root = self.server.static_root
        if static_root is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        result_route = bool(re.fullmatch(r"/r/r_[0-9a-f]{32}", path))
        if path == "/" or result_route:
            target = static_root / "index.html"
            cache_control = "no-store"
        elif path.startswith("/assets/"):
            relative = Path(unquote(path.removeprefix("/")))
            target = (static_root / relative).resolve()
            assets_root = (static_root / "assets").resolve()
            try:
                target.relative_to(assets_root)
            except ValueError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
                return
            cache_control = "public, max-age=31536000, immutable"
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        if not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        headers = {"Cache-Control": cache_control}
        if target.name == "index.html":
            headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "style-src-elem 'self'; style-src-attr 'unsafe-inline'; "
                "font-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
                "connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
            )
        self._send_bytes(HTTPStatus.OK, target.read_bytes(), content_type, headers=headers)


def build_server(
    host: str,
    port: int,
    service: LocalScanJobService,
    *,
    static_root: Path | None = None,
    verbose: bool = False,
) -> LocalScanHttpServer:
    return LocalScanHttpServer(
        (host, port),
        service,
        static_root=static_root,
        verbose=verbose,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--static-root", type=Path, default=ROOT / "viewer" / "dist")
    parser.add_argument("--data-dir", type=Path, default=ROOT / ".dom-xray-data")
    parser.add_argument(
        "--retention-hours",
        type=float,
        default=24.0,
        help="Local proof retention only; production policy remains an explicit launch decision.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    store_key = load_or_create_store_key(args.data_dir / "store.key")
    result_backend = FilesystemResultStore(
        args.data_dir / "results",
        keys=(store_key,),
        retention_seconds=args.retention_hours * 60 * 60,
    )
    service = LocalScanJobService(result_backend=result_backend)
    server = build_server(
        args.host,
        args.port,
        service,
        static_root=args.static_root,
        verbose=args.verbose,
    )
    print(
        f"DOM X-Ray local scan API listening on http://{args.host}:{server.server_port} "
        "(seeded fixtures only; arbitrary public scanning disabled)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        service.shutdown()


if __name__ == "__main__":
    main()
