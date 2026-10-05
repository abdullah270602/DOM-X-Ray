"""Process-level deadline boundary for disposable scanner workers.

This module deliberately supervises a command rather than a Playwright page.
The worker command must own the browser and atomically persist its result before
exiting. A normal zero exit is the only outcome that makes that artifact eligible
for use. Production still requires the worker to run inside the deployment's
reviewed container or equivalent operating-system containment boundary.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Sequence


MAX_WORKER_SECONDS = 15.0
MIN_WORKER_SECONDS = 1.0
TERMINATION_RESERVE_SECONDS = 0.5
MAX_WORKER_RESULT_BYTES = 4_000_000
RESULT_NONCE_ENV = "DOM_X_RAY_WORKER_RESULT_NONCE"


@dataclass(frozen=True)
class WorkerRun:
    outcome: Literal["completed", "crashed", "invalid-result", "timeout"]
    returncode: int | None
    duration_ms: float
    deadline_seconds: float
    artifact_present: bool

    @property
    def artifact_eligible(self) -> bool:
        """Whether the transport envelope may proceed to schema validation."""

        return (
            self.outcome == "completed"
            and self.returncode == 0
            and self.artifact_present
        )


class WorkerContainmentError(RuntimeError):
    """Raised when the supervisor cannot prove that its root worker exited."""


class _WindowsJob:
    """Kill-on-close Job Object for one Windows worker process tree."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.AssignProcessToJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
        ]
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        if not kernel32.SetInformationJobObject(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel32.CloseHandle(handle)
            raise error
        process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
        if not kernel32.AssignProcessToJobObject(handle, process_handle):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel32.CloseHandle(handle)
            raise error
        self._kernel32 = kernel32
        self._handle = handle

    def terminate(self) -> None:
        import ctypes

        if self._handle and not self._kernel32.TerminateJobObject(self._handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    """Resume every initial thread after the suspended process joins its Job."""

    import ctypes
    from ctypes import wintypes

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Thread32First.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ThreadEntry32),
    ]
    kernel32.Thread32Next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ThreadEntry32),
    ]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    resumed = 0
    try:
        entry = ThreadEntry32()
        entry.dwSize = ctypes.sizeof(ThreadEntry32)
        has_entry = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while has_entry:
            if entry.th32OwnerProcessID == process.pid:
                thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                if not thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if kernel32.ResumeThread(thread) == 0xFFFFFFFF:
                        raise ctypes.WinError(ctypes.get_last_error())
                    resumed += 1
                finally:
                    kernel32.CloseHandle(thread)
            has_entry = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)
    if resumed == 0:
        raise WorkerContainmentError(
            f"suspended worker process {process.pid} exposed no resumable thread"
        )


def _validated_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("worker command must be a non-empty argument sequence")
    normalized = tuple(str(part) for part in command)
    if any(not part for part in normalized):
        raise ValueError("worker command arguments must be non-empty")
    return normalized


def _validated_deadline(deadline_seconds: float) -> float:
    if isinstance(deadline_seconds, bool) or not isinstance(
        deadline_seconds, (int, float)
    ):
        raise ValueError("worker deadline must be a positive number")
    normalized = float(deadline_seconds)
    if normalized < MIN_WORKER_SECONDS or normalized > MAX_WORKER_SECONDS:
        raise ValueError(
            f"worker deadline must be within [{MIN_WORKER_SECONDS}, "
            f"{MAX_WORKER_SECONDS}] seconds"
        )
    return normalized


def _remaining_seconds(outer_deadline: float) -> float:
    return max(0.0, outer_deadline - time.monotonic())


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    outer_deadline: float,
    windows_job: _WindowsJob | None = None,
) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        if windows_job is not None:
            windows_job.terminate()
        else:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(0.05, _remaining_seconds(outer_deadline)),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                pass
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        process.wait(timeout=max(0.0, _remaining_seconds(outer_deadline)))
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=max(0.0, _remaining_seconds(outer_deadline)))
        except subprocess.TimeoutExpired as error:
            raise WorkerContainmentError(
                f"worker process {process.pid} survived deadline termination"
            ) from error


def _artifact_is_valid(path: Path, nonce: str, max_bytes: int = MAX_WORKER_RESULT_BYTES) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return False
        if metadata.st_size <= 0 or metadata.st_size > max_bytes:
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("supervisorNonce") == nonce
        and "result" in payload
    )


def run_worker_command(
    command: Sequence[str],
    *,
    result_path: str | Path,
    deadline_seconds: float = MAX_WORKER_SECONDS,
    cwd: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
    max_result_bytes: int = MAX_WORKER_RESULT_BYTES,
) -> WorkerRun:
    """Run one disposable worker under a wall-clock process deadline.

    The outer clock starts immediately before process creation. It reserves a
    bounded tail for process-tree termination, so both timeout classification and
    cleanup stay inside the declared wall-time ceiling. Standard streams are
    closed so an untrusted page cannot create an unbounded supervisor buffer.
    Callers may narrow the result byte limit, never exceed the hard ceiling;
    file size is checked before JSON parsing.
    """

    normalized_command = _validated_command(command)
    normalized_deadline = _validated_deadline(deadline_seconds)
    if (isinstance(max_result_bytes, bool) or not isinstance(max_result_bytes, int)
            or not 1 <= max_result_bytes <= MAX_WORKER_RESULT_BYTES):
        raise ValueError("invalid worker result byte limit")
    normalized_result_path = Path(result_path)
    if normalized_result_path.exists():
        raise ValueError("worker result path must be unique and absent before launch")
    result_nonce = secrets.token_hex(16)
    worker_environment = (
        os.environ.copy() if environment is None else dict(environment)
    )
    worker_environment[RESULT_NONCE_ENV] = result_nonce
    popen_options: dict[str, object] = {
        "cwd": str(cwd) if cwd is not None else None,
        "env": worker_environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
    }
    if os.name == "nt":
        popen_options["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
            | 0x00000004
        )
    else:
        popen_options["start_new_session"] = True

    started = time.monotonic()
    outer_deadline = started + normalized_deadline
    process = subprocess.Popen(normalized_command, **popen_options)  # type: ignore[arg-type]
    windows_job = None
    if os.name == "nt":
        try:
            windows_job = _WindowsJob(process)
            _resume_windows_process(process)
        except (OSError, WorkerContainmentError) as error:
            if windows_job is not None:
                windows_job.terminate()
                windows_job.close()
            else:
                process.kill()
            process.wait(timeout=max(0.0, _remaining_seconds(outer_deadline)))
            raise WorkerContainmentError(
                "worker could not be contained and resumed through a Windows Job Object"
            ) from error
    termination_reserve = min(
        TERMINATION_RESERVE_SECONDS,
        normalized_deadline * 0.4,
    )
    execution_deadline = outer_deadline - termination_reserve
    remaining_seconds = max(
        0.0,
        execution_deadline - time.monotonic(),
    )
    try:
        try:
            returncode = process.wait(timeout=remaining_seconds)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(
                process,
                outer_deadline=outer_deadline,
                windows_job=windows_job,
            )
            return WorkerRun(
                outcome="timeout",
                returncode=None,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                deadline_seconds=normalized_deadline,
                artifact_present=normalized_result_path.is_file(),
            )
    finally:
        if windows_job is not None:
            windows_job.close()

    artifact_present = normalized_result_path.exists()
    artifact_valid = _artifact_is_valid(normalized_result_path, result_nonce, max_result_bytes)
    if returncode == 0 and artifact_valid:
        outcome = "completed"
    elif returncode == 0:
        outcome = "invalid-result"
    else:
        outcome = "crashed"
    return WorkerRun(
        outcome=outcome,
        returncode=returncode,
        duration_ms=round((time.monotonic() - started) * 1000, 3),
        deadline_seconds=normalized_deadline,
        artifact_present=artifact_present,
    )
