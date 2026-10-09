"""Deployment-neutral transport boundary for one public scan.

This module composes two already-proven gates without choosing an API framework,
resolver, HTTPS implementation, queue, or container platform:

1. the target is independently validated into an ephemeral address grant before
   any worker launch is constructed; and
2. only a nonce/size/exit-eligible supervised worker artifact is parsed, schema
   checked, semantically checked, and returned to the caller.

The launch adapter still has to pin its connector to ``grant.destination.addresses``.
Passing the grant proves the integration seam, not production egress containment.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

from scanner.destination_policy import (
    DestinationPolicy,
    DestinationPurpose,
    ValidatedDestination,
)
from scanner.worker_supervisor import (
    MAX_WORKER_SECONDS,
    WorkerRun,
    run_worker_command,
)


TransportOutcome = Literal[
    "admitted",
    "worker-timeout",
    "worker-crashed",
    "worker-invalid-result",
    "launch-failed",
    "supervisor-failed",
    "invalid-envelope",
    "invalid-record",
]
RecordValidator = Callable[[dict[str, Any]], None]
ConnectionResult = TypeVar("ConnectionResult")


@dataclass(frozen=True, repr=False)
class PublicScanGrant:
    """Ephemeral launch grant; its repr omits the target and resolved addresses."""

    target_url: str
    destination: ValidatedDestination

    def __repr__(self) -> str:
        return (
            "PublicScanGrant("
            f"purpose={self.destination.purpose!r}, "
            f"scheme={self.destination.scheme!r}, "
            f"hostname={self.destination.hostname!r}, "
            f"port={self.destination.port!r}, "
            f"address_count={len(self.destination.addresses)})"
        )


@dataclass(frozen=True)
class WorkerLaunch:
    """Command material created only after the destination grant exists."""

    command: Sequence[str]
    cwd: str | Path | None = None
    environment: Mapping[str, str] | None = None
    input_payload: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ScanTransportResult:
    """Content-free transport outcome; a record exists only after both validators."""

    outcome: TransportOutcome
    worker: WorkerRun | None
    record: dict[str, Any] | None

    @property
    def admitted(self) -> bool:
        return self.outcome == "admitted" and self.record is not None


LaunchWorker = Callable[[PublicScanGrant, Path], WorkerLaunch]


def check_public_scan_grant(grant: PublicScanGrant) -> None:
    """Recheck a trusted launch grant's complete shape without resolving DNS."""
    try:
        if (not isinstance(grant, PublicScanGrant)
                or not isinstance(grant.destination, ValidatedDestination)
                or grant.destination.purpose != "initial"
                or not isinstance(grant.destination.addresses, tuple)):
            raise ValueError("invalid grant")
        checked = DestinationPolicy(lambda _host, _port: grant.destination.addresses).validate(
            grant.target_url, purpose="initial")
        if checked != grant.destination:
            raise ValueError("noncanonical grant")
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid-public-scan-grant") from None


def decode_public_scan_grant(payload: object) -> PublicScanGrant:
    """Decode only grant data, never runtime paths, commands or resolver settings."""
    if not isinstance(payload, dict) or set(payload) != {'targetUrl', 'destination'}:
        raise ValueError('invalid-public-scan-grant')
    destination = payload['destination']
    if (not isinstance(destination, dict)
            or set(destination) != {'purpose', 'scheme', 'hostname', 'port', 'addresses'}
            or not isinstance(destination['addresses'], list)
            or isinstance(destination['port'], bool) or not isinstance(destination['port'], int)
            or any(not isinstance(destination[key], str) for key in ('purpose', 'scheme', 'hostname'))):
        raise ValueError('invalid-public-scan-grant')
    grant = PublicScanGrant(payload['targetUrl'],
        ValidatedDestination(**{**destination, 'addresses': tuple(destination['addresses'])}))
    check_public_scan_grant(grant)
    return grant


def public_scan_target_matches(url: str, grant: PublicScanGrant) -> bool:
    """Match the initial URL, including path, with no network resolution.

    Initial targets disallow query/fragment material. The local policy check
    prevents normalization from silently accepting those or unsafe syntax.
    """
    try:
        checked = DestinationPolicy(lambda _host, _port: grant.destination.addresses).validate(
            url, purpose="initial")
        return checked == grant.destination and _normalized_url_identity(url) == _normalized_url_identity(grant.target_url)
    except (TypeError, ValueError, AttributeError):
        return False


def _worker_outcome(run: WorkerRun) -> TransportOutcome:
    if run.outcome == "timeout":
        return "worker-timeout"
    if run.outcome == "crashed":
        return "worker-crashed"
    return "worker-invalid-result"


def authorize_connection(
    target_url: str,
    *,
    purpose: DestinationPurpose,
    policy: DestinationPolicy,
    connector: Callable[[ValidatedDestination], ConnectionResult],
) -> ConnectionResult:
    """Give a connector only a freshly validated destination grant."""

    return policy.authorize_and_connect(
        target_url,
        purpose=purpose,
        connector=connector,
    )


def _normalized_url_identity(url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL has no hostname")
    try:
        normalized_hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        normalized_hostname = hostname.lower()
    scheme = parsed.scheme.lower()
    effective_port = parsed.port if parsed.port is not None else (80 if scheme == "http" else 443)
    return scheme, normalized_hostname, effective_port, parsed.path or "/"


def _record_matches_grant(requested_url: object, grant: PublicScanGrant) -> bool:
    if not isinstance(requested_url, str):
        return False
    return _normalized_url_identity(requested_url) == _normalized_url_identity(
        grant.target_url
    )


def _read_record_envelope(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"supervisorNonce", "result"}:
        raise ValueError("invalid worker envelope")
    result = payload["result"]
    if not isinstance(result, dict) or set(result) != {"record"}:
        raise ValueError("invalid worker result")
    record = result["record"]
    if not isinstance(record, dict):
        raise ValueError("invalid scan record")
    return record


def run_public_scan_transport(
    target_url: str,
    *,
    policy: DestinationPolicy,
    launch_worker: LaunchWorker,
    schema_validator: RecordValidator,
    semantic_validator: RecordValidator,
    deadline_seconds: float = MAX_WORKER_SECONDS,
    temporary_root: str | Path | None = None,
    worker_supervisor: Callable[[WorkerLaunch, Path, float], WorkerRun] | None = None,
) -> ScanTransportResult:
    """Validate, supervise, and admit one scan without publishing partial output.

    ``DestinationPolicyError`` propagates before ``launch_worker`` is invoked.
    All worker or record failures collapse to allowlisted outcome values and carry
    no untrusted error text. Temporary result artifacts are destroyed on return.
    An explicit supervisor is trusted deployment code, not visitor configuration.
    Stdin payloads require that provider; the process default never ignores them.
    """

    target_url = policy.canonical_url(target_url, purpose="initial")
    destination = policy.validate(target_url, purpose="initial")
    grant = PublicScanGrant(target_url=target_url, destination=destination)
    temporary_parent = None if temporary_root is None else str(temporary_root)

    with tempfile.TemporaryDirectory(
        prefix="dom-xray-scan-transport-",
        dir=temporary_parent,
    ) as temporary:
        result_path = Path(temporary) / "worker-result.json"
        try:
            launch = launch_worker(grant, result_path)
        except Exception:
            return ScanTransportResult(
                outcome="launch-failed",
                worker=None,
                record=None,
            )
        if not isinstance(launch, WorkerLaunch):
            return ScanTransportResult(
                outcome="launch-failed",
                worker=None,
                record=None,
            )
        try:
            if worker_supervisor is None:
                if launch.input_payload is not None:
                    raise ValueError('worker stdin requires an explicit trusted supervisor')
                run = run_worker_command(
                    launch.command, result_path=result_path, deadline_seconds=deadline_seconds,
                    cwd=launch.cwd, environment=launch.environment)
            else:
                run = worker_supervisor(launch, result_path, deadline_seconds)
            if not isinstance(run, WorkerRun):
                raise ValueError('invalid worker supervision result')
        except Exception:
            return ScanTransportResult(
                outcome="supervisor-failed",
                worker=None,
                record=None,
            )
        if not run.artifact_eligible:
            return ScanTransportResult(
                outcome=_worker_outcome(run),
                worker=run,
                record=None,
            )

        try:
            record = _read_record_envelope(result_path)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return ScanTransportResult(
                outcome="invalid-envelope",
                worker=run,
                record=None,
            )

        try:
            schema_validator(copy.deepcopy(record))
            semantic_validator(copy.deepcopy(record))
            if not _record_matches_grant(record.get("requestedUrl"), grant):
                raise ValueError("scan record does not match its destination grant")
        except Exception:
            return ScanTransportResult(
                outcome="invalid-record",
                worker=run,
                record=None,
            )

        return ScanTransportResult(
            outcome="admitted",
            worker=run,
            record=record,
        )
