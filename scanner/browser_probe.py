"""Controlled Chromium probe used only for deterministic Gate 0 fixtures.

This module proves browser instrumentation choices without selecting the public
application stack. It is intentionally local-only: production resolver/egress
integration, queueing, and public-suffix handling remain release gates.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from playwright.sync_api import Browser, Error as PlaywrightError, Route

from scanner.aggregation import aggregate_nodes
from scanner.destination_policy import is_forbidden_literal_host
from scanner.insights import select_hero_insight


VIEWPORT = {"width": 1440, "height": 900}
QUALIFYING_TYPES = {
    "Document",
    "Stylesheet",
    "Image",
    "Media",
    "Font",
    "Script",
    "XHR",
    "Fetch",
}
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
REDIRECT_LIMIT = 10
MAX_REQUESTS = 500
MAX_RESPONSE_BYTES = 20_000_000
MAX_TOTAL_RECEIVED_BYTES = 50_000_000
MAX_AUXILIARY_EVENTS = 100
NETWORK_LIMIT_REASONS = frozenset(
    {"request-limit", "response-byte-limit", "total-byte-limit"}
)
MAX_INSPECTED_ELEMENTS = 20_000
MAX_GEOMETRY_CANDIDATES = 5_000
INTERSTITIAL_CLASSIFIER_VERSION = "login-gate-structural-v1"
HTTP_ERROR_INTERSTITIAL_CLASSIFIER_VERSION = "http-error-status-v1"
SCANNER_USER_AGENT = "DOM-X-Ray-Scanner-Fixture/0.1"
SENSITIVE_OUTBOUND_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "referer"}
)


INIT_SCRIPT = r"""
(() => {
  const rect = value => ({
    x: value.x,
    y: value.y,
    width: value.width,
    height: value.height,
  });
  const state = {
    activitySerial: 0,
    layoutShiftSupported: false,
    mutationObserverReady: false,
    shifts: [],
    shiftNodeRefs: [],
  };
  Object.defineProperty(window, '__domXRayProbe', { value: state });

  try {
    const observer = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        state.activitySerial += 1;
        state.shifts.push({
          timestampMs: entry.startTime,
          value: entry.value,
          hadRecentInput: entry.hadRecentInput,
          sources: (entry.sources || []).slice(0, 12).map(source => {
            const nodeRef = source.node && source.node.nodeType === Node.ELEMENT_NODE
              ? state.shiftNodeRefs.push(source.node) - 1
              : null;
            return {
              nodeRef,
              previousRect: rect(source.previousRect),
              currentRect: rect(source.currentRect),
            };
          }),
        });
      }
    });
    observer.observe({ type: 'layout-shift', buffered: true });
    state.layoutShiftSupported = true;
  } catch (_) {
    state.layoutShiftSupported = false;
  }

  const installMutationObserver = () => {
    if (!document.body || state.mutationObserverReady) return;
    const ignored = node => {
      const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
      return Boolean(element && element.closest('script, style'));
    };
    const observer = new MutationObserver(records => {
      if (records.some(record => !ignored(record.target))) state.activitySerial += 1;
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ['class', 'style', 'hidden', 'open', 'width', 'height', 'src', 'srcset', 'sizes', 'href'],
    });
    state.mutationObserverReady = true;
  };
  addEventListener('DOMContentLoaded', installMutationObserver, { once: true });
})();
"""


@dataclass
class ProbeResult:
    record: dict[str, Any]
    blocked_requests: list[dict[str, Any]]
    layout_shift_supported: bool
    fixture_node_ids: dict[str, str]
    remaining_auxiliary_page_count: int


@dataclass
class AuxiliaryEventCounter:
    """Saturating, content-free popup/download observation state."""

    limit: int
    popup_attempt_count: int = 0
    download_attempt_count: int = 0
    truncated: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or self.limit <= 0
            or self.limit > MAX_AUXILIARY_EVENTS
        ):
            raise ValueError(
                "auxiliary event limit must be a positive integer no greater than "
                f"{MAX_AUXILIARY_EVENTS}"
            )

    @property
    def observed_count(self) -> int:
        return self.popup_attempt_count + self.download_attempt_count

    def observe(self, event_type: str) -> None:
        if event_type not in {"popup", "download"}:
            raise ValueError(f"unsupported auxiliary event type: {event_type}")
        if self.observed_count >= self.limit:
            self.truncated = True
            return
        if event_type == "popup":
            self.popup_attempt_count += 1
        else:
            self.download_attempt_count += 1


@dataclass
class NavigationPolicyResult:
    blocked_requests: list[dict[str, str]]
    final_url: str
    navigation_error: str | None
    response_status: int | None


def registrable_domain_for_fixture(hostname: str | None) -> str | None:
    """Return the reserved-name registrable domain used by local fixtures.

    Production code must replace this with the pinned Public Suffix List rule.
    """

    if not hostname:
        return None
    host = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else host
    return host


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 80 if parsed.scheme == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return f"{parsed.scheme}://{hostname}{port}"


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path or "/", "", ""))


def _match_url(url: str) -> str:
    """Canonical in-memory URL key; query participates and is never published."""

    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return urlunsplit(
        (parsed.scheme.lower(), f"{hostname}{port}", parsed.path or "/", parsed.query, "")
    )


def correlate_worker_bootstrap_egress_bytes(
    network_rows: list[dict[str, Any]],
    egress_observations: list[dict[str, Any]],
    correlation_key: Callable[[str], str],
) -> int:
    """Apply exact proxy wire bytes to uniquely matched worker bootstrap rows.

    The proxy retains only an opaque keyed identity for each full URL. An
    identity/method group is usable only when it contains exactly one attached
    worker bootstrap and one successfully relayed ``serviceworker`` fetch.
    Repeated identical requests remain unknown rather than assigning bytes by
    timing or list order.
    """

    bootstraps_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    observations_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in network_rows:
        if not row.get("workerBootstrap") or row.get("transferredBytes") is not None:
            continue
        key = (
            str(row.get("method", "")).upper(),
            correlation_key(str(row.get("url", ""))),
        )
        bootstraps_by_key.setdefault(key, []).append(row)
    for observation in egress_observations:
        wire_bytes = observation.get("browserWireBytes")
        status = observation.get("responseStatus")
        opaque_key = observation.get("correlationKey")
        if (
            observation.get("fetchDestination") != "serviceworker"
            or observation.get("outcome") != "relayed"
            or not isinstance(opaque_key, str)
            or not opaque_key
            or isinstance(wire_bytes, bool)
            or not isinstance(wire_bytes, int)
            or wire_bytes < 0
            or isinstance(status, bool)
            or not isinstance(status, int)
            or not 200 <= status < 300
        ):
            continue
        key = (
            str(observation.get("method", "")).upper(),
            opaque_key,
        )
        observations_by_key.setdefault(key, []).append(observation)

    matched = 0
    for key, bootstraps in bootstraps_by_key.items():
        observations = observations_by_key.get(key, [])
        if len(bootstraps) != 1 or len(observations) != 1:
            continue
        bootstrap = bootstraps[0]
        observation = observations[0]
        bootstrap["transferredBytes"] = int(observation["browserWireBytes"])
        bootstrap["status"] = int(observation["responseStatus"])
        bootstrap["egressBootstrapBytes"] = True
        matched += 1
    return matched


def correlate_policy_blocks(
    ordered_network: list[dict[str, Any]],
    blocked_requests: list[dict[str, Any]],
) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Correlate each instrument block with only its first CDP occurrence.

    A page or service worker can read and replay a response marker after the
    original response arrives. Every proxy block therefore has an independent
    random ID, and later replays remain ordinary page-controlled responses.
    """

    blocked_by_id = {
        str(item["blockId"]): item
        for item in blocked_requests
        if item.get("blockId") is not None
    }
    claimed_ids: set[str] = set()
    trusted_by_hop: dict[tuple[str, str, int], dict[str, Any]] = {}
    for item in ordered_network:
        block_id = item.get("policyBlockId")
        if block_id is None:
            continue
        normalized_id = str(block_id)
        if normalized_id in claimed_ids or normalized_id not in blocked_by_id:
            continue
        claimed_ids.add(normalized_id)
        trusted_by_hop[
            (str(item["ownerKey"]), str(item["requestId"]), int(item["hopIndex"]))
        ] = blocked_by_id[normalized_id]
    return trusted_by_hop


def _resource_type(cdp_type: str | None) -> str:
    normalized = (cdp_type or "Other").lower()
    return normalized if normalized in {
        "document", "stylesheet", "image", "media", "font", "script", "fetch", "xhr"
    } else "other"


def request_block_reason(method: str, url: str) -> str | None:
    """Return the first request-policy rejection represented by this proof."""

    parsed = urlsplit(url)
    if method.upper() not in ALLOWED_METHODS:
        return "method"
    if parsed.scheme not in {"http", "https"}:
        return "scheme"
    if parsed.username is not None or parsed.password is not None:
        return "credentials"
    if is_forbidden_literal_host(parsed.hostname):
        return "private-literal-host"
    return None


def classify_transfer_source(
    *,
    from_service_worker: bool,
    from_cache: bool,
    transferred_bytes: int | None,
) -> str:
    """Choose one mutually exclusive transfer source in evidence-priority order."""

    if from_service_worker:
        return "service-worker"
    if from_cache:
        return "cache"
    if transferred_bytes is not None:
        return "network"
    return "unknown"


def classify_interstitial_v1(signals: dict[str, int | None]) -> str | None:
    """Classify only direct HTTP errors or a strong isolated credential gate."""

    final_document_status = signals.get("finalDocumentStatus")
    if isinstance(final_document_status, int) and 400 <= final_document_status <= 599:
        return "error-document"

    if (
        signals.get("visibleFormCount") == 1
        and signals.get("visibleCredentialFormCount") == 1
        and signals.get("visiblePasswordInputCount", 0) >= 1
        and signals.get("visibleIdentityInputCount", 0) >= 1
        and signals.get("visibleSubmitControlCount", 0) >= 1
        and signals.get("visibleCompetingContentCount", 0) == 0
    ):
        return "login-wall"
    return None


def validate_fixture_target(url: str, *, allow_trusted_loopback: bool = False) -> None:
    """Keep the proof harness physically scoped to reserved local fixtures."""

    parsed = urlsplit(url)
    allowed_host = bool(
        parsed.hostname
        and (
            parsed.hostname.endswith(".test")
            or (allow_trusted_loopback and parsed.hostname == "localhost")
        )
    )
    if parsed.scheme != "http" or not allowed_host:
        raise ValueError("browser_probe accepts reserved HTTP .test fixtures only")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("browser_probe fixture targets cannot contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("browser_probe fixture targets cannot contain query or fragment data")


def _make_request_guard(
    blocked: list[dict[str, str]],
    *,
    trusted_loopback_origin: str | None = None,
) -> Any:
    def guard(route: Route) -> None:
        request = route.request
        reason = request_block_reason(request.method, request.url)
        if (
            reason == "private-literal-host"
            and trusted_loopback_origin is not None
            and _origin(request.url) == trusted_loopback_origin
        ):
            reason = None

        if reason:
            blocked.append(
                {
                    "url": _redacted_url(request.url),
                    "method": request.method,
                    "reason": reason,
                    "redirect": "false",
                }
            )
            route.abort("blockedbyclient")
        else:
            headers = {
                name: value
                for name, value in request.headers.items()
                if name.lower() not in SENSITIVE_OUTBOUND_HEADERS
            }
            headers["user-agent"] = SCANNER_USER_AGENT
            route.continue_(headers=headers)

    return guard


def probe_navigation_policy(
    browser: Browser,
    url: str,
    *,
    proxy_server: str,
) -> NavigationPolicyResult:
    """Exercise the fixture-only browser request guard without producing a scan record."""

    validate_fixture_target(url)
    blocked_requests: list[dict[str, str]] = []
    context = browser.new_context(
        accept_downloads=False,
        proxy={"server": proxy_server},
        user_agent=SCANNER_USER_AGENT,
    )
    context.clear_permissions()
    context.route("**/*", _make_request_guard(blocked_requests))
    page = context.new_page()
    error: str | None = None
    response_status: int | None = None
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=10_000)
        response_status = response.status if response is not None else None
    except PlaywrightError as exc:
        error = str(exc)
    finally:
        final_url = _redacted_url(page.url) if page.url.startswith(("http://", "https://")) else page.url
        context.close()
    return NavigationPolicyResult(blocked_requests, final_url, error, response_status)


def _stacking_context(element: dict[str, Any]) -> dict[str, Any]:
    if element["parentId"] is None:
        return {"creates": True, "rule": "document-root"}
    if element["stackingRule"]:
        return {"creates": True, "rule": element["stackingRule"]}
    return {"creates": False, "rule": None}


def probe_page(
    browser: Browser,
    url: str,
    *,
    hard_stop_seconds: float = 12.0,
    proxy_server: str | None = None,
    cache_disabled: bool = True,
    trusted_loopback_fixture: bool = False,
    policy_block_log: list[dict[str, Any]] | None = None,
    egress_observation_snapshot: Callable[[], list[dict[str, Any]]] | None = None,
    egress_correlation_key: Callable[[str], str] | None = None,
    max_requests: int = MAX_REQUESTS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    max_total_received_bytes: int = MAX_TOTAL_RECEIVED_BYTES,
    max_inspected_elements: int = MAX_INSPECTED_ELEMENTS,
    max_geometry_candidates: int = MAX_GEOMETRY_CANDIDATES,
    max_auxiliary_events: int = MAX_AUXILIARY_EVENTS,
) -> ProbeResult:
    for name, value, ceiling in (
        ("max_requests", max_requests, MAX_REQUESTS),
        ("max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES),
        (
            "max_total_received_bytes",
            max_total_received_bytes,
            MAX_TOTAL_RECEIVED_BYTES,
        ),
        ("max_inspected_elements", max_inspected_elements, MAX_INSPECTED_ELEMENTS),
        ("max_geometry_candidates", max_geometry_candidates, MAX_GEOMETRY_CANDIDATES),
        ("max_auxiliary_events", max_auxiliary_events, MAX_AUXILIARY_EVENTS),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        if value > ceiling:
            raise ValueError(f"{name} cannot exceed its hard ceiling of {ceiling}")
    validate_fixture_target(url, allow_trusted_loopback=trusted_loopback_fixture)
    if proxy_server is not None and policy_block_log is None:
        raise ValueError("proxy-backed fixture capture requires its policy block log")
    if (egress_observation_snapshot is None) != (egress_correlation_key is None):
        raise ValueError("egress observation snapshot and correlation key must be paired")
    if proxy_server is None and egress_observation_snapshot is not None:
        raise ValueError("egress observations require their enforcing proxy")
    if proxy_server is None and (
        max_requests != MAX_REQUESTS
        or max_response_bytes != MAX_RESPONSE_BYTES
        or max_total_received_bytes != MAX_TOTAL_RECEIVED_BYTES
    ):
        raise ValueError("lower network limits require an enforcing egress proxy")
    blocked_requests: list[dict[str, Any]] = (
        policy_block_log if policy_block_log is not None else []
    )
    network: dict[tuple[str, str, int], dict[str, Any]] = {}
    current_hops: dict[tuple[str, str], int] = {}
    chain_ordinals: dict[tuple[str, str], int] = {}
    next_chain_ordinal = [0]
    worker_sessions: dict[str, str] = {}
    worker_target_ids: set[str] = set()
    next_worker_command_id = [0]
    active_qualifying_requests: set[tuple[str, str, int]] = set()
    last_network_activity = [time.monotonic()]
    navigation_started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    auxiliary_events = AuxiliaryEventCounter(max_auxiliary_events)
    auxiliary_handler_failure: list[str | None] = [None]

    def observe_auxiliary_page(auxiliary_page: Any) -> None:
        auxiliary_events.observe("popup")
        last_network_activity[0] = time.monotonic()
        auxiliary_page.on("download", observe_download)
        try:
            auxiliary_page.close()
        except Exception:
            auxiliary_handler_failure[0] = "popup-close-failed"

    def observe_download(download: Any) -> None:
        auxiliary_events.observe("download")
        last_network_activity[0] = time.monotonic()
        try:
            download.cancel()
        except Exception:
            auxiliary_handler_failure[0] = "download-cancel-failed"

    context = browser.new_context(
        viewport=VIEWPORT,
        device_scale_factor=1,
        locale="en-US",
        timezone_id="UTC",
        color_scheme="light",
        reduced_motion="no-preference",
        service_workers="allow",
        accept_downloads=False,
        user_agent=SCANNER_USER_AGENT,
        proxy={"server": proxy_server} if proxy_server else None,
    )
    try:
        context.clear_permissions()
        if proxy_server is None:
            context.route(
                "**/*",
                _make_request_guard(
                    blocked_requests,
                    trusted_loopback_origin=_origin(url) if trusted_loopback_fixture else None,
                ),
            )
        context.add_init_script(INIT_SCRIPT)
        page = context.new_page()
        page.on("download", observe_download)
        context.on("page", observe_auxiliary_page)
        cdp = context.new_cdp_session(page)
        main_frame_id = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
    except Exception:
        context.close()
        raise

    def record_request(
        owner_key: str,
        request_owner: str,
        params: dict[str, Any],
    ) -> None:
        request_id = params["requestId"]
        request_key = (owner_key, request_id)
        if request_key not in chain_ordinals:
            next_chain_ordinal[0] += 1
            chain_ordinals[request_key] = next_chain_ordinal[0]
            hop_index = 0
        else:
            hop_index = current_hops[request_key] + 1
            previous = network[(owner_key, request_id, hop_index - 1)]
            active_qualifying_requests.discard((owner_key, request_id, hop_index - 1))
            redirect_response = params.get("redirectResponse")
            if redirect_response is not None:
                previous["status"] = redirect_response.get("status")
                previous["fromDiskCache"] = redirect_response.get("fromDiskCache", False)
                previous["fromServiceWorker"] = redirect_response.get("fromServiceWorker", False)
                encoded_length = redirect_response.get("encodedDataLength")
                previous["transferredBytes"] = (
                    int(round(encoded_length)) if isinstance(encoded_length, (int, float)) else None
                )
                previous["finishedTimestamp"] = params.get("timestamp")
                previous["redirectedToUrl"] = params["request"]["url"]
                if previous["type"] in QUALIFYING_TYPES:
                    last_network_activity[0] = time.monotonic()
        current_hops[request_key] = hop_index
        network[(owner_key, request_id, hop_index)] = {
            "ownerKey": owner_key,
            "requestOwner": request_owner,
            "requestId": request_id,
            "chainOrdinal": chain_ordinals[request_key],
            "hopIndex": hop_index,
            "url": params["request"]["url"],
            "method": params["request"]["method"],
            "initiatorType": params.get("initiator", {}).get("type"),
            "type": params.get("type", "Other"),
            "startedTimestamp": params.get("timestamp"),
            "decodedBodyBytes": None,
            "transferredBytes": None,
            "finishedTimestamp": None,
            "fromDiskCache": False,
            "fromServiceWorker": False,
            "failed": False,
            "redirectedToUrl": None,
            "isMainNavigation": (
                request_owner == "page"
                and params.get("frameId") == main_frame_id
                and params.get("type") == "Document"
            ),
            "workerBootstrap": False,
            "policyBlockId": None,
        }
        if network[(owner_key, request_id, hop_index)]["type"] in QUALIFYING_TYPES:
            active_qualifying_requests.add((owner_key, request_id, hop_index))

    def record_response(owner_key: str, params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        request_key = (owner_key, request_id)
        item = network.get((owner_key, request_id, current_hops.get(request_key, 0)))
        if item is None:
            return
        response = params["response"]
        item["type"] = params.get("type", item["type"])
        if item["type"] in QUALIFYING_TYPES and item["finishedTimestamp"] is None:
            active_qualifying_requests.add(
                (owner_key, request_id, current_hops.get(request_key, 0))
            )
        item["status"] = response.get("status")
        item["fromDiskCache"] = response.get("fromDiskCache", False)
        item["fromServiceWorker"] = response.get("fromServiceWorker", False)
        item["policyBlockId"] = next(
            (
                str(value)
                for name, value in response.get("headers", {}).items()
                if str(name).lower() == "x-dom-x-ray-block-id"
            ),
            None,
        )

    def record_finished(owner_key: str, params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        request_key = (owner_key, request_id)
        item = network.get((owner_key, request_id, current_hops.get(request_key, 0)))
        if item is None:
            return
        item["transferredBytes"] = int(round(params.get("encodedDataLength", 0)))
        item["finishedTimestamp"] = params.get("timestamp")
        active_qualifying_requests.discard(
            (owner_key, request_id, current_hops.get(request_key, 0))
        )
        if item["type"] in QUALIFYING_TYPES:
            last_network_activity[0] = time.monotonic()

    def record_failed(owner_key: str, params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        request_key = (owner_key, request_id)
        item = network.get((owner_key, request_id, current_hops.get(request_key, 0)))
        if item is None:
            return
        item["failed"] = True
        item["finishedTimestamp"] = params.get("timestamp")
        active_qualifying_requests.discard(
            (owner_key, request_id, current_hops.get(request_key, 0))
        )
        if item["type"] in QUALIFYING_TYPES:
            last_network_activity[0] = time.monotonic()

    def record_served_from_cache(owner_key: str, params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        request_key = (owner_key, request_id)
        item = network.get((owner_key, request_id, current_hops.get(request_key, 0)))
        if item is not None:
            item["fromDiskCache"] = True

    def send_worker_command(session_id: str, method: str, params: dict[str, Any] | None = None) -> None:
        next_worker_command_id[0] += 1
        cdp.send(
            "Target.sendMessageToTarget",
            {
                "sessionId": session_id,
                "message": json.dumps(
                    {
                        "id": next_worker_command_id[0],
                        "method": method,
                        "params": params or {},
                    }
                ),
            },
        )

    def on_attached_to_target(params: dict[str, Any]) -> None:
        session_id = params["sessionId"]
        target = params["targetInfo"]
        if target.get("type") != "service_worker":
            send_worker_command(session_id, "Runtime.runIfWaitingForDebugger")
            return

        target_id = target["targetId"]
        worker_sessions[session_id] = target_id
        if target_id not in worker_target_ids:
            worker_target_ids.add(target_id)
            next_chain_ordinal[0] += 1
            bootstrap_id = f"bootstrap:{target_id}"
            network[(target_id, bootstrap_id, 0)] = {
                "ownerKey": target_id,
                "requestOwner": "service-worker",
                "requestId": bootstrap_id,
                "chainOrdinal": next_chain_ordinal[0],
                "hopIndex": 0,
                "url": target.get("url", ""),
                "method": "GET",
                "initiatorType": "service-worker-registration",
                "type": "Script",
                "startedTimestamp": time.monotonic(),
                "decodedBodyBytes": None,
                "transferredBytes": None,
                "finishedTimestamp": None,
                "fromDiskCache": False,
                "fromServiceWorker": False,
                "failed": False,
                "redirectedToUrl": None,
                "isMainNavigation": False,
                "workerBootstrap": True,
                "policyBlockId": None,
            }
        send_worker_command(session_id, "Network.enable")
        send_worker_command(
            session_id,
            "Network.setCacheDisabled",
            {"cacheDisabled": cache_disabled},
        )
        send_worker_command(session_id, "Runtime.runIfWaitingForDebugger")

    def on_received_from_target(params: dict[str, Any]) -> None:
        session_id = params["sessionId"]
        owner_key = worker_sessions.get(session_id)
        if owner_key is None:
            return
        message = json.loads(params["message"])
        method = message.get("method")
        event = message.get("params", {})
        if method == "Network.requestWillBeSent":
            record_request(owner_key, "service-worker", event)
        elif method == "Network.responseReceived":
            record_response(owner_key, event)
        elif method == "Network.loadingFinished":
            record_finished(owner_key, event)
        elif method == "Network.loadingFailed":
            record_failed(owner_key, event)
        elif method == "Network.requestServedFromCache":
            record_served_from_cache(owner_key, event)

    try:
        cdp.on("Network.requestWillBeSent", lambda params: record_request("page", "page", params))
        cdp.on("Network.responseReceived", lambda params: record_response("page", params))
        cdp.on("Network.loadingFinished", lambda params: record_finished("page", params))
        cdp.on("Network.loadingFailed", lambda params: record_failed("page", params))
        cdp.on(
            "Network.requestServedFromCache",
            lambda params: record_served_from_cache("page", params),
        )
        cdp.on("Target.attachedToTarget", on_attached_to_target)
        cdp.on("Target.receivedMessageFromTarget", on_received_from_target)
        cdp.send("Network.enable")
        cdp.send("Network.setCacheDisabled", {"cacheDisabled": cache_disabled})
        cdp.send(
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": False,
            },
        )
    except Exception:
        context.close()
        raise

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=10_000)
        dom_content_loaded = time.monotonic()
        last_activity_serial = int(page.evaluate("window.__domXRayProbe.activitySerial"))
        last_dom_activity = dom_content_loaded
        settled = False

        while time.monotonic() - navigation_started < hard_stop_seconds:
            if auxiliary_handler_failure[0] is not None:
                raise RuntimeError(auxiliary_handler_failure[0])
            state = page.evaluate(
                "({ serial: window.__domXRayProbe.activitySerial, ready: document.readyState })"
            )
            now = time.monotonic()
            if int(state["serial"]) != last_activity_serial:
                last_activity_serial = int(state["serial"])
                last_dom_activity = now
            quiet_started = max(dom_content_loaded + 0.5, last_dom_activity, last_network_activity[0])
            if (
                state["ready"] == "complete"
                and not active_qualifying_requests
                and now - quiet_started >= 0.75
            ):
                settled = True
                break
            page.wait_for_timeout(50)

        if auxiliary_handler_failure[0] is not None:
            raise RuntimeError(auxiliary_handler_failure[0])
        remaining_auxiliary_page_count = sum(
            other is not page and not other.is_closed() for other in context.pages
        )
        if remaining_auxiliary_page_count:
            raise RuntimeError("popup-close-invariant-failed")
        capture_monotonic = time.monotonic()
        page_state = page.evaluate(
            r"""
            (limits => {
              const stackingRule = element => {
                const style = getComputedStyle(element);
                if (['fixed', 'sticky'].includes(style.position)) return `position-${style.position}`;
                if (style.position !== 'static' && style.zIndex !== 'auto') return 'positioned-z-index';
                if (Number(style.opacity) < 1) return 'opacity';
                if (style.transform !== 'none') return 'transform';
                if (style.filter !== 'none') return 'filter';
                if (style.isolation === 'isolate') return 'isolation';
                return null;
              };
              const rawElements = document.getElementsByTagName('*');
              const rawDomNodeCount = rawElements.length;
              const inspectedNodeCount = Math.min(
                rawDomNodeCount,
                limits.maxInspectedElements,
              );
              const allElements = [];
              for (let index = 0; index < inspectedNodeCount; index += 1) {
                allElements.push(rawElements[index]);
              }
              const domNodeLimitReached = rawDomNodeCount > inspectedNodeCount;
              const visiblyRendered = element => {
                const style = getComputedStyle(element);
                if (style.display === 'none') return false;
                if (['hidden', 'collapse'].includes(style.visibility)) return false;
                if (Number(style.opacity) <= 0.01) return false;
                const box = element.getBoundingClientRect();
                const width = Math.max(0, Math.min(box.right, innerWidth) - Math.max(box.left, 0));
                const height = Math.max(0, Math.min(box.bottom, innerHeight) - Math.max(box.top, 0));
                return width * height >= 16;
              };
              const visibleForms = domNodeLimitReached
                ? []
                : allElements.filter(
                    element => element.tagName.toLowerCase() === 'form' && visiblyRendered(element)
                  );
              const visibleCredentialForms = visibleForms.filter(form => {
                const inputs = [...form.querySelectorAll('input')].filter(visiblyRendered);
                const passwords = inputs.filter(input => input.type === 'password');
                const identities = inputs.filter(input => {
                  const token = `${input.name} ${input.id} ${input.autocomplete}`.toLowerCase();
                  return input.type === 'email'
                    || input.autocomplete === 'username'
                    || /(?:^|\s)(?:user(?:name)?|email|login)(?:\s|$)/.test(token)
                    || (input.type === 'text' && inputs.length <= 3);
                });
                const submits = [...form.querySelectorAll(
                  'button[type="submit"], button:not([type]), input[type="submit"]'
                )].filter(visiblyRendered);
                return passwords.length > 0 && identities.length > 0 && submits.length > 0;
              });
              const visibleCredentialInputs = visibleCredentialForms.flatMap(
                form => [...form.querySelectorAll('input')].filter(visiblyRendered)
              );
              const visibleCredentialSubmits = visibleCredentialForms.flatMap(
                form => [...form.querySelectorAll(
                  'button[type="submit"], button:not([type]), input[type="submit"]'
                )].filter(visiblyRendered)
              );
              const primaryCredentialForm = visibleCredentialForms.length === 1
                ? visibleCredentialForms[0]
                : null;
              const visibleCompetingContent = primaryCredentialForm
                ? allElements.filter(element => {
                    if (!visiblyRendered(element)) return false;
                    if (primaryCredentialForm.contains(element)
                      || element.contains(primaryCredentialForm)) return false;
                    const tag = element.tagName.toLowerCase();
                    const hasDirectText = [...element.childNodes].some(
                      node => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent.trim())
                    );
                    const isCompetingLandmark = [
                      'article', 'section', 'aside', 'nav', 'header', 'footer'
                    ].includes(tag) || ['article', 'feed', 'navigation'].includes(
                      element.getAttribute('role') || ''
                    );
                    const isCompetingMedia = [
                      'img', 'video', 'canvas', 'iframe', 'svg'
                    ].includes(tag);
                    return hasDirectText || isCompetingLandmark || isCompetingMedia;
                  })
                : [];
              const nonvisual = new Set([
                'head', 'meta', 'link', 'title', 'base', 'script', 'style', 'noscript', 'template'
              ]);
              const semanticTags = new Set([
                'header', 'nav', 'main', 'article', 'section', 'aside', 'footer', 'form'
              ]);
              const replacedTags = new Set(['img', 'video', 'canvas', 'iframe', 'svg']);
              const shiftNodes = new Set(window.__domXRayProbe.shiftNodeRefs);
              const safeToken = token => /^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(token);
              const redactToken = token => {
                if (!safeToken(token) || token.length > 18) return 'xray-redacted';
                const diversity = new Set(token.toLowerCase()).size / token.length;
                if (token.length >= 13 && diversity >= 0.75 && /[a-z]/i.test(token) && /[0-9]/.test(token)) {
                  return 'xray-redacted';
                }
                return CSS.escape(token);
              };
              const selectorFor = element => {
                let selector = element.tagName.toLowerCase();
                if (element.id) selector += `#${redactToken(element.id)}`;
                const classes = [...element.classList].slice(0, 2).map(redactToken);
                if (classes.length) selector += classes.map(value => `.${value}`).join('');
                return selector.slice(0, 96);
              };
              const exactResourceUrls = element => {
                const result = new Set();
                const add = value => {
                  if (!value) return;
                  try {
                    const resolved = new URL(value, document.baseURI);
                    if (['http:', 'https:'].includes(resolved.protocol)) result.add(resolved.href);
                  } catch (_) {}
                };
                if (element instanceof HTMLImageElement) add(element.currentSrc || element.src);
                if (element instanceof HTMLVideoElement) {
                  add(element.currentSrc || element.src);
                  add(element.poster);
                }
                if (element instanceof HTMLAudioElement) add(element.currentSrc || element.src);
                if (element instanceof HTMLIFrameElement) add(element.src);
                if (element instanceof HTMLSourceElement) add(element.src);
                if (element instanceof HTMLInputElement && element.type === 'image') add(element.src);
                const style = getComputedStyle(element);
                for (const property of ['backgroundImage', 'borderImageSource', 'maskImage', 'listStyleImage']) {
                  for (const match of style[property].matchAll(/url\((?:"([^"]+)"|'([^']+)'|([^)]*))\)/g)) {
                    add((match[1] || match[2] || match[3] || '').trim());
                  }
                }
                return [...result];
              };
              const candidates = [];
              let geometryCandidateLimitReached = false;
              for (let index = 0; index < allElements.length; index += 1) {
                const element = allElements[index];
                const tag = element.tagName.toLowerCase();
                if (nonvisual.has(tag)) continue;
                const box = element.getBoundingClientRect();
                const clippedWidth = Math.max(0, Math.min(box.right, innerWidth) - Math.max(box.left, 0));
                const clippedHeight = Math.max(0, Math.min(box.bottom, innerHeight) - Math.max(box.top, 0));
                if (clippedWidth * clippedHeight < 16) continue;
                const style = getComputedStyle(element);
                if (style.display === 'none') continue;
                if (['hidden', 'collapse'].includes(style.visibility)) continue;
                if (Number(style.opacity) <= 0.01) continue;
                const resourceUrls = exactResourceUrls(element);
                const stackRule = stackingRule(element);
                const semantic = semanticTags.has(tag) || Boolean(element.getAttribute('role'));
                const hasDirectText = [...element.childNodes].some(
                  node => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent.trim())
                );
                const borderWidth = ['borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth']
                  .reduce((sum, property) => sum + (Number.parseFloat(style[property]) || 0), 0);
                const hasDistinctPaint = hasDirectText
                  || style.backgroundImage !== 'none'
                  || !['transparent', 'rgba(0, 0, 0, 0)'].includes(style.backgroundColor)
                  || borderWidth > 0
                  || style.boxShadow !== 'none'
                  || style.outlineStyle !== 'none';
                if (candidates.length >= limits.maxGeometryCandidates) {
                  geometryCandidateLimitReached = true;
                  continue;
                }
                candidates.push({
                  element,
                  index,
                  id: `n-${String(index + 1).padStart(5, '0')}`,
                  box,
                  clippedRect: {
                    x: Math.max(box.left, 0),
                    y: Math.max(box.top, 0),
                    width: clippedWidth,
                    height: clippedHeight,
                  },
                  stackingRule: stackRule,
                  exactResourceUrls: resourceUrls,
                  mandatory: element === document.documentElement
                    || element === document.body
                    || semantic
                    || replacedTags.has(tag)
                    || resourceUrls.length > 0
                    || Boolean(stackRule)
                    || shiftNodes.has(element),
                  semanticDistinctness: semantic ? 1 : 0,
                  hasDistinctPaint,
                });
              }
              const candidateIds = new Map(candidates.map(item => [item.element, item.id]));
              const nodes = candidates.map(item => {
                const { element, box } = item;
                let parent = element.parentElement;
                while (parent && !candidateIds.has(parent)) parent = parent.parentElement;
                let depth = 0;
                for (let current = element.parentElement; current; current = current.parentElement) depth += 1;
                return {
                  id: item.id,
                  parentId: parent ? candidateIds.get(parent) : null,
                  tag: element.tagName.toLowerCase(),
                  selector: selectorFor(element),
                  rect: { x: box.x, y: box.y, width: box.width, height: box.height },
                  domDepth: depth,
                  stackingRule: item.stackingRule,
                  exactResourceUrls: item.exactResourceUrls,
                  fixtureMarker: element.dataset.xrayId || null,
                  clippedRect: item.clippedRect,
                  mandatory: item.mandatory,
                  semanticDistinctness: item.semanticDistinctness,
                  hasDistinctPaint: item.hasDistinctPaint,
                  preorderIndex: item.index,
                };
              });
              return {
                title: document.title,
                finalUrl: location.href,
                userAgent: navigator.userAgent,
                document: {
                  width: document.documentElement.scrollWidth,
                  height: document.documentElement.scrollHeight,
                },
                rawDomNodeCount,
                inspectedNodeCount,
                rawMaxDomDepth: Math.max(0, ...allElements.map(element => {
                  let depth = 0;
                  for (let current = element.parentElement; current; current = current.parentElement) depth += 1;
                  return depth;
                })),
                interstitialSignals: {
                  visibleFormCount: visibleForms.length,
                  visibleCredentialFormCount: visibleCredentialForms.length,
                  visiblePasswordInputCount: visibleCredentialInputs.filter(
                    input => input.type === 'password'
                  ).length,
                  visibleIdentityInputCount: visibleCredentialInputs.filter(input => {
                    const token = `${input.name} ${input.id} ${input.autocomplete}`.toLowerCase();
                    return input.type === 'email'
                      || input.autocomplete === 'username'
                      || /(?:^|\s)(?:user(?:name)?|email|login)(?:\s|$)/.test(token)
                      || (input.type === 'text' && visibleCredentialInputs.length <= 3);
                  }).length,
                  visibleSubmitControlCount: visibleCredentialSubmits.length,
                  visibleCompetingContentCount: visibleCompetingContent.length,
                },
                nodes,
                domNodeLimitReached,
                geometryCandidateLimitReached,
                shifts: window.__domXRayProbe.shifts.map(shift => ({
                  timestampMs: shift.timestampMs,
                  value: shift.value,
                  hadRecentInput: shift.hadRecentInput,
                  sources: shift.sources.map(source => {
                    const node = source.nodeRef === null
                      ? null
                      : window.__domXRayProbe.shiftNodeRefs[source.nodeRef];
                    const candidateId = node ? candidateIds.get(node) : undefined;
                    return {
                      nodeId: candidateId || null,
                      previousRect: source.previousRect,
                      currentRect: source.currentRect,
                    };
                  }),
                })),
                layoutShiftSupported: window.__domXRayProbe.layoutShiftSupported,
              };
            })
            """,
            {
                "maxInspectedElements": max_inspected_elements,
                "maxGeometryCandidates": max_geometry_candidates,
            },
        )

        final_page_domain = registrable_domain_for_fixture(urlsplit(page_state["finalUrl"]).hostname)
        exact_targets: dict[str, list[str]] = {}
        for item in page_state["nodes"]:
            for resource_url in item["exactResourceUrls"]:
                exact_targets.setdefault(_match_url(resource_url), []).append(item["id"])
        if (
            egress_observation_snapshot is not None
            and egress_correlation_key is not None
        ):
            correlate_worker_bootstrap_egress_bytes(
                list(network.values()),
                egress_observation_snapshot(),
                egress_correlation_key,
            )
        ordered_network = sorted(
            network.values(),
            key=lambda value: (
                value["chainOrdinal"],
                value["hopIndex"],
                value["url"],
            ),
        )
        resource_id_by_hop = {
            (item["ownerKey"], item["requestId"], item["hopIndex"]): f"r-{index + 1:03d}"
            for index, item in enumerate(ordered_network)
        }
        blocked_reason_by_key = {
            (str(item["method"]).upper(), str(item["url"])): str(item["reason"])
            for item in blocked_requests
        }
        trusted_block_by_hop = correlate_policy_blocks(
            ordered_network,
            blocked_requests,
        )
        resource_rows = []
        resource_id_by_block_id: dict[str, str] = {}
        for item in ordered_network:
            parsed = urlsplit(item["url"])
            if parsed.scheme not in {"http", "https"}:
                continue
            block_key = (item["method"].upper(), _redacted_url(item["url"]))
            hop_key = (item["ownerKey"], item["requestId"], item["hopIndex"])
            trusted_block = trusted_block_by_hop.get(hop_key)
            fallback_reason = blocked_reason_by_key.get(block_key)
            if fallback_reason in NETWORK_LIMIT_REASONS:
                fallback_reason = None
            block_reason = (
                str(trusted_block["reason"])
                if trusted_block is not None
                else fallback_reason
            )
            if block_reason in {
                "credentials",
                "fixture-host",
                "private-literal-host",
                "scheme",
            }:
                continue
            resource_domain = registrable_domain_for_fixture(parsed.hostname)
            transfer_source = classify_transfer_source(
                from_service_worker=item["fromServiceWorker"],
                from_cache=item["fromDiskCache"],
                transferred_bytes=item["transferredBytes"],
            )
            start = item.get("startedTimestamp")
            finish = item.get("finishedTimestamp")
            duration_ms = round((finish - start) * 1000, 3) if start is not None and finish is not None else None
            resource_id = resource_id_by_hop[
                (item["ownerKey"], item["requestId"], item["hopIndex"])
            ]
            redirected_from_id = (
                resource_id_by_hop.get(
                    (item["ownerKey"], item["requestId"], item["hopIndex"] - 1)
                )
                if item["hopIndex"] > 0
                else None
            )
            attributed_node_ids = (
                exact_targets.get(_match_url(item["url"]), [])
                if item["requestOwner"] == "page"
                else []
            )
            resource_rows.append(
                {
                    "id": resource_id,
                    "displayUrl": _redacted_url(item["url"]),
                    "origin": _origin(item["url"]),
                    "registrableDomain": resource_domain,
                    "type": _resource_type(item["type"]),
                    "initiatorType": item["initiatorType"],
                    "requestOwner": item["requestOwner"],
                    "party": "first" if resource_domain == final_page_domain else "third",
                    "partyRule": "registrable-domain-v1-fixture",
                    "transferSource": transfer_source,
                    "transferredBytes": item["transferredBytes"],
                    "decodedBodyBytes": item["decodedBodyBytes"],
                    "durationMs": duration_ms,
                    "requestChainId": f"q-{item['chainOrdinal']:03d}",
                    "redirectHopIndex": item["hopIndex"],
                    "redirectedFromResourceId": redirected_from_id,
                    "responseStatus": int(item["status"]) if item.get("status") is not None else None,
                    "attributionScope": "exact-element" if attributed_node_ids else "page-level",
                    "attributedNodeIds": attributed_node_ids,
                }
            )
            if trusted_block is not None and trusted_block.get("blockId") is not None:
                resource_id_by_block_id.setdefault(
                    str(trusted_block["blockId"]),
                    resource_id,
                )

        redirect_rows = [
            {
                "hopIndex": item["hopIndex"] + 1,
                "fromUrl": _redacted_url(item["url"]),
                "toUrl": _redacted_url(item["redirectedToUrl"]),
                "status": int(item["status"]),
                "followed": True,
                "rejectionCode": None,
            }
            for item in ordered_network
            if item["isMainNavigation"] and item["redirectedToUrl"] is not None
        ]

        resources_by_node: dict[str, list[str]] = {}
        for resource in resource_rows:
            for node_id in resource["attributedNodeIds"]:
                resources_by_node.setdefault(node_id, []).append(resource["id"])
        nodes = [
            {
                "id": item["id"],
                "parentId": item["parentId"],
                "tag": item["tag"],
                "selector": item["selector"],
                "rect": {key: round(float(value), 3) for key, value in item["rect"].items()},
                "domDepth": item["domDepth"],
                "stackingContext": _stacking_context(item),
                "memberNodeIds": [],
                "aggregationRule": None,
                "resourceIds": resources_by_node.get(item["id"], []),
            }
            for item in page_state["nodes"]
        ]
        aggregation_metadata = {
            item["id"]: {
                "preorderIndex": item["preorderIndex"],
                "clippedRect": item["clippedRect"],
                "mandatory": item["mandatory"],
                "semanticDistinctness": item["semanticDistinctness"],
                "hasDistinctPaint": item["hasDistinctPaint"],
            }
            for item in page_state["nodes"]
        }
        external_hub_count = len(
            {
                resource["registrableDomain"]
                for resource in resource_rows
                if resource["party"] == "third" and resource["registrableDomain"] is not None
            }
        )
        aggregation = aggregate_nodes(
            nodes,
            aggregation_metadata,
            resource_rows,
            max_scene_objects=650,
            external_hub_count=external_hub_count,
        )
        nodes = aggregation.nodes
        shifts = [
            {
                "id": f"ls-{index + 1:03d}",
                "timestampMs": round(float(item["timestampMs"]), 3),
                "value": float(item["value"]),
                "hadRecentInput": bool(item["hadRecentInput"]),
                "sources": item["sources"],
            }
            for index, item in enumerate(page_state["shifts"])
        ]
        terminal_main_documents = [
            item
            for item in ordered_network
            if item["isMainNavigation"] and item["redirectedToUrl"] is None
        ]
        final_document_status = None
        terminal_main_document_limit_reason = None
        if terminal_main_documents:
            terminal_main_document = max(
                terminal_main_documents,
                key=lambda item: (item["chainOrdinal"], item["hopIndex"]),
            )
            if terminal_main_document.get("status") is not None:
                final_document_status = int(terminal_main_document["status"])
            terminal_block = trusted_block_by_hop.get(
                (
                    terminal_main_document["ownerKey"],
                    terminal_main_document["requestId"],
                    terminal_main_document["hopIndex"],
                )
            )
            if (
                terminal_block is not None
                and str(terminal_block.get("reason")) in NETWORK_LIMIT_REASONS
            ):
                terminal_main_document_limit_reason = str(terminal_block["reason"])
        interstitial_signals = dict(page_state["interstitialSignals"])
        interstitial_signals["finalDocumentStatus"] = (
            None
            if terminal_main_document_limit_reason is not None
            else final_document_status
        )
        interstitial_kind = classify_interstitial_v1(interstitial_signals)
        limitations = []
        if page_state["domNodeLimitReached"]:
            limitations.append(
                {
                    "code": "dom-inspection-limit",
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        f"The document contained {page_state['rawDomNodeCount']} elements; "
                        f"inspection stopped after the first {page_state['inspectedNodeCount']}."
                    ),
                    "invalidatesMetrics": [
                        "candidate_count",
                        "geometry",
                        "login_gate_classification",
                        "max_dom_depth",
                        "scene_completeness",
                        "visual_region_count",
                    ],
                }
            )
        if page_state["geometryCandidateLimitReached"]:
            limitations.append(
                {
                    "code": "geometry-candidate-limit",
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        "More viewport geometry qualified than the capture budget allows; "
                        f"only the first {max_geometry_candidates} candidates were retained."
                    ),
                    "invalidatesMetrics": [
                        "candidate_count",
                        "geometry",
                        "scene_completeness",
                        "visual_region_count",
                    ],
                }
            )
        if not settled:
            limitations.append(
                {
                    "code": "settle-timeout",
                    "scope": "scan",
                    "targetId": None,
                    "message": "The deterministic page did not become quiet before the capture hard stop.",
                    "invalidatesMetrics": ["geometry"],
                }
            )
        if aggregation.fallback_rule is not None:
            limitations.append(
                {
                    "code": aggregation.fallback_rule,
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        "Mandatory evidence exceeded the scene-object budget; exact node and "
                        "resource evidence remains inspectable outside the bounded overview."
                    ),
                    "invalidatesMetrics": ["scene_completeness", "visual_region_count"],
                }
            )
        if auxiliary_events.truncated:
            limitations.append(
                {
                    "code": "auxiliary-event-limit",
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        "Popup and download observation reached the capture boundary of "
                        f"{max_auxiliary_events} events; later events were still denied but "
                        "were not counted by type."
                    ),
                    "invalidatesMetrics": [
                        "download_attempt_count",
                        "page_behavior",
                        "popup_attempt_count",
                    ],
                }
            )
        worker_bootstrap_unmeasured = any(
            item["workerBootstrap"] and item["transferredBytes"] is None
            for item in ordered_network
        )
        bootstrap_resource_ids = {
            resource_id_by_hop[(item["ownerKey"], item["requestId"], item["hopIndex"])]
            for item in ordered_network
            if item["workerBootstrap"]
            and (item["ownerKey"], item["requestId"], item["hopIndex"])
            in resource_id_by_hop
        }
        unknown_nonbootstrap_resources = [
            resource
            for resource in resource_rows
            if resource["transferredBytes"] is None
            and resource["id"] not in bootstrap_resource_ids
        ]
        service_worker_present = bool(context.service_workers) or any(
            item["fromServiceWorker"] for item in ordered_network
        )
        worker_target_unobserved = service_worker_present and not worker_target_ids
        unfinished_worker_request = any(
            item["requestOwner"] == "service-worker"
            and not item["workerBootstrap"]
            and item["finishedTimestamp"] is None
            for item in ordered_network
        )
        if worker_bootstrap_unmeasured:
            limitations.append(
                {
                    "code": "service-worker-bootstrap-bytes-unavailable",
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        "The service-worker bootstrap script request was identified, but its "
                        "transfer bytes were unavailable before target attachment."
                    ),
                    "invalidatesMetrics": ["request_count", "total_transferred_bytes"],
                }
            )
        if worker_target_unobserved:
            limitations.append(
                {
                    "code": "service-worker-target-unobserved",
                    "scope": "scan",
                    "targetId": None,
                    "message": "A service worker was present, but its target could not be attached.",
                    "invalidatesMetrics": ["request_count", "total_transferred_bytes"],
                }
            )
        if unfinished_worker_request:
            limitations.append(
                {
                    "code": "service-worker-request-incomplete",
                    "scope": "scan",
                    "targetId": None,
                    "message": "A worker-owned request did not finish inside the capture window.",
                    "invalidatesMetrics": ["request_count", "total_transferred_bytes"],
                }
            )
        for resource in unknown_nonbootstrap_resources:
            limitations.append(
                {
                    "code": f"resource-bytes-unavailable-{resource['id']}",
                    "scope": "resource",
                    "targetId": resource["id"],
                    "message": "This request had no completed canonical transfer-byte value.",
                    "invalidatesMetrics": [
                        "request_count",
                        "resource_mass",
                        "total_transferred_bytes",
                    ],
                }
            )
        ordered_blocked_requests = sorted(
            blocked_requests,
            key=lambda item: (
                str(item.get("method", "")),
                str(item.get("url", "")),
                str(item.get("reason", "")),
            ),
        )
        request_limit_reached = any(
            str(item.get("reason")) == "request-limit"
            for item in ordered_blocked_requests
        )
        byte_limit_reached = any(
            str(item.get("reason"))
            in NETWORK_LIMIT_REASONS - {"request-limit"}
            for item in ordered_blocked_requests
        )
        request_limit_reported = False
        total_byte_limit_reported = False
        for index, blocked in enumerate(ordered_blocked_requests):
            target_id = resource_id_by_block_id.get(str(blocked.get("blockId")))
            reason = str(blocked["reason"])
            if reason == "request-limit":
                if request_limit_reported:
                    continue
                request_limit_reported = True
                limitations.append(
                    {
                        "code": "request-limit",
                        "scope": "scan",
                        "targetId": None,
                        "message": (
                            "The capture stopped origin-bound requests when its "
                            f"{max_requests}-request boundary was reached."
                        ),
                        "invalidatesMetrics": [
                            "page_behavior",
                            "request_count",
                            "resource_mass",
                            "total_transferred_bytes",
                        ],
                    }
                )
                continue
            if reason == "response-byte-limit":
                limitations.append(
                    {
                        "code": (
                            f"response-byte-limit-{target_id}"
                            if target_id is not None
                            else f"response-byte-limit-{index + 1}"
                        ),
                        "scope": "resource" if target_id is not None else "scan",
                        "targetId": target_id,
                        "message": (
                            "The upstream response exceeded the per-response boundary of "
                            f"{max_response_bytes} received bytes and was not relayed."
                        ),
                        "invalidatesMetrics": [
                            "page_behavior",
                            "request_count",
                            "resource_mass",
                            "total_transferred_bytes",
                        ],
                    }
                )
                continue
            if reason == "total-byte-limit":
                if total_byte_limit_reported:
                    continue
                total_byte_limit_reported = True
                limitations.append(
                    {
                        "code": "total-byte-limit",
                        "scope": "scan",
                        "targetId": None,
                        "message": (
                            "The capture stopped upstream transfer when its total boundary of "
                            f"{max_total_received_bytes} received bytes was reached."
                        ),
                        "invalidatesMetrics": [
                            "page_behavior",
                            "request_count",
                            "resource_mass",
                            "total_transferred_bytes",
                        ],
                    }
                )
                continue
            invalidates_metrics = ["page_behavior", "total_transferred_bytes"]
            invalidates_metrics.append(
                "resource_mass" if target_id is not None else "request_count"
            )
            limitations.append(
                {
                    "code": f"blocked-request-{index + 1}",
                    "scope": "resource" if target_id is not None else "scan",
                    "targetId": target_id,
                    "message": f"A {blocked['reason']} request was blocked by the fixture probe.",
                    "invalidatesMetrics": invalidates_metrics,
                }
            )
        if interstitial_kind == "login-wall":
            limitations.append(
                {
                    "code": INTERSTITIAL_CLASSIFIER_VERSION,
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        "A visible credential gate was captured; this does not establish that "
                        "the requested destination content was reached."
                    ),
                    "invalidatesMetrics": ["hero_insight", "intended_page_content"],
                }
            )
        elif interstitial_kind == "error-document":
            limitations.append(
                {
                    "code": HTTP_ERROR_INTERSTITIAL_CLASSIFIER_VERSION,
                    "scope": "scan",
                    "targetId": None,
                    "message": (
                        f"The final main document returned HTTP {final_document_status}; "
                        "this captured error response is not treated as the intended destination content."
                    ),
                    "invalidatesMetrics": ["hero_insight", "intended_page_content"],
                }
            )

        duration_ms = round((capture_monotonic - navigation_started) * 1000, 3)
        worker_capture_incomplete = (
            worker_bootstrap_unmeasured
            or worker_target_unobserved
            or unfinished_worker_request
        )
        measurement_incomplete = (
            worker_capture_incomplete
            or bool(unknown_nonbootstrap_resources)
            or bool(blocked_requests)
            or page_state["domNodeLimitReached"]
            or page_state["geometryCandidateLimitReached"]
            or aggregation.fallback_rule is not None
            or auxiliary_events.truncated
        )
        if interstitial_kind is not None:
            record_status = "interstitial"
            failure_code = "interstitial"
        elif settled and not measurement_incomplete:
            record_status = "complete"
            failure_code = None
        else:
            record_status = "partial"
            failure_code = (
                "resource-limit"
                if (
                    request_limit_reached
                    or byte_limit_reached
                    or
                    page_state["domNodeLimitReached"]
                    or page_state["geometryCandidateLimitReached"]
                    or aggregation.fallback_rule is not None
                    or auxiliary_events.truncated
                )
                else "measurement-unavailable"
            )

        limits_reached = []
        if not settled:
            limits_reached.append("time")
        if request_limit_reached:
            limits_reached.append("requests")
        if byte_limit_reached:
            limits_reached.append("bytes")
        if page_state["domNodeLimitReached"]:
            limits_reached.append("dom-nodes")
        if page_state["geometryCandidateLimitReached"]:
            limits_reached.append("candidates")
        if aggregation.fallback_rule is not None:
            limits_reached.append("regions")
        if auxiliary_events.truncated:
            limits_reached.append("auxiliary-events")

        record = {
            "schemaVersion": "0.1.0",
            "mappingVersion": "mapping-v0.1.0",
            "scanId": f"browser-proof-{urlsplit(url).hostname}",
            "status": record_status,
            "failureCode": failure_code,
            "requestedUrl": _redacted_url(url),
            "finalUrl": _redacted_url(page_state["finalUrl"]),
            "capturedAt": started_at.isoformat().replace("+00:00", "Z"),
            "capture": {
                "scannerVersion": "fixture-probe-v0.1.0",
                "browser": f"Chromium {browser.version}",
                "userAgent": page_state["userAgent"],
                "locale": "en-US",
                "viewport": {"width": 1440, "height": 900, "deviceScaleFactor": 1},
                "startedAt": started_at.isoformat().replace("+00:00", "Z"),
                "durationMs": duration_ms,
                "stabilizationMs": round((capture_monotonic - dom_content_loaded) * 1000, 3),
                "capturePointMs": duration_ms,
                "observationWindowMs": duration_ms,
                "cachePolicy": "cold" if cache_disabled else "mixed",
                "timezone": "UTC",
                "region": "local-gate-0",
                "inspectedNodeCount": page_state["inspectedNodeCount"],
                "candidateNodeCount": aggregation.candidate_count,
                "renderedRegionCount": aggregation.rendered_count,
                "aggregatedNodeCount": aggregation.aggregated_count,
                "requestCount": len(resource_rows),
                "requestsWithoutByteData": sum(row["transferredBytes"] is None for row in resource_rows),
                "requestLimit": max_requests,
                "perResponseByteLimit": max_response_bytes,
                "totalByteLimit": max_total_received_bytes,
                "transferAccountingRule": (
                    "cdp-plus-egress-service-worker-bootstrap-v1"
                    if any(item.get("egressBootstrapBytes") for item in ordered_network)
                    else (
                        "cdp-page-worker-target-loading-finished-v1"
                        if worker_target_ids
                        else "cdp-loading-finished-encoded-data-length-v1"
                    )
                ),
                "redirectCount": len(redirect_rows),
                "redirectLimit": REDIRECT_LIMIT,
                "redirects": redirect_rows,
                "popupAttemptCount": auxiliary_events.popup_attempt_count,
                "downloadAttemptCount": auxiliary_events.download_attempt_count,
                "auxiliaryEventLimit": max_auxiliary_events,
                "auxiliaryEventCountTruncated": auxiliary_events.truncated,
                "limitsReached": limits_reached,
            },
            "page": {
                "title": page_state["title"],
                "registrableDomain": final_page_domain or "unknown.test",
                "document": page_state["document"],
                "rawDomNodeCount": page_state["rawDomNodeCount"],
                "maxDomDepth": page_state["rawMaxDomDepth"],
                "screenshotStatus": "omitted",
                "screenshotRef": None,
            },
            "nodes": nodes,
            "resources": resource_rows,
            "layoutShifts": shifts,
            "insights": [],
            "limitations": limitations,
        }
        record["insights"] = select_hero_insight(record)
        return ProbeResult(
            record=record,
            blocked_requests=blocked_requests,
            layout_shift_supported=bool(page_state["layoutShiftSupported"]),
            fixture_node_ids={
                item["fixtureMarker"]: item["id"]
                for item in page_state["nodes"]
                if item["fixtureMarker"] is not None
            },
            remaining_auxiliary_page_count=remaining_auxiliary_page_count,
        )
    finally:
        try:
            cdp.send(
                "Target.setAutoAttach",
                {
                    "autoAttach": False,
                    "waitForDebuggerOnStart": False,
                    "flatten": False,
                },
            )
        except PlaywrightError:
            pass
        context.close()
