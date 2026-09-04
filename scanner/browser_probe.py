"""Controlled Chromium probe used only for deterministic Gate 0 fixtures.

This module proves browser instrumentation choices without selecting the public
application stack. It is intentionally local-only: production egress isolation,
DNS rebinding defense, queueing, and public-suffix handling remain release gates.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from playwright.sync_api import Browser, Route


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
          sources: (entry.sources || []).slice(0, 12).map(source => ({
            nodeId: source.node && source.node.closest
              ? source.node.closest('[data-xray-id]')?.dataset.xrayId || null
              : null,
            previousRect: rect(source.previousRect),
            currentRect: rect(source.currentRect),
          })),
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
    blocked_requests: list[dict[str, str]]
    layout_shift_supported: bool


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


def _resource_type(cdp_type: str | None) -> str:
    normalized = (cdp_type or "Other").lower()
    return normalized if normalized in {
        "document", "stylesheet", "image", "media", "font", "script", "fetch", "xhr"
    } else "other"


def _is_forbidden_literal_host(hostname: str | None) -> bool:
    if not hostname:
        return True
    host = hostname.rstrip(".").lower()
    if host in {"localhost", "metadata.google.internal"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def request_block_reason(method: str, url: str) -> str | None:
    """Return the first request-policy rejection represented by this proof."""

    parsed = urlsplit(url)
    if method.upper() not in ALLOWED_METHODS:
        return "method"
    if parsed.scheme not in {"http", "https"}:
        return "scheme"
    if parsed.username is not None or parsed.password is not None:
        return "credentials"
    if _is_forbidden_literal_host(parsed.hostname):
        return "private-literal-host"
    return None


def validate_fixture_target(url: str) -> None:
    """Keep the proof harness physically scoped to reserved local fixtures."""

    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname or not parsed.hostname.endswith(".test"):
        raise ValueError("browser_probe accepts reserved HTTP .test fixtures only")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("browser_probe fixture targets cannot contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("browser_probe fixture targets cannot contain query or fragment data")


def _make_request_guard(blocked: list[dict[str, str]]) -> Any:
    def guard(route: Route) -> None:
        request = route.request
        reason = request_block_reason(request.method, request.url)

        if reason:
            blocked.append({"url": _redacted_url(request.url), "method": request.method, "reason": reason})
            route.abort("blockedbyclient")
        else:
            route.continue_()

    return guard


def _stacking_context(element: dict[str, Any]) -> dict[str, Any]:
    if element["parentId"] is None:
        return {"creates": True, "rule": "document-root"}
    if element["stackingRule"]:
        return {"creates": True, "rule": element["stackingRule"]}
    return {"creates": False, "rule": None}


def probe_page(browser: Browser, url: str, *, hard_stop_seconds: float = 12.0) -> ProbeResult:
    validate_fixture_target(url)
    blocked_requests: list[dict[str, str]] = []
    network: dict[str, dict[str, Any]] = {}
    last_network_activity = [time.monotonic()]
    navigation_started = time.monotonic()
    started_at = datetime.now(timezone.utc)

    context = browser.new_context(
        viewport=VIEWPORT,
        device_scale_factor=1,
        locale="en-US",
        timezone_id="UTC",
        color_scheme="light",
        reduced_motion="no-preference",
        service_workers="allow",
        accept_downloads=False,
    )
    context.clear_permissions()
    context.route("**/*", _make_request_guard(blocked_requests))
    context.add_init_script(INIT_SCRIPT)
    page = context.new_page()
    page.on("popup", lambda popup: popup.close())
    cdp = context.new_cdp_session(page)

    def on_request(params: dict[str, Any]) -> None:
        network[params["requestId"]] = {
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
        }

    def on_response(params: dict[str, Any]) -> None:
        item = network.get(params["requestId"])
        if item is None:
            return
        response = params["response"]
        item["type"] = params.get("type", item["type"])
        item["status"] = response.get("status")
        item["fromDiskCache"] = response.get("fromDiskCache", False)
        item["fromServiceWorker"] = response.get("fromServiceWorker", False)

    def on_finished(params: dict[str, Any]) -> None:
        item = network.get(params["requestId"])
        if item is None:
            return
        item["transferredBytes"] = int(round(params.get("encodedDataLength", 0)))
        item["finishedTimestamp"] = params.get("timestamp")
        if item["type"] in QUALIFYING_TYPES:
            last_network_activity[0] = time.monotonic()

    def on_failed(params: dict[str, Any]) -> None:
        item = network.get(params["requestId"])
        if item is None:
            return
        item["failed"] = True
        item["finishedTimestamp"] = params.get("timestamp")
        if item["type"] in QUALIFYING_TYPES:
            last_network_activity[0] = time.monotonic()

    cdp.on("Network.requestWillBeSent", on_request)
    cdp.on("Network.responseReceived", on_response)
    cdp.on("Network.loadingFinished", on_finished)
    cdp.on("Network.loadingFailed", on_failed)
    cdp.send("Network.enable")
    cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=10_000)
        dom_content_loaded = time.monotonic()
        last_activity_serial = int(page.evaluate("window.__domXRayProbe.activitySerial"))
        last_dom_activity = dom_content_loaded
        settled = False

        while time.monotonic() - navigation_started < hard_stop_seconds:
            state = page.evaluate(
                "({ serial: window.__domXRayProbe.activitySerial, ready: document.readyState })"
            )
            now = time.monotonic()
            if int(state["serial"]) != last_activity_serial:
                last_activity_serial = int(state["serial"])
                last_dom_activity = now
            quiet_started = max(dom_content_loaded + 0.5, last_dom_activity, last_network_activity[0])
            if state["ready"] == "complete" and now - quiet_started >= 0.75:
                settled = True
                break
            page.wait_for_timeout(50)

        capture_monotonic = time.monotonic()
        page_state = page.evaluate(
            r"""
            (() => {
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
              const nodes = [...document.querySelectorAll('[data-xray-id]')].map(element => {
                const box = element.getBoundingClientRect();
                const parent = element.parentElement?.closest('[data-xray-id]');
                let depth = 0;
                for (let current = element.parentElement; current; current = current.parentElement) depth += 1;
                return {
                  id: element.dataset.xrayId,
                  parentId: parent?.dataset.xrayId || null,
                  tag: element.tagName.toLowerCase(),
                  selector: `${element.tagName.toLowerCase()}[data-xray-id="${element.dataset.xrayId}"]`,
                  rect: { x: box.x, y: box.y, width: box.width, height: box.height },
                  domDepth: depth,
                  stackingRule: stackingRule(element),
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
                nodes,
                shifts: window.__domXRayProbe.shifts,
                layoutShiftSupported: window.__domXRayProbe.layoutShiftSupported,
              };
            })()
            """
        )

        final_page_domain = registrable_domain_for_fixture(urlsplit(page_state["finalUrl"]).hostname)
        resource_rows = []
        for item in sorted(network.values(), key=lambda value: (value.get("startedTimestamp") or 0, value["url"])):
            parsed = urlsplit(item["url"])
            if parsed.scheme not in {"http", "https"}:
                continue
            resource_domain = registrable_domain_for_fixture(parsed.hostname)
            if item["fromServiceWorker"]:
                transfer_source = "service-worker"
            elif item["fromDiskCache"]:
                transfer_source = "cache"
            elif item["transferredBytes"] is not None:
                transfer_source = "network"
            else:
                transfer_source = "unknown"
            start = item.get("startedTimestamp")
            finish = item.get("finishedTimestamp")
            duration_ms = round((finish - start) * 1000, 3) if start is not None and finish is not None else None
            resource_rows.append(
                {
                    "id": f"r-{len(resource_rows) + 1:03d}",
                    "displayUrl": _redacted_url(item["url"]),
                    "origin": _origin(item["url"]),
                    "registrableDomain": resource_domain,
                    "type": _resource_type(item["type"]),
                    "initiatorType": item["initiatorType"],
                    "party": "first" if resource_domain == final_page_domain else "third",
                    "partyRule": "registrable-domain-v1-fixture",
                    "transferSource": transfer_source,
                    "transferredBytes": item["transferredBytes"],
                    "decodedBodyBytes": item["decodedBodyBytes"],
                    "durationMs": duration_ms,
                    "attributionScope": "page-level",
                    "attributedNodeIds": [],
                }
            )

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
                "resourceIds": [],
            }
            for item in page_state["nodes"]
        ]
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
        limitations = []
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
        for index, blocked in enumerate(blocked_requests):
            limitations.append(
                {
                    "code": f"blocked-request-{index + 1}",
                    "scope": "scan",
                    "targetId": None,
                    "message": f"A {blocked['reason']} request was blocked by the fixture probe.",
                    "invalidatesMetrics": [],
                }
            )

        duration_ms = round((capture_monotonic - navigation_started) * 1000, 3)
        record = {
            "schemaVersion": "0.1.0",
            "mappingVersion": "mapping-v0.1.0",
            "scanId": f"browser-proof-{urlsplit(url).hostname}",
            "status": "complete" if settled else "partial",
            "failureCode": None if settled else "measurement-unavailable",
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
                "cachePolicy": "cold",
                "timezone": "UTC",
                "region": "local-gate-0",
                "inspectedNodeCount": len(nodes),
                "renderedRegionCount": len(nodes),
                "aggregatedNodeCount": 0,
                "requestCount": len(resource_rows),
                "requestsWithoutByteData": sum(row["transferredBytes"] is None for row in resource_rows),
                "transferAccountingRule": "cdp-loading-finished-encoded-data-length-v1",
                "limitsReached": [] if settled else ["time"],
            },
            "page": {
                "title": page_state["title"],
                "registrableDomain": final_page_domain or "unknown.test",
                "document": page_state["document"],
                "rawDomNodeCount": len(nodes),
                "maxDomDepth": max((node["domDepth"] for node in nodes), default=0),
                "screenshotStatus": "omitted",
                "screenshotRef": None,
            },
            "nodes": nodes,
            "resources": resource_rows,
            "layoutShifts": shifts,
            "insights": [],
            "limitations": limitations,
        }
        return ProbeResult(
            record=record,
            blocked_requests=blocked_requests,
            layout_shift_supported=bool(page_state["layoutShiftSupported"]),
        )
    finally:
        context.close()
