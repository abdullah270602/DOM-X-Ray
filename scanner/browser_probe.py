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

from playwright.sync_api import Browser, Error as PlaywrightError, Route

from scanner.aggregation import aggregate_nodes


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
    blocked_requests: list[dict[str, str]]
    layout_shift_supported: bool
    fixture_node_ids: dict[str, str]


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


def _make_request_guard(
    blocked: list[dict[str, str]],
) -> Any:
    def guard(route: Route) -> None:
        request = route.request
        reason = request_block_reason(request.method, request.url)

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
            route.continue_()

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
    context = browser.new_context(accept_downloads=False, proxy={"server": proxy_server})
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
) -> ProbeResult:
    validate_fixture_target(url)
    blocked_requests: list[dict[str, str]] = []
    network: dict[tuple[str, int], dict[str, Any]] = {}
    current_hops: dict[str, int] = {}
    chain_ordinals: dict[str, int] = {}
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
        proxy={"server": proxy_server} if proxy_server else None,
    )
    context.clear_permissions()
    context.route("**/*", _make_request_guard(blocked_requests))
    context.add_init_script(INIT_SCRIPT)
    page = context.new_page()
    page.on("popup", lambda popup: popup.close())
    cdp = context.new_cdp_session(page)
    main_frame_id = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]

    def on_request(params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        if request_id not in chain_ordinals:
            chain_ordinals[request_id] = len(chain_ordinals) + 1
            hop_index = 0
        else:
            hop_index = current_hops[request_id] + 1
            previous = network[(request_id, hop_index - 1)]
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
        current_hops[request_id] = hop_index
        network[(request_id, hop_index)] = {
            "requestId": request_id,
            "chainOrdinal": chain_ordinals[request_id],
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
            "isMainNavigation": params.get("frameId") == main_frame_id and params.get("type") == "Document",
        }

    def on_response(params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        item = network.get((request_id, current_hops.get(request_id, 0)))
        if item is None:
            return
        response = params["response"]
        item["type"] = params.get("type", item["type"])
        item["status"] = response.get("status")
        item["fromDiskCache"] = response.get("fromDiskCache", False)
        item["fromServiceWorker"] = response.get("fromServiceWorker", False)

    def on_finished(params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        item = network.get((request_id, current_hops.get(request_id, 0)))
        if item is None:
            return
        item["transferredBytes"] = int(round(params.get("encodedDataLength", 0)))
        item["finishedTimestamp"] = params.get("timestamp")
        if item["type"] in QUALIFYING_TYPES:
            last_network_activity[0] = time.monotonic()

    def on_failed(params: dict[str, Any]) -> None:
        request_id = params["requestId"]
        item = network.get((request_id, current_hops.get(request_id, 0)))
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
              const allElements = [...document.querySelectorAll('*')];
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
                rawDomNodeCount: allElements.length,
                inspectedNodeCount: allElements.length,
                rawMaxDomDepth: Math.max(0, ...allElements.map(element => {
                  let depth = 0;
                  for (let current = element.parentElement; current; current = current.parentElement) depth += 1;
                  return depth;
                })),
                nodes,
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
            })()
            """
        )

        final_page_domain = registrable_domain_for_fixture(urlsplit(page_state["finalUrl"]).hostname)
        exact_targets: dict[str, list[str]] = {}
        for item in page_state["nodes"]:
            for resource_url in item["exactResourceUrls"]:
                exact_targets.setdefault(_match_url(resource_url), []).append(item["id"])
        ordered_network = sorted(
            network.values(),
            key=lambda value: (
                value.get("startedTimestamp") or 0,
                value["chainOrdinal"],
                value["hopIndex"],
                value["url"],
            ),
        )
        resource_id_by_hop = {
            (item["requestId"], item["hopIndex"]): f"r-{index + 1:03d}"
            for index, item in enumerate(ordered_network)
        }
        resource_rows = []
        for item in ordered_network:
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
            resource_id = resource_id_by_hop[(item["requestId"], item["hopIndex"])]
            redirected_from_id = (
                resource_id_by_hop.get((item["requestId"], item["hopIndex"] - 1))
                if item["hopIndex"] > 0
                else None
            )
            attributed_node_ids = exact_targets.get(_match_url(item["url"]), [])
            resource_rows.append(
                {
                    "id": resource_id,
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
                    "requestChainId": f"q-{item['chainOrdinal']:03d}",
                    "redirectHopIndex": item["hopIndex"],
                    "redirectedFromResourceId": redirected_from_id,
                    "responseStatus": int(item["status"]) if item.get("status") is not None else None,
                    "attributionScope": "exact-element" if attributed_node_ids else "page-level",
                    "attributedNodeIds": attributed_node_ids,
                }
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
                "inspectedNodeCount": page_state["inspectedNodeCount"],
                "candidateNodeCount": aggregation.candidate_count,
                "renderedRegionCount": aggregation.rendered_count,
                "aggregatedNodeCount": aggregation.aggregated_count,
                "requestCount": len(resource_rows),
                "requestsWithoutByteData": sum(row["transferredBytes"] is None for row in resource_rows),
                "transferAccountingRule": "cdp-loading-finished-encoded-data-length-v1",
                "redirectCount": len(redirect_rows),
                "redirectLimit": REDIRECT_LIMIT,
                "redirects": redirect_rows,
                "limitsReached": [] if settled else ["time"],
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
        return ProbeResult(
            record=record,
            blocked_requests=blocked_requests,
            layout_shift_supported=bool(page_state["layoutShiftSupported"]),
            fixture_node_ids={
                item["fixtureMarker"]: item["id"]
                for item in page_state["nodes"]
                if item["fixtureMarker"] is not None
            },
        )
    finally:
        context.close()
