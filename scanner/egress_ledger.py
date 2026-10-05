"""Bounded, scan-local correlation evidence; never a public artifact."""

from hashlib import blake2b
import secrets
from threading import Lock
from urllib.parse import urlsplit, urlunsplit


def redacted_url(url):
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path or "/", "", ""))


def match_url(url):
    """Query-sensitive identity, used only as input to a scan-keyed digest."""
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return urlunsplit((parsed.scheme.lower(), f"{hostname}{port}", parsed.path or "/", parsed.query, ""))


class EgressLedger:
    def __init__(self, limit=1_000):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise ValueError("invalid ledger limit")
        self.limit = limit
        self.truncated = False
        self.blocked = []
        self._rows = []
        self._secret = secrets.token_bytes(32)
        self._lock = Lock()

    def correlation_key(self, url):
        return blake2b(match_url(url).encode("utf-8"), key=self._secret, digest_size=16).hexdigest()

    def begin(self, url, method, headers):
        destination = next((v for n, v in headers if n == "sec-fetch-dest"), "")
        row = dict(url=redacted_url(url), correlationKey=self.correlation_key(url),
                   method=method, document=destination == "document", fetchDestination=destination,
                   outcome="pending", responseStatus=None, upstreamBytesRead=None,
                   upstreamWireBytes=None, browserWireBytes=None)
        with self._lock:
            if len(self._rows) >= self.limit:
                self.truncated = True
                return None
            self._rows.append(row)
        return row

    def finish(self, row, **evidence):
        if row is not None:
            with self._lock:
                row.update(evidence)

    def block(self, row, *, block_id, reason, status, wire_bytes, upstream_bytes):
        # Record authority before sending a marker that Chromium may observe.
        with self._lock:
            if len(self.blocked) >= self.limit:
                self.truncated = True
            elif row is not None:
                self.blocked.append(dict(blockId=block_id, url=row["url"], sourceUrl=row["url"],
                    method=row["method"], reason=reason, redirect="false", wireBytes=wire_bytes,
                    upstreamBytesRead=upstream_bytes))
            if row is not None:
                row.update(outcome="blocked", responseStatus=status, blockId=block_id,
                           upstreamBytesRead=upstream_bytes)

    def snapshot(self):
        with self._lock:
            return [dict(row) for row in self._rows]
