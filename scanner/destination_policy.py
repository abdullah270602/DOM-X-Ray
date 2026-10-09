"""Deployment-neutral public-destination validation for scanner egress.

The policy resolves each hostname independently and returns only addresses that
the caller may pin in its connector.  It does not perform network I/O itself,
choose a production resolver, or replace a deployment egress firewall.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, TypeVar
from urllib.parse import urljoin, urlsplit


DestinationPurpose = Literal["initial", "redirect", "subresource"]
Resolver = Callable[[str, int], Iterable[str]]
T = TypeVar("T")

DEFAULT_ALLOWED_PORTS = frozenset({80, 443})
MAX_DNS_ANSWERS = 16

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_NUMERIC_COMPONENT = re.compile(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)\Z")
_DENIED_HOSTS = frozenset({"localhost", "metadata.google.internal"})
_DENIED_HOST_SUFFIXES = (".localhost", ".local")
# Registry snapshot last updated 2025-10-09:
# https://www.iana.org/assignments/iana-ipv4-special-registry/
# https://www.iana.org/assignments/iana-ipv6-special-registry/
_IANA_REGISTRY_SNAPSHOT = "2025-10-09"
_DENIED_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
_DENIED_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::/96",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "2620:4f:8000::/48",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
    )
)


class DestinationPolicyError(ValueError):
    """A content-free destination-policy rejection."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, repr=False)
class ValidatedDestination:
    """An in-memory connector grant; resolver answers must not be persisted."""

    purpose: DestinationPurpose
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            "ValidatedDestination("
            f"purpose={self.purpose!r}, scheme={self.scheme!r}, "
            f"hostname={self.hostname!r}, port={self.port!r}, "
            f"address_count={len(self.addresses)})"
        )


def _reject(reason: str) -> None:
    raise DestinationPolicyError(reason) from None


def is_public_address(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is safe for the public-only connector boundary.

    The explicit networks mirror the IANA special-purpose registries at
    ``_IANA_REGISTRY_SNAPSHOT``.  ``is_global`` remains defense in depth for
    categories represented by the standard library, and multicast is denied
    separately because Python may classify multicast addresses as global.
    """

    try:
        address = (
            value
            if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            else ipaddress.ip_address(value)
        )
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv4Address):
        if any(address in network for network in _DENIED_IPV4_NETWORKS):
            return False
    else:
        if address.scope_id is not None or address.ipv4_mapped is not None:
            return False
        if address.sixtofour is not None or address.teredo is not None:
            return False
        if any(address in network for network in _DENIED_IPV6_NETWORKS):
            return False
    return address.is_global and not address.is_multicast


def is_forbidden_literal_host(hostname: str | None) -> bool:
    """Conservatively classify literals/special local names without resolving DNS."""

    if not hostname:
        return True
    host = hostname.rstrip(".").lower()
    if host in _DENIED_HOSTS or host.endswith(_DENIED_HOST_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return _looks_like_ambiguous_ipv4(host)
    return not is_public_address(address)


def _looks_like_ambiguous_ipv4(hostname: str) -> bool:
    components = hostname.split(".")
    return 1 <= len(components) <= 4 and all(
        bool(_NUMERIC_COMPONENT.fullmatch(component)) for component in components
    )


def _validated_hostname(hostname: str | None, authority: str) -> tuple[str, str | None]:
    if not hostname or not hostname.isascii():
        _reject("malformed-host")
    host = hostname.lower()
    if host.endswith(".") or len(host) > 253:
        _reject("malformed-host")
    if host in _DENIED_HOSTS or host.endswith(_DENIED_HOST_SUFFIXES):
        _reject("forbidden-hostname")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if authority.startswith("["):
            _reject("malformed-host")
        if _looks_like_ambiguous_ipv4(host):
            _reject("ambiguous-ipv4")
        labels = host.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            _reject("malformed-host")
        return host, None

    if isinstance(address, ipaddress.IPv6Address) and not authority.startswith("["):
        _reject("malformed-host")
    if not is_public_address(address):
        _reject("forbidden-address")
    return address.compressed, address.compressed


def _resolved_addresses(
    resolver: Resolver,
    hostname: str,
    port: int,
    *,
    max_answers: int,
) -> tuple[str, ...]:
    try:
        answers = resolver(hostname, port)
        if isinstance(answers, (str, bytes)):
            _reject("invalid-dns-answer")
        iterator = iter(answers)
        observed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for answer in iterator:
            if len(observed) >= max_answers:
                _reject("dns-answer-limit")
            if not isinstance(answer, str) or "%" in answer:
                _reject("invalid-dns-answer")
            try:
                address = ipaddress.ip_address(answer)
            except ValueError:
                _reject("invalid-dns-answer")
            observed.append(address)
    except DestinationPolicyError:
        raise
    except Exception:
        _reject("dns-unavailable")

    if not observed:
        _reject("dns-unavailable")
    if any(not is_public_address(address) for address in observed):
        _reject("forbidden-address")
    unique = sorted(set(observed), key=lambda item: (item.version, int(item)))
    return tuple(address.compressed for address in unique)


class DestinationPolicy:
    """Validate each destination and hand a pinned-address grant to a connector."""

    def __init__(
        self,
        resolver: Resolver,
        *,
        allowed_ports: Iterable[int] = DEFAULT_ALLOWED_PORTS,
        max_answers: int = MAX_DNS_ANSWERS,
    ) -> None:
        ports = tuple(allowed_ports)
        if not ports or any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or port <= 0
            or port > 65535
            for port in ports
        ):
            raise ValueError("allowed ports must be integers within [1, 65535]")
        if (
            isinstance(max_answers, bool)
            or not isinstance(max_answers, int)
            or max_answers <= 0
            or max_answers > MAX_DNS_ANSWERS
        ):
            raise ValueError(
                f"max_answers must be within [1, {MAX_DNS_ANSWERS}]"
            )
        self._resolver = resolver
        self.allowed_ports = frozenset(ports)
        self.max_answers = max_answers

    def canonical_url(self, url: str, *, purpose: DestinationPurpose) -> str:
        """Legacy identity seam; a trusted shared-parser policy overrides this."""
        return url

    def resolve_redirect(self, reference: str, base: str) -> str:
        """Legacy resolution; trusted shared-parser policy overrides this."""
        return urljoin(base, reference)

    def validate(
        self,
        url: str,
        *,
        purpose: DestinationPurpose,
    ) -> ValidatedDestination:
        if purpose not in {"initial", "redirect", "subresource"}:
            raise ValueError("unknown destination purpose")
        if not isinstance(url, str) or not url:
            _reject("invalid-url")
        if url != url.strip(" \t\r\n\f\v") or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in url
        ):
            _reject("invalid-url")
        if "\\" in url:
            _reject("invalid-url")

        scheme_separator = url.find("://")
        if scheme_separator < 1:
            _reject("invalid-url")
        authority = url[scheme_separator + 3 :].split("/", 1)[0]
        authority = authority.split("?", 1)[0].split("#", 1)[0]
        if not authority or "%" in authority:
            _reject("malformed-authority")

        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            _reject("malformed-authority")
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            _reject("unsupported-scheme")
        if parsed.username is not None or parsed.password is not None:
            _reject("credentials")
        if purpose == "initial" and ("?" in url or "#" in url):
            _reject("initial-target-data")

        effective_port = port if port is not None else (80 if scheme == "http" else 443)
        if effective_port not in self.allowed_ports:
            _reject("disallowed-port")
        hostname, literal_address = _validated_hostname(parsed.hostname, authority)
        addresses = (
            (literal_address,)
            if literal_address is not None
            else _resolved_addresses(
                self._resolver,
                hostname,
                effective_port,
                max_answers=self.max_answers,
            )
        )
        return ValidatedDestination(
            purpose=purpose,
            scheme=scheme,
            hostname=hostname,
            port=effective_port,
            addresses=addresses,
        )

    def authorize_and_connect(
        self,
        url: str,
        *,
        purpose: DestinationPurpose,
        connector: Callable[[ValidatedDestination], T],
    ) -> T:
        """Invoke a connector only after this request's independent validation."""

        destination = self.validate(url, purpose=purpose)
        return connector(destination)
