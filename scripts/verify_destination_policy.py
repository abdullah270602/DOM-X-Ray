"""Verify public-only URL/DNS decisions without contacting the network."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.destination_policy import (  # noqa: E402
    MAX_DNS_ANSWERS,
    DestinationPolicy,
    DestinationPolicyError,
    ValidatedDestination,
    is_public_address,
)


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class SequenceResolver:
    def __init__(self, answers: list[object]) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    def __call__(self, hostname: str, port: int) -> list[str]:
        self.calls.append((hostname, port))
        if not self.answers:
            raise RuntimeError("resolver sequence exhausted")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return list(answer)  # type: ignore[arg-type]


def expect_rejection(
    policy: DestinationPolicy,
    url: str,
    reason: str,
    *,
    purpose: str = "initial",
) -> DestinationPolicyError:
    try:
        policy.validate(url, purpose=purpose)  # type: ignore[arg-type]
    except DestinationPolicyError as error:
        require(error.reason == reason, f"{url!r} produced {error.reason!r}, not {reason!r}")
        require(str(error) == reason, "policy error leaked target details")
        return error
    raise AssertionError(f"destination policy accepted {url!r}")


def verify_address_corpus() -> None:
    public = (
        "1.1.1.1",
        "8.8.8.8",
        PUBLIC_V4,
        "2001:4860:4860::8888",
        PUBLIC_V6,
    )
    forbidden = (
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.0.0.9",
        "192.0.0.10",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.168.0.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:93.184.216.34",
        "::127.0.0.1",
        "::10.0.0.1",
        "::169.254.169.254",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:1::1",
        "2001:2::1",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
        "2001:db8::1",
        "2002:0a00:0001::",
        "2620:4f:8000::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    )
    require(all(is_public_address(value) for value in public), "public address corpus regressed")
    require(
        all(not is_public_address(value) for value in forbidden),
        "forbidden address corpus regressed",
    )
    require(not is_public_address("not-an-address"), "invalid address became public")


def verify_url_and_resolution_policy() -> None:
    resolver = SequenceResolver(
        [
            [PUBLIC_V6, PUBLIC_V4, PUBLIC_V4],
            [PUBLIC_V4],
            [PUBLIC_V6],
        ]
    )
    policy = DestinationPolicy(resolver)
    initial = policy.validate("HTTPS://Example.COM/path", purpose="initial")
    require(
        initial.scheme == "https"
        and initial.hostname == "example.com"
        and initial.port == 443
        and initial.addresses == (PUBLIC_V4, PUBLIC_V6),
        "initial hostname validation did not normalize and sort its grant",
    )
    subresource = policy.validate(
        "http://assets.example.com/image.png?token=secret#ignored",
        purpose="subresource",
    )
    require(
        subresource.hostname == "assets.example.com"
        and subresource.port == 80,
        "subresource destination rejected ordinary request data",
    )
    redirect = policy.validate(
        "https://redirect.example.com/next?state=opaque#fragment",
        purpose="redirect",
    )
    require(
        redirect.hostname == "redirect.example.com"
        and redirect.addresses == (PUBLIC_V6,),
        "redirect destination was not independently resolved",
    )
    require(
        resolver.calls
        == [
            ("example.com", 443),
            ("assets.example.com", 80),
            ("redirect.example.com", 443),
        ],
        "hostname resolver inputs drifted",
    )
    require(
        PUBLIC_V4 not in repr(initial) and PUBLIC_V6 not in repr(initial),
        "validated destination repr exposed resolver answers",
    )

    literal_calls = SequenceResolver([])
    literal_policy = DestinationPolicy(literal_calls)
    literal = literal_policy.validate(f"https://{PUBLIC_V4}/", purpose="initial")
    literal_v6 = literal_policy.validate(f"https://[{PUBLIC_V6}]/", purpose="initial")
    require(
        literal.addresses == (PUBLIC_V4,)
        and literal_v6.addresses == (PUBLIC_V6,)
        and not literal_calls.calls,
        "public literals were re-resolved or normalized incorrectly",
    )

    rejected_urls = (
        (" https://example.com/", "invalid-url"),
        ("https://example.com/\n", "invalid-url"),
        ("https:\\example.com/", "invalid-url"),
        ("ftp://example.com/", "unsupported-scheme"),
        ("https://user:secret@example.com/", "credentials"),
        ("https://example.com/?token=secret", "initial-target-data"),
        ("https://example.com/#secret", "initial-target-data"),
        ("https://example.com/?", "initial-target-data"),
        ("https://example.com/#", "initial-target-data"),
        ("https://example.com./", "malformed-host"),
        ("https://example.com:8080/", "disallowed-port"),
        ("https://example.com:0/", "disallowed-port"),
        ("http://example.com:000/", "disallowed-port"),
        ("https://exa%6dple.com/", "malformed-authority"),
        ("https://bücher.example/", "malformed-host"),
        ("https://bad_host.example/", "malformed-host"),
        ("https://[example.com]/", "malformed-authority"),
        ("https://localhost/", "forbidden-hostname"),
        ("https://service.localhost/", "forbidden-hostname"),
        ("https://printer.local/", "forbidden-hostname"),
        ("https://metadata.google.internal/", "forbidden-hostname"),
        ("http://127.0.0.1/", "forbidden-address"),
        ("http://[::1]/", "forbidden-address"),
        ("http://[::127.0.0.1]/", "forbidden-address"),
        ("http://2130706433/", "ambiguous-ipv4"),
        ("http://127.1/", "ambiguous-ipv4"),
        ("http://0177.0.0.1/", "ambiguous-ipv4"),
        ("http://0x7f000001/", "ambiguous-ipv4"),
        ("https:///missing-host", "malformed-authority"),
    )
    rejecting_policy = DestinationPolicy(lambda _host, _port: [PUBLIC_V4])
    for url, reason in rejected_urls:
        expect_rejection(rejecting_policy, url, reason)
    try:
        rejecting_policy.validate(
            "https://example.com/",
            purpose="unknown",  # type: ignore[arg-type]
        )
    except ValueError:
        pass
    else:
        raise AssertionError("destination policy accepted an unknown purpose")


def verify_dns_fail_closed() -> None:
    cases: tuple[tuple[object, str], ...] = (
        ([], "dns-unavailable"),
        (RuntimeError("resolver-secret-canary-6194072835"), "dns-unavailable"),
        (["not-an-address"], "invalid-dns-answer"),
        ([PUBLIC_V4, "127.0.0.1"], "forbidden-address"),
        ([PUBLIC_V4, "fc00::1"], "forbidden-address"),
        (["fe80::1%3"], "invalid-dns-answer"),
        ([PUBLIC_V4] * (MAX_DNS_ANSWERS + 1), "dns-answer-limit"),
    )
    for answers, reason in cases:
        resolver = SequenceResolver([answers])
        error = expect_rejection(
            DestinationPolicy(resolver),
            "https://public.example/",
            reason,
        )
        require(len(resolver.calls) == 1, "a rejected destination was resolved more than once")
        if isinstance(answers, Exception):
            formatted_error = "".join(traceback.format_exception(error))
            require(
                "resolver-secret-canary-6194072835" not in formatted_error,
                "resolver failure details leaked through policy exception chaining",
            )

    for invalid_ports in ([], [0], [True], [65536]):
        try:
            DestinationPolicy(lambda _host, _port: [PUBLIC_V4], allowed_ports=invalid_ports)
        except ValueError:
            continue
        raise AssertionError(f"destination policy accepted invalid ports {invalid_ports!r}")
    for invalid_max in (0, True, MAX_DNS_ANSWERS + 1):
        try:
            DestinationPolicy(lambda _host, _port: [PUBLIC_V4], max_answers=invalid_max)
        except ValueError:
            continue
        raise AssertionError(f"destination policy accepted invalid answer cap {invalid_max!r}")


def verify_rebinding_no_contact() -> None:
    resolver = SequenceResolver([[PUBLIC_V4], ["127.0.0.1"]])
    policy = DestinationPolicy(resolver)
    connector_ledger: list[ValidatedDestination] = []

    def connector(destination: ValidatedDestination) -> str:
        connector_ledger.append(destination)
        return "contacted"

    first = policy.authorize_and_connect(
        "https://rebind.example/resource",
        purpose="subresource",
        connector=connector,
    )
    require(first == "contacted" and len(connector_ledger) == 1, "public resolution was not connected")
    expect_rejection(
        policy,
        "https://rebind.example/resource",
        "forbidden-address",
        purpose="subresource",
    )
    require(
        len(connector_ledger) == 1
        and connector_ledger[0].addresses == (PUBLIC_V4,)
        and resolver.calls
        == [("rebind.example", 443), ("rebind.example", 443)],
        "rebound private resolution reached the connector or skipped revalidation",
    )


def main() -> None:
    verify_address_corpus()
    verify_url_and_resolution_policy()
    verify_dns_fail_closed()
    verify_rebinding_no_contact()
    print(
        "Validated 51 public/forbidden addresses, 29 malformed or unsafe URLs, "
        "7 DNS failure modes, and public-to-private rebinding rejection before contact."
    )


if __name__ == "__main__":
    main()
