# Bounded system DNS adapter

Status: real process-deadline and integration evidence; deployment DNS policy open.

`scanner/bounded_resolver.py` provides `BoundedSystemResolver`, the synchronous
`(hostname, port) -> address strings` callable accepted by `DestinationPolicy`.
It runs one new isolated Python helper for every call. There is no application
answer/grant cache. Initial requests, CONNECT checks, redirects, and subresources
resolve independently; only the resulting validated numeric grant can reach
the pinned connector. The adapter does not disable OS resolver caching or select
authoritative DNS servers. Deployment must pin/review the system resolver and
hosts configuration, and constrain DNS egress separately from browser egress.

## Protocol and limits

The parent accepts only canonical ASCII hostnames and ports 80/443. Literal IPs
are handled directly by `DestinationPolicy`, not sent to DNS. Each call creates
a private temporary directory, writes a small mode-0600 hostname/port input, and
launches `resolver_worker.py` with `python -I -S`. Hostnames are not in argv;
URLs, paths, queries, headers, and provider error messages never enter the
protocol. Helpers receive a minimal environment: Windows system essentials,
private TEMP/TMP paths, and the supervisor nonce. App credentials, Python and
resolver override variables are not inherited. Standard streams are discarded.
The trusted helper calls OS
`getaddrinfo` for IPv4/IPv6 TCP endpoints and ignores canonical/reverse names.
Its input is restricted to a regular file of at most 512 bytes with exact keys.

Each observed address is preserved, including duplicates, until the policy can
validate the entire answer set. The helper rejects the seventeenth answer rather
than returning a truncated allowed prefix. Scoped addresses, non-TCP endpoints,
family/port mismatches, and malformed addresses produce an empty failure result.
Private answers are not filtered out: `DestinationPolicy` rejects the whole set
if any observed answer is forbidden. Successful answers are canonical numeric
strings, never connection instructions or stored DNS logs.

The helper atomically writes a nonce-scoped JSON envelope. The supervisor now
accepts an optional stricter `max_result_bytes`; DNS uses 2,048 bytes rather than
the unchanged 4,000,000-byte default for scan records. The supervisor rejects
oversized/nonregular/stale/malformed output before eligibility and JSON loading.
The resolver then rejects extra/duplicate fields, unexpected types/outcomes,
noncanonical addresses, empty success sets, and more than sixteen answers. A
zero exit plus a nonce-matched regular file is necessary, never sufficient.

Defaults are three seconds per lookup (including semaphore wait and setup),
four concurrent helper invocations per resolver and per Python process, five
hundred lookup attempts, and a maximum
fifteen-second monotonic scan lifetime. Lookup budgets may be set within 1–3
seconds; lifetime within 1–15 seconds. A helper is launched only with at least
one second remaining for the existing supervisor and termination reserve. An
exact one-second budget may therefore reject before launch after setup costs.
The lookup cap is not the HTTP request cap: CONNECT and request/redirect
revalidation can each consume a lookup. All attempts count, including failed
ones that acquire both slots before setup. A waited-out semaphore call starts no process.
The process-wide cap is not a distributed service cap: deployment must also
bound the number of outer scan workers. Separate-process workers have separate
semaphores. Resolver instances may lower their own concurrency bound, not raise
the hard four-child ceiling in one Python process.

Deadline failure is `dns-timeout`, cap failure is `dns-lookup-limit`, and provider
or process/artifact failure is content-free `dns-unavailable`. Answer-limit and
invalid-answer reasons remain distinct. Temporary input/output files are removed
on success and failure. POSIX 0700/0600 intent is tested conditionally; Windows
ACL privacy still needs deployment evidence. Subprocess/OS/filesystem stalls
remain subject to destruction of the entire outer disposable worker; this
adapter is not an independent containment boundary.

The API behavior follows Python's official
[getaddrinfo documentation](https://docs.python.org/3/library/socket.html#socket.getaddrinfo)
and [subprocess documentation](https://docs.python.org/3/library/subprocess.html).

## Reproducible evidence

`python scripts/verify_bounded_resolver.py` is deterministic and proves:

- actual helper getaddrinfo arguments, IPv4/IPv6/duplicate preservation, and the 16-answer fence;
- twenty-three malformed/private/failure cases, including mixed-family answers and a private seventeenth answer;
- strict 2 KiB supervisor admission, nonce eligibility, duplicate-field rejection, and discarded provider streams;
- repeated same-host initial/redirect/subresource lookups and public-to-private rebinding denied before connector contact;
- real hung processes/descendants killed after early valid output, with no admitted grant;
- per-instance and cross-instance process caps, waited-out semaphore, lookup cap, lifetime expiry, minimal environment, and private artifact cleanup.

Symlink and POSIX mode checks run only on POSIX; this Windows run did not prove
those platform-specific assertions. Existing worker-deadline, destination-policy,
scan-transport, and origin-exchange verifiers cover compatibility.

Optional `--public` adds one labeled live system DNS smoke. On 2026-10-05 it
admitted eight public `www.python.org` answers in 297 ms. A separate anonymous
HEAD through this resolver, `OriginExchange`, and `connect_pinned` returned HTTP
200, 1,233 raw HTTP wire bytes, and zero body bytes under a seven-second budget
with normal origin certificate validation. The restricted shell's first HEAD
failed; the approved network check succeeded. This is one-machine composition
evidence, not deployed DNS configuration, a reliability corpus, or latency proof.

## Next release evidence

Wire this adapter into the actual public worker/grant path, install per-scan root
trust only in its disposable browser profile, prove browser bypass denial under
independent network containment, then exercise representative public pages and
end-to-end latency. Arbitrary public scanning remains disabled.
