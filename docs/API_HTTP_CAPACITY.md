# Local HTTP handler capacity and idle I/O

The local server now admits at most `max_http_handlers` concurrent request
handler threads (engineering default 16). A nonblocking semaphore is acquired
before thread construction and released after handler/socket cleanup. Accepted
sockets use `http_idle_timeout_seconds` (default 10). Both constructor options
are validated before listener construction: handler count must be a positive
integer, timeout positive and finite. `build_server` exposes the same options;
this checkpoint does not add CLI tuning or select production load policy.

Overflow creates no handler or job. The accept loop discards at most one
4096-byte prefix with a timeout of at most 50ms, then attempts a fixed empty
503 response with no-store, Retry-After 1 and Connection close, with send timeout
at most one second. The prefix is not parsed, persisted or logged. Closure is
mandatory even after I/O failure. This is best-effort HTTP signaling: oversized,
slow or disconnected peers may receive only a reset/close, not a readable 503.
Overflow has no job identifier or JSON job body; clients must handle transport
unavailability rather than assume every response is a job document.

## Evidence

```powershell
python scripts/verify_api_http_capacity.py
python -O scripts/verify_api_http_capacity.py
python scripts/verify_api_parser_concurrency.py
python scripts/verify_whatwg_api_admission.py
python scripts/verify_local_scan_api.py
```

Final normal and optimized capacity tests passed with actual loopback sockets:
two idle handlers occupy a configured two-slot server, a normal third health
request receives empty no-store 503/Retry-After without submission/rejection or
job creation, both idle sockets close under a selected 400ms test timeout,
capacity returns for a successful health request, and owned handler/host threads
are joined. Controlled mocked thread-start and overflow-read/send failures
separately verify no slot leak/over-release and mandatory closure. Invalid
configuration cases are rejected before parent listener construction.

The initial normal and optimized attempts failed with Windows
`ConnectionAbortedError` before a readable overflow response. They are not
passes. The bounded prefix discard allowed the final ordinary-request tests
to pass. Closing with unread input can produce reset behavior (the
[Linux TCP implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c)
also has an unread-data close/reset branch); that source is not proof of the
specific Windows failure cause or of guaranteed delivery on other platforms.

Parser-concurrency, configured admission, and the full existing seeded API
regressions passed afterward, including publication, binary artifact routes,
restart/deletion, reuse and target correlation. Public scanning stayed disabled.

## Remaining boundaries

Socket timeout is **idle blocking I/O**, not an absolute request/header/body
deadline: a slow-drip peer can keep a slot occupied. It does not preempt parser
hash I/O, Python handler computation, result backend operations or renderer
work. Synchronous overflow handling can occupy the accept loop for its bounded
read/send windows, and no hard scheduler/platform timing bound is established.
Kernel backlog, total connections, aggregate memory, job/deletion history,
distributed rate/cost enforcement, edge ingress and load/proxy behavior remain
separate release requirements. The cap covers HTTP handler threads, not all
process threads, Node/render children or multiple API instances. Local socket
tests and engineering defaults do not establish a hardened public deployment.
