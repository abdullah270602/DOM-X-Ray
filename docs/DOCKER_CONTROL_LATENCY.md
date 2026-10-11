# Gate 3: read-only Docker control latency

## Scope and safeguards

`scripts/verify_docker_control_latency.py` compares five `docker --context
desktop-linux info --format '{{json .}}'` calls with five fixed HTTP/1.1
`GET /v1.51/info` requests through one `docker system dial-stdio` process.
It creates no containers, changes no settings, and accesses no host namespaces.
Each mode runs inside the existing owned 15-second Windows worker Job, with a
12-second inner budget. It stops the owned client in `finally`, never retries a
failed attempt, and requires outer worker eligibility before reading evidence.

Captured replies are bounded, require exactly five complete responses, reject
ambiguous framing, and require stable Linux/cgroup-v2 engine identity. Raw engine
metadata and provider errors are not logged. Identity hashes are used only for
private comparison. Failed attempts retain timing, completed-response count and
their own exit status rather than borrowing the preceding call's status.

This is a diagnostic, not an alternative supervisor. CLI negotiation and fixed
API requests are different workloads; sequential order and host load are not
controlled. [Docker's Engine API documentation](https://docs.docker.com/reference/api/engine/)
describes versioned requests. The current upstream
[stdio implementation](https://github.com/docker/cli/blob/master/cli/command/system/dial_stdio.go)
marks the command hidden/internal; that source was not verified against the
installed binary and cannot establish this failure's cause.

## Final-version native observation, 2026-10-11

Docker Desktop's `desktop-linux` endpoint was observed as
`npipe:////./pipe/dockerDesktopLinuxEngine`; client version was 28.3.2 and server
API version 1.51. The final run recorded:

- CLI: five valid replies, exit 0; durations 1.053473, 1.080899, 1.123373,
  1.115664 and 1.068514 seconds. Total 5.441922 seconds, median 1.080899 seconds;
  outer supervised duration 7.016310 seconds.
- Stdio: exit 0, but response validation failed; zero validated complete batches,
  failed-attempt duration 0.389057 seconds, outer duration 1.875959 seconds.
- Overall verifier: exit 1 because the comparison did not complete.

The short failed attempt is **not a speedup**. Its exit 0 distinguishes it from
a nonzero client failure but does not prove valid protocol output. Both workers
terminated; no Docker resources were created. Earlier observations showed the
same qualitative failure and are not independent reliability benchmarks.

## Input-lifetime experiment, 2026-10-11

An explicit diagnostic-only `--keep-dial-input` option leaves the client's stdin
open after flushing the fixed requests. The fifth request still sends
`Connection: close`; the engine closes the response stream, then the client
exits. The existing `stop(deadline)` finally closes remaining owned pipes.
The default close-input baseline and production supervisor are unchanged.
Evidence adds only output byte count and the held-input boolean, never contents.

Two held-input native trials completed with exit 0 and five valid responses per
mode. Each trial privately verified matching engine identity between modes:

| Trial | Five CLI calls, total | CLI median | One connection, five replies | Supervised CLI / connection |
| --- | ---: | ---: | ---: | ---: |
| 1 | 5.458738 s | 1.086266 s | 0.622087 s | 6.986648 / 2.123586 s |
| 2 | 5.703529 s | 1.140954 s | 0.623043 s | 7.300374 / 2.147220 s |

Both connection trials returned 63,949 bytes. Between them, the close-input
baseline again exited 0 but failed validation: 489 bytes, 0.411664 seconds,
zero validated batches and overall verifier exit 1. Its five CLI calls passed
but varied from 1.171939 to 2.190919 seconds. This supports input lifetime as a
relevant factor, not a fully established internal failure mechanism. These are
descriptive timings, not a randomized performance benchmark, scanner capture
pass, long-lived transport proof or general reliability estimate.

Normal/optimized controls additionally verify the option reaches the diagnostic
pipe, complete held-input replies are validated, and a held-input timeout
records no completed replies, no stale exit/byte count, one timed attempt,
cleanup and redaction. Mock cleanup is not native timeout containment proof.

## Verification and remaining work

Final normal and optimized contract runs passed: fixed/chunked reply parsing,
wire/body caps, exact response count, identity drift, malformed/ambiguous framing,
GET-only requests, nonzero-client cleanup/no-retry/redaction, and partial CLI
completion followed by timeout with non-stale exit accounting. These are mock
and captured-protocol controls, not native containment or capture proofs.

No production transport, deadline, cleanup semantics or journal schema changed.
The observation motivates a separately reviewed, bounded control-channel
implementation. Before production adoption, the next acceptance steps are:

1. Build a test-only request adapter with a closed endpoint/method allowlist;
   never accept visitor-provided daemon routes, engine endpoints or headers.
2. Bind the fixed context, API version and engine identity; enforce bounded
   request/response bytes and deadline-controlled I/O. Do not add implicit
   reconnect/retry after an uncertain resource mutation.
3. Preserve exact identity/token ownership, intent-before-create journal order,
   immutable image/policy pins, resource readback, stop/PID-zero/removal proofs
   and cleanup deadlines. Attach/upgrade streaming is a distinct protocol and
   needs independent coverage rather than reusing this buffered info decoder.
4. Prove malformed replies, disconnects before/after mutation, blocked I/O,
   crash recovery and native owned-client termination. Then run the existing
   pair/cleanup fault matrix and successful API capture/publication under
   unchanged limits before considering adoption.

Missing durable volume-removal
proofs remain preserved as described in `PAIR_STARTUP_EXPERIMENT.md`.
Independent host cgroup binding and successful scanner release gates remain
open. Public scanning stays disabled.
