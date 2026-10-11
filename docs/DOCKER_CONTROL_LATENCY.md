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

## Verification and remaining work

Final normal and optimized contract runs passed: fixed/chunked reply parsing,
wire/body caps, exact response count, identity drift, malformed/ambiguous framing,
GET-only requests, nonzero-client cleanup/no-retry/redaction, and partial CLI
completion followed by timeout with non-stale exit accounting. These are mock
and captured-protocol controls, not native containment or capture proofs.

No production transport, deadline, cleanup semantics or journal schema changed.
The observation motivates a separately reviewed, bounded control-channel
investigation; adoption requires identity/ownership, timeout, crash ambiguity,
cleanup and native capture/publication parity. Missing durable volume-removal
proofs remain preserved as described in `PAIR_STARTUP_EXPERIMENT.md`.
Independent host cgroup binding and successful scanner release gates remain
open. Public scanning stays disabled.
