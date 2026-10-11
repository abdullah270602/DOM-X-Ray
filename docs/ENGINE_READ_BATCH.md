# Gate 3: test-only exact-ID read adapter

`scripts/experimental_engine_reads.py` is a buffered read adapter, not a scanner
or cleanup supervisor. It is not imported by production code. It generates only
versioned `GET /info` and `GET /containers/{full-id}/json` requests, matching the
[Docker Engine v1.51 inspect API](https://docs.docker.com/reference/api/engine/version/v1.51/).
It accepts no visitor URL, method, daemon route, endpoint or arbitrary headers.

## Contract

- A tuple contains one to three exact container targets. Each has a full lowercase
  64-hex ID, a constrained `dom-x-ray-` name and a 32-hex lease token. Duplicate
  IDs, names with request delimiters and abbreviated IDs are rejected before I/O.
- Engine-info requests bookend the inspection batch. Both must identify the same
  Linux/cgroup-v2 engine. This is same-stream consistency, not independent host
  cgroup binding or a durable engine identity pin across invocations.
- An inspect 200 must match the exact ID, name and lease label. The private row is
  returned to the trusted caller, which still owes the entire existing resource,
  image, policy, namespace and state readback. Ownership alone is not preflight.
- A bounded JSON 404 message becomes `None`, an absence observation only. It
  cannot resolve a durable journal obligation or establish kernel emptiness.
- HTTP framing, per-response body/header sizes, total wire size, response count
  and trailing output are checked. Unknown statuses, identity drift, duplicate
  JSON keys, and malformed/ambiguous/incomplete replies fail closed. Nothing is
  returned until the whole batch validates.
- The fixed `desktop-linux` CLI context and API v1.51 are used. Input remains open
  through the final `Connection: close` reply. The trusted deadline must be
  finite, future and at most 12 seconds away. The client is stopped in `finally`,
  with no reconnect or retry.
- The caller must already be inside an owned worker process tree. The helper
  itself is not a containment boundary and does not claim crash-proof cleanup.

## Evidence, 2026-10-11

`scripts/verify_experimental_engine_reads.py` passes normal and optimized Python
contracts for the request allowlist, invalid plans, exact ownership mismatches,
bookend identity drift, missing observations, framing/size faults, success and
timeout stop paths, and invalid/unbounded budgets refusing client creation.
The first sandbox run failed Python executable path resolution; it is not counted
as a pass. Elevated read-access runs passed. These are synthetic protocol and
mock lifecycle controls, not native fault containment proofs.

The final native verifier runs inside the existing 15-second Windows worker Job,
with a 12-second child budget. It probes engine info, a cryptographically random
full-ID inspection, then engine info. It creates no resources and performs no
inventory listing. It outputs counts and timing only; engine info, error text,
IDs, tokens and inspect payloads are not persisted or printed.

Final-version native result: exit 0, three validated responses, one not-found
observation, 0.485972 seconds for the batch and 2.455203 seconds supervised. The
earlier pre-deadline-guard native trial also passed at 0.507517 / 2.540260 seconds.
Neither probes a real owned container's 200 response, mutation/attach, blocked
native I/O or scanner capture/publication. No general reliability rate is claimed.

## Next acceptance step

Integrate this adapter only into a verifier-selected pair candidate, preserving
the production preflight, exact journal obligations and unchanged deadlines.
Prove actual owned-container 200 readback parity, malformed-response refusal,
timeout/cleanup paths and successful capture/publication before adoption.
Mutations and attach/upgrade streaming are outside this adapter and need their
own reviewed protocol and crash-ambiguity handling. The unresolved volume proof
journals remain preserved. Public scanning and all production behavior are
unchanged; Gate 3 remains open.
