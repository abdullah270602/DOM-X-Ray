# Opt-in pinned WHATWG API admission

`LocalScanJobService(target_parser=parser)` now accepts an explicitly constructed,
operator-pinned `WhatwgUrlParser`. The default local service/CLI remains
unconfigured and seeded-only; explicit CLI flags now provide the opt-in wiring.
No executable/source pins are discovered automatically in the
service, no public executor is installed, and arbitrary scanning stays disabled.

With that configuration, the service parses the initial target before executor
support checks or admission reservation. Its canonical `href` is passed to
support checks, duplicate/origin keys, the queue, and execution. Structural URL
rejections return content-free 403 `rejected/invalid-target` jobs. A missing or
changed parser pin returns 503 `failed/internal-error`, using the existing job
schema rather than presenting an infrastructure fault as invalid user input.
Neither outcome contacts the executor or reserves admission capacity.

After normal bundle schema/binding validation, result publication additionally
requires `record.requestedUrl` to equal the submitted canonical target exactly
and remain canonical under the pinned parser. A differently spelled but
equivalent URL is not silently accepted as truthful canonical wire identity.
The unconfigured fixture mode retains its existing narrow target comparison.

## Evidence

```powershell
python scripts/verify_whatwg_api_admission.py
python -O scripts/verify_whatwg_api_admission.py
python scripts/verify_local_scan_api.py
python scripts/verify_scan_api_contract.py
```

The new test ran the real pinned Node parser against a real loopback HTTP API,
normally and optimized (selected Node v22.18.0). Only the test derives pins from its selected local
files. It proved Unicode/IDN/emoji and dot-path/default-port canonicalization
before a still-disabled support check; forbidden credentials, empty query and
fragment delimiters, ambiguous IPv4 and nonallowed port rejection before
executor contact; changed-parser guard failure as a fixed schema-valid job
without private error detail; canonical queue input and duplicate reservation;
and strict result-identity helper checks. It also rejects an arbitrary parser
object before creating the job pool.

The execution seam in this new test is deliberately fake and ends with
`capture-failed`: it does not prove successful parser-configured publication,
public DNS/origin egress, or actual browser capture. The existing unconfigured
seeded HTTP regression separately passed actual supervised fixture admission,
publication, restart/deletion and poster/video route checks. The API contract
suite passed submission, lifecycle and three bundle binding controls. These
separate scopes must not be combined into a public production claim. The
subsequent configured-parser publication evidence is recorded below.

An initial test exposed that `rejected/internal-error` violates the existing
job schema. That run failed; the corrected `failed/internal-error` mapping was
verified by the final normal and optimized runs. No schema was relaxed.

## Remaining release integration

### Configured-parser seeded publication checkpoint

```powershell
python scripts/verify_whatwg_api_publication.py
python -O scripts/verify_whatwg_api_publication.py
```

Both final runs passed with the actual pinned parser, real loopback HTTP API,
real supervised `FixtureScanExecutor`, mapping pipeline, poster/video generation
and `MemoryResultStore` publication. A raw default-port/dot-path gallery URL
became the canonical requested identity before execution, produced a schema-
and cross-binding-valid ready bundle, and reused the same result when submitted
in canonical spelling. Binary GET/HEAD/conditional ETag checks verified exact
manifest hashes, byte lengths, media types and no-store headers for both exports.

Two negative controls replayed the real schema-valid fixture execution: its
gallery record returned for a clean request, and its correct gallery record
returned after the parser guard became unavailable. Both produced fixed
`failed/internal-error` jobs, never called storage publication, left the result
absent in their fresh memory backends, and exposed no private parser canary.
These controlled executor seams isolate the publication checks; they are not
additional browser captures. The admitted positive execution remains the real
supervised seeded transport, not public-origin scanning.

The first run failed its five-second **observation** timeout and drained service
work before terminating. It is not a pass. The final harness waits up to thirty
seconds for publication, without changing scan/renderer execution deadlines.
This does not establish the twenty-second product target or p90 performance.
`-O` here covers the test/API process, not propagation into fixture/render child
processes. No deployed restart/storage/CDN or public scanner proof is claimed.

The admission suite passed again normally and optimized after extracting its
shared test-only parser constructor. Test-derived exact-file hashes establish
pin enforcement for that exercised instance, not independent pin provenance or
production pin distribution. No default API/CLI configuration or scanner release
gate was enabled by this evidence checkpoint.

### Explicit CLI configuration checkpoint

The local CLI now accepts all four options together:

- `--url-parser-node`: absolute, canonical operator-selected Node executable.
- `--url-parser-node-sha256`: reviewed executable SHA-256.
- `--url-parser-module-sha256`: reviewed `shared/public_url.mjs` SHA-256.
- `--url-parser-worker-sha256`: reviewed `scanner/public_url_worker.mjs` SHA-256.

All omitted preserves the default fixture mode. Partial configuration or failed
path/hash verification exits with a fixed configuration error before backend
initialization, job-pool creation or server binding. There is no hash discovery,
download, PATH selection, pin fallback or public-scanner enable switch in this
startup helper. Operators must supply reviewed pins from their release process,
not derive expected hashes from whatever files happen to exist at each startup.
Providing syntax pins does not substitute for trusted binary provenance.

```powershell
python scripts/verify_whatwg_api_configuration.py
python -O scripts/verify_whatwg_api_configuration.py
```

Both tests passed with real file/pin checks and mocked backend/hosting. They
verify absent default, exact configured path/pins, each missing option, each
wrong pin/path, relative executable rejection, and no storage/pool/server calls
for rejected configuration. The tests do not start a live CLI service or prove
deployment. The real loopback admission test and API schema suite passed again
after this wiring change. Earlier service/publication proof remains separate
evidence; no default policy or scan deadline changed.

### Remaining deployment requirements

Deployment still must supply reviewed immutable pins and a bounded parser
runtime, integrate the selected production executor/resolver/egress and broker
raw binding, and measure full submit-to-reveal latency. The parser only handles
structural syntax: DNS/address authorization and rebinding defense remain the
executor's destination-policy responsibility. HTTP JSON/body/schema bounds
remain unchanged, so this is not a claim of accepting every spelling allowed
by the shared parser. Hash/metadata reads and repeated disposable parser calls
are not a hard whole-request deadline or established throughput bound.

See [backend transport adoption](WHATWG_BACKEND_ADOPTION.md),
[shared URL policy](SHARED_URL_POLICY.md), and [API contract](SCAN_API.md).
