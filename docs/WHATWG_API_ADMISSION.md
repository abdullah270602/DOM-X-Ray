# Opt-in pinned WHATWG API admission

`LocalScanJobService(target_parser=parser)` now accepts an explicitly constructed,
operator-pinned `WhatwgUrlParser`. The default local service/CLI remains unchanged
and seeded-only. No executable/source pins are discovered automatically in the
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
separate scopes must not be combined into a public production claim.

An initial test exposed that `rejected/internal-error` violates the existing
job schema. That run failed; the corrected `failed/internal-error` mapping was
verified by the final normal and optimized runs. No schema was relaxed.

## Remaining release integration

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
