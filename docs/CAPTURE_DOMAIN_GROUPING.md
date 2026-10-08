# Gate 0 — PSL-backed controlled capture and unknown-domain propagation

`probe_page` now accepts an optional, exact `PinnedPublicSuffixList` supplied by
trusted operator code. It uses the classifier for the final page and each HTTP(S)
resource, then records the rule, exact PSL SHA-256 and IDNA version in optional
`capture.domainGrouping`. Resource `partyRule` must match that recorded rule.
No visitor input or worker payload selects a classifier. The existing target and
egress guards are unchanged; the probe remains reserved-fixture-only.

Default calls still use the explicitly labeled fixture grouping helper. The new
IDNA dependency is imported lazily only for the opt-in path; existing Docker
images/default workers are not silently given an unbuilt dependency or changed
grouping semantics.

## Unknown is not third party

A suffix-only, literal-IP or unclassifiable page has a null registrable domain
in opt-in capture. Every resource then has `party: unknown`, even when its own
domain is known. Neither two null domains nor a null/known comparison creates a
first- or third-party claim. The scan schema and semantic admission allow that
null only with grouping provenance and reject classified resources when the
page boundary is unknown. Third-party hero selection therefore sees no classified
requests and cannot fabricate a domain comparison.

The result-manifest display identity uses the final URL's hostname in this case,
with `recordRef: #/finalUrl` and `derivation: url-hostname-v1`. It does not change
the null measurement into a fake registrable domain. The result schema requires
this derivation for the URL reference and forbids it for the original direct
domain reference. Known-domain golden result manifests stay byte-identical.
The frontend scan/result types accept the explicit null and derived identity.
This is a prelaunch contract extension under the existing versioned schemas,
distinguished by its new party rule/provenance, not a deployed compatibility claim.

## Evidence — 2026-10-08

`verify_capture_domain_grouping.py` uses actual Chromium 140.0.7339.16 and a
dedicated loopback HTTP server through the existing reserved-host policy proxy.
The compact test-only PSL declares `github.test` as a PRIVATE suffix. Three actual
captures prove:

- `alice.github.test` and its CDN are first party; Bob's tenant/CDN are third party.
- The suffix-only page `github.test` has null domain, all unknown parties and no
  third-party insight. Its public display identity is the derived hostname.
- Default fixture mode still uses its original boundary and emits no PSL metadata.
- Each record passes scan schema/semantics, scene construction/schema and result
  construction/schema. Three forged provenance/party records reject.

Normal and optimized final runs pass. Early fixture attempts named nonexistent
proxy methods and omitted the semantic validator argument; those were fixed
without changing production guard behavior. Review caught an actual downstream
gap: result-manifest creation originally rejected a null page domain. The derived
identity path and expanded result-level verification fix that gap.

Regression evidence: three original scan fixtures plus 15 negative controls;
scan-transport address/admission matrix; scene, result and viewer-runtime suites;
frontend typecheck and all 50 tests across seven suites. The first sandboxed
frontend run failed to read generated temporary module files before loading six
suites. It was allowed to finish, then rerun with normal temporary-file access;
no application policy was relaxed. No broad temporary-file cleanup was used.

```powershell
.dom-xray-data/domain-venv/Scripts/python.exe scripts/verify_capture_domain_grouping.py
.dom-xray-data/domain-venv/Scripts/python.exe -O scripts/verify_capture_domain_grouping.py
python scripts/validate_fixtures.py
python scripts/verify_result_manifest.py
```

The fixture dataset is not the full deployed PSL. Full immutable snapshot parsing
is separately verified in [PUBLIC_SUFFIX.md](PUBLIC_SUFFIX.md). Snapshot packaging,
shared WHATWG/UTS #46 compatibility, candidate-image dependency adoption, actual
public broker egress/API integration, Docker recovery and production/product gates
remain open. Public arbitrary-URL scanning stays disabled.
