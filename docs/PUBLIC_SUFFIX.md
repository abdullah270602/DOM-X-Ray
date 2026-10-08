# Gate 0 — Offline pinned domain-boundary classifier

The existing capture helper still uses reserved-fixture last-two-label grouping;
it is not replaced or represented as production-ready by this checkpoint.
`PinnedPublicSuffixList` implements the official prevailing-rule algorithm with
both ICANN and PRIVATE sections, longest exact/wildcard match, exception priority
and fallback `*`. It preserves the distinction between a suffix and a registrable
domain. A wildcard does not implicitly register its base. Independent hosted
tenants such as `alice.github.io` and `bob.github.io` stay separate.
See the [official PSL format and algorithm](https://github.com/publicsuffix/list/wiki/format).

Runtime construction accepts bounded UTF-8 bytes and an operator-selected exact
SHA-256 digest, not a URL. Rule maps are read-only. It performs no DNS, network,
cache refresh or file write. Inputs/rules are length-bounded before IDNA work;
malformed names, pins, section order and rule syntax reject. IP literals return
no public suffix/registrable domain; they are not mistaken for DNS registrations.
An unknown suffix uses the standard default rule, not a claim of DNS existence.
This class is not a URL parser, destination validator or SSRF authorization seam.

Unicode host/rule normalization uses pinned `idna==3.15` with UTS #46 and STD3
checks. It deliberately does not use Python's older built-in IDNA codec.
[Package documentation](https://pypi.org/project/idna/3.15/) describes that
normalization. PyPI marks the globally installed 3.11 as affected by
[CVE-2026-45409](https://pypi.org/pypi/idna/3.11/json); no global package was
upgraded. `requirements-domain.txt` pins the official universal 3.15 wheel hash.
Testing uses an ignored project-only environment. Candidate Docker images and
their existing dependency manifests remain unchanged, not silently repinned.

## Evidence — 2026-10-08

Normal/optimized focused tests cover country-code boundaries, wildcard base and
exception behavior, PRIVATE tenant separation, suffix-only/null cases, default
rules, Unicode/A-label equivalence, sharp-s normalization, literal IP distinction,
invalid names/list data, duplicate rules, size bounds, wrong hash and wrong
dependency version. The compact list is explicitly a fixture, not a deployment
dataset. Review found no prevailing-rule defect; LF-only splitting and explicit
default-rule PRIVATE provenance were tightened before final verification.

A full official snapshot was independently fetched over verified HTTPS at
[commit 3929462652695bad04f0a27afb600974014a3c8b](https://github.com/publicsuffix/list/tree/3929462652695bad04f0a27afb600974014a3c8b):
335,389 bytes; SHA-256
`2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7`;
10,018 exact, 310 wildcard and eight exception rules. The full file parses and
the selected country-code, hosted-tenant, exception and Unicode checks pass.
The verifier uses that immutable revision and digest, never a moving branch.
The first discovery request assumed a nonexistent branch and failed; repository
metadata was then read to resolve its actual default branch and immutable revision.

```powershell
python -m venv .dom-xray-data/domain-venv
.dom-xray-data/domain-venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-domain.txt
.dom-xray-data/domain-venv/Scripts/python.exe scripts/verify_public_suffix.py
.dom-xray-data/domain-venv/Scripts/python.exe -O scripts/verify_public_suffix.py
.dom-xray-data/domain-venv/Scripts/python.exe scripts/verify_public_suffix_snapshot.py --fetch
```

`--fetch` is explicit build/test source retrieval, not runtime scanner behavior;
`--snapshot` verifies already available bytes without network access.
Snapshot deployment packaging/license/update policy, cross-language shared
WHATWG URL/UTS #46 compatibility, capture provenance/party-rule adoption and
representative-browser comparison remain open. No public URL scanner was enabled.

The later [controlled-capture checkpoint](CAPTURE_DOMAIN_GROUPING.md) adds opt-in
PSL grouping, exact snapshot provenance and unknown-domain propagation through
scan, scene and result contracts. Public parser/runtime/API adoption remains open.
