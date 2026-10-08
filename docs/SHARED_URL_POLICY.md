# Shared structural URL policy checkpoint

This Gate 0 checkpoint uses the same `shared/public_url.mjs` source in the
visitor form and an operator-pinned, disposable Node helper. It does not enable
arbitrary public scanning or authorize a network destination.

## Contract

`public-url-whatwg-v1` wraps each runtime's native `URL` implementation. Inputs
must be explicit absolute HTTP/S URLs, at most 2,048 UTF-16 code units, without
ASCII control/space characters, backslashes, unpaired surrogates, credentials or
escaped authorities. Initial targets reject even empty `?` and `#` delimiters;
redirects/subresources can retain query data. Host labels, trailing dots, ambiguous
raw numeric IPv4 forms and effective ports outside 80/443 are rejected.
Native serialization canonicalizes Unicode hosts, default ports and dot segments.

Successful output contains the exact policy identifier, canonical href, scheme,
hostname and effective port. Private IP literals can pass structural parsing:
the independent destination policy must still deny forbidden addresses and
resolve/revalidate every destination before the connector uses a numeric grant.
This parser is not a replacement for DNS, rebinding or egress controls.

## Backend seam and limits

`scanner/whatwg_url.py` requires trusted operator SHA-256 pins for the absolute
Node executable, shared module and fixed helper. The verification script discovers
its own local pins only as fixture setup; production pins must be provisioned
independently. Pins are checked before every invocation, but this is not protection
against a privileged concurrent filesystem replacement.

The helper receives bounded JSON over stdin and returns one bounded JSON line.
The Python caller verifies nonce, exact fields/types, fixed failure codes and
serialized URL consistency. Malformed output and local faults become content-free
`url-parser-unavailable` failures. The child inherits only Windows `SystemRoot`
(an empty environment on POSIX), not Node startup hooks or host secrets.

The two-second process-control deadline starts before child creation. Metadata
and hash reads precede that clock and are not hard-preemptible. Cleanup targets
the owned Node process, not an independently proven process tree/cgroup. No
memory/PID sandbox, production container image, broker/API adoption or hard
overall deadline is claimed. Production isolation and adoption remain open.

## Verification on 2026-10-08

- Actual Node v22.18.0 and Chromium 140.0.7339.16 agree on 26 selected canonical
  and rejected inputs using the same source. This is a bounded compatibility
  corpus, not universal WHATWG standards-conformance evidence.
- Canonical Unicode identity reaches a simulated resolver; normalized loopback
  literals, including fullwidth IPv4 input, are denied before DNS contact.
- Three bad pins, configuration drift, six malformed/inconsistent reply cases,
  an actual hung Node process and inherited `NODE_OPTIONS` injection fail closed.
  The hung owned process is confirmed exited.
- The verifier passes normally and with Python optimization enabled. Existing
  held-pipe readiness, EOF, overflow and cleanup regression checks pass with the
  optional child environment parameter's default behavior unchanged.
- All 73 frontend tests pass, including preservation/focus of invalid input and
  no submission for empty query/fragment delimiters. The production viewer build
  passes; its existing large-chunk performance warning remains unresolved.
- One desktop (1280×900) and mobile (390×844) error-state batch confirms actionable
  inline copy, preserved/focused input and no horizontal overflow. Local ignored
  screenshots are `.dom-xray-data/url-entry-desktop.png` and
  `.dom-xray-data/url-entry-mobile.png`; these are error-state checks, not a full
  scene/performance audit.

Commands: `python scripts/verify_whatwg_url.py`,
`python -O scripts/verify_whatwg_url.py`,
`python scripts/verify_held_docker_pipe.py`, and, within `viewer`,
`npm.cmd run test -- --run` and `npm.cmd run build`.
`scripts/verify_url_entry_ui.py` uses the task-owned local preview on port 64020.

The incumbent Instrument Panorama design is unchanged. Impeccable hardening
guided input preservation, field focus and actionable inline validation copy.
Docker native recovery proof is still pending; no Docker settings, socket,
images, containers or volumes were changed by this checkpoint.
