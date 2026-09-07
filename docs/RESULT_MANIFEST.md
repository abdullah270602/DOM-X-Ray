# DOM X-Ray Result Manifest

Status: prototype contract v0.1

## Purpose

`result-manifest-v0.1.0` is the immutable handoff shared by the public result
route, poster renderer, and video renderer. It binds a product-owned opaque
result path to one scan record, mapping registry, scene manifest, hero claim,
limitation set, and pair of bounded export targets.

It does not replace the scan record or scene manifest. The scan remains the
measurement source of truth; the scene remains the sole geometry/topology input;
the result manifest prevents the link and export surfaces from silently choosing
different inputs or copy.

## Identity and integrity

Every manifest contains canonical SHA-256 hashes of:

- the complete normalized scan record;
- the exact renderer-neutral scene manifest;
- the mapping registry used to derive that scene;
- the complete result hero binding, including its numeric evidence and
  limitations, or canonical JSON `null` when no hero exists;
- the result ID and fixed `/r/{resultId}` path together with the versioned source
  identities above.

Poster and video targets repeat the result-binding, scene, and hero hashes. If
artifact bytes are registered, their exact byte length and SHA-256 hash are
computed by the builder. Changing a claim, evidence value, limitation, geometry
input, mapping rule, result route, or artifact payload changes or invalidates the
binding.

The source hashes use canonical UTF-8 JSON with sorted object keys and compact
separators. They are integrity identifiers, not signatures or authentication.

## Share eligibility

- A complete or honestly partial scan with the single share-eligible hero is
  `artifact-eligible`.
- A complete or partial scan without a defensible hero is `link-only`; poster and
  video targets are `ineligible`. A neutral summary never becomes a superlative.
- Interstitial, blocked, and failed results are `unavailable` for export and
  cannot carry a hero.
- A partial eligible result must include the product-owned `PARTIAL CAPTURE`
  label, the `partial-status` layer, every scan limitation, and every limitation
  attached to the hero. The `limitation-disclosure` layer is also mandatory and
  receives the exact product-authored limitation message from the scan record.

The builder accepts only a scan record that has already passed the scan schema
and semantic validator. It additionally rejects a hero whose limitations do not
exactly match the record, whose selection rule is disabled, or whose evidence is
invalidated. The manifest copies the hero statement, primary/support values,
units, attribution levels, source pointers, mapping rule, selection rule, and
limitation codes from the immutable scan. It does not generate captions or
target-page copy.

## Public route

Result IDs have the form `r_` plus 128 bits represented as 32 lowercase hex
characters. Production must generate them with a cryptographically secure random
source. The committed fixture IDs are fixed test vectors, not evidence of runtime
randomness.

The only public path is `/r/{resultId}`. The strict field allowlist has no place
for a deletion token, original query/fragment, target resource URL, selector,
page title, target HTML, script, font, SVG, or live asset reference. Copied public
strings reject control characters and angle brackets; the future renderer must
still render every string as inert text rather than HTML. The page identity is
the bounded registrable-domain label plus its scan-record pointer. A future
no-login deletion capability must be separately generated and must never enter
this manifest or public route.

## Export targets

Both targets are square 1080 × 1080 outputs with an 8 MB envelope:

- poster: `image/png`, no duration;
- video: `video/mp4`, exactly 5000 ms, matching the authored reveal duration.

Required layers are product-owned and explicit. An eligible artifact includes
page identity, the bound scene, the exact hero fact, DOM X-Ray identity, and the
new-scan CTA. A partial artifact additionally includes `partial-status` and
`limitation-disclosure`.

Byte registration proves only hash, size, and source-manifest association. It
does not inspect the media container, decode pixels, prove H.264 compatibility,
or prove that rendered pixels match the claim. Those require the selected
renderer/encoder, golden visual comparison, and current X upload/recompression
testing before Gate 5 can pass.

## Deterministic fixtures

Three committed manifests are generated from the shared scan fixtures:

- `fixtures/result-manifest/clean.json` — no hero, stable link only;
- `fixtures/result-manifest/image-heavy.json` — complete, artifact-eligible;
- `fixtures/result-manifest/third-party-heavy.json` — partial,
  artifact-eligible with its limitation and visible partial layer.

Regenerate or check them with:

```sh
python scripts/export_result_fixtures.py
python scripts/export_result_fixtures.py --check
python scripts/verify_result_manifest.py
```

The verifier validates the Draft 2020-12 schema, byte-compares every golden,
resolves all evidence pointers, recomputes all source bindings, checks that target
URLs/titles/selectors do not leak, covers a partial result with no hero, exercises
ready byte envelopes, and rejects scene/mapping/ID/artifact, unsafe-text,
invalidated-hero, route-identity, schema, and cross-source tampering.

## Deferred production proof

This contract does not provide storage, route availability, deletion, retention,
publication/privacy state, moderation, takedown, Open Graph delivery, rendering,
encoding, or social-platform compatibility. It does not authorize a public launch
or settle any open product/legal policy. Those remain explicit roadmap gates.
