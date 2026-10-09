# Smaller browser validators without removing admission checks

This Gate 1/3 performance checkpoint follows Impeccable's measure-first guidance
while preserving the approved Instrument Panorama UI, copy, controls and styles.
It does not prove real-device Core Web Vitals, renderer performance or the public
submit-to-share latency target.

Source-map inspection identified generated browser validators as the largest
individual source in the main entry bundle: 790,710 source characters before the
change. The renderer's largest sources remain Three.js/React Three Fiber. The
icon import graph was inspected, but no icon changes were made: it was not the
largest measured main-entry source.

`viewer/scripts/sync-fixtures.mjs` now sets `inlineRefs: false` when generating
standalone AJV validators. [AJV's documented option](https://ajv.js.org/options.html#inlinerefs)
compiles referenced schemas separately rather than inlining them. Schema files,
strictness, formats and `allErrors: true` are unchanged; no admission checks were
removed or deferred. Generated source is rebuilt through the existing fixture
sync step and remains ignored, not a hand-edited artifact.

## Production build observations on 2026-10-09

| Build-reported JavaScript size | Before | After |
| --- | ---: | ---: |
| Main entry, minified | 983.80 KB | 925.08 KB |
| Main entry, gzip | 167.03 KB | 164.66 KB |
| Lazy Three.js scene, minified | 909.67 KB | 909.67 KB |

The main entry is about 6% smaller before transfer compression; the compressed
reduction is about 1.4%. These are build size observations, not measured network
load times. Large-chunk warnings remain visible. The scene chunk is unchanged in
size and no warning threshold was increased to conceal the remaining work.

## Verification

`npm.cmd run verify:validators` (within `viewer`) regenerates the current
validators and compares them to the former inline-reference AJV configuration.
469 selected fixture/mutation cases agree on acceptance and normalized
`instancePath`, `keyword`, `message` and `params` errors. Error order and
`schemaPath` are intentionally excluded; the existing UI error formatter uses
instance paths and messages. The corpus covers all six exported validators,
three seeded profiles, top-level missing/type/extra-property faults, nested
bundle faults and selected invalid job shapes. It is not exhaustive schema
equivalence proof.

All 73 frontend tests and the production TypeScript/Vite build pass. One bounded
desktop/mobile production-preview inspection (1280×900, 390×844) confirmed the
existing URL-entry error presentation, focused/preserved input and no horizontal
overflow. Screenshots remain local ignored evidence under `.dom-xray-data`.
This text-fallback inspection is not a full WebGL interaction or device benchmark.
Smaller-model review found no concrete option/harness correctness issue within
the selected scope.

The task-owned production preview is `http://127.0.0.1:64021/`.
`python scripts/verify_url_entry_ui.py --base-url http://127.0.0.1:64021` uses it;
the script retains port 64020 as its existing default. No public hosting/cache
settings, scanner restrictions or Docker resources changed.
