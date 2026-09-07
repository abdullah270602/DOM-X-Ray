# DOM X-Ray Viewer Runtime

Status: executable renderer-neutral contract `viewer-runtime-v0.1.0`

## Purpose

The viewer runtime is the behavioral handoff between the immutable scan/scene/result
contracts and every eventual presentation path. It does not render pixels and does
not choose React, Three.js, a camera library, or an encoder. It fixes the product
behavior those implementations must share: the five-stage reveal, replay and scrub,
Structure/Weight/Origins modes, selection and isolation, reduced-motion steps,
fallback text, partial-state disclosure, and evidence lookup.

`scanner.viewer_runtime.build_viewer_runtime()` accepts an already admitted scan
record and its exact scene and result manifests. It rebuilds and byte-compares the
scene, validates the result/source/route binding, and then produces one serializable
model conforming to `VIEWER_RUNTIME.schema.json`. A ready poster or video may add
valid bounded artifact metadata, but it cannot change the bound scan, scene, hero,
route, or export eligibility.

## Boundary

The runtime consumes, but never recalculates:

- scene object membership, geometry, parentage, topology, mass, transfer state,
  object budget, and hero identity from `scene-manifest-v0.1.0`;
- public page identity, exact hero copy, honest status, limitation disclosure,
  share eligibility, and result identity from `result-manifest-v0.1.0`;
- mapping formulas and rule values from `mapping-v0.1.0`;
- raw measurement and provenance values from the immutable scan record.

The runtime includes cryptographic hashes for all four inputs. It carries only
product-authored labels, the bounded page identity, the exact bound finding, and
local JSON Pointers. It does not copy page titles, selectors, or resource URLs into
the persistent runtime model. Those sanitized scan fields remain available only
when a visitor deliberately opens an evidence dossier.

## Shared access paths

The same ordered `selectables` and source pointers serve three paths:

1. `webgl` — a scene renderer plus the accessible shell;
2. `reduced-motion` — user-advanced stage snapshots with no camera or continuous
   geometry motion;
3. `text` — the no-WebGL evidence and finding presentation.

No fallback may invent a separate summary, hide limitations, or resolve evidence
from different inputs. An evidence-only node is selectable in the reduced-motion
and text paths but has `renderable: false` and can never become a 3D object or an
isolation target.

## Reveal channels

The authored duration remains exactly 5000 ms. Each stage has a deterministic
start/end boundary and an end-state over five normalized channels:

| Stage | Page | Structure | Weight | Origins | Finding |
|---|---:|---:|---:|---:|---:|
| Flat | 1 | 0 | 0 | 0 | 0 |
| Structure | 1 | 1 | 0 | 0 | 0 |
| Weight | 1 | 1 | 1 | 0 | 0 |
| Party | 1 | 1 | 1 | 1 | 0 |
| Hero | 1 | 1 | 1 | 1 | 1 |

For ordinary motion, `presentation_frame()` linearly exposes only the active
channel between the source manifest's stage boundaries. This normalized progress
does not prescribe easing. In reduced-motion mode, each user advance displays the
complete stage snapshot; there is no in-between geometry or camera motion.

Camera pose, easing, lighting, and material interpolation remain renderer-owned.
They may make the reveal beautiful, but they cannot change stage order, channel
meaning, endpoints, measurements, or evidence.

## Modes and interaction reducer

The modes are exactly `structure`, `weight`, and `origins`. A mode changes emphasis
only. The model explicitly preserves object membership, geometry, measurements,
and endpoints across every mode.

`reduce_viewer_state(model, state, event)` is a pure reducer. It performs no scan,
navigation, fetch, storage, or renderer action. Accepted events are:

- `tick { deltaMs }`, `seek { elapsedMs }`, `pause`, `play`, and `skip-reveal` for
  the standard timeline; reduced motion deliberately rejects `skip-reveal` so its
  five user-advanced stages cannot be bypassed;
- `advance-stage` for reduced motion;
- `replay`, which resets the authored timeline, mode, selection, and isolation but
  never rescans;
- `set-mode { mode }`;
- `select { id }`, `isolate-selected`, `clear-isolation`, and `clear-selection`.

Unknown events, IDs, modes, invalid fields, internally inconsistent stage/time or
selection/isolation state, reduced-motion ticks, and attempts to isolate
non-renderable evidence fail closed. Replay from the same state produces the same
next state. State is plain JSON and never contains a Three.js object.

## Evidence dossiers

Every selectable has explicit scene, record, mapping, result, and limitation
pointers. `resolve_selection()` resolves them into a dossier and rejects an absent,
out-of-range, or malformed pointer. Selectables cover:

- every scene region, aggregate, page bus, external hub, and resource path;
- every evidence-only node retained outside the bounded scene;
- the primary hero or neutral capture summary;
- capture status and limitation disclosure.

This is the common source model for pointer, keyboard, touch, reduced-motion, and
text-only inspection. A frontend may format the values, but it may not replace a
raw value, downgrade an unknown to zero, or omit its attribution/mapping source.

## Deterministic evidence

Three committed runtime models are generated from the shared clean, image-heavy,
and third-party-heavy fixtures:

```sh
python scripts/export_viewer_runtime_fixtures.py
python scripts/export_viewer_runtime_fixtures.py --check
python scripts/verify_viewer_runtime.py
```

The verifier checks the schema and byte-identical goldens; resolves every dossier;
proves the runtime model does not contain page titles, resource URLs, or meaningful
selectors; exercises exact hero, neutral, partial, interstitial, evidence-only,
cache, service-worker, unknown, and blocked states; and verifies deterministic
scrub, replay, modes, selection, isolation, and reduced-motion stages. Tampered
source bindings, zero-coerced unknowns, unresolved pointers, fallback evidence
splits, invalid reducer events, and schema drift fail closed.

## Deferred implementation proof

This contract is not the interactive viewer. It provides no HTML, WebGL rendering,
keyboard focus management, touch controls, camera bounds, responsive layout,
visual regression image, frame-time data, or user-comprehension evidence. Those
remain Gate 1 implementation and evaluation work after the application stack is
approved.
