# DOM X-Ray Scene Manifest

Status: executable renderer-neutral contract `scene-manifest-v0.1.0`

The scene manifest is the only derived input a visual renderer needs. It converts an immutable scan record plus its matching mapping registry into explicit world geometry, topology, visual evidence states, reveal stages, and source references. It is not a replacement for the scan record: the record remains the source of truth and the evidence drawer resolves the manifest's JSON Pointers against it.

`scanner.scene_manifest.build_scene_manifest(record)` is the reference implementation. Clean, image-heavy, third-party-heavy, overflow, endpoint, and transfer-state controls must all pass through that same function. A WebGL renderer, a no-WebGL fallback, an export renderer, and a regression screenshot route may present the manifest differently, but none may choose different endpoints, regroup domains, recalculate mass, coerce unknown bytes to zero, or create scene objects for evidence-only nodes.

## Top-level shape

| Field | Meaning |
|---|---|
| `manifestVersion` | Version of the derived contract, currently `scene-manifest-v0.1.0` |
| `scanId`, `mappingVersion`, `status`, `failureCode` | Identity and honesty state copied from the source record |
| `frame` | Captured viewport, 12-unit world plane, scale, origin, and axis convention |
| `budget` | The exact 650-slot accounting used before rendering |
| `objects` | Ordered regions/aggregates, the logical page bus when needed, then sorted external hubs |
| `connections` | One resource path per scan-record resource, in source order |
| `hero` | The unique `hero:true` insight or `null`; only the former is share-eligible |
| `reveal`, `reducedMotion` | A copied, version-pinned playback contract |
| `limitations` | Compact limitation references; human-readable messages remain in the scan record |

Stable storage and regression fingerprints use `stable_manifest_json`, which sorts object keys and removes insignificant whitespace. List order is semantic and deterministic.

## Object identities and budget

- Every node with `sceneIncluded !== false` becomes exactly one `region:<nodeId>` object. A node with a non-null aggregation rule has kind `aggregate`; every other represented node has kind `region`.
- Evidence-only nodes do not become objects. They remain visible through aggregate membership and connection `evidenceOnlyTargetNodeIds`.
- A logical `bus:page` exists exactly when at least one resource path names it as a source, target, or evidence-only fallback. It is a connection anchor and does not consume an aggregation slot.
- Every unique third-party registrable domain becomes exactly one `hub:<domain>` object. Hubs consume aggregation slots.
- `budget.countedObjectCount` is therefore `regionCount + hubCount`; it must not exceed the registry limit. Runtime instrumentation separately reports actual Three.js objects and draw calls because instancing/batching is an implementation property, not scan evidence.

Parent links use the nearest scene-included ancestor. Geometry is clipped to the captured viewport and mapped exactly once. A region's final z position is structural separation plus its stacking-context seam.

## Resource endpoint matrix

| Party | Attribution | Source | Target |
|---|---|---|---|
| first or unknown | exact | Page bus | Every represented exact region |
| third | exact | Registrable-domain hub | Every represented exact region |
| first or unknown | probable, page-level, or unknown | Page bus | Page bus |
| third | probable, page-level, or unknown | Registrable-domain hub | Page bus |

If an exact target is evidence-only, the manifest keeps its node ID and names `bus:page` as a display fallback. This is a visual routing fallback, not a change from exact attribution. The inspector must say that the exact region is outside the bounded scene overview.

One connection is one logical resource even when exact attribution names several target regions. A renderer may draw a branched path, but the branches must not be counted or labelled as repeated transfers.

## Weight and transfer states

Region mass sums only known bytes from exactly attributed linked resources. Unknown exact resources become separate marker entries with their own cache/worker/unknown state and never contribute zero; a resource-targeted limitation that invalidates `resource_mass` suppresses that resource's derived plate and cable mass regardless of its code. Targeted blocked resources become broken-outline markers. Probable links may be inspectable from a node but never become region mass.

A scan-level limitation invalidates completeness and dependent aggregate/hero claims; it does not erase a different resource's still-valid observed byte value. This preserves the truth contract's rule that a partial scan retains valid observed data. The manifest carries that scan limitation at the top level so the renderer cannot present the surviving measurements as a complete load.

Each resource path retains three independent facts:

- `transferSource`: network, cache, service-worker, or unknown.
- `outcome`: HTTP response, explicitly no completed response, policy/limit block, or not recorded by an older fixture.
- `measurement.transferredBytes`: an integer including measured zero, or `null` for unknown.

The resulting redundant styles are solid known mass, cache hollow, worker-stamped hollow, measured-zero hollow, unknown hatch, or broken outline. A delivered HTTP error remains an HTTP response—its observed wire bytes are not discarded merely because the status is 4xx/5xx. A targeted scanner block uses a broken outline and no derived mass.

## Renderer obligations

The renderer may choose meshes, instancing, labels, camera easing, and responsive composition inside the approved viewer contract. It must treat IDs, coordinates, z values, endpoints, byte-derived mass/thickness, hub order/angles, stage intervals, hero evidence, and limitation references as immutable. Every selectable visual resolves to its manifest evidence refs and from there to the source record. No visual label may turn “third party” into “tracker,” DOM depth into speed, or unknown transfer into zero.
