# ADR-001: Application Stack and Runtime Split

Status: **proposed — explicit user approval required before scaffolding**

Date: 2026-09-06

## Decision to approve

Build DOM X-Ray as two deliberately separate runtimes:

1. A static viewer application using **React, TypeScript, Vite, Three.js, and React Three Fiber**.
2. A separately deployed, containerized scanner service built around the existing Python controlled Playwright/Chromium probe.

The Gate 1 implementation is local and fixture-driven. Choosing a commercial hosting vendor is not required to build or validate it; the deployment target at this stage is an architectural target: static assets for the viewer and an isolated container runtime for scanning.

## Why this fits the product

- The viewer has substantial ordinary interface state—URL submission, result status, modes, evidence, fallback content, share controls—and a single schema-driven 3D stage. React can own the accessible shell while React Three Fiber expresses the Three.js scene in the same component and state model.
- Vite builds the viewer to a static `dist` directory, keeping the public result surface portable across static hosts and allowing Gate 1 to stay independent of production scanner infrastructure.
- React Three Fiber is a renderer for Three.js rather than a replacement for it. The implementation can use Three.js materials, geometry, instancing, raycasting, and performance instrumentation directly.
- The scene moves during the five-second reveal and direct manipulation, then becomes mostly still. On-demand rendering after motion settles avoids running a permanent animation loop for an idle inspection table.
- The existing scanner loads untrusted public URLs. Keeping it outside the viewer process preserves the network-policy, browser-sandbox, rate-limit, timeout, and resource-boundary work already expressed in the truth contract and threat model.

## Proposed repository shape

```text
viewer/
  src/
    app/                 accessible application shell and routes
    scene/               R3F scene components; no scan-specific claims
    domain/              pure ScanRecord → SceneModel transformation
    fixtures/            fixture loading adapters, not fixture-specific UI
    styles/              tokens and layout matching the approved comp
  public/
  index.html
  package.json
  vite.config.ts
scanner/                 existing controlled scanner code
docs/                    truth, mapping, viewer, and decision contracts
fixtures/                shared deterministic source records and pages
```

The viewer imports or copies validated fixture records through an explicit build step; it does not reach across directories with runtime filesystem assumptions.

## Frontend boundaries

- TypeScript runs in strict mode.
- A pure, deterministic `ScanRecord → SceneModel` mapper is the only path from captured evidence to renderable objects.
- The React shell owns URL entry, statuses, hero text, evidence, modes, sharing, keyboard/touch alternatives, reduced motion, and the no-WebGL path.
- React Three Fiber owns the canvas, camera, lights, geometry, material states, selection raycasting, and scene instrumentation.
- Three.js objects are not stored in application state. Per-frame updates do not set React state.
- `@react-three/drei` is not a default dependency. Add a narrowly selected helper only when it removes verified complexity without changing the visual contract.
- No global state library is introduced for Gate 1. React state plus small typed domain stores are sufficient until evidence proves otherwise.
- The reveal timeline is a deterministic function of scan record, mapping version, elapsed time, motion preference, and explicit user input. It does not depend on incidental component mount timing.
- After the reveal and camera interaction settle, render on demand rather than continuously.

## Scanner boundary

- The viewer never navigates a submitted URL in the visitor's browser and never receives privileged scanner credentials.
- The scanner remains a separate network service with isolated browser contexts, destination validation, redirect revalidation, egress enforcement, and hard resource limits.
- Development and deployment must pin compatible Playwright package, browser, and container versions together.
- Production scanning of untrusted sites must not run as root with the browser sandbox disabled. The container and host require a reviewed non-root user, seccomp/user-namespace configuration, process limits, and network egress policy.
- Gate 1 uses only checked-in deterministic fixtures. Public scanning is not enabled by scaffolding the viewer.
- The existing scanner remains Python during Gate 1; this decision does not authorize a scanner rewrite.
- Request-count and transferred-byte semantics are proven only in the deterministic local egress proxy; production integration, whole-worker containment, and browser-process deadlines remain unresolved release gates recorded in `ROADMAP.md` and `docs/GATE_0_EVIDENCE.md`. A local fixture viewer does not satisfy or bypass them.

## Deployment target

The approved architectural target is:

```text
browser → static viewer/result assets
        → narrow scan API → queue/worker → isolated Chromium container
                           → immutable versioned scan record + sanitized capture
```

The first implementation does not choose a cloud vendor or create production infrastructure. Vendor selection waits for the Gate 3 requirements: controlled egress, public-DNS revalidation, browser isolation, durable rate enforcement, immutable storage, deletion policy, regional constraints, and measured cost.

## Alternatives considered

### Vanilla TypeScript + Three.js

This removes the React renderer but makes the accessible shell, evidence synchronization, responsive states, and canvas/UI lifecycle more manual. It remains a fallback if measured React/R3F overhead prevents the Gate 1 frame budget; it is not the recommended starting point.

### A full-stack React framework

Server rendering does not materially improve the fixture-driven interactive viewer, and coupling page routes to a server runtime invites accidental scanner co-location. A full-stack framework can be reconsidered if stable result metadata, social previews, or authenticated administration later require it.

### One viewer-and-scanner process

Rejected. A public static UI and a browser process visiting untrusted pages have different security, scaling, and failure boundaries.

## Evidence for the proposal

- [React Three Fiber introduction](https://r3f.docs.pmnd.rs/getting-started/introduction)
- [React Three Fiber scaling and on-demand rendering](https://r3f.docs.pmnd.rs/advanced/scaling-performance)
- [Vite production build](https://vite.dev/guide/build)
- [Vite static deployment](https://vite.dev/guide/static-deploy)
- [Playwright Docker guidance for untrusted browsing](https://playwright.dev/docs/docker)

## Consequences after approval

The next commit may scaffold only the local fixture-driven viewer. It must include the direction contract as the first `<body>` comment, strict TypeScript, fixture validation at the boundary, a pure scene mapper, and the approved Instrument Panorama shell. Scanner API integration, public submission, persistence, and production deployment remain later gated work.
