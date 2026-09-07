import { describe, expect, it } from "vitest";
import { dossierFor } from "./pointer";
import { fixtures, fixtureNames } from "./fixtures";
import { presentationFrame, reduceViewerState } from "./runtime";

describe("fixture boundary", () => {
  it("admits all committed fixtures with one data path", () => {
    for (const name of fixtureNames) {
      const bundle = fixtures[name];
      expect(bundle.runtime.scanId).toBe(bundle.scene.scanId);
      expect(bundle.scene.budget.countedObjectCount).toBeLessThanOrEqual(650);
      expect(bundle.scene.objects.map((item) => item.id)).not.toContain(
        expect.stringMatching(/^evidence:/),
      );
    }
  });

  it("resolves renderable and text-only evidence through the same pointers", () => {
    const image = fixtures["image-heavy"];
    const region = dossierFor(image, "region:n-hero");
    const finding = dossierFor(image, "finding:primary");
    expect(region.rows.some((row) => row.ref === "#/nodes/2")).toBe(true);
    expect(finding.rows.some((row) => row.namespace === "result")).toBe(true);
  });
});

describe("deterministic runtime", () => {
  const runtime = fixtures["image-heavy"].runtime;

  it("matches stage boundaries and interpolation", () => {
    let state = runtime.initialStates.standard;
    state = reduceViewerState(runtime, state, { type: "tick", deltaMs: 700 });
    expect(state.stageId).toBe("structure");
    state = reduceViewerState(runtime, state, { type: "tick", deltaMs: 500 });
    expect(presentationFrame(runtime, state).channels.structure).toBe(0.5);
    state = reduceViewerState(runtime, state, { type: "seek", elapsedMs: 4600 });
    expect(presentationFrame(runtime, state).channels.finding).toBe(0.5);
    state = reduceViewerState(runtime, state, { type: "seek", elapsedMs: 5000 });
    expect(presentationFrame(runtime, state).channels.finding).toBe(1);
  });

  it("replays from the authored beginning", () => {
    let state = reduceViewerState(runtime, runtime.initialStates.standard, {
      type: "seek",
      elapsedMs: 5000,
    });
    state = reduceViewerState(runtime, state, { type: "set-mode", mode: "weight" });
    state = reduceViewerState(runtime, state, { type: "select", id: "region:n-hero" });
    state = reduceViewerState(runtime, state, { type: "replay" });
    expect(state).toMatchObject({
      elapsedMs: 0,
      stageId: "flat",
      mode: "structure",
      selectedId: null,
      isolatedId: null,
    });
  });

  it("preserves five explicit reduced-motion steps", () => {
    let state = runtime.initialStates.reducedMotion;
    const stages = [state.stageId];
    for (let index = 0; index < 4; index += 1) {
      state = reduceViewerState(runtime, state, { type: "advance-stage" });
      stages.push(state.stageId);
    }
    expect(stages).toEqual(["flat", "structure", "weight", "party", "hero"]);
    expect(state.playback).toBe("complete");
    expect(() =>
      reduceViewerState(runtime, runtime.initialStates.reducedMotion, {
        type: "tick",
        deltaMs: 16,
      }),
    ).toThrow();
  });
});
