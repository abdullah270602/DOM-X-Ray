import type {
  ChannelValues,
  ViewerEvent,
  ViewerRuntime,
  ViewerState,
} from "./types";

const zeroChannels: ChannelValues = {
  page: 0,
  structure: 0,
  weight: 0,
  origins: 0,
  finding: 0,
};

function stageForElapsed(runtime: ViewerRuntime, elapsedMs: number) {
  const index = runtime.playback.stages.findIndex(
    (stage) => elapsedMs < stage.endMs,
  );
  const stageIndex = index === -1 ? runtime.playback.stages.length - 1 : index;
  const stage = runtime.playback.stages[stageIndex];
  if (!stage) throw new Error("Viewer runtime has no playback stages.");
  return { stage, stageIndex };
}

function timelineState(
  runtime: ViewerRuntime,
  state: ViewerState,
  requestedElapsedMs: number,
  playback = state.playback,
): ViewerState {
  const elapsedMs = Math.max(
    0,
    Math.min(runtime.playback.durationMs, Math.round(requestedElapsedMs)),
  );
  const { stage, stageIndex } = stageForElapsed(runtime, elapsedMs);
  const complete = elapsedMs === runtime.playback.durationMs;
  return {
    ...state,
    elapsedMs,
    stageIndex,
    stageId: stage.id,
    phase: complete
      ? "exploring"
      : state.motion === "reduced"
        ? "stepping"
        : "revealing",
    playback: complete ? "complete" : playback,
  };
}

function commit(current: ViewerState, next: ViewerState): ViewerState {
  const comparableCurrent = { ...current, revision: 0 };
  const comparableNext = { ...next, revision: 0 };
  return JSON.stringify(comparableCurrent) === JSON.stringify(comparableNext)
    ? current
    : { ...next, revision: current.revision + 1 };
}

export function reduceViewerState(
  runtime: ViewerRuntime,
  state: ViewerState,
  event: ViewerEvent,
): ViewerState {
  let next = state;

  switch (event.type) {
    case "tick":
      if (state.motion !== "standard") throw new Error("Reduced motion rejects tick.");
      if (state.playback !== "playing") return state;
      next = timelineState(runtime, state, state.elapsedMs + event.deltaMs);
      break;
    case "seek":
      if (state.motion !== "standard") throw new Error("Reduced motion uses stage advance.");
      next = timelineState(runtime, state, event.elapsedMs, "paused");
      break;
    case "pause":
      if (state.motion !== "standard") throw new Error("Reduced motion rejects pause.");
      next = state.playback === "playing" ? { ...state, playback: "paused" } : state;
      break;
    case "play":
      if (state.motion !== "standard") throw new Error("Reduced motion rejects play.");
      if (state.elapsedMs >= runtime.playback.durationMs) {
        throw new Error("Completed reveal requires replay.");
      }
      next = { ...state, playback: "playing" };
      break;
    case "skip-reveal":
      if (state.motion !== "standard") throw new Error("Reduced motion preserves every stage.");
      next = timelineState(runtime, state, runtime.playback.durationMs);
      break;
    case "replay": {
      const source =
        state.motion === "reduced"
          ? runtime.initialStates.reducedMotion
          : runtime.initialStates.standard;
      next = { ...source };
      break;
    }
    case "advance-stage": {
      if (state.motion !== "reduced") throw new Error("Standard motion rejects stage advance.");
      const nextIndex = Math.min(
        runtime.playback.stages.length - 1,
        state.stageIndex + 1,
      );
      const stage = runtime.playback.stages[nextIndex];
      if (!stage) throw new Error("Viewer runtime has no next stage.");
      const elapsed =
        nextIndex === runtime.playback.stages.length - 1
          ? runtime.playback.durationMs
          : stage.startMs;
      next = timelineState(runtime, state, elapsed, "paused");
      break;
    }
    case "set-mode":
      next = { ...state, mode: event.mode };
      break;
    case "select": {
      if (!runtime.selectables.some((item) => item.id === event.id)) {
        throw new Error(`Unknown selectable: ${event.id}`);
      }
      next = {
        ...state,
        selectedId: event.id,
        isolatedId: state.isolatedId === event.id ? state.isolatedId : null,
      };
      break;
    }
    case "isolate-selected": {
      const selectable = runtime.selectables.find(
        (item) => item.id === state.selectedId,
      );
      if (!selectable?.renderable) {
        throw new Error("Only renderable evidence can be isolated.");
      }
      next = { ...state, isolatedId: selectable.id };
      break;
    }
    case "clear-isolation":
      next = { ...state, isolatedId: null };
      break;
    case "clear-selection":
      next = { ...state, selectedId: null, isolatedId: null };
      break;
  }

  return commit(state, next);
}

export function presentationFrame(runtime: ViewerRuntime, state: ViewerState) {
  const active = runtime.playback.stages[state.stageIndex];
  if (!active) throw new Error("Viewer state points to an absent stage.");

  if (state.motion === "reduced") {
    return {
      stageId: active.id,
      stageProgress: 1,
      channels: { ...active.targetChannels },
    };
  }

  const prior =
    state.stageIndex === 0
      ? { page: 1, structure: 0, weight: 0, origins: 0, finding: 0 }
      : runtime.playback.stages[state.stageIndex - 1]?.targetChannels;
  if (!prior) throw new Error("Viewer runtime stage order is invalid.");
  const duration = active.endMs - active.startMs;
  const stageProgress = Math.min(
    1,
    Math.max(0, (state.elapsedMs - active.startMs) / duration),
  );
  const channels = { ...zeroChannels };
  for (const name of Object.keys(channels) as Array<keyof ChannelValues>) {
    channels[name] = Number(
      (prior[name] + (active.targetChannels[name] - prior[name]) * stageProgress).toFixed(6),
    );
  }

  if (state.elapsedMs === runtime.playback.durationMs) {
    return {
      stageId: active.id,
      stageProgress: 1,
      channels: { ...active.targetChannels },
    };
  }
  return {
    stageId: active.id,
    stageProgress: Number(stageProgress.toFixed(6)),
    channels,
  };
}
