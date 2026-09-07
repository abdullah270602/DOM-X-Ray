import {
  ArrowCounterClockwise,
  ArrowsOutLineHorizontal,
  Cube,
  FlowArrow,
  Pause,
  Play,
  Stack,
} from "@phosphor-icons/react";
import type {
  ModeId,
  ViewerEvent,
  ViewerRuntime,
  ViewerState,
} from "../domain/types";

const modeIcons = {
  structure: Stack,
  weight: Cube,
  origins: FlowArrow,
};

export function InstrumentRail({
  runtime,
  state,
  send,
}: {
  runtime: ViewerRuntime;
  state: ViewerState;
  send: (event: ViewerEvent) => void;
}) {
  const progress = Math.round((state.elapsedMs / runtime.playback.durationMs) * 100);
  return (
    <nav className="instrument-rail" aria-label="Viewer controls">
      <div className="mode-controls" aria-label="Inspection mode">
        {runtime.modes.map((mode) => {
          const Icon = modeIcons[mode.id];
          return (
            <button
              key={mode.id}
              type="button"
              className={state.mode === mode.id ? "is-active" : ""}
              aria-pressed={state.mode === mode.id}
              onClick={() => send({ type: "set-mode", mode: mode.id as ModeId })}
            >
              <Icon size={18} weight="regular" aria-hidden="true" />
              {mode.label}
            </button>
          );
        })}
      </div>

      <div className="playback-controls">
        <button type="button" onClick={() => send({ type: "replay" })}>
          <ArrowCounterClockwise size={19} weight="bold" aria-hidden="true" />
          REPLAY
        </button>
        {state.motion === "reduced" ? (
          <button
            type="button"
            onClick={() => send({ type: "advance-stage" })}
            disabled={state.playback === "complete"}
          >
            NEXT STAGE
          </button>
        ) : (
          <button
            className="play-pause"
            type="button"
            onClick={() =>
              send({
                type: state.playback === "playing" ? "pause" : "play",
              })
            }
            disabled={state.playback === "complete"}
            aria-label={state.playback === "playing" ? "Pause reveal" : "Play reveal"}
          >
            {state.playback === "playing" ? (
              <Pause size={18} weight="fill" aria-hidden="true" />
            ) : (
              <Play size={18} weight="fill" aria-hidden="true" />
            )}
          </button>
        )}
      </div>

      <label className="timeline-control">
        <span>{state.stageId.toUpperCase()}</span>
        <input
          type="range"
          min="0"
          max={runtime.playback.durationMs}
          step="50"
          value={state.elapsedMs}
          disabled={state.motion === "reduced"}
          onChange={(event) =>
            send({ type: "seek", elapsedMs: Number(event.currentTarget.value) })
          }
          aria-label={`Reveal timeline, ${progress} percent`}
        />
        <output>{progress}%</output>
      </label>

      <div className="orbit-instruction" aria-hidden="true">
        <ArrowsOutLineHorizontal className="orbit-mark" size={21} />
        DRAG TO INSPECT DEPTH
      </div>
    </nav>
  );
}
