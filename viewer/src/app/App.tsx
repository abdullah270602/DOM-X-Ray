import {
  ArrowRight,
  Check,
  Copy,
  Crosshair,
  GlobeSimple,
  ListMagnifyingGlass,
  Warning,
} from "@phosphor-icons/react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { dossierFor } from "../domain/pointer";
import { fixtureFromUrl, fixtureNames, fixtures } from "../domain/fixtures";
import { presentationFrame, reduceViewerState } from "../domain/runtime";
import type {
  FixtureName,
  ViewerEvent,
  ViewerRuntime,
  ViewerState,
} from "../domain/types";
import type { ScenePerformance } from "../scene/InstrumentScene";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { InstrumentRail } from "./InstrumentRail";
import { TextScene } from "./TextScene";

const InstrumentScene = lazy(async () => {
  const module = await import("../scene/InstrumentScene");
  return { default: module.InstrumentScene };
});

function initialFixture(): FixtureName {
  const value = new URLSearchParams(window.location.search).get("fixture");
  return fixtureNames.includes(value as FixtureName) ? (value as FixtureName) : "image-heavy";
}

function prefersReducedMotion() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("motion") === "reduced") return true;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function initialViewerState(runtime: ViewerRuntime, reduced: boolean) {
  const params = new URLSearchParams(window.location.search);
  let state = reduced
    ? runtime.initialStates.reducedMotion
    : runtime.initialStates.standard;
  if (!reduced) {
    const requestedTime = Number(params.get("time"));
    if (Number.isFinite(requestedTime) && requestedTime > 0) {
      state = reduceViewerState(runtime, state, {
        type: "seek",
        elapsedMs: requestedTime,
      });
    }
  }
  const mode = params.get("mode");
  if (mode === "structure" || mode === "weight" || mode === "origins") {
    state = reduceViewerState(runtime, state, { type: "set-mode", mode });
  }
  return state;
}

export function supportsWebGL() {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") || canvas.getContext("webgl"));
  } catch {
    return false;
  }
}

const emptyPerformance: ScenePerformance = {
  frameMs: null,
  fps: null,
  drawCalls: 0,
  triangles: 0,
};

export function App() {
  const [fixtureName, setFixtureName] = useState<FixtureName>(initialFixture);
  const bundle = fixtures[fixtureName];
  const reduced = useMemo(prefersReducedMotion, []);
  const [state, setState] = useState<ViewerState>(() =>
    initialViewerState(bundle.runtime, reduced),
  );
  const [url, setUrl] = useState(bundle.record.requestedUrl);
  const [fieldError, setFieldError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [performance, setPerformance] = useState<ScenePerformance>(emptyPerformance);
  const [showTextScene, setShowTextScene] = useState(
    () => new URLSearchParams(window.location.search).get("fallback") === "text" || !supportsWebGL(),
  );
  const inputRef = useRef<HTMLInputElement>(null);
  const loadTimer = useRef<number | null>(null);

  const send = useCallback(
    (event: ViewerEvent) => {
      setState((current) => reduceViewerState(bundle.runtime, current, event));
    },
    [bundle.runtime],
  );

  useEffect(() => {
    if (state.motion !== "standard" || state.playback !== "playing") return undefined;
    let previous = window.performance.now();
    const interval = window.setInterval(() => {
      const current = window.performance.now();
      const deltaMs = Math.max(0, Math.round(current - previous));
      previous = current;
      send({ type: "tick", deltaMs });
    }, 50);
    return () => window.clearInterval(interval);
  }, [send, state.motion, state.playback]);

  useEffect(
    () => () => {
      if (loadTimer.current !== null) window.clearTimeout(loadTimer.current);
    },
    [],
  );

  const frame = presentationFrame(bundle.runtime, state);
  const dossier = useMemo(
    () => (state.selectedId ? dossierFor(bundle, state.selectedId) : null),
    [bundle, state.selectedId],
  );
  const findingId = bundle.runtime.selectables.find((item) =>
    ["hero-finding", "neutral-summary"].includes(item.kind),
  )?.id;

  function loadFixture(nextName: FixtureName, nextUrl = fixtures[nextName].record.requestedUrl) {
    const nextBundle = fixtures[nextName];
    setFixtureName(nextName);
    setUrl(nextUrl);
    setState(initialViewerState(nextBundle.runtime, reduced));
    setPerformance(emptyPerformance);
    setFieldError("");
    const params = new URLSearchParams(window.location.search);
    params.set("fixture", nextName);
    window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    let parsed: URL;
    try {
      parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error("Unsupported protocol");
    } catch {
      setFieldError("Enter a complete public HTTP or HTTPS URL.");
      inputRef.current?.focus();
      return;
    }
    setFieldError("");
    setLoading(true);
    if (loadTimer.current !== null) window.clearTimeout(loadTimer.current);
    loadTimer.current = window.setTimeout(() => {
      loadFixture(fixtureFromUrl(parsed.href), parsed.href);
      setLoading(false);
    }, 650);
  }

  async function copyFinding() {
    const text = `${bundle.runtime.presentation.finding.statement}\n\nDOM X-Ray local proof: ${bundle.runtime.resultPath}`;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  return (
    <main className="app-shell">
      <section className="instrument-column" aria-labelledby="product-title">
        <header className="brand-lockup">
          <h1 id="product-title">
            <span>DOM</span>
            <span>X-RAY</span>
          </h1>
        </header>

        <form className="scan-form" onSubmit={submit} noValidate>
          <label htmlFor="scan-url">PUBLIC PAGE URL</label>
          <div className={fieldError ? "url-field has-error" : "url-field"}>
            <input
              ref={inputRef}
              id="scan-url"
              name="url"
              type="url"
              inputMode="url"
              value={url}
              onChange={(event) => setUrl(event.currentTarget.value)}
              aria-describedby="scan-help scan-error"
              aria-invalid={Boolean(fieldError)}
              disabled={loading}
            />
            <GlobeSimple size={22} weight="regular" aria-hidden="true" />
          </div>
          <p id="scan-help">Local fixture proof. No live website is fetched yet.</p>
          {fieldError && (
            <p id="scan-error" className="field-error" role="alert">
              <Warning size={16} weight="fill" aria-hidden="true" />
              {fieldError}
            </p>
          )}
          <button className="xray-button" type="submit" disabled={loading}>
            {loading ? "PREPARING CUTAWAY" : "X-RAY DEMO"}
            {!loading && <ArrowRight size={22} weight="bold" aria-hidden="true" />}
          </button>
        </form>

        <div className="fixture-switcher">
          <label htmlFor="fixture">DEMO RECORD</label>
          <select
            id="fixture"
            value={fixtureName}
            onChange={(event) => loadFixture(event.currentTarget.value as FixtureName)}
          >
            <option value="clean">Clean page</option>
            <option value="image-heavy">Image-heavy page</option>
            <option value="third-party-heavy">Third-party-heavy page</option>
          </select>
        </div>

        <article className="finding-block" aria-live="polite">
          <div className="capture-status">
            <span className={`status-mark status-${bundle.runtime.presentation.status}`} />
            {bundle.runtime.presentation.statusLabel}
          </div>
          <div className="finding-symbol" aria-hidden="true">
            <Crosshair size={30} weight="regular" />
          </div>
          <p>{bundle.runtime.presentation.finding.statement}</p>
          <button
            className="evidence-button"
            type="button"
            disabled={!findingId}
            onClick={() => findingId && send({ type: "select", id: findingId })}
          >
            VIEW EVIDENCE
            <ArrowRight size={19} weight="bold" aria-hidden="true" />
          </button>
          {bundle.runtime.presentation.finding.shareEligible && (
            <button className="copy-button" type="button" onClick={copyFinding}>
              {copied ? <Check size={18} weight="bold" /> : <Copy size={18} />}
              {copied ? "COPIED" : "COPY FINDING"}
            </button>
          )}
        </article>

        <dl className="capture-plate">
          <div>
            <dt>CAPTURED</dt>
            <dd>{new Date(bundle.record.capturedAt).toLocaleDateString("en-US")}</dd>
          </div>
          <div>
            <dt>URL</dt>
            <dd>{bundle.runtime.presentation.pageLabel}</dd>
          </div>
          <div>
            <dt>METHOD</dt>
            <dd>NAVIGATION</dd>
          </div>
          <div>
            <dt>BY</dt>
            <dd>DOM X-RAY 0.1</dd>
          </div>
        </dl>
      </section>

      <section className="model-stage" aria-label="Interactive document object model cutaway">
        <div className="stage-heading">
          <div>
            <span>{bundle.runtime.presentation.pageLabel}</span>
            <strong>{state.stageId.toUpperCase()}</strong>
          </div>
          <button
            className="text-toggle"
            type="button"
            aria-pressed={showTextScene}
            onClick={() => setShowTextScene((value) => !value)}
          >
            <ListMagnifyingGlass size={18} aria-hidden="true" />
            {showTextScene ? "SHOW 3D MODEL" : "OBJECT INDEX"}
          </button>
        </div>

        <div className="stage-canvas">
          {showTextScene ? (
            <TextScene
              bundle={bundle}
              selectedId={state.selectedId}
              onSelect={(id) => send({ type: "select", id })}
            />
          ) : (
            <Suspense
              fallback={
                <div className="stage-loading" role="status">
                  CALIBRATING OPTICS
                </div>
              }
            >
              <InstrumentScene
                key={bundle.name}
                manifest={bundle.scene}
                channels={frame.channels}
                mode={state.mode}
                selectedId={state.selectedId}
                isolatedId={state.isolatedId}
                playing={state.playback === "playing"}
                onSelect={(id) => send({ type: "select", id })}
                onPerformance={setPerformance}
              />
            </Suspense>
          )}
        </div>

        <div className="model-caption">
          <span>DOCUMENT OBJECT MODEL</span>
          <strong>CROSS-SECTIONAL VIEW</strong>
        </div>
        <dl className="performance-plate" aria-label="Scene performance evidence">
          <div><dt>OBJECTS</dt><dd>{bundle.scene.budget.countedObjectCount}/{bundle.scene.budget.limit}</dd></div>
          <div><dt>DRAW</dt><dd>{performance.drawCalls || "MEASURING"}</dd></div>
          <div><dt>FRAME</dt><dd>{performance.frameMs === null ? "MEASURING" : `${performance.frameMs} MS`}</dd></div>
          <div><dt>FPS</dt><dd>{performance.fps ?? "MEASURING"}</dd></div>
        </dl>

        <EvidenceDrawer
          dossier={dossier}
          isolated={state.isolatedId === state.selectedId && state.selectedId !== null}
          onClose={() => send({ type: "clear-selection" })}
          onToggleIsolation={() =>
            send({ type: state.isolatedId ? "clear-isolation" : "isolate-selected" })
          }
        />
      </section>

      <InstrumentRail runtime={bundle.runtime} state={state} send={send} />
    </main>
  );
}
