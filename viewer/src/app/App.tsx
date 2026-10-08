import {
  ArrowRight,
  Check,
  Crosshair,
  GlobeSimple,
  LinkSimple,
  ListMagnifyingGlass,
  ShareNetwork,
  SpinnerGap,
  Trash,
  Warning,
} from "@phosphor-icons/react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  createDeletionToken,
  deleteResult,
  fetchViewerBundle,
  pollScanJob,
  resultIdFromPath,
  submitScan,
} from "../domain/api";
import { dossierFor } from "../domain/pointer";
import { fixtureNames, fixtures } from "../domain/fixtures";
import { presentationFrame, reduceViewerState } from "../domain/runtime";
import type {
  FixtureName,
  ScanJob,
  ScanJobProgress,
  ViewerBundle,
  ViewerEvent,
  ViewerRuntime,
  ViewerState,
} from "../domain/types";
import type { ScenePerformance } from "../scene/InstrumentScene";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { InstrumentRail } from "./InstrumentRail";
import { TextScene } from "./TextScene";
import { ShareDialog } from "../share/ShareDialog";
import { parsePublicUrl } from "../../../shared/public_url.mjs";

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
  renderer: null,
};

const jobLabels: Record<ScanJobProgress, string> = {
  admission: "CHECKING TARGET",
  queued: "SCAN QUEUED",
  capturing: "ADMITTING CAPTURE",
  mapping: "MAPPING MEASUREMENTS",
  publishing: "PUBLISHING RESULT",
  complete: "IMMUTABLE RESULT READY",
  rejected: "SCAN NOT ADMITTED",
  failed: "SCAN INCOMPLETE",
};

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function ownerStorageKey(resultId: string): string {
  return `dom-x-ray:owner:${resultId}`;
}

function storedOwnerToken(resultId: string): string | null {
  try {
    const token = window.localStorage.getItem(ownerStorageKey(resultId));
    return token && /^dxrd_[0-9a-f]{64}$/.test(token) ? token : null;
  } catch {
    return null;
  }
}

function storeOwnerToken(resultId: string, token: string): void {
  try {
    window.localStorage.setItem(ownerStorageKey(resultId), token);
  } catch {
    // The result still works when private storage is unavailable; deletion will not survive reload.
  }
}

function removeOwnerToken(resultId: string): void {
  try {
    window.localStorage.removeItem(ownerStorageKey(resultId));
  } catch {
    // Nothing else can be done when origin-local storage is unavailable.
  }
}

export function App() {
  const firstFixture = initialFixture();
  const [fixtureName, setFixtureName] = useState<FixtureName | null>(firstFixture);
  const [bundle, setBundle] = useState<ViewerBundle>(() => fixtures[firstFixture]);
  const reduced = useMemo(prefersReducedMotion, []);
  const [state, setState] = useState<ViewerState>(() =>
    initialViewerState(bundle.runtime, reduced),
  );
  const [url, setUrl] = useState(bundle.record.requestedUrl);
  const [fieldError, setFieldError] = useState("");
  const [resultNotice, setResultNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [ownerToken, setOwnerToken] = useState<string | null>(null);
  const [shareOpen, setShareOpen] = useState(false);
  const [linkCopyState, setLinkCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [performance, setPerformance] = useState<ScenePerformance>(emptyPerformance);
  const [showTextScene, setShowTextScene] = useState(
    () => new URLSearchParams(window.location.search).get("fallback") === "text" || !supportsWebGL(),
  );
  const inputRef = useRef<HTMLInputElement>(null);
  const shareButtonRef = useRef<HTMLButtonElement>(null);
  const linkCopyTimerRef = useRef<number | null>(null);
  const requestRef = useRef<AbortController | null>(null);

  const closeShare = useCallback(() => {
    setShareOpen(false);
    window.requestAnimationFrame(() => shareButtonRef.current?.focus());
  }, []);

  const focusNewScan = useCallback(() => {
    setShareOpen(false);
    window.requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
  }, []);

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
      if (linkCopyTimerRef.current !== null) window.clearTimeout(linkCopyTimerRef.current);
    },
    [],
  );

  const activateBundle = useCallback(
    (nextBundle: ViewerBundle) => {
      setBundle(nextBundle);
      setUrl(nextBundle.record.requestedUrl);
      setState(initialViewerState(nextBundle.runtime, reduced));
      setPerformance(emptyPerformance);
      setFieldError("");
      setResultNotice("");
      setShareOpen(false);
      setLinkCopyState("idle");
    },
    [reduced],
  );

  useEffect(() => {
    let routeController: AbortController | null = null;

    const openCurrentLocation = () => {
      routeController?.abort();
      requestRef.current?.abort();
      const resultId = resultIdFromPath(window.location.pathname);
      if (!resultId) {
        requestRef.current = null;
        const nextName = initialFixture();
        setFixtureName(nextName);
        activateBundle(fixtures[nextName]);
        setOwnerToken(null);
        setJob(null);
        setLoading(false);
        return;
      }

      const controller = new AbortController();
      routeController = controller;
      requestRef.current = controller;
      setLoading(true);
      setOwnerToken(null);
      setJob(null);
      void fetchViewerBundle(`/api/results/${resultId}`, resultId, controller.signal)
        .then((nextBundle) => {
          if (requestRef.current !== controller) return;
          activateBundle(nextBundle);
          setFixtureName(null);
          setOwnerToken(storedOwnerToken(resultId));
        })
        .catch((error: unknown) => {
          if (requestRef.current === controller && !isAbortError(error)) {
            setOwnerToken(null);
            setFieldError("This immutable result is unavailable. Choose a seeded capture below.");
          }
        })
        .finally(() => {
          if (requestRef.current === controller) {
            requestRef.current = null;
            setLoading(false);
          }
        });
    };

    openCurrentLocation();
    window.addEventListener("popstate", openCurrentLocation);
    return () => {
      window.removeEventListener("popstate", openCurrentLocation);
      routeController?.abort();
      requestRef.current?.abort();
    };
  }, [activateBundle]);

  const frame = presentationFrame(bundle.runtime, state);
  const dossier = useMemo(
    () => (state.selectedId ? dossierFor(bundle, state.selectedId) : null),
    [bundle, state.selectedId],
  );
  const findingId = bundle.runtime.selectables.find((item) =>
    ["hero-finding", "neutral-summary"].includes(item.kind),
  )?.id;

  function loadFixture(nextName: FixtureName, nextUrl = fixtures[nextName].record.requestedUrl) {
    requestRef.current?.abort();
    requestRef.current = null;
    const nextBundle = fixtures[nextName];
    setFixtureName(nextName);
    activateBundle(nextBundle);
    setOwnerToken(null);
    setUrl(nextUrl);
    setJob(null);
    setLoading(false);
    const params = new URLSearchParams(window.location.search);
    params.set("fixture", nextName);
    window.history.replaceState(null, "", `/?${params}`);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = parsePublicUrl(url);
    if (!parsed.ok) {
      setFieldError(parsed.code === "initial-target-data"
        ? "Remove query parameters and fragments before scanning."
        : parsed.code === "credentials"
          ? "Remove the username and password from the URL."
          : parsed.code === "disallowed-port"
            ? "Use a public HTTP or HTTPS URL on port 80 or 443."
            : "Enter a complete public HTTP or HTTPS URL.");
      inputRef.current?.focus();
      return;
    }
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setFieldError("");
    setResultNotice("");
    setLoading(true);
    setJob(null);
    let loadingPublishedResult = false;
    const candidateOwnerToken = createDeletionToken();
    try {
      const submission = await submitScan(
        parsed.href,
        candidateOwnerToken,
        controller.signal,
      );
      const submitted = submission.job;
      if (requestRef.current !== controller) return;
      setJob(submitted);
      const terminal = await pollScanJob(submitted, controller.signal, (nextJob) => {
        if (requestRef.current === controller) setJob(nextJob);
      });
      if (requestRef.current !== controller) return;
      if (terminal.state !== "ready" || terminal.result === null) {
        setFieldError(terminal.error?.message ?? "The scan did not produce a result.");
        return;
      }
      if (submission.ownsResult) {
        storeOwnerToken(terminal.result.resultId, candidateOwnerToken);
      }
      loadingPublishedResult = true;
      const nextBundle = await fetchViewerBundle(
        terminal.result.bundleUrl,
        terminal.result.resultId,
        controller.signal,
      );
      if (requestRef.current !== controller) return;
      activateBundle(nextBundle);
      setFixtureName(null);
      setOwnerToken(
        submission.ownsResult
          ? candidateOwnerToken
          : storedOwnerToken(terminal.result.resultId),
      );
      setJob(terminal);
      window.history.pushState(null, "", nextBundle.result.resultPath);
    } catch (error) {
      if (requestRef.current === controller && !isAbortError(error)) {
        if (loadingPublishedResult) {
          setJob(null);
          setFieldError(
            "The scan finished, but its immutable result could not be verified. Your current result is unchanged.",
          );
        } else {
          setFieldError(
            error instanceof Error
              ? error.message
              : "The scanner connection was interrupted. Try the seeded capture again.",
          );
        }
      }
    } finally {
      if (requestRef.current === controller) {
        requestRef.current = null;
        setLoading(false);
      }
    }
  }

  async function deletePublishedResult() {
    const resultId = bundle.result.resultId;
    if (!ownerToken || fixtureName !== null || deleting) return;
    const confirmed = window.confirm(
      "Delete this result? Anyone with the link will lose access. This cannot be undone.",
    );
    if (!confirmed) return;

    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setDeleting(true);
    setFieldError("");
    setResultNotice("");
    try {
      await deleteResult(resultId, ownerToken, controller.signal);
      if (requestRef.current !== controller) return;
      removeOwnerToken(resultId);
      setOwnerToken(null);
      setDeleting(false);
      loadFixture(initialFixture());
      setResultNotice("RESULT DELETED · SHARED LINK REMOVED");
    } catch (error) {
      if (requestRef.current === controller && !isAbortError(error)) {
        setFieldError(
          error instanceof Error
            ? error.message
            : "The result could not be deleted. Try again.",
        );
      }
    } finally {
      if (requestRef.current === controller) {
        requestRef.current = null;
        setDeleting(false);
      }
    }
  }

  async function copyResultLink() {
    const resultUrl = new URL(bundle.result.resultPath, window.location.origin).href;
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(resultUrl);
      setLinkCopyState("copied");
    } catch {
      setLinkCopyState("failed");
    }
    if (linkCopyTimerRef.current !== null) window.clearTimeout(linkCopyTimerRef.current);
    linkCopyTimerRef.current = window.setTimeout(() => setLinkCopyState("idle"), 2200);
  }

  const resultUrl = new URL(bundle.result.resultPath, window.location.origin).href;
  const published = fixtureName === null;
  const posterEligible =
    published &&
    bundle.runtime.presentation.finding.shareEligible &&
    bundle.result.shareState === "artifact-eligible" &&
    bundle.result.exports.poster.eligible;
  const linkOnly = published && bundle.result.shareState === "link-only";

  return (
    <>
    <main
      className="app-shell"
      aria-hidden={shareOpen ? true : undefined}
      inert={shareOpen ? true : undefined}
    >
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
              aria-describedby={fieldError ? "scan-help scan-error" : "scan-help"}
              aria-invalid={Boolean(fieldError)}
              disabled={loading || deleting}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
            />
            <GlobeSimple size={22} weight="regular" aria-hidden="true" />
          </div>
          <p id="scan-help">
            Seeded safety proof: these three captures cross the real worker boundary. Arbitrary public scanning stays off.
          </p>
          {job && (
            <div className={`job-readout job-${job.state}`} role="status" aria-live="polite">
              <span className="job-mark" aria-hidden="true" />
              <span>
                <strong>{jobLabels[job.progress]}</strong>
                <small>
                  {job.state === "ready"
                    ? "STABLE RESULT ROUTE"
                    : job.state === "failed" || job.state === "rejected"
                      ? "NO RESULT PUBLISHED"
                      : "SEEDED WORKER PIPELINE"}
                </small>
              </span>
            </div>
          )}
          {fieldError && (
            <p id="scan-error" className="field-error" role="alert">
              <Warning size={16} weight="fill" aria-hidden="true" />
              {fieldError}
            </p>
          )}
          {resultNotice && (
            <p className="result-notice" role="status" aria-live="polite">
              <Check size={16} weight="bold" aria-hidden="true" />
              {resultNotice}
            </p>
          )}
          <button className="xray-button" type="submit" disabled={loading || deleting}>
            {loading && <SpinnerGap className="job-spinner" size={20} weight="bold" aria-hidden="true" />}
            {loading
              ? job?.state === "ready"
                ? "LOADING RESULT"
                : jobLabels[job?.progress ?? "admission"]
              : "START X-RAY"}
            {!loading && <ArrowRight size={22} weight="bold" aria-hidden="true" />}
          </button>
        </form>

        <div className="fixture-switcher">
          <label htmlFor="fixture">SEEDED CAPTURE</label>
          <select
            id="fixture"
            value={fixtureName ?? ""}
            onChange={(event) => loadFixture(event.currentTarget.value as FixtureName)}
            disabled={loading || deleting}
          >
            {fixtureName === null && <option value="" disabled>Published result</option>}
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
          {posterEligible && (
            <button
              ref={shareButtonRef}
              className="copy-button"
              type="button"
              onClick={() => setShareOpen(true)}
              aria-haspopup="dialog"
            >
              <ShareNetwork size={18} weight="regular" aria-hidden="true" />
              SHARE RESULT
            </button>
          )}
          {linkOnly && (
            <>
              <button className="copy-button" type="button" onClick={copyResultLink}>
                {linkCopyState === "copied" ? (
                  <Check size={18} weight="bold" aria-hidden="true" />
                ) : (
                  <LinkSimple size={18} aria-hidden="true" />
                )}
                {linkCopyState === "copied"
                  ? "RESULT LINK COPIED"
                  : linkCopyState === "failed"
                    ? "COPY FAILED"
                    : "COPY RESULT LINK"}
              </button>
              {linkCopyState !== "idle" && (
                <span className="sr-only" role={linkCopyState === "failed" ? "alert" : "status"}>
                  {linkCopyState === "failed"
                    ? "CLIPBOARD BLOCKED · USE YOUR BROWSER COPY CONTROL"
                    : "RESULT LINK COPIED"}
                </span>
              )}
            </>
          )}
          {fixtureName === null && ownerToken && (
            <button
              className="delete-button"
              type="button"
              onClick={deletePublishedResult}
              disabled={deleting}
            >
              {deleting ? (
                <SpinnerGap className="job-spinner" size={17} weight="bold" aria-hidden="true" />
              ) : (
                <Trash size={17} aria-hidden="true" />
              )}
              {deleting ? "DELETING RESULT" : "DELETE RESULT"}
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
            <dd>{fixtureName === null ? "ADMITTED" : "FIXTURE"}</dd>
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
                key={bundle.runtime.resultId}
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
          <div><dt>RENDER</dt><dd>{performance.renderer ?? "MEASURING"}</dd></div>
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
    {shareOpen && published && (
      <ShareDialog
        bundle={bundle}
        resultUrl={resultUrl}
        onClose={closeShare}
        onNewScan={focusNewScan}
      />
    )}
    </>
  );
}
