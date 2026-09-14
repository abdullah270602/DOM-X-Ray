import {
  ArrowRight,
  Check,
  Copy,
  DownloadSimple,
  LinkSimple,
  SpinnerGap,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ViewerBundle } from "../domain/types";
import { fetchPublishedPoster } from "./publishedPoster";
import {
  PosterContractError,
  downloadBlob,
  posterDataUrl,
  posterFilename,
  posterModelFor,
  posterSvgFor,
  rasterizePosterSvg,
  shareCaptionFor,
  shareLinkFor,
} from "./poster";

interface ShareDialogProps {
  bundle: ViewerBundle;
  resultUrl: string;
  onClose: () => void;
  onNewScan: () => void;
}

type ShareFeedback =
  | { kind: "success" | "error"; message: string }
  | null;

type HostedPosterState =
  | { kind: "local" }
  | { kind: "checking"; key: string }
  | { kind: "ready"; key: string; blob: Blob; previewUrl: string; url: string }
  | { kind: "unavailable"; key: string };

function shareErrorMessage(error: unknown): string {
  if (error instanceof PosterContractError) {
    if (error.code === "png-size") return "POSTER EXCEEDS 5 MB · COPY THE RESULT LINK INSTEAD";
    if (error.code === "content-overflow") return "POSTER COPY DOES NOT FIT · COPY THE RESULT LINK INSTEAD";
  }
  return "SHARE ACTION FAILED · TRY AGAIN OR COPY THE RESULT LINK";
}

async function writeClipboard(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
  await navigator.clipboard.writeText(value);
}

export function ShareDialog({
  bundle,
  resultUrl,
  onClose,
  onNewScan,
}: ShareDialogProps) {
  const panelRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const feedbackTimerRef = useRef<number | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [feedback, setFeedback] = useState<ShareFeedback>(null);
  const poster = bundle.result.exports.poster;
  const hostedPosterKey = poster.state === "ready" && poster.artifact !== null
    ? [
        bundle.result.resultId,
        resultUrl,
        poster.artifact.sha256,
        poster.artifact.byteLength,
        poster.eligible,
        poster.mediaType,
        poster.width,
        poster.height,
        poster.maxByteLength,
        poster.sourceResultBindingSha256,
        poster.sourceSceneSha256,
        poster.sourceHeroSha256,
        bundle.result.shareState,
        bundle.result.hero?.shareEligible,
      ].join("|")
    : null;
  const hasHostedPoster = hostedPosterKey !== null;
  const [hostedPoster, setHostedPoster] = useState<HostedPosterState>(
    hostedPosterKey === null
      ? { kind: "local" }
      : { kind: "checking", key: hostedPosterKey },
  );
  const currentHostedPoster: HostedPosterState = hostedPosterKey === null
    ? { kind: "local" }
    : hostedPoster.kind !== "local" && hostedPoster.key === hostedPosterKey
      ? hostedPoster
      : { kind: "checking", key: hostedPosterKey };

  const prepared = useMemo(() => {
    let link: string | null = null;
    try {
      link = shareLinkFor(bundle, resultUrl, window.location.origin);
    } catch (error) {
      return {
        model: null,
        svg: null,
        previewUrl: null,
        caption: null,
        link: null,
        error,
      };
    }
    try {
      const model = posterModelFor(bundle);
      const svg = posterSvgFor(model);
      return {
        model,
        svg,
        previewUrl: posterDataUrl(svg),
        caption: shareCaptionFor(bundle, resultUrl, window.location.origin),
        link,
        error: null,
      };
    } catch (error) {
      return {
        model: null,
        svg: null,
        previewUrl: null,
        caption: null,
        link,
        error,
      };
    }
  }, [bundle, resultUrl]);

  useEffect(() => {
    if (hostedPosterKey === null) {
      setHostedPoster({ kind: "local" });
      return;
    }
    const controller = new AbortController();
    let previewUrl: string | null = null;
    setHostedPoster({ kind: "checking", key: hostedPosterKey });
    void fetchPublishedPoster(
      bundle,
      resultUrl,
      window.location.origin,
      controller.signal,
    ).then(({ blob, url }) => {
      if (controller.signal.aborted) return;
      previewUrl = URL.createObjectURL(blob);
      setHostedPoster({ kind: "ready", key: hostedPosterKey, blob, previewUrl, url });
    }).catch(() => {
      if (!controller.signal.aborted) {
        setHostedPoster({ kind: "unavailable", key: hostedPosterKey });
      }
    });
    return () => {
      controller.abort();
      if (previewUrl !== null) URL.revokeObjectURL(previewUrl);
    };
  }, [bundle, hostedPosterKey, resultUrl]);

  useEffect(() => {
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const panel = panelRef.current;
      if (!panel) return;
      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = originalOverflow;
      if (feedbackTimerRef.current !== null) window.clearTimeout(feedbackTimerRef.current);
    };
  }, [onClose]);

  function report(next: ShareFeedback) {
    setFeedback(next);
    if (feedbackTimerRef.current !== null) window.clearTimeout(feedbackTimerRef.current);
    feedbackTimerRef.current = window.setTimeout(() => setFeedback(null), 2600);
  }

  async function copy(value: string, success: string) {
    try {
      await writeClipboard(value);
      report({ kind: "success", message: success });
    } catch {
      report({ kind: "error", message: "CLIPBOARD BLOCKED · USE YOUR BROWSER COPY CONTROL" });
    }
  }

  async function downloadPoster() {
    if (!prepared.model || !prepared.svg || downloading) return;
    setDownloading(true);
    setFeedback(null);
    try {
      const blob = currentHostedPoster.kind === "ready"
        ? currentHostedPoster.blob
        : await rasterizePosterSvg(
            prepared.svg,
            prepared.model.posterMaxByteLength,
          );
      downloadBlob(blob, posterFilename(prepared.model.pageLabel));
      report({
        kind: "success",
        message: currentHostedPoster.kind === "ready"
          ? "VERIFIED HOSTED PNG · DOWNLOAD STARTED"
          : "1080 × 1080 PNG · DOWNLOAD STARTED",
      });
    } catch (error) {
      report({ kind: "error", message: shareErrorMessage(error) });
    } finally {
      setDownloading(false);
    }
  }

  const pageLabel = bundle.result.pageIdentity.label;
  const statusLabel = bundle.result.statusPresentation.label;
  const previewUrl = currentHostedPoster.kind === "ready"
    ? currentHostedPoster.previewUrl
    : prepared.previewUrl;

  return (
    <div
      className="share-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={panelRef}
        className="share-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="share-title"
        aria-describedby="share-description"
      >
        <header className="share-header">
          <div>
            <h2 id="share-title">SHARE RESULT</h2>
            <p id="share-description">{pageLabel}</p>
            <span className="share-status">
              <span className={bundle.result.status === "partial" ? "status-mark status-partial" : "status-mark"} />
              {statusLabel}
            </span>
          </div>
          <button ref={closeRef} className="share-close" type="button" onClick={onClose} aria-label="CLOSE SHARE RESULT">
            <X size={30} weight="light" aria-hidden="true" />
          </button>
        </header>

        {previewUrl && prepared.model ? (
          <figure className="share-preview">
            <img
              src={previewUrl}
              alt={`${prepared.model.pageLabel} DOM X-Ray poster preview. ${prepared.model.statusLabel}. ${prepared.model.headline}. ${prepared.model.statement}`}
            />
            <figcaption>
              {currentHostedPoster.kind === "ready"
                ? `1080 × 1080 PNG · VERIFIED HOSTED ARTIFACT · ${Math.ceil(currentHostedPoster.blob.size / 1_000)} KB`
                : currentHostedPoster.kind === "checking"
                  ? "1080 × 1080 PNG · VERIFYING HOSTED ARTIFACT"
                  : currentHostedPoster.kind === "unavailable"
                    ? "1080 × 1080 PNG · LOCAL FALLBACK · HOSTED COPY UNAVAILABLE"
                    : `1080 × 1080 PNG · LOCAL EXPORT · MAX ${prepared.model.posterMaxByteLength / 1_000_000} MB`}
            </figcaption>
          </figure>
        ) : (
          <div className="share-preview-error" role="alert">
            <WarningCircle size={28} weight="regular" aria-hidden="true" />
            <strong>POSTER CONTRACT COULD NOT BE VERIFIED</strong>
            <span>{prepared.link ? "The stable result link is still available." : "No share output is available."}</span>
          </div>
        )}

        {hasHostedPoster && (
          <div
            className={`share-publication share-publication-${currentHostedPoster.kind}`}
          >
            <span role="status" aria-live="polite">
              {currentHostedPoster.kind === "checking" && (
                <SpinnerGap className="job-spinner" size={17} weight="bold" aria-hidden="true" />
              )}
              {currentHostedPoster.kind === "ready" && (
                <Check size={17} weight="bold" aria-hidden="true" />
              )}
              {currentHostedPoster.kind === "unavailable" && (
                <WarningCircle size={17} aria-hidden="true" />
              )}
              {currentHostedPoster.kind === "checking"
                ? "VERIFYING SERVER COPY"
                : currentHostedPoster.kind === "ready"
                  ? "SERVER COPY MATCHES IMMUTABLE MANIFEST"
                  : currentHostedPoster.kind === "unavailable"
                    ? "SERVER COPY UNAVAILABLE · LOCAL EXPORT STILL WORKS"
                    : "LOCAL EXPORT"}
            </span>
            {currentHostedPoster.kind === "ready" && (
              <button
                type="button"
                onClick={() => copy(currentHostedPoster.url, "PNG LINK COPIED")}
              >
                <LinkSimple size={17} aria-hidden="true" />
                COPY PNG LINK
              </button>
            )}
          </div>
        )}

        <div className="share-actions" aria-label="Share actions">
          <button
            className="share-action share-action-primary"
            type="button"
            onClick={downloadPoster}
            disabled={!prepared.svg || downloading}
          >
            {downloading ? (
              <SpinnerGap className="job-spinner" size={21} weight="bold" aria-hidden="true" />
            ) : (
              <DownloadSimple size={22} weight="bold" aria-hidden="true" />
            )}
            {downloading ? "BUILDING PNG" : "DOWNLOAD POSTER"}
          </button>
          <button
            className="share-action"
            type="button"
            onClick={() => prepared.caption && copy(prepared.caption.text, "CAPTION COPIED")}
            disabled={!prepared.caption || prepared.caption.tooLong}
            aria-describedby={prepared.caption?.tooLong ? "caption-limit" : undefined}
          >
            <Copy size={21} aria-hidden="true" />
            {prepared.caption?.tooLong ? "CAPTION TOO LONG" : "COPY CAPTION"}
          </button>
          <button
            className="share-action"
            type="button"
            onClick={() => prepared.link && copy(prepared.link, "RESULT LINK COPIED")}
            disabled={!prepared.link}
          >
            <LinkSimple size={21} aria-hidden="true" />
            COPY RESULT LINK
          </button>
        </div>

        {prepared.caption?.tooLong && (
          <p id="caption-limit" className="share-limit">
            {prepared.caption.effectiveLength}/280 EFFECTIVE CHARACTERS · COPY THE RESULT LINK INSTEAD
          </p>
        )}
        {feedback && (
          <p
            className={`share-feedback share-feedback-${feedback.kind}`}
            role={feedback.kind === "error" ? "alert" : "status"}
            aria-live="polite"
          >
            {feedback.kind === "success" ? <Check size={16} weight="bold" aria-hidden="true" /> : <WarningCircle size={16} aria-hidden="true" />}
            {feedback.message}
          </p>
        )}

        <button className="share-new-scan" type="button" onClick={onNewScan}>
          X-RAY ANOTHER SITE
          <ArrowRight size={19} weight="bold" aria-hidden="true" />
        </button>
      </section>
    </div>
  );
}
