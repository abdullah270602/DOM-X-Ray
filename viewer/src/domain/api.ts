import { validateScanJob, validateViewerBundle } from "./fixtures";
import type { ScanJob, ViewerBundle } from "./types";

export const scanApiVersion = "scan-api-v0.1.0" as const;

type Wait = (milliseconds: number, signal: AbortSignal) => Promise<void>;

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new Error("The scanner returned an unreadable response.");
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function immutableResponseJson(response: Response): Promise<unknown> {
  const payload = await response.arrayBuffer();
  const etag = response.headers.get("ETag");
  if (!etag || !/^"[0-9a-f]{64}"$/.test(etag)) {
    throw new Error("The immutable result is missing its strong content identity.");
  }
  const digest = await crypto.subtle.digest("SHA-256", payload);
  if (`"${hex(new Uint8Array(digest))}"` !== etag) {
    throw new Error("The immutable result failed its content identity check.");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    throw new Error("The immutable result contained unreadable JSON.");
  }
}

export async function submitScan(url: string, signal: AbortSignal): Promise<ScanJob> {
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ apiVersion: scanApiVersion, url }),
    signal,
  });
  return validateScanJob(await responseJson(response));
}

export async function fetchScanJob(jobId: string, signal: AbortSignal): Promise<ScanJob> {
  const response = await fetch(`/api/scans/${encodeURIComponent(jobId)}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal,
  });
  if (!response.ok) throw new Error("The scan job is no longer available.");
  return validateScanJob(await responseJson(response));
}

export async function fetchViewerBundle(
  bundleUrl: string,
  sourceId: string,
  signal: AbortSignal,
): Promise<ViewerBundle> {
  const response = await fetch(bundleUrl, {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error("The immutable result could not be loaded.");
  const bundle = validateViewerBundle(sourceId, await immutableResponseJson(response));
  const expectedPath = `/r/${sourceId}`;
  if (
    bundle.result.resultId !== sourceId ||
    bundle.runtime.resultId !== sourceId ||
    bundle.result.resultPath !== expectedPath ||
    bundle.runtime.resultPath !== expectedPath
  ) {
    throw new Error("The immutable result identity does not match the requested route.");
  }
  return bundle;
}

export const wait: Wait = (milliseconds, signal) =>
  new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = window.setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timer);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
  });

export async function pollScanJob(
  initial: ScanJob,
  signal: AbortSignal,
  onUpdate: (job: ScanJob) => void,
  waitFor: Wait = wait,
): Promise<ScanJob> {
  let current = initial;
  let consecutiveFailures = 0;
  while (current.state === "queued" || current.state === "running") {
    const delay = Math.min(5000, Math.max(250, current.pollAfterMs ?? 500));
    await waitFor(delay, signal);
    try {
      current = await fetchScanJob(current.jobId, signal);
      consecutiveFailures = 0;
      onUpdate(current);
    } catch (error) {
      if (signal.aborted) throw error;
      consecutiveFailures += 1;
      if (consecutiveFailures >= 3) throw error;
      await waitFor(500 * 2 ** (consecutiveFailures - 1), signal);
    }
  }
  return current;
}

export function resultIdFromPath(pathname: string): string | null {
  const match = /^\/r\/(r_[0-9a-f]{32})$/.exec(pathname);
  return match?.[1] ?? null;
}
