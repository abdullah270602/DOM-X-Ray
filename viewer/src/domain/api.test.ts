import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchViewerBundle, pollScanJob, resultIdFromPath, submitScan } from "./api";
import { fixtures } from "./fixtures";
import type { ScanJob } from "./types";


const jobId = "j_0123456789abcdef0123456789abcdef";
const resultId = "r_0123456789abcdef0123456789abcdef";

function job(state: ScanJob["state"], progress: ScanJob["progress"]): ScanJob {
  const ready = state === "ready";
  const terminalError = state === "failed" || state === "rejected";
  return {
    apiVersion: "scan-api-v0.1.0",
    jobId,
    state,
    progress,
    submittedAt: "2026-09-09T12:00:00Z",
    updatedAt: "2026-09-09T12:00:01Z",
    scanStatus: ready ? "complete" : null,
    result: ready
      ? { resultId, resultPath: `/r/${resultId}`, bundleUrl: `/api/results/${resultId}` }
      : null,
    error: terminalError
      ? {
          code: state === "rejected" ? "scanner-disabled" : "capture-failed",
          message: "The scan did not run.",
          retryable: false,
        }
      : null,
    pollAfterMs: state === "queued" || state === "running" ? 250 : null,
  };
}

function jsonResponse(value: object, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function immutableJsonResponse(value: object, etagOverride?: string): Promise<Response> {
  const body = JSON.stringify(value);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  const etag =
    etagOverride ??
    `"${Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("")}"`;
  return new Response(body, {
    headers: { "Content-Type": "application/json", ETag: etag },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("scan API boundary", () => {
  it("retains a typed rejection returned with a non-success HTTP status", async () => {
    const rejected = job("rejected", "rejected");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(rejected, 503)));
    const result = await submitScan("https://public.example/", new AbortController().signal);
    expect(result).toEqual(rejected);
  });

  it("polls only while work is non-terminal and emits admitted states", async () => {
    const running = job("running", "mapping");
    const ready = job("ready", "complete");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(running))
      .mockResolvedValueOnce(jsonResponse(ready));
    vi.stubGlobal("fetch", fetchMock);
    const observed: string[] = [];
    const result = await pollScanJob(
      job("queued", "queued"),
      new AbortController().signal,
      (next) => observed.push(`${next.state}/${next.progress}`),
      async () => undefined,
    );
    expect(observed).toEqual(["running/mapping", "ready/complete"]);
    expect(result.result?.resultId).toBe(resultId);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("validates every document and hash before admitting a fetched bundle", async () => {
    const fixture = fixtures.clean;
    const raw = {
      bundleVersion: fixture.bundleVersion,
      record: fixture.record,
      scene: fixture.scene,
      result: fixture.result,
      runtime: fixture.runtime,
      mapping: fixture.mapping,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableJsonResponse(raw)));
    const admitted = await fetchViewerBundle(
      `/api/results/${fixture.result.resultId}`,
      fixture.result.resultId,
      new AbortController().signal,
    );
    expect(admitted.runtime.resultId).toBe(fixture.result.resultId);

    const drifted = structuredClone(raw);
    drifted.record.scanId = "fixture-relabeled";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableJsonResponse(drifted)));
    await expect(
      fetchViewerBundle("/api/results/drifted", "drifted", new AbortController().signal),
    ).rejects.toThrow(/viewer bundle|scan record|scan identities/i);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableJsonResponse(raw)));
    await expect(
      fetchViewerBundle(
        `/api/results/${resultId}`,
        resultId,
        new AbortController().signal,
      ),
    ).rejects.toThrow(/identity.*requested route/i);

    const wrongPath = structuredClone(raw);
    wrongPath.result.resultPath = `/r/${resultId}`;
    wrongPath.runtime.resultPath = `/r/${resultId}`;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableJsonResponse(wrongPath)));
    await expect(
      fetchViewerBundle(
        `/api/results/${fixture.result.resultId}`,
        fixture.result.resultId,
        new AbortController().signal,
      ),
    ).rejects.toThrow(/identity.*requested route/i);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(await immutableJsonResponse(raw, `"${"0".repeat(64)}"`)),
    );
    await expect(
      fetchViewerBundle(
        `/api/results/${fixture.result.resultId}`,
        fixture.result.resultId,
        new AbortController().signal,
      ),
    ).rejects.toThrow(/content identity check/i);
  });

  it("recognizes only opaque stable result routes", () => {
    expect(resultIdFromPath(`/r/${resultId}`)).toBe(resultId);
    expect(resultIdFromPath(`/r/${resultId}/extra`)).toBeNull();
    expect(resultIdFromPath("/r/gallery-example")).toBeNull();
  });
});
