import { afterEach, describe, expect, it, vi } from "vitest";
import { fixtures } from "../domain/fixtures";
import type { ViewerBundle } from "../domain/types";
import {
  PublishedVideoError,
  fetchPublishedVideo,
  publishedVideoUrlFor,
  videoFilename,
} from "./publishedVideo";

const origin = "https://dom-x-ray.example";

function videoBytes(label = "trusted motion"): Uint8Array {
  return new Uint8Array([
    0, 0, 0, 20,
    ...new TextEncoder().encode("ftypisom"),
    ...new TextEncoder().encode(label),
  ]);
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

async function publishedBundle(bytes: Uint8Array): Promise<ViewerBundle> {
  const bundle = structuredClone(fixtures["image-heavy"]);
  bundle.result.exports.video.state = "ready";
  bundle.result.exports.video.artifact = {
    sha256: hex(await crypto.subtle.digest("SHA-256", ownedArrayBuffer(bytes))),
    byteLength: bytes.byteLength,
  };
  return bundle;
}

function responseFor(
  bytes: Uint8Array,
  url: string,
  sha256: string,
  overrides: {
    status?: number;
    contentType?: string;
    contentLength?: string | null;
    etag?: string;
    redirected?: boolean;
    url?: string;
  } = {},
): Response {
  const headers = new Headers({
    "Content-Type": overrides.contentType ?? "video/mp4",
    ETag: overrides.etag ?? `"${sha256}"`,
  });
  if (overrides.contentLength !== null) {
    headers.set("Content-Length", overrides.contentLength ?? String(bytes.byteLength));
  }
  const response = new Response(ownedArrayBuffer(bytes), {
    status: overrides.status ?? 200,
    headers,
  });
  Object.defineProperties(response, {
    url: { value: overrides.url ?? url },
    redirected: { value: overrides.redirected ?? false },
  });
  return response;
}

async function expectCode(action: Promise<unknown>, code: string): Promise<void> {
  await expect(action).rejects.toMatchObject({
    name: "PublishedVideoError",
    code,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("published video verification", () => {
  it("derives one exact same-origin route and verifies its immutable bytes", async () => {
    const bytes = videoBytes();
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = `${origin}/api/results/${bundle.result.resultId}/video.mp4`;
    const artifact = bundle.result.exports.video.artifact!;
    const fetchMock = vi.fn().mockResolvedValue(responseFor(bytes, url, artifact.sha256));
    vi.stubGlobal("fetch", fetchMock);

    expect(publishedVideoUrlFor(bundle, resultUrl, origin)).toBe(url);
    const published = await fetchPublishedVideo(bundle, resultUrl, origin);
    expect(published.url).toBe(url);
    expect(published.blob.type).toBe("video/mp4");
    expect(new Uint8Array(await published.blob.arrayBuffer())).toEqual(bytes);
    expect(fetchMock).toHaveBeenCalledWith(
      url,
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      }),
    );
    expect(videoFilename("Gallery / Home")).toBe("gallery-home-dom-x-ray.mp4");
  });

  it("fails closed before fetch when route, state, or source binding drifts", async () => {
    const bytes = videoBytes();
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    expect(() => publishedVideoUrlFor(bundle, `${resultUrl}?token=bad`, origin)).toThrow(
      PublishedVideoError,
    );
    const wrongDuration = structuredClone(bundle);
    wrongDuration.result.exports.video.durationMs = 4_999 as 5000;
    expect(() => publishedVideoUrlFor(wrongDuration, resultUrl, origin)).toThrow(
      expect.objectContaining({ code: "not-published" }),
    );
    const rebound = structuredClone(bundle);
    rebound.result.exports.video.sourceHeroSha256 = "0".repeat(64);
    expect(() => publishedVideoUrlFor(rebound, resultUrl, origin)).toThrow(
      expect.objectContaining({ code: "invalid-binding" }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["HTTP failure", { status: 404 }, "invalid-response"],
    ["redirect", { redirected: true }, "invalid-response"],
    ["redirect URL", { url: `${origin}/wrong.mp4` }, "invalid-response"],
    ["content type", { contentType: "text/html" }, "invalid-response"],
    ["content length", { contentLength: "999" }, "invalid-response"],
    ["ETag", { etag: '"' + "0".repeat(64) + '"' }, "invalid-response"],
  ])("rejects a bad %s response", async (_label, overrides, expectedCode) => {
    const bytes = videoBytes();
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedVideoUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.video.artifact!;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(bytes, url, artifact.sha256, overrides)),
    );
    await expectCode(fetchPublishedVideo(bundle, resultUrl, origin), expectedCode);
  });

  it("rejects malformed, truncated, oversized, and digest-mismatched bodies", async () => {
    const expected = videoBytes();
    const bundle = await publishedBundle(expected);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedVideoUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.video.artifact!;

    for (const bytes of [expected.slice(0, -1), new Uint8Array([...expected, 0])]) {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          responseFor(bytes, url, artifact.sha256, {
            contentLength: String(artifact.byteLength),
          }),
        ),
      );
      await expectCode(fetchPublishedVideo(bundle, resultUrl, origin), "invalid-response");
    }

    const malformed = new Uint8Array(expected.byteLength).fill(7);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(malformed, url, artifact.sha256)),
    );
    await expectCode(fetchPublishedVideo(bundle, resultUrl, origin), "invalid-response");

    const wrong = new Uint8Array(expected);
    wrong[12] = (wrong[12] ?? 0) ^ 1;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(wrong, url, artifact.sha256)),
    );
    await expectCode(fetchPublishedVideo(bundle, resultUrl, origin), "digest-mismatch");
  });

  it("maps network and abort failures to stable content-free errors", async () => {
    const bytes = videoBytes();
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("private response body")));
    await expectCode(fetchPublishedVideo(bundle, resultUrl, origin), "network-failed");

    const controller = new AbortController();
    controller.abort();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new DOMException("private detail", "AbortError")),
    );
    await expectCode(
      fetchPublishedVideo(bundle, resultUrl, origin, controller.signal),
      "aborted",
    );
  });
});
