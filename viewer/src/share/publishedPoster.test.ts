import { afterEach, describe, expect, it, vi } from "vitest";
import { fixtures } from "../domain/fixtures";
import type { ViewerBundle } from "../domain/types";
import {
  PublishedPosterError,
  fetchPublishedPoster,
  publishedPosterUrlFor,
} from "./publishedPoster";

const origin = "https://dom-x-ray.example";

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

async function digest(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", ownedArrayBuffer(bytes)));
}

async function publishedBundle(bytes: Uint8Array): Promise<ViewerBundle> {
  const bundle = structuredClone(fixtures["image-heavy"]);
  bundle.result.exports.poster.state = "ready";
  bundle.result.exports.poster.artifact = {
    sha256: await digest(bytes),
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
    "Content-Type": overrides.contentType ?? "image/png",
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
    name: "PublishedPosterError",
    code,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("published poster verification", () => {
  it("derives one exact same-origin route and verifies its immutable bytes", async () => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = `${origin}/api/results/${bundle.result.resultId}/poster.png`;
    const artifact = bundle.result.exports.poster.artifact!;
    const fetchMock = vi.fn().mockResolvedValue(responseFor(bytes, url, artifact.sha256));
    vi.stubGlobal("fetch", fetchMock);

    expect(publishedPosterUrlFor(bundle, resultUrl, origin)).toBe(url);
    const published = await fetchPublishedPoster(bundle, resultUrl, origin);
    expect(published.url).toBe(url);
    expect(published.blob.type).toBe("image/png");
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
  });

  it("fails closed before fetch when route, state, or source binding drifts", async () => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    expect(() => publishedPosterUrlFor(bundle, `${resultUrl}?token=bad`, origin)).toThrow(
      PublishedPosterError,
    );
    const notReady = structuredClone(bundle);
    notReady.result.exports.poster.state = "not-generated";
    notReady.result.exports.poster.artifact = null;
    expect(() => publishedPosterUrlFor(notReady, resultUrl, origin)).toThrow(
      expect.objectContaining({ code: "not-published" }),
    );
    const rebound = structuredClone(bundle);
    rebound.result.exports.poster.sourceHeroSha256 = "0".repeat(64);
    expect(() => publishedPosterUrlFor(rebound, resultUrl, origin)).toThrow(
      expect.objectContaining({ code: "invalid-binding" }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["HTTP failure", { status: 404 }, "invalid-response"],
    ["redirect", { redirected: true }, "invalid-response"],
    ["redirect URL", { url: `${origin}/wrong.png` }, "invalid-response"],
    ["content type", { contentType: "text/html" }, "invalid-response"],
    ["content length", { contentLength: "999" }, "invalid-response"],
    ["ETag", { etag: '"' + "0".repeat(64) + '"' }, "invalid-response"],
  ])("rejects a bad %s response", async (_label, overrides, expectedCode) => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedPosterUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.poster.artifact!;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(bytes, url, artifact.sha256, overrides)),
    );
    await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), expectedCode);
  });

  it("rejects truncated, oversized, and digest-mismatched bodies", async () => {
    const expected = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(expected);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedPosterUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.poster.artifact!;

    for (const bytes of [expected.slice(0, -1), new Uint8Array([...expected, 0])]) {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          responseFor(bytes, url, artifact.sha256, {
            contentLength: String(artifact.byteLength),
          }),
        ),
      );
      await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), "invalid-response");
    }

    const wrong = new Uint8Array(expected.byteLength).fill(7);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(wrong, url, artifact.sha256)),
    );
    await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), "digest-mismatch");
  });

  it("rejects an unstreamable body before attempting an unbounded fallback read", async () => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedPosterUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.poster.artifact!;
    const response = new Response(null, {
      status: 200,
      headers: {
        "Content-Type": "image/png",
        "Content-Length": String(artifact.byteLength),
        ETag: `"${artifact.sha256}"`,
      },
    });
    Object.defineProperties(response, {
      url: { value: url },
      redirected: { value: false },
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), "invalid-response");
  });

  it("normalizes digest runtime failures without exposing browser details", async () => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    const url = publishedPosterUrlFor(bundle, resultUrl, origin);
    const artifact = bundle.result.exports.poster.artifact!;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseFor(bytes, url, artifact.sha256)),
    );
    vi.spyOn(crypto.subtle, "digest").mockRejectedValueOnce(new Error("private crypto detail"));

    await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), "digest-unavailable");
  });

  it("maps network and abort failures to stable content-free errors", async () => {
    const bytes = new TextEncoder().encode("trusted poster bytes");
    const bundle = await publishedBundle(bytes);
    const resultUrl = `${origin}${bundle.result.resultPath}`;
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("private response body")));
    await expectCode(fetchPublishedPoster(bundle, resultUrl, origin), "network-failed");

    const controller = new AbortController();
    controller.abort();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new DOMException("private detail", "AbortError")),
    );
    await expectCode(
      fetchPublishedPoster(bundle, resultUrl, origin, controller.signal),
      "aborted",
    );
  });
});
