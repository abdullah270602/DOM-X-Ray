import type { ViewerBundle } from "../domain/types";

const VIDEO_SIZE = 1080;
const VIDEO_DURATION_MS = 5_000;
const VIDEO_BYTE_LIMIT = 8_000_000;
const RESULT_ID = /^r_[0-9a-f]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export type PublishedVideoErrorCode =
  | "invalid-binding"
  | "not-published"
  | "network-failed"
  | "aborted"
  | "invalid-response"
  | "digest-unavailable"
  | "digest-mismatch";

export class PublishedVideoError extends Error {
  readonly code: PublishedVideoErrorCode;

  constructor(code: PublishedVideoErrorCode, message: string) {
    super(message);
    this.name = "PublishedVideoError";
    this.code = code;
  }
}

function requirePublished(
  condition: unknown,
  code: PublishedVideoErrorCode,
  message: string,
): asserts condition {
  if (!condition) throw new PublishedVideoError(code, message);
}

function parseUrl(value: string, label: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new PublishedVideoError("invalid-binding", `${label} is invalid.`);
  }
}

export function publishedVideoUrlFor(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
): string {
  const trusted = parseUrl(trustedOrigin, "Trusted origin");
  const result = parseUrl(resultUrl, "Result URL");
  const resultId = bundle.result.resultId;
  const video = bundle.result.exports.video;
  const artifact = video.artifact;

  requirePublished(
    ["http:", "https:"].includes(trusted.protocol) &&
      !trusted.username &&
      !trusted.password &&
      trusted.pathname === "/" &&
      !trusted.search &&
      !trusted.hash &&
      ["http:", "https:"].includes(result.protocol) &&
      !result.username &&
      !result.password &&
      result.origin === trusted.origin &&
      result.pathname === bundle.result.resultPath &&
      !result.search &&
      !result.hash &&
      RESULT_ID.test(resultId) &&
      bundle.result.resultPath === `/r/${resultId}`,
    "invalid-binding",
    "The published video route is not bound to this result.",
  );
  requirePublished(
    bundle.result.shareState === "artifact-eligible" &&
      bundle.result.hero?.shareEligible === true &&
      video.eligible &&
      video.state === "ready" &&
      video.mediaType === "video/mp4" &&
      video.width === VIDEO_SIZE &&
      video.height === VIDEO_SIZE &&
      video.durationMs === VIDEO_DURATION_MS &&
      video.maxByteLength === VIDEO_BYTE_LIMIT &&
      artifact !== null &&
      SHA256.test(artifact.sha256) &&
      Number.isInteger(artifact.byteLength) &&
      artifact.byteLength > 0 &&
      artifact.byteLength <= VIDEO_BYTE_LIMIT,
    "not-published",
    "This result has no verified hosted video.",
  );
  requirePublished(
    video.sourceResultBindingSha256 === bundle.result.sourceHashes.resultBindingSha256 &&
      video.sourceSceneSha256 === bundle.result.sourceHashes.sceneManifestSha256 &&
      video.sourceHeroSha256 === bundle.result.sourceHashes.heroSha256,
    "invalid-binding",
    "The hosted video sources do not match this result.",
  );

  return new URL(`/api/results/${resultId}/video.mp4`, trusted).href;
}

function abortLike(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

async function boundedResponseBytes(
  response: Response,
  expectedLength: number,
): Promise<Uint8Array> {
  requirePublished(
    response.body !== null,
    "invalid-response",
    "The hosted video body cannot be verified.",
  );
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > expectedLength) {
        await reader.cancel();
        throw new PublishedVideoError(
          "invalid-response",
          "The hosted video exceeds its immutable byte length.",
        );
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  requirePublished(
    total === expectedLength,
    "invalid-response",
    "The hosted video byte length is invalid.",
  );
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function hexadecimal(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function fetchPublishedVideo(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
  signal?: AbortSignal,
): Promise<{ url: string; blob: Blob }> {
  const url = publishedVideoUrlFor(bundle, resultUrl, trustedOrigin);
  const artifact = bundle.result.exports.video.artifact;
  requirePublished(
    artifact !== null,
    "not-published",
    "This result has no verified hosted video.",
  );

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: signal ?? null,
    });
  } catch (error) {
    if (signal?.aborted || abortLike(error)) {
      throw new PublishedVideoError("aborted", "Hosted video verification was cancelled.");
    }
    throw new PublishedVideoError("network-failed", "The hosted video could not be reached.");
  }

  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  const contentLength = response.headers.get("Content-Length");
  const etag = response.headers.get("ETag");
  requirePublished(
    response.ok &&
      response.status === 200 &&
      !response.redirected &&
      response.url === url &&
      contentType === "video/mp4" &&
      etag === `"${artifact.sha256}"` &&
      (contentLength === null || contentLength === String(artifact.byteLength)),
    "invalid-response",
    "The hosted video response failed verification.",
  );

  let bytes: Uint8Array;
  try {
    bytes = await boundedResponseBytes(response, artifact.byteLength);
  } catch (error) {
    if (error instanceof PublishedVideoError) throw error;
    if (signal?.aborted || abortLike(error)) {
      throw new PublishedVideoError("aborted", "Hosted video verification was cancelled.");
    }
    throw new PublishedVideoError("invalid-response", "The hosted video body was unreadable.");
  }

  requirePublished(
    bytes.byteLength >= 12 &&
      String.fromCharCode(...bytes.subarray(4, 8)) === "ftyp",
    "invalid-response",
    "The hosted video is not an MP4 file.",
  );
  requirePublished(
    globalThis.crypto?.subtle !== undefined,
    "digest-unavailable",
    "This browser cannot verify the hosted video.",
  );
  if (signal?.aborted) {
    throw new PublishedVideoError("aborted", "Hosted video verification was cancelled.");
  }
  const body = ownedArrayBuffer(bytes);
  let digest: string;
  try {
    digest = hexadecimal(await globalThis.crypto.subtle.digest("SHA-256", body));
  } catch {
    throw new PublishedVideoError(
      "digest-unavailable",
      "This browser cannot verify the hosted video.",
    );
  }
  requirePublished(
    digest === artifact.sha256,
    "digest-mismatch",
    "The hosted video does not match its immutable manifest.",
  );
  return {
    url,
    blob: new Blob([body], { type: "video/mp4" }),
  };
}

export function videoFilename(pageLabel: string): string {
  const safeLabel = pageLabel
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  return `${safeLabel || "result"}-dom-x-ray.mp4`;
}
