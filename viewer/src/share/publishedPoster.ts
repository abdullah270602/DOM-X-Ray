import type { ViewerBundle } from "../domain/types";

const POSTER_SIZE = 1080;
const POSTER_BYTE_LIMIT = 5_000_000;
const RESULT_ID = /^r_[0-9a-f]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export type PublishedPosterErrorCode =
  | "invalid-binding"
  | "not-published"
  | "network-failed"
  | "aborted"
  | "invalid-response"
  | "digest-unavailable"
  | "digest-mismatch";

export class PublishedPosterError extends Error {
  readonly code: PublishedPosterErrorCode;

  constructor(code: PublishedPosterErrorCode, message: string) {
    super(message);
    this.name = "PublishedPosterError";
    this.code = code;
  }
}

function requirePublished(
  condition: unknown,
  code: PublishedPosterErrorCode,
  message: string,
): asserts condition {
  if (!condition) throw new PublishedPosterError(code, message);
}

function parseUrl(value: string, label: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new PublishedPosterError("invalid-binding", `${label} is invalid.`);
  }
}

export function publishedPosterUrlFor(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
): string {
  const trusted = parseUrl(trustedOrigin, "Trusted origin");
  const result = parseUrl(resultUrl, "Result URL");
  const resultId = bundle.result.resultId;
  const poster = bundle.result.exports.poster;
  const artifact = poster.artifact;

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
    "The published poster route is not bound to this result.",
  );
  requirePublished(
    bundle.result.shareState === "artifact-eligible" &&
      bundle.result.hero?.shareEligible === true &&
      poster.eligible &&
      poster.state === "ready" &&
      poster.mediaType === "image/png" &&
      poster.width === POSTER_SIZE &&
      poster.height === POSTER_SIZE &&
      poster.maxByteLength === POSTER_BYTE_LIMIT &&
      artifact !== null &&
      SHA256.test(artifact.sha256) &&
      Number.isInteger(artifact.byteLength) &&
      artifact.byteLength > 0 &&
      artifact.byteLength <= POSTER_BYTE_LIMIT,
    "not-published",
    "This result has no verified hosted poster.",
  );
  requirePublished(
    poster.sourceResultBindingSha256 === bundle.result.sourceHashes.resultBindingSha256 &&
      poster.sourceSceneSha256 === bundle.result.sourceHashes.sceneManifestSha256 &&
      poster.sourceHeroSha256 === bundle.result.sourceHashes.heroSha256,
    "invalid-binding",
    "The hosted poster sources do not match this result.",
  );

  return new URL(`/api/results/${resultId}/poster.png`, trusted).href;
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
    "The hosted poster body cannot be verified.",
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
        throw new PublishedPosterError(
          "invalid-response",
          "The hosted poster exceeds its immutable byte length.",
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
    "The hosted poster byte length is invalid.",
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

export async function fetchPublishedPoster(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
  signal?: AbortSignal,
): Promise<{ url: string; blob: Blob }> {
  const url = publishedPosterUrlFor(bundle, resultUrl, trustedOrigin);
  const artifact = bundle.result.exports.poster.artifact;
  requirePublished(
    artifact !== null,
    "not-published",
    "This result has no verified hosted poster.",
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
      throw new PublishedPosterError("aborted", "Hosted poster verification was cancelled.");
    }
    throw new PublishedPosterError("network-failed", "The hosted poster could not be reached.");
  }

  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  const contentLength = response.headers.get("Content-Length");
  const etag = response.headers.get("ETag");
  requirePublished(
    response.ok &&
      response.status === 200 &&
      !response.redirected &&
      response.url === url &&
      contentType === "image/png" &&
      etag === `"${artifact.sha256}"` &&
      (contentLength === null || contentLength === String(artifact.byteLength)),
    "invalid-response",
    "The hosted poster response failed verification.",
  );

  let bytes: Uint8Array;
  try {
    bytes = await boundedResponseBytes(response, artifact.byteLength);
  } catch (error) {
    if (error instanceof PublishedPosterError) throw error;
    if (signal?.aborted || abortLike(error)) {
      throw new PublishedPosterError("aborted", "Hosted poster verification was cancelled.");
    }
    throw new PublishedPosterError("invalid-response", "The hosted poster body was unreadable.");
  }

  requirePublished(
    globalThis.crypto?.subtle !== undefined,
    "digest-unavailable",
    "This browser cannot verify the hosted poster.",
  );
  if (signal?.aborted) {
    throw new PublishedPosterError("aborted", "Hosted poster verification was cancelled.");
  }
  const body = ownedArrayBuffer(bytes);
  let digest: string;
  try {
    digest = hexadecimal(await globalThis.crypto.subtle.digest("SHA-256", body));
  } catch {
    throw new PublishedPosterError(
      "digest-unavailable",
      "This browser cannot verify the hosted poster.",
    );
  }
  requirePublished(
    digest === artifact.sha256,
    "digest-mismatch",
    "The hosted poster does not match its immutable manifest.",
  );
  return {
    url,
    blob: new Blob([body], { type: "image/png" }),
  };
}
