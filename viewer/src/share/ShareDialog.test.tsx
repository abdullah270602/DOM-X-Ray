// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fixtures } from "../domain/fixtures";
import type { ViewerBundle } from "../domain/types";
import { ShareDialog } from "./ShareDialog";

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hexadecimal(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

async function readyBundle(bytes: Uint8Array): Promise<ViewerBundle> {
  const bundle = structuredClone(fixtures["image-heavy"]);
  bundle.result.exports.poster.state = "ready";
  bundle.result.exports.poster.artifact = {
    sha256: hexadecimal(await crypto.subtle.digest("SHA-256", ownedArrayBuffer(bytes))),
    byteLength: bytes.byteLength,
  };
  return bundle;
}

function posterResponse(bytes: Uint8Array, url: string, sha256: string): Response {
  const response = new Response(ownedArrayBuffer(bytes), {
    status: 200,
    headers: {
      "Content-Type": "image/png",
      "Content-Length": String(bytes.byteLength),
      ETag: `"${sha256}"`,
    },
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:verified-poster");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ShareDialog hosted poster", () => {
  it("shows, downloads, and copies a hosted PNG only after digest verification", async () => {
    const bytes = new TextEncoder().encode("trusted hosted poster");
    const bundle = await readyBundle(bytes);
    const resultUrl = `${window.location.origin}${bundle.result.resultPath}`;
    const posterUrl = `${window.location.origin}/api/results/${bundle.result.resultId}/poster.png`;
    const artifact = bundle.result.exports.poster.artifact!;
    vi.mocked(fetch).mockResolvedValue(posterResponse(bytes, posterUrl, artifact.sha256));
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext");
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);

    render(
      <ShareDialog
        bundle={bundle}
        resultUrl={resultUrl}
        onClose={vi.fn()}
        onNewScan={vi.fn()}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "SHARE RESULT" });
    await within(dialog).findByText("SERVER COPY MATCHES IMMUTABLE MANIFEST");
    expect(within(dialog).getByRole("img").getAttribute("src")).toBe("blob:verified-poster");
    expect(within(dialog).getByText(/VERIFIED HOSTED ARTIFACT/u)).toBeTruthy();

    await user.click(within(dialog).getByRole("button", { name: "COPY PNG LINK" }));
    await within(dialog).findByText("PNG LINK COPIED");
    expect(writeText).toHaveBeenCalledWith(posterUrl);

    await user.click(within(dialog).getByRole("button", { name: "DOWNLOAD POSTER" }));
    await within(dialog).findByText("VERIFIED HOSTED PNG · DOWNLOAD STARTED");
    expect(canvasContext).not.toHaveBeenCalled();
  });

  it("keeps the evidence-bound local export when hosted verification fails", async () => {
    const bytes = new TextEncoder().encode("trusted hosted poster");
    const bundle = await readyBundle(bytes);
    const resultUrl = `${window.location.origin}${bundle.result.resultPath}`;
    vi.mocked(fetch).mockRejectedValue(new Error("private network detail"));

    render(
      <ShareDialog
        bundle={bundle}
        resultUrl={resultUrl}
        onClose={vi.fn()}
        onNewScan={vi.fn()}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "SHARE RESULT" });
    await within(dialog).findByText("SERVER COPY UNAVAILABLE · LOCAL EXPORT STILL WORKS");
    expect(within(dialog).getByRole("img").getAttribute("src")).toMatch(/^data:image\/svg\+xml/u);
    expect(
      (within(dialog).getByRole("button", { name: "DOWNLOAD POSTER" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(within(dialog).queryByRole("button", { name: "COPY PNG LINK" })).toBeNull();
  });

  it("revokes the verified preview URL when the dialog closes", async () => {
    const bytes = new TextEncoder().encode("trusted hosted poster");
    const bundle = await readyBundle(bytes);
    const resultUrl = `${window.location.origin}${bundle.result.resultPath}`;
    const posterUrl = `${window.location.origin}/api/results/${bundle.result.resultId}/poster.png`;
    const artifact = bundle.result.exports.poster.artifact!;
    vi.mocked(fetch).mockResolvedValue(posterResponse(bytes, posterUrl, artifact.sha256));
    const rendered = render(
      <ShareDialog
        bundle={bundle}
        resultUrl={resultUrl}
        onClose={vi.fn()}
        onNewScan={vi.fn()}
      />,
    );
    await screen.findByText("SERVER COPY MATCHES IMMUTABLE MANIFEST");
    rendered.unmount();
    await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:verified-poster"));
  });

  it("never exposes a previously verified poster after the result binding changes", async () => {
    const bytes = new TextEncoder().encode("trusted hosted poster");
    const firstBundle = await readyBundle(bytes);
    const firstResultUrl = `${window.location.origin}${firstBundle.result.resultPath}`;
    const firstPosterUrl = `${window.location.origin}/api/results/${firstBundle.result.resultId}/poster.png`;
    const artifact = firstBundle.result.exports.poster.artifact!;
    let resolveSecond: ((response: Response) => void) | undefined;
    const secondResponse = new Promise<Response>((resolve) => {
      resolveSecond = resolve;
    });
    vi.mocked(fetch)
      .mockResolvedValueOnce(posterResponse(bytes, firstPosterUrl, artifact.sha256))
      .mockImplementationOnce(() => secondResponse);

    const rendered = render(
      <ShareDialog
        bundle={firstBundle}
        resultUrl={firstResultUrl}
        onClose={vi.fn()}
        onNewScan={vi.fn()}
      />,
    );
    await screen.findByText("SERVER COPY MATCHES IMMUTABLE MANIFEST");

    const secondBundle = structuredClone(firstBundle);
    secondBundle.result.resultId = `r_${"b".repeat(32)}`;
    secondBundle.result.resultPath = `/r/${secondBundle.result.resultId}`;
    const secondResultUrl = `${window.location.origin}${secondBundle.result.resultPath}`;
    const secondPosterUrl = `${window.location.origin}/api/results/${secondBundle.result.resultId}/poster.png`;
    rendered.rerender(
      <ShareDialog
        bundle={secondBundle}
        resultUrl={secondResultUrl}
        onClose={vi.fn()}
        onNewScan={vi.fn()}
      />,
    );

    expect(screen.getByText("VERIFYING SERVER COPY")).toBeTruthy();
    expect(screen.getByRole("img").getAttribute("src")).toMatch(/^data:image\/svg\+xml/u);
    expect(screen.queryByRole("button", { name: "COPY PNG LINK" })).toBeNull();

    resolveSecond?.(posterResponse(bytes, secondPosterUrl, artifact.sha256));
    await screen.findByText("SERVER COPY MATCHES IMMUTABLE MANIFEST");
  });
});
