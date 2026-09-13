// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fixtures } from "../domain/fixtures";
import type { ScanJob } from "../domain/types";
import { App } from "./App";


function readyJob(resultId: string): ScanJob {
  return {
    apiVersion: "scan-api-v0.1.0",
    jobId: "j_0123456789abcdef0123456789abcdef",
    state: "ready",
    progress: "complete",
    submittedAt: "2026-09-11T00:00:00Z",
    updatedAt: "2026-09-11T00:00:01Z",
    scanStatus: "complete",
    result: {
      resultId,
      resultPath: `/r/${resultId}`,
      bundleUrl: `/api/results/${resultId}`,
    },
    error: null,
    pollAfterMs: null,
  };
}

async function immutableResponse(value: object): Promise<Response> {
  const body = JSON.stringify(value);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  const etag = `"${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}"`;
  return new Response(body, { headers: { "Content-Type": "application/json", ETag: etag } });
}

function wireBundleFor(name: keyof typeof fixtures) {
  const fixture = fixtures[name];
  return {
    bundleVersion: fixture.bundleVersion,
    record: fixture.record,
    scene: fixture.scene,
    result: fixture.result,
    runtime: fixture.runtime,
    mapping: fixture.mapping,
  };
}

beforeEach(() => {
  window.history.replaceState(null, "", "/?fixture=image-heavy&fallback=text");
  window.localStorage.clear();
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({
      matches: false,
      media: "",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  );
  vi.stubGlobal("confirm", vi.fn(() => true));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("published result ownership", () => {
  it("keeps deletion authority local, survives reload storage, and recovers after deletion", async () => {
    const fixture = fixtures["image-heavy"];
    const resultId = fixture.result.resultId;
    const wireBundle = {
      bundleVersion: fixture.bundleVersion,
      record: fixture.record,
      scene: fixture.scene,
      result: fixture.result,
      runtime: fixture.runtime,
      mapping: fixture.mapping,
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(readyJob(resultId)), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(await immutableResponse(wireBundle))
      .mockResolvedValueOnce(await immutableResponse(wireBundle))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    const firstRender = render(<App />);
    await user.click(screen.getByRole("button", { name: "START X-RAY" }));

    await screen.findByRole("button", { name: "DELETE RESULT" });
    expect(screen.getByText("STABLE RESULT ROUTE")).toBeTruthy();
    expect(screen.queryByText(readyJob(resultId).jobId)).toBeNull();
    expect(screen.queryByText(resultId)).toBeNull();
    const stored = window.localStorage.getItem(`dom-x-ray:owner:${resultId}`);
    expect(stored).toMatch(/^dxrd_[0-9a-f]{64}$/);
    expect(window.location.pathname).toBe(`/r/${resultId}`);

    firstRender.unmount();
    window.history.replaceState(null, "", `/r/${resultId}?fallback=text`);
    render(<App />);
    const deleteButton = await screen.findByRole("button", { name: "DELETE RESULT" });
    await user.click(deleteButton);
    await screen.findByText("RESULT DELETED · SHARED LINK REMOVED");
    expect(window.confirm).toHaveBeenCalledOnce();
    expect(window.localStorage.getItem(`dom-x-ray:owner:${resultId}`)).toBeNull();
    expect(screen.queryByRole("button", { name: "DELETE RESULT" })).toBeNull();
    expect(window.location.pathname).toBe("/");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));

    expect(JSON.stringify(fetchMock.mock.calls.slice(0, 3))).not.toContain(stored);
    expect(fetchMock.mock.calls[3]?.[1]).toEqual(
      expect.objectContaining({ headers: { "X-Deletion-Token": stored } }),
    );
  });

  it("does not expose deletion controls to a browser without the local key", async () => {
    const fixture = fixtures.clean;
    const resultId = fixture.result.resultId;
    const wireBundle = {
      bundleVersion: fixture.bundleVersion,
      record: fixture.record,
      scene: fixture.scene,
      result: fixture.result,
      runtime: fixture.runtime,
      mapping: fixture.mapping,
    };
    window.history.replaceState(null, "", `/r/${resultId}?fallback=text`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableResponse(wireBundle)));

    render(<App />);
    const input = screen.getByLabelText("PUBLIC PAGE URL") as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe("https://clean.example/"));
    expect(screen.queryByRole("button", { name: "DELETE RESULT" })).toBeNull();
  });
});

describe("published result sharing", () => {
  it("opens a protected preview, copies the exact caption, and restores trigger focus", async () => {
    const fixture = fixtures["image-heavy"];
    const resultId = fixture.result.resultId;
    window.history.replaceState(null, "", `/r/${resultId}?fallback=text`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableResponse(wireBundleFor("image-heavy"))));
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    render(<App />);
    const shareButton = await screen.findByRole("button", { name: "SHARE RESULT" });
    expect(screen.queryByRole("button", { name: "COPY FINDING" })).toBeNull();
    await user.click(shareButton);

    const dialog = screen.getByRole("dialog", { name: "SHARE RESULT" });
    expect(within(dialog).getByRole("img").getAttribute("src")).toMatch(/^data:image\/svg\+xml/u);
    expect(within(dialog).getByRole("button", { name: "DOWNLOAD POSTER" })).toBeTruthy();
    const closeButton = within(dialog).getByRole("button", { name: "CLOSE SHARE RESULT" });
    const newScanButton = within(dialog).getByRole("button", { name: "X-RAY ANOTHER SITE" });
    await waitFor(() => expect(document.activeElement).toBe(closeButton));
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(newScanButton);
    await user.tab();
    expect(document.activeElement).toBe(closeButton);

    await user.click(within(dialog).getByRole("button", { name: "COPY CAPTION" }));
    await screen.findByText("CAPTION COPIED");
    expect(writeText).toHaveBeenCalledWith(
      `${fixture.result.hero?.statement}\n\n${window.location.origin}${fixture.result.resultPath}`,
    );

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "SHARE RESULT" })).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(shareButton));
  });

  it("reports clipboard failure and moves directly to the next URL task", async () => {
    const fixture = fixtures["third-party-heavy"];
    const resultId = fixture.result.resultId;
    window.history.replaceState(null, "", `/r/${resultId}?fallback=text`);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(await immutableResponse(wireBundleFor("third-party-heavy"))),
    );
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("blocked"));
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "SHARE RESULT" }));
    const dialog = screen.getByRole("dialog", { name: "SHARE RESULT" });
    await user.click(within(dialog).getByRole("button", { name: "COPY RESULT LINK" }));
    await screen.findByText("CLIPBOARD BLOCKED · USE YOUR BROWSER COPY CONTROL");
    expect(screen.queryByText("RESULT LINK COPIED")).toBeNull();

    await user.click(within(dialog).getByRole("button", { name: "X-RAY ANOTHER SITE" }));
    const input = screen.getByLabelText("PUBLIC PAGE URL");
    await waitFor(() => expect(document.activeElement).toBe(input));
  });

  it("keeps seeded fixture previews free of public share controls", () => {
    render(<App />);
    expect(screen.queryByRole("button", { name: "SHARE RESULT" })).toBeNull();
    expect(screen.queryByRole("button", { name: "COPY RESULT LINK" })).toBeNull();
  });

  it("keeps a published neutral result link-only", async () => {
    const fixture = fixtures.clean;
    window.history.replaceState(null, "", `/r/${fixture.result.resultId}?fallback=text`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableResponse(wireBundleFor("clean"))));
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);

    render(<App />);
    const copyLink = await screen.findByRole("button", { name: "COPY RESULT LINK" });
    expect(screen.queryByRole("button", { name: "SHARE RESULT" })).toBeNull();
    await user.click(copyLink);
    expect(writeText).toHaveBeenCalledWith(
      `${window.location.origin}${fixture.result.resultPath}`,
    );
    expect(screen.getByRole("button", { name: "RESULT LINK COPIED" })).toBeTruthy();
  });

  it("announces a clipboard failure for a published link-only result", async () => {
    const fixture = fixtures.clean;
    window.history.replaceState(null, "", `/r/${fixture.result.resultId}?fallback=text`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await immutableResponse(wireBundleFor("clean"))));
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("blocked"));

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "COPY RESULT LINK" }));
    expect(screen.getByRole("button", { name: "COPY FAILED" })).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toBe(
      "CLIPBOARD BLOCKED · USE YOUR BROWSER COPY CONTROL",
    );
    expect(screen.queryByText("RESULT LINK COPIED")).toBeNull();
  });
});
