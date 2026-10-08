import { describe, expect, it } from "vitest";
import { parsePublicUrl } from "../../../shared/public_url.mjs";

describe("shared public URL structural policy", () => {
  it.each([
    ["https://EXAMPLE.com:443/a/../b", "https://example.com/b"],
    ["https://bücher.example/", "https://xn--bcher-kva.example/"],
    ["https://faß.example/", "https://xn--fa-hia.example/"],
    ["https://食狮.公司.cn/", "https://xn--85x722f.xn--55qx5d.cn/"],
    ["http://[2606:4700:4700::1111]/", "http://[2606:4700:4700::1111]/"],
    ["https://example.com/%2e%2e/b", "https://example.com/b"],
  ])("canonicalizes %s", (input, href) => {
    expect(parsePublicUrl(input)).toMatchObject({ ok: true, href });
  });
  it.each([
    ["https://example.com/?", "initial-target-data"],
    ["https://example.com/#", "initial-target-data"],
    ["https://@example.com/", "credentials"],
    ["https://user:pass@example.com/", "credentials"],
    ["https://%65xample.com/", "malformed-authority"],
    ["https://example.com:8443/", "disallowed-port"],
    ["http://2130706433/", "ambiguous-ipv4"],
    ["http://127.1/", "ambiguous-ipv4"],
    ["http://0177.0.0.1/", "ambiguous-ipv4"],
    ["https://example.com./", "malformed-host"],
    ["https://foo_bar.example/", "malformed-host"],
    ["https://example.com/\\private", "invalid-url"],
    [" https://example.com/", "invalid-url"],
    ["https://example.com/\ud800", "invalid-url"],
  ])("rejects %s", (input, code) => {
    expect(parsePublicUrl(input)).toEqual({ ok: false, code });
  });
  it("retains subresource query data without treating syntax as a destination grant", () => {
    expect(parsePublicUrl("https://example.com/script?v=1", "subresource")).toMatchObject({ ok: true });
    expect(parsePublicUrl("http://127.0.0.1/")).toMatchObject({ ok: true });
    expect(parsePublicUrl("x".repeat(2049))).toEqual({ ok: false, code: "invalid-url" });
  });
});
