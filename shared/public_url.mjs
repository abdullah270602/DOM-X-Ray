// Shared structural policy over each runtime's native WHATWG URL implementation.
// This does not resolve DNS or authorize any destination.
export const PUBLIC_URL_POLICY = "public-url-whatwg-v1";
export const MAX_URL_LENGTH = 2048;

export function parsePublicUrl(value, purpose = "initial") {
  const fail = (code) => ({ ok: false, code });
  if (!["initial", "redirect", "subresource"].includes(purpose)) return fail("invalid-purpose");
  if (typeof value !== "string" || !value || value.length > MAX_URL_LENGTH ||
      /[\u0000-\u0020\u007f\\\uD800-\uDFFF]/u.test(value)) return fail("invalid-url");
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu.exec(value)?.[1];
  if (!authority) return fail("invalid-url");
  if (authority.includes("@")) return fail("credentials");
  if (authority.includes("%")) return fail("malformed-authority");
  if (purpose === "initial" && /[?#]/u.test(value)) return fail("initial-target-data");
  let parsed;
  try { parsed = new URL(value); } catch { return fail("invalid-url"); }
  if (!["http:", "https:"].includes(parsed.protocol)) return fail("unsupported-scheme");
  if (parsed.username || parsed.password) return fail("credentials");
  if (parsed.href.length > MAX_URL_LENGTH) return fail("invalid-url");
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "");
  if (!hostname || hostname.endsWith(".") || hostname.length > 253) return fail("malformed-host");
  if (!hostname.includes(":")) {
    if (hostname.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
      return fail("malformed-host");
    }
    const rawHost = authority.replace(/:[0-9]*$/u, "").toLowerCase();
    const components = rawHost.split(".");
    if (components.length <= 4 && components.every((part) => /^(?:0x[0-9a-f]+|[0-9]+)$/u.test(part))) {
      if (components.length !== 4 || components.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part) || Number(part) > 255)) {
        return fail("ambiguous-ipv4");
      }
    }
  }
  const scheme = parsed.protocol.slice(0, -1);
  const port = parsed.port ? Number(parsed.port) : scheme === "https" ? 443 : 80;
  if (![80, 443].includes(port)) return fail("disallowed-port");
  return { ok: true, policy: PUBLIC_URL_POLICY, href: parsed.href, scheme, hostname, port };
}

export function resolvePublicUrl(reference, base) {
  const fail = (code) => ({ ok: false, code });
  const checkedBase = parsePublicUrl(base, "subresource");
  if (!checkedBase.ok) return checkedBase;
  if (typeof reference !== "string" || reference.length > MAX_URL_LENGTH ||
      /[\u0000-\u0020\u007f\\\uD800-\uDFFF]/u.test(reference)) return fail("invalid-url");
  // Validate raw absolute/network authorities before serialization can erase
  // empty userinfo or reinterpret numeric/escaped hosts. Scheme-bearing refs
  // retain the policy's explicit scheme:// requirement.
  if (/^[a-z][a-z0-9+.-]*:/iu.test(reference)) {
    return parsePublicUrl(reference, "redirect");
  }
  if (reference.startsWith("//")) {
    return parsePublicUrl(checkedBase.scheme + ":" + reference, "redirect");
  }
  try {
    return parsePublicUrl(new URL(reference, checkedBase.href).href, "redirect");
  } catch {
    return fail("invalid-url");
  }
}
