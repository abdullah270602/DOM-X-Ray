export const PUBLIC_URL_POLICY: "public-url-whatwg-v1";
export const MAX_URL_LENGTH: 2048;
export type PublicUrlResult = { ok: false; code: string } | {
  ok: true; policy: "public-url-whatwg-v1"; href: string; scheme: "http" | "https";
  hostname: string; port: number;
};
export function parsePublicUrl(value: unknown, purpose?: "initial" | "redirect" | "subresource"): PublicUrlResult;
export function resolvePublicUrl(reference: unknown, base: unknown): PublicUrlResult;
