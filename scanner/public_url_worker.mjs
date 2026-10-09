import { parsePublicUrl, resolvePublicUrl } from "../shared/public_url.mjs";

let bytes = 0;
const chunks = [];
for await (const chunk of process.stdin) {
  bytes += chunk.length;
  if (bytes > 16384) process.exit(2);
  chunks.push(chunk);
}
try {
  const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const fields = input && Object.keys(input).sort().join(",");
  if (!input || !["nonce,purpose,url", "base,nonce,purpose,url"].includes(fields) ||
      typeof input.nonce !== 'string' || !/^[0-9a-f]{32}$/u.test(input.nonce)) process.exit(2);
  if (fields.startsWith("base,") && input.purpose !== "redirect") process.exit(2);
  const result = fields.startsWith("base,") ? resolvePublicUrl(input.url, input.base)
    : parsePublicUrl(input.url, input.purpose);
  process.stdout.write(JSON.stringify({ nonce: input.nonce, result }) + "\n");
} catch {
  process.exit(2);
}
