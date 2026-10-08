import { parsePublicUrl } from "../shared/public_url.mjs";

let bytes = 0;
const chunks = [];
for await (const chunk of process.stdin) {
  bytes += chunk.length;
  if (bytes > 16384) process.exit(2);
  chunks.push(chunk);
}
try {
  const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!input || Object.keys(input).sort().join(",") !== "nonce,purpose,url" ||
      typeof input.nonce !== 'string' || !/^[0-9a-f]{32}$/u.test(input.nonce)) process.exit(2);
  const result = parsePublicUrl(input.url, input.purpose);
  process.stdout.write(JSON.stringify({ nonce: input.nonce, result }) + "\n");
} catch {
  process.exit(2);
}
