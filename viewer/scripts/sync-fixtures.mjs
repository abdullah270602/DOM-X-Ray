import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const viewerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(viewerRoot, "..");
const outputRoot = resolve(viewerRoot, "src", "fixtures", "generated");
const fixtureGroups = [
  ["fixtures/scan", "scan"],
  ["fixtures/scene-manifest", "scene-manifest"],
  ["fixtures/result-manifest", "result-manifest"],
  ["fixtures/viewer-runtime", "viewer-runtime"],
];
const contractFiles = [
  "docs/SCAN_RECORD.schema.json",
  "docs/SCENE_MANIFEST.schema.json",
  "docs/RESULT_MANIFEST.schema.json",
  "docs/VIEWER_RUNTIME.schema.json",
  "docs/MAPPING_REGISTRY.v0.1.json",
];

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
for (const [source, target] of fixtureGroups) {
  await cp(resolve(repositoryRoot, source), resolve(outputRoot, target), { recursive: true });
}
await mkdir(resolve(outputRoot, "contracts"), { recursive: true });
for (const source of contractFiles) {
  await cp(
    resolve(repositoryRoot, source),
    resolve(outputRoot, "contracts", source.split("/").at(-1)),
  );
}
console.log("Synced validated viewer fixtures from the repository contracts.");
