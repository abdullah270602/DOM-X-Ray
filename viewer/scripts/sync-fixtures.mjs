import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standaloneCode from "ajv/dist/standalone/index.js";

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
  "docs/SCAN_SUBMISSION.schema.json",
  "docs/SCAN_JOB.schema.json",
  "docs/VIEWER_BUNDLE.schema.json",
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

const schemaFiles = contractFiles.filter((path) => path.endsWith(".schema.json"));
const schemas = await Promise.all(
  schemaFiles.map(async (path) => JSON.parse(await readFile(resolve(repositoryRoot, path), "utf8"))),
);
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictTypes: false,
  strictRequired: false,
  code: { source: true, esm: true },
});
addFormats(ajv);
schemas.forEach((schema) => ajv.addSchema(schema));
const validatorExports = {
  validateRecord: "https://dom-x-ray.invalid/schema/scan-record-v0.1.json",
  validateScene: "https://dom-x-ray.invalid/schema/scene-manifest-v0.1.0.json",
  validateResult: "https://dom-x-ray.invalid/schema/result-manifest-v0.1.0.json",
  validateRuntime: "https://dom-x-ray.invalid/schema/viewer-runtime-v0.1.0.json",
  validateBundle: "https://dom-x-ray.invalid/schema/viewer-bundle-v0.1.0.json",
  validateJob: "https://dom-x-ray.invalid/schema/scan-job-v0.1.0.json",
};

function browserEsmValidatorCode(source) {
  const imports = [
    'import ajvFormatsModule from "ajv-formats/dist/formats.js";',
    'import ajvEqualModule from "ajv/dist/runtime/equal.js";',
    'import ajvUcs2LengthModule from "ajv/dist/runtime/ucs2length.js";',
    "const ajvRuntimeDefault = (module) => typeof module === \"function\" ? module : module.default;",
  ].join("\n");
  const rewritten = source
    .replaceAll('require("ajv-formats/dist/formats")', "ajvFormatsModule")
    .replaceAll('require("ajv/dist/runtime/equal").default', "ajvRuntimeDefault(ajvEqualModule)")
    .replaceAll(
      'require("ajv/dist/runtime/ucs2length").default',
      "ajvRuntimeDefault(ajvUcs2LengthModule)",
    );
  if (rewritten.includes("require(")) {
    throw new Error("AJV emitted an unhandled CommonJS runtime dependency");
  }
  return `${imports}\n${rewritten}`;
}

await writeFile(
  resolve(outputRoot, "validators.mjs"),
  browserEsmValidatorCode(standaloneCode(ajv, validatorExports)),
  "utf8",
);
await writeFile(
  resolve(outputRoot, "validators.d.mts"),
  [
    'import type { ValidateFunction } from "ajv";',
    ...Object.keys(validatorExports).map((name) => `export const ${name}: ValidateFunction;`),
    "",
  ].join("\n"),
  "utf8",
);
console.log("Synced validated viewer fixtures from the repository contracts.");
