import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import * as generated from "../src/fixtures/generated/validators.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const names = ["SCAN_RECORD", "SCENE_MANIFEST", "RESULT_MANIFEST", "VIEWER_RUNTIME", "SCAN_SUBMISSION", "SCAN_JOB", "VIEWER_BUNDLE"];
const schemas = await Promise.all(names.map(async name => JSON.parse(await readFile(resolve(root, `docs/${name}.schema.json`), "utf8"))));
const baseline = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false, inlineRefs: true });
addFormats(baseline);
schemas.forEach(schema => baseline.addSchema(schema));
const pairs = [
  ["validateRecord", schemas[0], "scan"], ["validateScene", schemas[1], "scene-manifest"],
  ["validateResult", schemas[2], "result-manifest"], ["validateRuntime", schemas[3], "viewer-runtime"],
];
let count = 0;
function check(name, schema, value) {
  const validator = baseline.getSchema(schema.$id);
  const expected = validator(structuredClone(value));
  assert.equal(generated[name](structuredClone(value)), expected, `${name}: acceptance changed`);
  const reportedErrors = errors => (errors ?? []).map(({ instancePath, keyword, message, params }) =>
    JSON.stringify({ instancePath, keyword, message, params })).sort();
  assert.deepEqual(reportedErrors(generated[name].errors), reportedErrors(validator.errors),
    `${name}: reported validation errors changed`);
  count++;
}
for (const profile of ["clean", "image-heavy", "third-party-heavy"]) {
  const parts = {};
  for (const [name, schema, folder] of pairs) {
    const value = JSON.parse(await readFile(resolve(root, `fixtures/${folder}/${profile}.json`), "utf8"));
    parts[folder] = value;
    assert.equal(baseline.getSchema(schema.$id)(value), true, "invalid baseline fixture");
    check(name, schema, value);
    for (const key of Object.keys(value)) {
      const missing = structuredClone(value);
      delete missing[key];
      check(name, schema, missing);
      const wrong = structuredClone(value);
      wrong[key] = { unexpected: true };
      check(name, schema, wrong);
    }
    check(name, schema, { ...value, unexpectedProperty: true });
    for (const wrong of [null, [], false, 0, "not-a-record"]) check(name, schema, wrong);
  }
  const mapping = JSON.parse(await readFile(resolve(root, "docs/MAPPING_REGISTRY.v0.1.json"), "utf8"));
  const bundle = { bundleVersion: "viewer-bundle-v0.1.0", record: parts.scan,
    scene: parts["scene-manifest"], result: parts["result-manifest"], runtime: parts["viewer-runtime"], mapping };
  assert.equal(baseline.getSchema(schemas[6].$id)(bundle), true, "invalid baseline bundle");
  check("validateBundle", schemas[6], bundle);
  for (const key of ["record", "scene", "result", "runtime", "mapping"]) {
    const changed = structuredClone(bundle);
    changed[key].unexpectedProperty = true;
    check("validateBundle", schemas[6], changed);
    changed[key] = null;
    check("validateBundle", schemas[6], changed);
  }
}
for (const value of [null, {}, [], { jobId: "bad", state: "ready", progress: NaN }]) {
  check("validateJob", schemas[5], value);
}
console.log(`${count} selected validator decisions and normalized errors match the prior inline-reference compiler. Not exhaustive schema equivalence proof.`);
