import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import mappingJson from "../fixtures/generated/contracts/MAPPING_REGISTRY.v0.1.json";
import resultSchema from "../fixtures/generated/contracts/RESULT_MANIFEST.schema.json";
import scanSchema from "../fixtures/generated/contracts/SCAN_RECORD.schema.json";
import sceneSchema from "../fixtures/generated/contracts/SCENE_MANIFEST.schema.json";
import runtimeSchema from "../fixtures/generated/contracts/VIEWER_RUNTIME.schema.json";
import cleanRecord from "../fixtures/generated/scan/clean.json";
import imageRecord from "../fixtures/generated/scan/image-heavy.json";
import thirdRecord from "../fixtures/generated/scan/third-party-heavy.json";
import cleanScene from "../fixtures/generated/scene-manifest/clean.json";
import imageScene from "../fixtures/generated/scene-manifest/image-heavy.json";
import thirdScene from "../fixtures/generated/scene-manifest/third-party-heavy.json";
import cleanResult from "../fixtures/generated/result-manifest/clean.json";
import imageResult from "../fixtures/generated/result-manifest/image-heavy.json";
import thirdResult from "../fixtures/generated/result-manifest/third-party-heavy.json";
import cleanRuntime from "../fixtures/generated/viewer-runtime/clean.json";
import imageRuntime from "../fixtures/generated/viewer-runtime/image-heavy.json";
import thirdRuntime from "../fixtures/generated/viewer-runtime/third-party-heavy.json";
import { resolvePointer, validateSelectablePointers } from "./pointer";
import type {
  FixtureName,
  ResultManifest,
  ScanRecord,
  SceneManifest,
  ViewerBundle,
  ViewerRuntime,
} from "./types";

// The committed conditional schemas inherit array types from their parent branch.
// Ajv's strict type and required lints require inherited branch declarations to
// be repeated locally, so only those lints are disabled. Validation stays active.
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictTypes: false,
  strictRequired: false,
});
addFormats(ajv);

const validators = {
  record: ajv.compile(scanSchema),
  scene: ajv.compile(sceneSchema),
  result: ajv.compile(resultSchema),
  runtime: ajv.compile(runtimeSchema),
};

const rawCatalog: Record<
  FixtureName,
  { record: unknown; scene: unknown; result: unknown; runtime: unknown }
> = {
  clean: {
    record: cleanRecord,
    scene: cleanScene,
    result: cleanResult,
    runtime: cleanRuntime,
  },
  "image-heavy": {
    record: imageRecord,
    scene: imageScene,
    result: imageResult,
    runtime: imageRuntime,
  },
  "third-party-heavy": {
    record: thirdRecord,
    scene: thirdScene,
    result: thirdResult,
    runtime: thirdRuntime,
  },
};

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  if (!errors?.length) return "unknown contract error";
  return errors
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}

function assertSchema(
  label: string,
  value: unknown,
  validator: ValidateFunction,
): void {
  if (!validator(value)) {
    throw new Error(`${label} failed its JSON Schema: ${formatErrors(validator.errors)}`);
  }
}

function assertBundleIdentity(bundle: Omit<ViewerBundle, "name">): void {
  const { record, scene, result, runtime, mapping } = bundle;
  const scanIds = [record.scanId, scene.scanId, result.scanId, runtime.scanId];
  if (new Set(scanIds).size !== 1) throw new Error("Fixture scan identities drifted.");
  if (runtime.resultId !== result.resultId || runtime.resultPath !== result.resultPath) {
    throw new Error("Runtime route identity drifted from the result manifest.");
  }
  if (
    record.mappingVersion !== mapping.version ||
    scene.mappingVersion !== mapping.version ||
    result.mappingVersion !== mapping.version ||
    runtime.mappingVersion !== mapping.version
  ) {
    throw new Error("Fixture mapping versions drifted.");
  }
  if (result.sceneManifestVersion !== scene.manifestVersion) {
    throw new Error("Result and scene manifest versions drifted.");
  }
  if (
    runtime.sourceHashes.scanRecordSha256 !== result.sourceHashes.scanRecordSha256 ||
    runtime.sourceHashes.sceneManifestSha256 !== result.sourceHashes.sceneManifestSha256 ||
    runtime.sourceHashes.mappingRegistrySha256 !== result.sourceHashes.mappingRegistrySha256 ||
    runtime.sourceHashes.resultBindingSha256 !== result.sourceHashes.resultBindingSha256
  ) {
    throw new Error("Runtime source bindings drifted from the result manifest.");
  }

  const objectIds = new Set(scene.objects.map((item) => item.id));
  for (const connection of scene.connections) {
    const endpointIds = [
      connection.sourceObjectId,
      ...connection.targetObjectIds,
      ...(connection.fallbackObjectId ? [connection.fallbackObjectId] : []),
    ];
    endpointIds.forEach((id) => {
      if (!objectIds.has(id)) throw new Error(`Connection endpoint does not exist: ${id}`);
    });
  }

  const selectableIds = runtime.selectables.map((item) => item.id);
  if (new Set(selectableIds).size !== selectableIds.length) {
    throw new Error("Selectable IDs are not unique.");
  }
  runtime.selectables.forEach((selectable) => {
    validateSelectablePointers(bundle, selectable);
    if (!selectable.renderable && selectable.id === runtime.initialStates.standard.isolatedId) {
      throw new Error("Non-renderable evidence cannot be initially isolated.");
    }
  });
  runtime.presentation.limitationResultRefs.forEach((ref) => resolvePointer(result, ref));
}

function validateFixture(name: FixtureName): ViewerBundle {
  const raw = rawCatalog[name];
  assertSchema(`${name} scan record`, raw.record, validators.record);
  assertSchema(`${name} scene manifest`, raw.scene, validators.scene);
  assertSchema(`${name} result manifest`, raw.result, validators.result);
  assertSchema(`${name} viewer runtime`, raw.runtime, validators.runtime);

  const bundle: ViewerBundle = {
    name,
    record: raw.record as ScanRecord,
    scene: raw.scene as SceneManifest,
    result: raw.result as ResultManifest,
    runtime: raw.runtime as ViewerRuntime,
    mapping: mappingJson as ViewerBundle["mapping"],
  };
  assertBundleIdentity(bundle);
  return bundle;
}

export const fixtureNames: FixtureName[] = [
  "clean",
  "image-heavy",
  "third-party-heavy",
];

export const fixtures: Record<FixtureName, ViewerBundle> = {
  clean: validateFixture("clean"),
  "image-heavy": validateFixture("image-heavy"),
  "third-party-heavy": validateFixture("third-party-heavy"),
};

export function fixtureFromUrl(url: string): FixtureName {
  const host = new URL(url).hostname;
  if (host.includes("gallery") || host.includes("image")) return "image-heavy";
  if (host.includes("news") || host.includes("third")) return "third-party-heavy";
  return "clean";
}
