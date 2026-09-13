import type {
  EvidenceMetric,
  HubObject,
  PageBusObject,
  RegionObject,
  SceneObject,
  Vec3,
  ViewerBundle,
} from "../domain/types";

const POSTER_SIZE = 1080;
const POSTER_BYTE_LIMIT = 5_000_000;
const X_POST_LENGTH = 280;
const X_URL_LENGTH = 23;
const unsafePublicText = /[\u0000-\u001f\u007f<>]/u;

const palette = {
  paper: "#e9e1d2",
  paperLight: "#f3ede3",
  graphite: "#20251f",
  soft: "#565b51",
  red: "#d9492f",
  redDark: "#a92e1b",
  teal: "#2d6571",
  board: "#b8aa8b",
  brass: "#9b772f",
};

const resourceLabels: Record<string, string> = {
  image: "IMAGES",
  script: "SCRIPTS",
  stylesheet: "STYLESHEETS",
  font: "FONTS",
  video: "VIDEO",
  audio: "AUDIO",
  document: "DOCUMENTS",
  other: "OTHER",
};

const invalidatedMetricsByRule: Record<string, ReadonlySet<string>> = {
  "dominant-resource-type-share-v1": new Set([
    "total_transferred_bytes",
    "resource_type_transferred_bytes",
    "resource_mass",
  ]),
  "third-party-byte-share-v1": new Set([
    "total_transferred_bytes",
    "resource_type_transferred_bytes",
    "third_party_transferred_bytes",
    "resource_mass",
  ]),
  "largest-exact-resource-share-v1": new Set([
    "total_transferred_bytes",
    "resource_type_transferred_bytes",
    "resource_mass",
  ]),
  "third-party-request-share-v1": new Set(["request_count"]),
};

export type PosterErrorCode =
  | "ineligible-result"
  | "invalid-binding"
  | "invalid-evidence"
  | "invalid-topology"
  | "unsafe-text"
  | "content-overflow"
  | "rasterization-failed"
  | "png-size";

export class PosterContractError extends Error {
  readonly code: PosterErrorCode;

  constructor(code: PosterErrorCode, message: string) {
    super(message);
    this.name = "PosterContractError";
    this.code = code;
  }
}

interface PosterPoint {
  x: number;
  y: number;
}

interface PosterPlate {
  kind: "region" | "aggregate";
  center: Vec3;
  width: number;
  height: number;
  mass: number | null;
  thickness: number | null;
  style: string;
  order: number;
  highlighted: boolean;
}

interface PosterHub {
  center: Vec3;
  highlighted: boolean;
}

interface PosterBus {
  center: Vec3;
}

interface PosterConnection {
  source: Vec3;
  target: Vec3;
  strokeWidth: number;
  dashed: boolean;
  highlighted: boolean;
}

export interface PosterModel {
  width: 1080;
  height: 1080;
  pageLabel: string;
  productName: "DOM X-Ray";
  cta: "X-RAY ANOTHER SITE";
  statusLabel: string;
  partial: boolean;
  headline: string;
  statement: string;
  limitationMessages: string[];
  planeWidth: number;
  planeHeight: number;
  plates: PosterPlate[];
  hubs: PosterHub[];
  buses: PosterBus[];
  connections: PosterConnection[];
  posterMaxByteLength: number;
}

export interface ShareCaption {
  text: string;
  effectiveLength: number;
  tooLong: boolean;
}

function requireContract(
  condition: unknown,
  code: PosterErrorCode,
  message: string,
): asserts condition {
  if (!condition) throw new PosterContractError(code, message);
}

function safeText(value: unknown, label: string): string {
  requireContract(
    typeof value === "string" && value.length > 0 && !unsafePublicText.test(value),
    "unsafe-text",
    `The ${label} is not safe to render.`,
  );
  return value;
}

function finiteNumber(value: unknown, label: string): number {
  requireContract(
    typeof value === "number" && Number.isFinite(value),
    "invalid-binding",
    `${label} is not a finite number.`,
  );
  return value;
}

function finitePoint(value: Vec3, label: string): Vec3 {
  return {
    x: finiteNumber(value.x, `${label} x`),
    y: finiteNumber(value.y, `${label} y`),
    z: finiteNumber(value.z, `${label} z`),
  };
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => sameJsonValue(item, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return sameStrings(leftKeys, rightKeys) &&
    leftKeys.every((key) => sameJsonValue(left[key], right[key]));
}

function requireHeroRecordBinding(bundle: ViewerBundle): void {
  const hero = bundle.result.hero;
  requireContract(hero !== null, "ineligible-result", "This result has no hero evidence.");
  const recordMatch = /^#\/insights\/(\d+)$/u.exec(hero.recordRef);
  requireContract(recordMatch?.[1] !== undefined, "invalid-binding", "The hero record reference is invalid.");
  const insightIndex = Number(recordMatch[1]);
  const insight = bundle.record.insights[insightIndex];
  requireContract(isRecord(insight), "invalid-binding", "The hero record reference does not resolve.");
  requireContract(
    insight.id === hero.insightId && insight.hero === true && insight.kind === hero.kind &&
      insight.statement === hero.statement && insight.selectionRule === hero.selectionRule &&
      isStringArray(insight.limitationCodes) &&
      sameStrings(insight.limitationCodes, hero.limitationCodes) &&
      sameJsonValue(insight.evidence, hero.evidence),
    "invalid-binding",
    "The public hero is not an exact projection of its scan insight.",
  );

  const flattenedRefs: string[] = [];
  const seenRefs = new Set<string>();
  for (const evidence of hero.evidence) {
    requireContract(
      evidence.sourceRefs.length > 0 && new Set(evidence.sourceRefs).size === evidence.sourceRefs.length,
      "invalid-evidence",
      "Hero evidence must bind unique source references.",
    );
    safeText(evidence.rule, "hero evidence rule");
    for (const ref of evidence.sourceRefs) {
      requireContract(ref.startsWith("#/"), "invalid-evidence", "Hero evidence contains an invalid source reference.");
      if (!seenRefs.has(ref)) {
        seenRefs.add(ref);
        flattenedRefs.push(ref);
      }
    }
  }
  requireContract(
    sameStrings(flattenedRefs, hero.sourceRefs),
    "invalid-binding",
    "The hero source binding does not match its evidence.",
  );

  const resultLimitationCodes = bundle.result.limitations.map((item) => item.code);
  const recordLimitationCodes = bundle.record.limitations.map((item) =>
    isRecord(item) && typeof item.code === "string" ? item.code : null
  );
  requireContract(
    recordLimitationCodes.every((code): code is string => code !== null) &&
      sameStrings(hero.limitationCodes, resultLimitationCodes) &&
      sameStrings(hero.limitationCodes, recordLimitationCodes),
    "invalid-binding",
    "The hero limitation binding does not match the capture.",
  );
}

function resourceEvidenceRefs(
  bundle: ViewerBundle,
  evidence: EvidenceMetric,
  allowedFields: ReadonlySet<string>,
): Array<{ index: number; field: string }> {
  return evidence.sourceRefs.map((ref) => {
    const match = /^#\/resources\/(\d+)\/([A-Za-z][A-Za-z0-9]*)$/u.exec(ref);
    const index = match?.[1] === undefined ? Number.NaN : Number(match[1]);
    const field = match?.[2] ?? "";
    requireContract(
      Number.isSafeInteger(index) && bundle.record.resources[index] !== undefined && allowedFields.has(field),
      "invalid-evidence",
      "Headline evidence references an unsupported resource field.",
    );
    return { index, field };
  });
}

function sameUniqueIndices(actual: number[], expected: number[]): boolean {
  if (new Set(actual).size !== actual.length || new Set(expected).size !== expected.length) {
    return false;
  }
  const sortedActual = [...actual].sort((left, right) => left - right);
  const sortedExpected = [...expected].sort((left, right) => left - right);
  return sortedActual.length === sortedExpected.length &&
    sortedActual.every((value, index) => value === sortedExpected[index]);
}

function indicesForField(
  refs: Array<{ index: number; field: string }>,
  field: string,
): number[] {
  return refs.filter((ref) => ref.field === field).map((ref) => ref.index);
}

function knownByteRows(bundle: ViewerBundle): Array<{
  index: number;
  bytes: number;
  type: string;
  party: "first" | "third" | "unknown";
}> {
  return bundle.record.resources.flatMap((resource, index) => {
    if (resource.transferredBytes === null) return [];
    requireContract(
      Number.isSafeInteger(resource.transferredBytes) && resource.transferredBytes >= 0,
      "invalid-evidence",
      "Known resource byte measurements must be non-negative safe integers.",
    );
    return [{
      index,
      bytes: resource.transferredBytes,
      type: resource.type,
      party: resource.party,
    }];
  });
}

function roundedBytePercentage(numerator: number, denominator: number): number {
  requireContract(
    Number.isSafeInteger(numerator) && numerator >= 0 &&
      Number.isSafeInteger(denominator) && denominator > 0,
    "invalid-evidence",
    "Aggregate byte evidence requires a positive safe-integer denominator.",
  );
  const scaledNumerator = numerator * 1_000;
  requireContract(
    Number.isSafeInteger(scaledNumerator),
    "invalid-evidence",
    "Aggregate byte evidence exceeds the reproducible numeric range.",
  );
  const lower = Math.floor(scaledNumerator / denominator);
  const remainder = scaledNumerator % denominator;
  const doubledRemainder = remainder * 2;
  const rounded = doubledRemainder < denominator
    ? lower
    : doubledRemainder > denominator
    ? lower + 1
    : lower % 2 === 0
    ? lower
    : lower + 1;
  return rounded / 10;
}

function requireCaptureStatus(bundle: ViewerBundle): boolean {
  const { status, statusPresentation } = bundle.result;
  const partial = status === "partial";
  requireContract(
    (partial && statusPresentation.label === "PARTIAL CAPTURE" &&
      statusPresentation.partialLabelRequired && bundle.result.limitations.length > 0) ||
      (status === "complete" && statusPresentation.label === "COMPLETE CAPTURE" &&
        !statusPresentation.partialLabelRequired),
    "invalid-binding",
    "The capture status and public status presentation disagree.",
  );
  return partial;
}

function requireSceneHeroBinding(bundle: ViewerBundle): void {
  const hero = bundle.result.hero;
  requireContract(hero !== null, "ineligible-result", "This result has no hero evidence.");
  requireContract(
    bundle.scene.hero !== null && bundle.scene.hero.insightId === hero.insightId &&
      bundle.scene.hero.kind === hero.kind && bundle.scene.hero.statement === hero.statement &&
      bundle.scene.hero.shareEligible === hero.shareEligible &&
      bundle.scene.hero.recordRef === hero.recordRef &&
      sameStrings(bundle.scene.hero.sourceRefs, hero.sourceRefs) &&
      sameStrings(bundle.scene.hero.limitationCodes, hero.limitationCodes),
    "invalid-binding",
    "The scene hero and result hero disagree.",
  );
}

function numericEvidence(
  evidence: EvidenceMetric,
  metric: string,
  unit: string,
): number {
  requireContract(
    evidence.metric === metric && evidence.unit === unit,
    "invalid-evidence",
    `The ${metric} evidence binding is missing.`,
  );
  requireContract(
    evidence.level === "observed" || evidence.level === "derived",
    "invalid-evidence",
    "Poster headlines require observed or derived evidence.",
  );
  const value = finiteNumber(evidence.value, `${metric} value`);
  requireContract(value >= 0, "invalid-evidence", `${metric} cannot be negative.`);
  return value;
}

function oneDecimal(value: number): string {
  return value.toFixed(1).replace(/\.0$/u, "");
}

function byteHeadline(value: number): string {
  requireContract(Number.isInteger(value), "invalid-evidence", "Exact byte evidence must be an integer.");
  if (value < 1_000) return `${value} B`;
  if (value < 1_000_000) return `${oneDecimal(value / 1_000)} KB`;
  return `${oneDecimal(value / 1_000_000)} MB`;
}

function headlineFor(bundle: ViewerBundle): string {
  const hero = bundle.result.hero;
  requireContract(hero !== null, "ineligible-result", "This result has no shareable hero evidence.");
  const primary = hero.evidence.filter((item) => item.role === "primary");
  requireContract(primary.length === 1, "invalid-evidence", "The hero must bind one primary measurement.");
  const evidence = primary[0];
  requireContract(evidence !== undefined, "invalid-evidence", "The primary measurement is missing.");
  requireContract(
    bundle.mapping.heroSelection.enabledCandidates.includes(hero.selectionRule),
    "invalid-evidence",
    "The hero selection rule is not enabled by this mapping.",
  );
  requireContract(
    bundle.mapping.heroSelection.allowedPrimaryEvidence.includes(evidence.level),
    "invalid-evidence",
    "The primary evidence level is not approved by this mapping.",
  );

  switch (hero.selectionRule) {
    case "dominant-resource-type-share-v1": {
      const match = /^([a-z]+)_transfer_share$/u.exec(evidence.metric);
      const resourceType = match?.[1] ?? "";
      requireContract(
        Boolean(resourceLabels[resourceType]),
        "invalid-evidence",
        "The dominant resource type is not in the poster allowlist.",
      );
      const legacyRule = `round(${resourceType}Bytes * 1000 / totalBytes) / 10`;
      const currentRule = "round(typeBytes * 1000 / totalKnownBytes) / 10";
      const rules = new Set([legacyRule, currentRule]);
      const refs = resourceEvidenceRefs(
        bundle,
        evidence,
        new Set(["type", "transferredBytes"]),
      );
      const knownRows = knownByteRows(bundle);
      const knownIndices = knownRows.map((row) => row.index);
      const byteIndices = indicesForField(refs, "transferredBytes");
      const typeRefIndices = indicesForField(refs, "type");
      const typeRows = knownRows.filter((row) => row.type === resourceType);
      const typeCoverageValid = evidence.rule === currentRule
        ? sameUniqueIndices(typeRefIndices, knownIndices)
        : typeRefIndices.length === 0 || sameUniqueIndices(typeRefIndices, knownIndices);
      requireContract(
        hero.kind === "weight" && evidence.level === "derived" &&
          evidence.attributionScope === "page-level" && rules.has(evidence.rule) &&
          knownRows.length > 0 && typeRows.length > 0 &&
          sameUniqueIndices(byteIndices, knownIndices) && typeCoverageValid,
        "invalid-evidence",
        "The dominant resource evidence provenance is invalid.",
      );
      const value = numericEvidence(evidence, `${resourceType}_transfer_share`, "percent");
      const knownTotal = knownRows.reduce((sum, row) => sum + row.bytes, 0);
      const typeBytes = typeRows.reduce((sum, row) => sum + row.bytes, 0);
      requireContract(
        value <= 100 && value === roundedBytePercentage(typeBytes, knownTotal),
        "invalid-evidence",
        "The dominant resource percentage does not reproduce from its complete inputs.",
      );
      return `${oneDecimal(value)}%`;
    }
    case "third-party-byte-share-v1": {
      const refs = resourceEvidenceRefs(
        bundle,
        evidence,
        new Set(["party", "transferredBytes"]),
      );
      const knownRows = knownByteRows(bundle);
      const knownIndices = knownRows.map((row) => row.index);
      const byteIndices = indicesForField(refs, "transferredBytes");
      const partyIndices = indicesForField(refs, "party");
      const thirdPartyRows = knownRows.filter((row) => row.party === "third");
      requireContract(
        hero.kind === "third-party" && evidence.level === "derived" &&
          evidence.attributionScope === "page-level" &&
          evidence.rule === "round(thirdPartyBytes * 1000 / totalKnownBytes) / 10" &&
          knownRows.length > 0 && thirdPartyRows.length > 0 &&
          sameUniqueIndices(byteIndices, knownIndices) &&
          sameUniqueIndices(partyIndices, knownIndices),
        "invalid-evidence",
        "The third-party byte evidence provenance is invalid.",
      );
      const value = numericEvidence(evidence, "third_party_transfer_share", "percent");
      const knownTotal = knownRows.reduce((sum, row) => sum + row.bytes, 0);
      const thirdPartyBytes = thirdPartyRows.reduce((sum, row) => sum + row.bytes, 0);
      requireContract(
        value <= 100 && value === roundedBytePercentage(thirdPartyBytes, knownTotal),
        "invalid-evidence",
        "The third-party byte percentage does not reproduce from its complete inputs.",
      );
      return `${oneDecimal(value)}%`;
    }
    case "largest-exact-resource-share-v1": {
      const refs = resourceEvidenceRefs(
        bundle,
        evidence,
        new Set(["transferredBytes", "type", "attributionScope", "attributedNodeIds"]),
      );
      const fields = new Set(refs.map((ref) => ref.field));
      const indices = new Set(refs.map((ref) => ref.index));
      const exactScope = evidence.attributionScope === "exact-element" ||
        evidence.attributionScope === "exact-resource-link";
      requireContract(
        hero.kind === "weight" && evidence.level === "observed" && exactScope &&
          evidence.rule === "max(known transferredBytes for exactly linked resources)" &&
          refs.length === 4 && fields.size === 4 && indices.size === 1 &&
          ["transferredBytes", "type", "attributionScope", "attributedNodeIds"]
            .every((field) => fields.has(field)),
        "invalid-evidence",
        "The exact-resource evidence provenance is invalid.",
      );
      return byteHeadline(
        numericEvidence(evidence, "largest_exact_resource_transferred_bytes", "bytes"),
      );
    }
    case "third-party-request-share-v1": {
      const resourceSourceRefs = evidence.sourceRefs.filter(
        (ref) => ref !== "#/page/registrableDomain",
      );
      const requestRefs = resourceEvidenceRefs(
        bundle,
        { ...evidence, sourceRefs: resourceSourceRefs },
        new Set(["party"]),
      );
      requireContract(
        hero.kind === "third-party" && evidence.level === "derived" &&
          evidence.attributionScope === "page-level" &&
          new Set(["registrable-domain-v1", "count(resources where party is third)"])
            .has(evidence.rule) && requestRefs.length > 0 &&
          requestRefs.every((ref) => bundle.record.resources[ref.index]?.party === "third") &&
          evidence.sourceRefs.every((ref) =>
            ref === "#/page/registrableDomain" || /^#\/resources\/\d+\/party$/u.test(ref)
          ),
        "invalid-evidence",
        "The third-party request evidence provenance is invalid.",
      );
      const primaryValue = numericEvidence(evidence, "third_party_requests", "requests");
      const supports = hero.evidence.filter(
        (item) => item.role === "support" &&
          (item.metric === "observed_requests" || item.metric === "party_classified_requests"),
      );
      requireContract(
        supports.length === 1 && supports[0] !== undefined,
        "invalid-evidence",
        "Third-party request headlines require the observed request total.",
      );
      const support = supports[0];
      const total = numericEvidence(support, support.metric, "requests");
      if (support.metric === "observed_requests") {
        requireContract(
          support.level === "observed" && support.attributionScope === "page-level" &&
            support.rule === "capture-request-count-v1" &&
            sameStrings(support.sourceRefs, ["#/capture/requestCount"]) &&
            total === bundle.record.capture.requestCount,
          "invalid-evidence",
          "The observed request total provenance is invalid.",
        );
      } else {
        const classifiedRefs = resourceEvidenceRefs(bundle, support, new Set(["party"]));
        const classifiedIndices = bundle.record.resources.flatMap((resource, index) =>
          resource.party === "first" || resource.party === "third" ? [index] : []
        );
        const classifiedCount = classifiedIndices.length;
        requireContract(
          support.level === "derived" && support.attributionScope === "page-level" &&
            support.rule === "count(resources where party is first or third)" &&
            sameUniqueIndices(
              classifiedRefs.map((ref) => ref.index),
              classifiedIndices,
            ) && total === classifiedCount,
          "invalid-evidence",
          "The classified request total provenance is invalid.",
        );
      }
      const thirdPartyIndices = bundle.record.resources.flatMap((resource, index) =>
        resource.party === "third" ? [index] : []
      );
      requireContract(
        Number.isInteger(primaryValue) && Number.isInteger(total) && primaryValue <= total &&
          primaryValue === thirdPartyIndices.length &&
          sameUniqueIndices(requestRefs.map((ref) => ref.index), thirdPartyIndices),
        "invalid-evidence",
        "Request evidence must be whole counts within the observed total.",
      );
      return `${primaryValue} OF ${total}`;
    }
    default:
      throw new PosterContractError("invalid-evidence", "The hero rule has no poster mapping.");
  }
}

function resourceIndices(sourceRefs: string[]): number[] {
  return Array.from(
    new Set(
      sourceRefs.flatMap((ref) => {
        const match = /^#\/resources\/(\d+)(?:\/|$)/u.exec(ref);
        return match?.[1] === undefined ? [] : [Number(match[1])];
      }),
    ),
  );
}

function highlightedResources(bundle: ViewerBundle): Set<string> {
  const hero = bundle.result.hero;
  requireContract(hero !== null, "ineligible-result", "This result has no hero evidence.");
  const primary = hero.evidence.find((item) => item.role === "primary");
  requireContract(primary !== undefined, "invalid-evidence", "The primary measurement is missing.");

  if (hero.selectionRule === "dominant-resource-type-share-v1") {
    const match = /^([a-z]+)_transfer_share$/u.exec(primary.metric);
    const resourceType = match?.[1] ?? "";
    requireContract(Boolean(resourceLabels[resourceType]), "invalid-evidence", "Unknown resource type.");
    return new Set(
      bundle.record.resources
        .filter((resource) => resource.type === resourceType)
        .map((resource) => resource.id),
    );
  }

  if (
    hero.selectionRule === "third-party-byte-share-v1" ||
    hero.selectionRule === "third-party-request-share-v1"
  ) {
    return new Set(
      bundle.record.resources
        .filter((resource) => resource.party === "third")
        .map((resource) => resource.id),
    );
  }

  const referenced = resourceIndices(primary.sourceRefs)
    .map((index) => bundle.record.resources[index])
    .filter((resource) => resource !== undefined);
  const measuredBytes = finiteNumber(primary.value, "largest exact resource value");
  const exact = referenced.filter((resource) => resource.transferredBytes === measuredBytes);
  requireContract(
    exact.length === 1 && exact[0] !== undefined,
    "invalid-evidence",
    "Largest-resource evidence does not resolve to one exact resource.",
  );
  return new Set([exact[0].id]);
}

function projectableObject(object: SceneObject): object is RegionObject | HubObject | PageBusObject {
  return object.kind === "region" || object.kind === "aggregate" ||
    object.kind === "third-party-hub" || object.kind === "page-bus";
}

export function posterModelFor(bundle: ViewerBundle): PosterModel {
  const { record, result, scene } = bundle;
  const hero = result.hero;
  const poster = result.exports.poster;
  requireContract(
    record.scanId === scene.scanId && scene.scanId === result.scanId,
    "invalid-binding",
    "The scan, scene, and result identities disagree.",
  );
  requireContract(
    record.mappingVersion === scene.mappingVersion && scene.mappingVersion === result.mappingVersion,
    "invalid-binding",
    "The poster sources use different mapping versions.",
  );
  requireContract(
    result.sceneManifestVersion === scene.manifestVersion && scene.budget.countedObjectCount <= scene.budget.limit,
    "invalid-binding",
    "The result is not bound to this bounded scene.",
  );
  requireContract(
    result.shareState === "artifact-eligible" && hero !== null && hero.shareEligible &&
      poster.eligible && poster.mediaType === "image/png" && poster.width === POSTER_SIZE &&
      poster.height === POSTER_SIZE && poster.maxByteLength === POSTER_BYTE_LIMIT &&
      poster.state !== "ineligible",
    "ineligible-result",
    "This result is not eligible for a local 1080 × 1080 poster.",
  );
  requireContract(
    poster.sourceResultBindingSha256 === result.sourceHashes.resultBindingSha256 &&
      poster.sourceSceneSha256 === result.sourceHashes.sceneManifestSha256 &&
      poster.sourceHeroSha256 === result.sourceHashes.heroSha256,
    "invalid-binding",
    "The poster target is not bound to this result, scene, and hero.",
  );
  requireHeroRecordBinding(bundle);
  const invalidatedMetrics = new Set(
    result.limitations.flatMap((limitation) => limitation.invalidatesMetrics),
  );
  const ruleInvalidations = invalidatedMetricsByRule[hero.selectionRule];
  requireContract(
    ruleInvalidations !== undefined && !invalidatedMetrics.has("hero_insight") &&
      !Array.from(ruleInvalidations).some((metric) => invalidatedMetrics.has(metric)),
    "invalid-evidence",
    "A capture limitation invalidates this poster headline.",
  );
  const requiredLayers = new Set(result.content.requiredLayers);
  for (const layer of ["page-identity", "scene", "hero-fact", "product-identity", "new-scan-cta"]) {
    requireContract(requiredLayers.has(layer), "invalid-binding", `The poster omits ${layer}.`);
  }
  const partial = requireCaptureStatus(bundle);
  if (partial) {
    requireContract(
      result.statusPresentation.partialLabelRequired &&
        result.statusPresentation.label === "PARTIAL CAPTURE" &&
        requiredLayers.has("partial-status") && requiredLayers.has("limitation-disclosure") &&
        result.limitations.length > 0,
      "invalid-binding",
      "The partial poster disclosure is incomplete.",
    );
  }
  requireSceneHeroBinding(bundle);

  const pageLabel = safeText(result.pageIdentity.label, "page identity");
  requireContract(
    pageLabel.length <= 52,
    "content-overflow",
    "The page identity does not fit the poster header.",
  );
  const productName = safeText(result.content.productName, "product name");
  const cta = safeText(result.content.finalFrameCta, "poster action");
  const statusLabel = safeText(result.statusPresentation.label, "capture status");
  const statement = safeText(hero.statement, "hero statement");
  const limitationMessages = result.limitations.map((item) => safeText(item.message, "limitation"));
  const highlighted = highlightedResources(bundle);
  const objectById = new Map(scene.objects.map((object) => [object.id, object]));
  const plates: PosterPlate[] = [];
  const hubs: PosterHub[] = [];
  const buses: PosterBus[] = [];

  for (const object of scene.objects) {
    requireContract(projectableObject(object), "invalid-topology", "The scene contains an unknown object kind.");
    const center = finitePoint(object.positionWorld, "scene object position");
    if (object.kind === "region" || object.kind === "aggregate") {
      const width = finiteNumber(object.sizeWorld.width, "region width");
      const height = finiteNumber(object.sizeWorld.height, "region height");
      requireContract(width > 0 && height > 0, "invalid-topology", "Region dimensions must be positive.");
      const mass = object.weight.mass;
      if (mass !== null) finiteNumber(mass, "region mass");
      const thickness = object.weight.plateThicknessWorld;
      if (thickness !== null) finiteNumber(thickness, "region thickness");
      plates.push({
        kind: object.kind,
        center,
        width,
        height,
        mass,
        thickness,
        style: safeText(object.weight.plateStyle, "plate style"),
        order: object.documentOrder,
        highlighted: object.evidence.linkedResourceIds.some((id) => highlighted.has(id)),
      });
    } else if (object.kind === "third-party-hub") {
      hubs.push({
        center,
        highlighted: object.resourceIds.some((id) => highlighted.has(id)),
      });
    } else {
      buses.push({ center });
    }
  }

  const connections: PosterConnection[] = scene.connections.map((connection, index) => {
    const source = objectById.get(connection.sourceObjectId);
    const target = objectById.get(connection.targetObjectIds[0] ?? connection.fallbackObjectId ?? "");
    requireContract(source !== undefined && target !== undefined, "invalid-topology", "A scene connection endpoint is absent.");
    const sourcePoint = finitePoint(source.positionWorld, "connection source");
    let targetPoint = finitePoint(target.positionWorld, "connection target");
    if (source.id === target.id) {
      targetPoint = {
        x: scene.frame.planeWorld.width / 2 + 0.7,
        y: sourcePoint.y * 0.55 + (index % 3 - 1) * 0.18,
        z: 0.55,
      };
    }
    return {
      source: { ...sourcePoint, z: sourcePoint.z + 0.2 },
      target: { ...targetPoint, z: targetPoint.z + 0.2 },
      strokeWidth: connection.measurement.cableThicknessWorld === null
        ? 0.01
        : finiteNumber(connection.measurement.cableThicknessWorld, "connection thickness"),
      dashed: connection.visualState !== "solid",
      highlighted: highlighted.has(connection.resourceId),
    };
  });

  return {
    width: POSTER_SIZE,
    height: POSTER_SIZE,
    pageLabel,
    productName: productName as "DOM X-Ray",
    cta: cta as "X-RAY ANOTHER SITE",
    statusLabel,
    partial,
    headline: headlineFor(bundle),
    statement,
    limitationMessages,
    planeWidth: finiteNumber(scene.frame.planeWorld.width, "scene plane width"),
    planeHeight: finiteNumber(scene.frame.planeWorld.height, "scene plane height"),
    plates: plates.sort((left, right) => left.center.z - right.center.z || left.order - right.order),
    hubs,
    buses,
    connections,
    posterMaxByteLength: poster.maxByteLength,
  };
}

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function number(value: number): string {
  return Number(value.toFixed(2)).toString();
}

function project(point: Vec3): PosterPoint {
  return {
    x: 540 + point.x * 35 - point.y * 22,
    y: 475 + point.x * 10 + point.y * 12 - point.z * 290,
  };
}

function polygon(points: PosterPoint[]): string {
  return points.map((point) => `${number(point.x)},${number(point.y)}`).join(" ");
}

function platePoints(plate: PosterPlate, z = plate.center.z): PosterPoint[] {
  const halfWidth = plate.width / 2;
  const halfHeight = plate.height / 2;
  return [
    project({ x: plate.center.x - halfWidth, y: plate.center.y - halfHeight, z }),
    project({ x: plate.center.x + halfWidth, y: plate.center.y - halfHeight, z }),
    project({ x: plate.center.x + halfWidth, y: plate.center.y + halfHeight, z }),
    project({ x: plate.center.x - halfWidth, y: plate.center.y + halfHeight, z }),
  ];
}

function wrapText(value: string, maxCharacters: number, maximumLines: number, label: string): string[] {
  const words = value.split(/\s+/u);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    requireContract(word.length <= maxCharacters, "content-overflow", `${label} contains an unbreakable word.`);
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= maxCharacters) {
      current = candidate;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  requireContract(lines.length <= maximumLines, "content-overflow", `${label} does not fit the poster.`);
  return lines;
}

function textLines(lines: string[], x: number, firstY: number, lineHeight: number, className: string): string {
  return lines
    .map(
      (line, index) =>
        `<text class="${className}" x="${x}" y="${firstY + index * lineHeight}">${escapeXml(line)}</text>`,
    )
    .join("");
}

function sceneSvg(model: PosterModel): string {
  const base: PosterPlate = {
    kind: "region",
    center: { x: 0, y: 0, z: -0.38 },
    width: model.planeWidth * 1.08,
    height: model.planeHeight * 1.08,
    mass: null,
    thickness: 0.22,
    style: "base",
    order: -1,
    highlighted: false,
  };
  const baseTop = platePoints(base);
  const baseBottom = baseTop.map((point) => ({ x: point.x, y: point.y + 19 }));
  const connectionMarkup = model.connections.map((connection) => {
    const source = project(connection.source);
    const target = project(connection.target);
    const middleX = (source.x + target.x) / 2 + (target.x >= source.x ? 18 : -18);
    const middleY = Math.min(source.y, target.y) - 34;
    return `<path d="M ${number(source.x)} ${number(source.y)} Q ${number(middleX)} ${number(middleY)} ${number(target.x)} ${number(target.y)}" fill="none" stroke="${connection.highlighted ? palette.red : palette.teal}" stroke-width="${number(Math.max(1.7, Math.min(7, connection.strokeWidth * 64)))}" stroke-linecap="round" opacity="${connection.highlighted ? "0.94" : "0.7"}"${connection.dashed ? ' stroke-dasharray="11 8"' : ""}/>`;
  }).join("");
  const plateMarkup = [base, ...model.plates].map((plate) => {
    const top = platePoints(plate);
    const extrusion = plate.order === -1
      ? 19
      : Math.max(7, Math.min(30, 8 + (plate.mass ?? 0) * 22));
    const bottom = top.map((point) => ({ x: point.x, y: point.y + extrusion }));
    const face = plate.order === -1
      ? palette.board
      : plate.highlighted
        ? palette.red
        : (plate.mass ?? 0) > 0.72
          ? palette.graphite
          : plate.kind === "aggregate"
            ? "#d6c8ad"
            : palette.paperLight;
    const side = plate.order === -1
      ? "#8f8267"
      : plate.highlighted
        ? palette.redDark
        : (plate.mass ?? 0) > 0.72
          ? "#151914"
          : "#b7aa91";
    const contentStroke = plate.highlighted || (plate.mass ?? 0) > 0.72
      ? palette.paperLight
      : palette.graphite;
    const lineStart = {
      x: top[3]!.x * 0.72 + top[0]!.x * 0.28,
      y: top[3]!.y * 0.72 + top[0]!.y * 0.28,
    };
    const lineEnd = {
      x: top[2]!.x * 0.7 + top[1]!.x * 0.3,
      y: top[2]!.y * 0.7 + top[1]!.y * 0.3,
    };
    const guideLines = plate.order <= 0 ? "" : [0, 1, 2].map((row) => {
      const shift = row * 7;
      return `<line x1="${number(lineStart.x)}" y1="${number(lineStart.y + shift)}" x2="${number(lineEnd.x - row * 20)}" y2="${number(lineEnd.y + shift)}" stroke="${contentStroke}" stroke-width="2" opacity="0.24"/>`;
    }).join("");
    return `<g filter="url(#plate-shadow)"><polygon points="${polygon(bottom)}" fill="${side}" opacity="0.92"/><polygon points="${polygon(top)}" fill="${plate.style.includes("hollow") ? "url(#hatch)" : face}" fill-opacity="${plate.order === -1 ? "0.96" : "0.9"}" stroke="${palette.graphite}" stroke-width="1.2"${plate.kind === "aggregate" ? ' stroke-dasharray="6 5"' : ""}/>${guideLines}</g>`;
  }).join("");
  const busMarkup = model.buses.map((bus) => {
    const point = project(bus.center);
    return `<g><line x1="${number(point.x)}" y1="175" x2="${number(point.x)}" y2="${number(point.y + 96)}" stroke="${palette.graphite}" stroke-width="7"/><line x1="${number(point.x - 7)}" y1="175" x2="${number(point.x - 7)}" y2="${number(point.y + 96)}" stroke="${palette.brass}" stroke-width="3"/><rect x="${number(point.x - 17)}" y="${number(point.y - 3)}" width="34" height="22" fill="${palette.brass}" stroke="${palette.graphite}"/></g>`;
  }).join("");
  const hubMarkup = model.hubs.map((hub) => {
    const point = project({ ...hub.center, z: hub.center.z + 0.18 });
    const fill = hub.highlighted ? palette.red : palette.teal;
    return `<g filter="url(#plate-shadow)"><polygon points="${number(point.x)},${number(point.y - 19)} ${number(point.x + 21)},${number(point.y - 8)} ${number(point.x)},${number(point.y + 3)} ${number(point.x - 21)},${number(point.y - 8)}" fill="${fill}" stroke="${palette.graphite}"/><polygon points="${number(point.x - 21)},${number(point.y - 8)} ${number(point.x)},${number(point.y + 3)} ${number(point.x)},${number(point.y + 31)} ${number(point.x - 21)},${number(point.y + 20)}" fill="${palette.teal}" stroke="${palette.graphite}"/><polygon points="${number(point.x)},${number(point.y + 3)} ${number(point.x + 21)},${number(point.y - 8)} ${number(point.x + 21)},${number(point.y + 20)} ${number(point.x)},${number(point.y + 31)}" fill="${hub.highlighted ? palette.redDark : "#234e57"}" stroke="${palette.graphite}"/><rect x="${number(point.x - 29)}" y="${number(point.y + 31)}" width="58" height="7" fill="${palette.board}" stroke="${palette.graphite}"/></g>`;
  }).join("");
  const markerPlate = model.plates.find((plate) => plate.highlighted) ?? model.plates.find((plate) => plate.mass !== null);
  const marker = markerPlate
    ? (() => {
        const point = project({ ...markerPlate.center, z: markerPlate.center.z + 0.24 });
        return `<g stroke="${palette.red}" fill="none" stroke-width="2"><circle cx="${number(point.x)}" cy="${number(point.y)}" r="18"/><circle cx="${number(point.x)}" cy="${number(point.y)}" r="5"/><line x1="${number(point.x - 30)}" y1="${number(point.y)}" x2="${number(point.x + 30)}" y2="${number(point.y)}"/><line x1="${number(point.x)}" y1="${number(point.y - 30)}" x2="${number(point.x)}" y2="${number(point.y + 30)}"/></g>`;
      })()
    : "";
  const guides = `<g stroke="${palette.graphite}" stroke-width="1" opacity="0.28" stroke-dasharray="5 5"><line x1="${number(baseTop[0]!.x)}" y1="${number(baseTop[0]!.y - 170)}" x2="${number(baseTop[0]!.x)}" y2="${number(baseBottom[0]!.y + 40)}"/><line x1="${number(baseTop[2]!.x)}" y1="${number(baseTop[2]!.y - 310)}" x2="${number(baseTop[2]!.x)}" y2="${number(baseBottom[2]!.y + 40)}"/></g>`;
  return `<g aria-hidden="true">${guides}${connectionMarkup}${plateMarkup}${busMarkup}${hubMarkup}${marker}</g>`;
}

export function posterSvgFor(model: PosterModel): string {
  const statementLines = wrapText(model.statement, 58, 3, "Hero statement");
  const limitationLines = model.limitationMessages.flatMap((message) =>
    wrapText(message, 90, 3, "Limitation disclosure"),
  );
  requireContract(
    limitationLines.length <= 4,
    "content-overflow",
    "The full limitation disclosure does not fit the poster.",
  );
  const headlineSize = Math.min(184, Math.max(112, Math.floor(900 / (model.headline.length * 0.58))));
  const headlineBaseline = 790;
  const statementStart = model.partial ? 815 : 844;
  const statementLineHeight = model.partial ? 36 : 39;
  const limitationY = statementStart + statementLines.length * statementLineHeight + 10;
  const limitationHeight = limitationLines.length ? 26 + limitationLines.length * 27 : 0;
  const ctaY = model.partial ? limitationY + limitationHeight + 12 : 966;
  requireContract(ctaY + 62 <= 1058, "content-overflow", "Poster copy leaves no room for the action.");

  const statusColor = model.partial ? palette.redDark : palette.red;
  const accessibleDescription = `${model.statusLabel}. ${model.statement}${
    model.limitationMessages.length
      ? ` Limitations: ${model.limitationMessages.join(" ")}`
      : ""
  }`;
  const limitationMarkup = limitationLines.length
    ? `<g><rect x="42" y="${limitationY}" width="996" height="${limitationHeight}" fill="#efd5cc"/><circle cx="68" cy="${limitationY + limitationHeight / 2}" r="15" fill="${palette.redDark}"/><text x="68" y="${limitationY + limitationHeight / 2 + 7}" text-anchor="middle" font-family="Arial, sans-serif" font-size="22" font-weight="700" fill="${palette.paperLight}">!</text>${textLines(limitationLines, 96, limitationY + 32, 27, "limitation")}</g>`
    : "";

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1080" viewBox="0 0 1080 1080" role="img" aria-labelledby="poster-title poster-description"><title id="poster-title">${escapeXml(model.pageLabel)} DOM X-Ray result</title><desc id="poster-description">${escapeXml(accessibleDescription)}</desc><defs><pattern id="paper" width="38" height="38" patternUnits="userSpaceOnUse"><path d="M4 8h1M20 25h1M31 13h1" stroke="${palette.graphite}" stroke-width="1" opacity="0.055"/></pattern><pattern id="hatch" width="12" height="12" patternUnits="userSpaceOnUse" patternTransform="rotate(35)"><rect width="12" height="12" fill="${palette.paperLight}"/><line x1="0" y1="0" x2="0" y2="12" stroke="${palette.graphite}" stroke-width="2" opacity="0.3"/></pattern><filter id="plate-shadow" x="-20%" y="-20%" width="150%" height="170%"><feDropShadow dx="0" dy="14" stdDeviation="13" flood-color="#2c2318" flood-opacity="0.12"/></filter><style>.logo{font:800 51px/0.78 Arial Narrow,Arial,sans-serif;letter-spacing:5px;fill:${palette.graphite}}.meta{font:400 20px Courier New,monospace;letter-spacing:2px;fill:${palette.graphite}}.status{font:700 16px Courier New,monospace;letter-spacing:7px;fill:${palette.graphite}}.headline{font:800 ${headlineSize}px Arial Narrow,Arial,sans-serif;letter-spacing:-4px;fill:${palette.redDark}}.statement{font:500 34px Arial,sans-serif;letter-spacing:-0.6px;fill:${palette.graphite}}.limitation{font:500 20px Arial,sans-serif;fill:${palette.redDark}}.cta{font:700 20px Courier New,monospace;letter-spacing:5px;fill:${palette.paperLight}}</style></defs><rect width="1080" height="1080" fill="${palette.paper}"/><rect width="1080" height="1080" fill="url(#paper)"/><g stroke="${palette.graphite}" stroke-width="1" opacity="0.45"><line x1="42" y1="34" x2="194" y2="34"/><line x1="225" y1="34" x2="1036" y2="34"/><line x1="286" y1="20" x2="286" y2="114"/><circle cx="1002" cy="74" r="9" fill="none"/><line x1="973" y1="74" x2="1031" y2="74"/><line x1="1002" y1="45" x2="1002" y2="103"/></g><text class="logo" x="45" y="62">DOM</text><text class="logo" x="45" y="108">X-RAY</text><text class="meta" x="322" y="59">${escapeXml(model.pageLabel)}</text><circle cx="306" cy="91" r="8" fill="${statusColor}"/><text class="status" x="326" y="98">${escapeXml(model.statusLabel)}</text>${sceneSvg(model)}<text class="headline" x="42" y="${headlineBaseline}">${escapeXml(model.headline)}</text>${textLines(statementLines, 44, statementStart, statementLineHeight, "statement")}${limitationMarkup}<g><rect x="42" y="${ctaY}" width="444" height="62" fill="${palette.red}"/><text class="cta" x="67" y="${ctaY + 39}">${escapeXml(model.cta)}</text><line x1="416" y1="${ctaY + 31}" x2="457" y2="${ctaY + 31}" stroke="${palette.paperLight}" stroke-width="2"/><path d="M449 ${ctaY + 23}l9 8-9 8" fill="none" stroke="${palette.paperLight}" stroke-width="2"/></g></svg>`;
}

export function posterDataUrl(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function stableResultUrl(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
): string {
  let parsed: URL;
  let trusted: URL;
  try {
    parsed = new URL(resultUrl);
    trusted = new URL(trustedOrigin);
  } catch {
    throw new PosterContractError("invalid-binding", "The result link is not a valid URL.");
  }
  requireContract(
    ["http:", "https:"].includes(parsed.protocol) && !parsed.username && !parsed.password &&
      ["http:", "https:"].includes(trusted.protocol) && !trusted.username && !trusted.password &&
      trusted.pathname === "/" && !trusted.search && !trusted.hash &&
      parsed.origin === trusted.origin && !parsed.search && !parsed.hash &&
      parsed.pathname === bundle.result.resultPath,
    "invalid-binding",
    "The share link is not the stable result route.",
  );
  return parsed.href;
}

export function shareCaptionFor(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
): ShareCaption {
  const hero = bundle.result.hero;
  requireContract(
    bundle.result.shareState === "artifact-eligible" && hero !== null && hero.shareEligible,
    "ineligible-result",
    "This result has no shareable caption.",
  );
  requireHeroRecordBinding(bundle);
  requireSceneHeroBinding(bundle);
  const partial = requireCaptureStatus(bundle);
  const statement = safeText(hero.statement, "hero statement");
  const url = stableResultUrl(bundle, resultUrl, trustedOrigin);
  const prefix = partial ? "PARTIAL CAPTURE — " : "";
  const beforeUrl = `${prefix}${statement}\n\n`;
  const effectiveLength = Array.from(beforeUrl).length + X_URL_LENGTH;
  return {
    text: `${beforeUrl}${url}`,
    effectiveLength,
    tooLong: effectiveLength > X_POST_LENGTH,
  };
}

export function shareLinkFor(
  bundle: ViewerBundle,
  resultUrl: string,
  trustedOrigin: string,
): string {
  return stableResultUrl(bundle, resultUrl, trustedOrigin);
}

function loadSvgImage(svg: string): Promise<{ image: HTMLImageElement; url: string }> {
  const url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml;charset=utf-8" }));
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve({ image, url });
    image.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new PosterContractError("rasterization-failed", "The poster SVG could not be decoded."));
    };
    image.src = url;
  });
}

export async function rasterizePosterSvg(svg: string, maxByteLength: number): Promise<Blob> {
  requireContract(
    maxByteLength === POSTER_BYTE_LIMIT,
    "invalid-binding",
    "The poster byte envelope is not the approved 5 MB target.",
  );
  const loaded = await loadSvgImage(svg);
  try {
    const canvas = document.createElement("canvas");
    canvas.width = POSTER_SIZE;
    canvas.height = POSTER_SIZE;
    const context = canvas.getContext("2d");
    requireContract(context !== null, "rasterization-failed", "This browser cannot create a poster canvas.");
    context.drawImage(loaded.image, 0, 0, POSTER_SIZE, POSTER_SIZE);
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
    requireContract(blob !== null && blob.size > 0, "rasterization-failed", "The browser returned an empty PNG.");
    requireContract(blob.size <= maxByteLength, "png-size", "The PNG exceeds the approved 5 MB envelope.");
    return blob;
  } finally {
    URL.revokeObjectURL(loaded.url);
  }
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function posterFilename(pageLabel: string): string {
  const safeLabel = pageLabel.toLowerCase().replace(/[^a-z0-9.-]+/gu, "-").replace(/^-+|-+$/gu, "");
  return `${safeLabel || "result"}-dom-x-ray.png`;
}
