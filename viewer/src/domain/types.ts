export type FixtureName = "clean" | "image-heavy" | "third-party-heavy";
export type ModeId = "structure" | "weight" | "origins";
export type StageId = "flat" | "structure" | "weight" | "party" | "hero";
export type MotionPreference = "standard" | "reduced";

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

export interface Size2 {
  width: number;
  height: number;
}

export interface RegionObject {
  id: string;
  kind: "region" | "aggregate";
  parentId: string | null;
  positionWorld: Vec3;
  sizeWorld: Size2;
  structure: {
    domDepth: number;
    separationWorld: number;
    stackingSeamWorld: number;
    stackingRule: string | null;
  };
  weight: {
    knownTransferredBytes: number | null;
    mass: number | null;
    plateThicknessWorld: number | null;
    plateStyle: string;
    knownResourceIds: string[];
    unknownResourceIds: string[];
    unknownMarkers: unknown[];
    blockedResourceIds: string[];
    blockedMarkerStyle: string;
    massSuppressedResourceIds: string[];
    unknownMarkerStyle: string;
    limitationCodes: string[];
  };
  evidence: {
    recordRefs: string[];
    memberNodeIds: string[];
    linkedResourceIds: string[];
    aggregationRule: string | null;
  };
  documentOrder: number;
}

export interface PageBusObject {
  id: string;
  kind: "page-bus";
  parentId: null;
  positionWorld: Vec3;
  resourceIds: string[];
  evidence: { recordRefs: string[]; placementRule: string };
}

export interface HubObject {
  id: string;
  kind: "third-party-hub";
  parentId: null;
  domain: string;
  positionWorld: Vec3;
  radiusWorld: number;
  resourceIds: string[];
  evidence: {
    recordRefs: string[];
    groupingRule: string;
    placementRule: string;
    angleDegrees: number;
  };
}

export type SceneObject = RegionObject | PageBusObject | HubObject;

export interface SceneConnection {
  id: string;
  kind: "resource-path";
  resourceId: string;
  sourceObjectId: string;
  targetObjectIds: string[];
  fallbackObjectId: string | null;
  evidenceOnlyTargetNodeIds: string[];
  attributionScope: string;
  endpointRule: string;
  transferSource: string;
  outcome: string;
  visualState: string;
  measurement: {
    transferredBytes: number | null;
    mass: number | null;
    cableThicknessWorld: number;
    massSuppressedByLimitation: boolean;
  };
  evidence: { recordRefs: string[]; limitationRefs: string[] };
}

export interface SceneManifest {
  manifestVersion: "scene-manifest-v0.1.0";
  scanId: string;
  mappingVersion: "mapping-v0.1.0";
  status: string;
  failureCode: string | null;
  frame: {
    viewport: Size2;
    planeWorld: Size2;
    scaleCssPxToWorld: number;
  };
  budget: {
    limit: number;
    regionCount: number;
    hubCount: number;
    countedObjectCount: number;
  };
  objects: SceneObject[];
  connections: SceneConnection[];
  nonSceneNodes: Array<Record<string, unknown>>;
  hero: null | {
    insightId: string;
    kind: string;
    statement: string;
    shareEligible: boolean;
    recordRef: string;
    sourceRefs: string[];
    limitationCodes: string[];
  };
  limitations: Array<Record<string, unknown>>;
}

export interface ResultManifest {
  resultManifestVersion: "result-manifest-v0.1.0";
  resultId: string;
  resultPath: string;
  scanId: string;
  mappingVersion: "mapping-v0.1.0";
  sceneManifestVersion: "scene-manifest-v0.1.0";
  sourceHashes: {
    scanRecordSha256: string;
    sceneManifestSha256: string;
    mappingRegistrySha256: string;
    heroSha256: string;
    resultBindingSha256: string;
  };
  pageIdentity: { label: string; recordRef: string };
  status: string;
  failureCode: string | null;
  statusPresentation: { label: string; partialLabelRequired: boolean };
  shareState: string;
  hero: null | {
    statement: string;
    evidence: EvidenceMetric[];
    [key: string]: unknown;
  };
  limitations: Array<{ code: string; message: string; recordRef: string }>;
}

export interface EvidenceMetric {
  role: string;
  level: string;
  attributionScope: string;
  metric: string;
  value: string | number | null;
  unit: string;
  sourceRefs: string[];
  rule: string;
}

export interface ScanRecord {
  schemaVersion: "0.1.0";
  mappingVersion: "mapping-v0.1.0";
  scanId: string;
  status: string;
  failureCode: string | null;
  requestedUrl: string;
  finalUrl: string;
  capturedAt: string;
  capture: Record<string, unknown> & {
    durationMs: number;
    requestCount: number;
    renderedRegionCount: number;
  };
  page: Record<string, unknown> & {
    registrableDomain: string;
    title: string;
  };
  nodes: Array<Record<string, unknown>>;
  resources: Array<Record<string, unknown>>;
  insights: Array<Record<string, unknown>>;
  limitations: Array<Record<string, unknown>>;
}

export interface Selectable {
  id: string;
  kind: string;
  label: string;
  renderable: boolean;
  sceneRefs: string[];
  recordRefs: string[];
  mappingRefs: string[];
  resultRefs: string[];
  limitationRefs: string[];
  emphasisChannels: string[];
}

export interface PlaybackStage {
  id: StageId;
  startMs: number;
  endMs: number;
  meaning: string;
  targetChannels: ChannelValues;
}

export interface ChannelValues {
  page: number;
  structure: number;
  weight: number;
  origins: number;
  finding: number;
}

export interface ViewerState {
  motion: MotionPreference;
  phase: "revealing" | "stepping" | "exploring";
  playback: "playing" | "paused" | "complete";
  elapsedMs: number;
  stageIndex: number;
  stageId: StageId;
  mode: ModeId;
  selectedId: string | null;
  isolatedId: string | null;
  revision: number;
}

export interface ViewerRuntime {
  viewerRuntimeVersion: "viewer-runtime-v0.1.0";
  scanId: string;
  resultId: string;
  resultPath: string;
  mappingVersion: "mapping-v0.1.0";
  sourceHashes: {
    scanRecordSha256: string;
    sceneManifestSha256: string;
    mappingRegistrySha256: string;
    resultBindingSha256: string;
    resultManifestSha256: string;
  };
  presentation: {
    pageLabel: string;
    status: string;
    failureCode: string | null;
    statusLabel: string;
    partialLabelRequired: boolean;
    shareState: string;
    finding: {
      kind: "hero" | "neutral" | "unavailable";
      statement: string;
      shareEligible: boolean;
      resultRef: string | null;
      recordRef: string;
    };
    limitationResultRefs: string[];
  };
  playback: {
    durationMs: number;
    stages: PlaybackStage[];
    reducedMotion: { stepOrder: StageId[] };
  };
  modes: Array<{ id: ModeId; label: string; emphasizes: string[] }>;
  selectables: Selectable[];
  initialStates: { standard: ViewerState; reducedMotion: ViewerState };
}

export interface ViewerBundle {
  name: FixtureName;
  runtime: ViewerRuntime;
  scene: SceneManifest;
  result: ResultManifest;
  record: ScanRecord;
  mapping: Record<string, unknown> & { version: "mapping-v0.1.0" };
}

export type ViewerEvent =
  | { type: "tick"; deltaMs: number }
  | { type: "seek"; elapsedMs: number }
  | { type: "pause" | "play" | "skip-reveal" | "replay" | "advance-stage" }
  | { type: "set-mode"; mode: ModeId }
  | { type: "select"; id: string }
  | { type: "isolate-selected" | "clear-isolation" | "clear-selection" };

export interface EvidenceRow {
  namespace: "scene" | "record" | "mapping" | "result" | "limitation";
  ref: string;
  value: unknown;
}

export interface EvidenceDossier {
  selectable: Selectable;
  rows: EvidenceRow[];
}
