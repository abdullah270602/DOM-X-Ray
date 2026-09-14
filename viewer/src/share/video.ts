import type { ViewerBundle } from "../domain/types";
import {
  PosterContractError,
  posterModelFor,
  posterSvgFor,
  type ArtifactRevealStage,
  type PosterModel,
} from "./poster.ts";

export const VIDEO_SIZE = 1080 as const;
export const VIDEO_DURATION_MS = 5_000 as const;
export const VIDEO_FRAME_RATE = 30 as const;
export const VIDEO_FRAME_COUNT = 150 as const;
export const VIDEO_MAX_BYTE_LENGTH = 8_000_000 as const;

export const VIDEO_REVEAL_STAGES = [
  { id: "page", label: "01 / PAGE SURFACE" },
  { id: "structure", label: "02 / DOM STRUCTURE" },
  { id: "weight", label: "03 / TRANSFER WEIGHT" },
  { id: "origins", label: "04 / EXTERNAL ORIGINS" },
  { id: "hero", label: "05 / HERO EVIDENCE" },
] as const satisfies ReadonlyArray<{ id: ArtifactRevealStage; label: string }>;

export interface VideoModel {
  poster: PosterModel;
  width: 1080;
  height: 1080;
  durationMs: 5000;
  frameRate: 30;
  frameCount: 150;
  maxByteLength: 8_000_000;
}

export interface VideoStoryboardFrame {
  id: ArtifactRevealStage;
  label: string;
  svg: string;
}

export interface VideoStoryboard extends Omit<VideoModel, "poster"> {
  frames: VideoStoryboardFrame[];
}

function requireVideo(condition: unknown, message: string): asserts condition {
  if (!condition) throw new PosterContractError("invalid-binding", message);
}

export function videoModelFor(bundle: ViewerBundle): VideoModel {
  const target = bundle.result.exports.video;
  requireVideo(
    bundle.result.shareState === "artifact-eligible" &&
      target.eligible === true &&
      target.kind === "video" &&
      target.mediaType === "video/mp4" &&
      target.width === VIDEO_SIZE &&
      target.height === VIDEO_SIZE &&
      target.durationMs === VIDEO_DURATION_MS &&
      target.maxByteLength === VIDEO_MAX_BYTE_LENGTH &&
      target.state !== "ineligible",
    "This result is not eligible for the controlled five-second video.",
  );
  requireVideo(
    target.sourceResultBindingSha256 === bundle.result.sourceHashes.resultBindingSha256 &&
      target.sourceSceneSha256 === bundle.result.sourceHashes.sceneManifestSha256 &&
      target.sourceHeroSha256 === bundle.result.sourceHashes.heroSha256,
    "The video target is not bound to this result, scene, and hero.",
  );
  const requiredLayers = new Set(bundle.result.content.requiredLayers);
  for (const layer of ["page-identity", "scene", "hero-fact", "product-identity", "new-scan-cta"]) {
    requireVideo(requiredLayers.has(layer), `The video omits ${layer}.`);
  }
  return {
    poster: posterModelFor(bundle),
    width: VIDEO_SIZE,
    height: VIDEO_SIZE,
    durationMs: VIDEO_DURATION_MS,
    frameRate: VIDEO_FRAME_RATE,
    frameCount: VIDEO_FRAME_COUNT,
    maxByteLength: VIDEO_MAX_BYTE_LENGTH,
  };
}

export function videoStoryboardFor(bundle: ViewerBundle): VideoStoryboard {
  const model = videoModelFor(bundle);
  return {
    width: model.width,
    height: model.height,
    durationMs: model.durationMs,
    frameRate: model.frameRate,
    frameCount: model.frameCount,
    maxByteLength: model.maxByteLength,
    frames: VIDEO_REVEAL_STAGES.map((stage) => ({
      ...stage,
      svg: posterSvgFor(model.poster, {
        revealStage: stage.id,
        stageLabel: stage.label,
      }),
    })),
  };
}
