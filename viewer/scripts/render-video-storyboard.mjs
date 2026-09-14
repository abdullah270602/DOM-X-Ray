#!/usr/bin/env node
/*
 * Trusted video storyboard seam. The process receives one admitted viewer
 * bundle and emits only five product-owned SVG stages plus bounded metadata.
 */
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { videoStoryboardFor } from "../src/share/video.ts";

function usage() {
  throw new Error("usage: render-video-storyboard.mjs <bundle-json> <output-directory> <metadata-json>");
}

function requiredPath(value, label) {
  if (typeof value !== "string" || !value || !path.isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  return path.resolve(value);
}

const [bundleArgument, directoryArgument, metadataArgument] = process.argv.slice(2);
if (!bundleArgument || !directoryArgument || !metadataArgument || process.argv.length !== 5) usage();
const bundlePath = requiredPath(bundleArgument, "bundle path");
const outputDirectory = requiredPath(directoryArgument, "output directory");
const metadataPath = requiredPath(metadataArgument, "metadata path");
if (path.dirname(metadataPath) !== outputDirectory || bundlePath === metadataPath) {
  throw new Error("storyboard paths do not share the trusted output directory");
}

const bundle = JSON.parse(await fs.readFile(bundlePath, "utf8"));
const storyboard = videoStoryboardFor(bundle);
const frames = [];
for (const [index, frame] of storyboard.frames.entries()) {
  const filename = `stage-${index}.svg`;
  const framePath = path.join(outputDirectory, filename);
  const byteLength = Buffer.byteLength(frame.svg, "utf8");
  if (byteLength <= 0 || byteLength > 2_000_000) {
    throw new Error("storyboard SVG exceeds the trusted output limit");
  }
  await fs.writeFile(framePath, frame.svg, { encoding: "utf8", flag: "wx" });
  frames.push({ id: frame.id, label: frame.label, filename, byteLength });
}

await fs.writeFile(
  metadataPath,
  JSON.stringify({
    version: "video-storyboard-v0.1.0",
    width: storyboard.width,
    height: storyboard.height,
    durationMs: storyboard.durationMs,
    frameRate: storyboard.frameRate,
    frameCount: storyboard.frameCount,
    maxByteLength: storyboard.maxByteLength,
    frames,
  }),
  { encoding: "utf8", flag: "wx" },
);
