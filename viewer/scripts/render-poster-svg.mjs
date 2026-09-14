#!/usr/bin/env node
/*
 * Server-side poster model seam.  This process receives only an admitted
 * viewer bundle and writes only the caller-selected SVG path.  It never
 * opens a URL, starts a browser, or reads target-page data.
 */
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { posterModelFor, posterSvgFor } from "../src/share/poster.ts";

function usage() {
  throw new Error("usage: render-poster-svg.mjs <bundle-json> <svg-output>");
}

function requiredPath(value, label) {
  if (typeof value !== "string" || !value || !path.isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  return value;
}

const [bundleArgument, svgArgument] = process.argv.slice(2);
if (!bundleArgument || !svgArgument || process.argv.length !== 4) usage();
const bundlePath = requiredPath(bundleArgument, "bundle path");
const svgPath = requiredPath(svgArgument, "SVG path");
if (path.resolve(bundlePath) === path.resolve(svgPath)) {
  throw new Error("bundle and SVG paths must differ");
}

// The Python parent admits this exact by-value bundle through every component
// schema and cross-source hash check before starting the contained worker.
const bundle = JSON.parse(await fs.readFile(bundlePath, "utf8"));
if (
  bundle.result.shareState !== "artifact-eligible" ||
  bundle.result.hero === null ||
  bundle.result.hero.shareEligible !== true ||
  bundle.result.exports.poster.eligible !== true ||
  bundle.result.exports.poster.mediaType !== "image/png" ||
  bundle.result.exports.poster.width !== 1080 ||
  bundle.result.exports.poster.height !== 1080
) {
  throw new Error("viewer bundle is not eligible for a poster artifact");
}

const model = posterModelFor(bundle);
const svg = posterSvgFor(model);
if (Buffer.byteLength(svg, "utf8") > 2_000_000) {
  throw new Error("poster SVG exceeds the trusted output limit");
}
await fs.writeFile(svgPath, svg, { encoding: "utf8", flag: "wx" });
