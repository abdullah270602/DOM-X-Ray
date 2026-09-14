import { describe, expect, it } from "vitest";
import { fixtures } from "../domain/fixtures";
import type { EvidenceMetric, ViewerBundle } from "../domain/types";
import {
  PosterContractError,
  posterDataUrl,
  posterModelFor,
  posterSvgFor,
  shareCaptionFor,
  shareLinkFor,
} from "./poster";
import { VIDEO_REVEAL_STAGES, videoStoryboardFor } from "./video";

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function rebindHero(bundle: ViewerBundle): void {
  const hero = bundle.result.hero;
  if (!hero || !bundle.scene.hero) throw new Error("Expected a hero-bound fixture");
  hero.sourceRefs = Array.from(new Set(hero.evidence.flatMap((item) => item.sourceRefs)));
  Object.assign(bundle.scene.hero, {
    insightId: hero.insightId,
    kind: hero.kind,
    statement: hero.statement,
    shareEligible: true,
    recordRef: hero.recordRef,
    sourceRefs: [...hero.sourceRefs],
    limitationCodes: [...hero.limitationCodes],
  });
  const match = /^#\/insights\/(\d+)$/u.exec(hero.recordRef);
  if (match?.[1] === undefined) throw new Error("Expected a record insight reference");
  bundle.record.insights[Number(match[1])] = {
    id: hero.insightId,
    kind: hero.kind,
    hero: true,
    statement: hero.statement,
    evidence: clone(hero.evidence),
    selectionRule: hero.selectionRule,
    limitationCodes: [...hero.limitationCodes],
  };
}

function thirdPartyByteBundle(): ViewerBundle {
  const bundle = clone(fixtures["image-heavy"]);
  const hero = bundle.result.hero!;
  [3, 4, 5].forEach((index) => {
    bundle.record.resources[index]!.party = "third";
  });
  const knownIndices = bundle.record.resources.flatMap((resource, index) =>
    resource.transferredBytes === null ? [] : [index]
  );
  hero.kind = "third-party";
  hero.statement = "Responses from other domains accounted for 87.5% of this captured load.";
  hero.selectionRule = "third-party-byte-share-v1";
  hero.evidence = [<EvidenceMetric>{
    role: "primary",
    level: "derived",
    attributionScope: "page-level",
    metric: "third_party_transfer_share",
    value: 87.5,
    unit: "percent",
    sourceRefs: [
      ...knownIndices.map((index) => `#/resources/${index}/party`),
      ...knownIndices.map((index) => `#/resources/${index}/transferredBytes`),
    ],
    rule: "round(thirdPartyBytes * 1000 / totalKnownBytes) / 10",
  }];
  rebindHero(bundle);
  return bundle;
}

function expectPosterError(action: () => unknown, code: string) {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(PosterContractError);
    expect((error as PosterContractError).code).toBe(code);
    return;
  }
  throw new Error(`Expected poster error: ${code}`);
}

describe("truthful share poster", () => {
  it("builds a deterministic complete poster from bound evidence and scene geometry", () => {
    const bundle = fixtures["image-heavy"];
    const model = posterModelFor(bundle);
    const first = posterSvgFor(model);
    const second = posterSvgFor(posterModelFor(bundle));

    expect(model.headline).toBe("87.5%");
    expect(model.partial).toBe(false);
    expect(model.posterMaxByteLength).toBe(5_000_000);
    expect(model.plates.some((plate) => plate.highlighted)).toBe(true);
    expect(first).toBe(second);
    expect(first).toContain('width="1080" height="1080"');
    expect(first).toContain("gallery.example");
    expect(first).toContain(bundle.result.hero?.statement);
    expect(first).toContain("X-RAY ANOTHER SITE");
    expect(first).not.toContain("https://");
    expect(first).not.toContain(bundle.record.page.title);
    expect(first).not.toMatch(/<image|<script|@font-face/iu);
    expect(posterDataUrl(first)).toMatch(/^data:image\/svg\+xml;charset=utf-8,/u);
  });

  it("authors five deterministic truthful reveal stages ending on the complete share frame", () => {
    const bundle = fixtures["image-heavy"];
    const first = videoStoryboardFor(bundle);
    const second = videoStoryboardFor(bundle);

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      width: 1080,
      height: 1080,
      durationMs: 5_000,
      frameRate: 30,
      frameCount: 150,
      maxByteLength: 8_000_000,
    });
    expect(first.frames.map((frame) => frame.id)).toEqual(
      VIDEO_REVEAL_STAGES.map((stage) => stage.id),
    );
    expect(first.frames[0]?.svg).toContain("01 / PAGE SURFACE");
    expect(first.frames[0]?.svg).not.toContain(bundle.result.hero?.statement);
    expect(first.frames[1]?.svg).toContain("02 / DOM STRUCTURE");
    expect(first.frames[2]?.svg).toContain("03 / TRANSFER WEIGHT");
    expect(first.frames[3]?.svg).toContain("04 / EXTERNAL ORIGINS");
    expect(first.frames[4]?.svg).toContain("05 / HERO EVIDENCE");
    expect(first.frames[4]?.svg).toContain(bundle.result.hero?.statement);
    expect(first.frames[4]?.svg).toContain("X-RAY ANOTHER SITE");
    expect(first.frames.every((frame) => !frame.svg.includes("https://"))).toBe(true);
    expect(first.frames.every((frame) => !/<image|<script|@font-face/iu.test(frame.svg))).toBe(true);
  });

  it("keeps the partial label, exact limitation, numeric request headline, and caption prefix", () => {
    const bundle = fixtures["third-party-heavy"];
    const model = posterModelFor(bundle);
    const svg = posterSvgFor(model);
    const resultOrigin = "https://dom-x-ray.example";
    const resultUrl = `${resultOrigin}${bundle.result.resultPath}`;
    const caption = shareCaptionFor(bundle, resultUrl, resultOrigin);

    expect(model.headline).toBe("4 OF 8");
    expect(model.partial).toBe(true);
    expect(svg).toContain("PARTIAL CAPTURE");
    expect(svg).toContain(bundle.result.limitations[0]?.message);
    expect(caption.text).toBe(
      `PARTIAL CAPTURE — ${bundle.result.hero?.statement}\n\n${resultUrl}`,
    );
    expect(caption.tooLong).toBe(false);
    expect(caption.effectiveLength).toBe(
      Array.from(`PARTIAL CAPTURE — ${bundle.result.hero?.statement}\n\n`).length + 23,
    );
  });

  it("derives all enabled headline forms from evidence without parsing statement prose", () => {
    expect(posterModelFor(thirdPartyByteBundle()).headline).toBe("87.5%");

    const currentDominant = clone(fixtures["image-heavy"]);
    const knownDominantIndices = currentDominant.record.resources.flatMap((resource, index) =>
      resource.transferredBytes === null ? [] : [index]
    );
    currentDominant.result.hero!.evidence[0]!.sourceRefs = [
      ...knownDominantIndices.map((index) => `#/resources/${index}/type`),
      ...knownDominantIndices.map((index) => `#/resources/${index}/transferredBytes`),
    ];
    currentDominant.result.hero!.evidence[0]!.rule =
      "round(typeBytes * 1000 / totalKnownBytes) / 10";
    rebindHero(currentDominant);
    expect(posterModelFor(currentDominant).headline).toBe("87.5%");

    const bytes = clone(fixtures["image-heavy"]);
    const bytesHero = bytes.result.hero!;
    const exactRefs = [
      "#/resources/5/transferredBytes",
      "#/resources/5/type",
      "#/resources/5/attributionScope",
      "#/resources/5/attributedNodeIds",
    ];
    bytes.record.resources[5]!.transferredBytes = 600_000;
    bytes.record.resources[5]!.attributionScope = "exact-resource-link";
    bytesHero.statement = "One exactly linked image response contributed 600 KB in this captured load.";
    bytesHero.selectionRule = "largest-exact-resource-share-v1";
    bytesHero.evidence = [<EvidenceMetric>{
      role: "primary",
      level: "observed",
      attributionScope: "exact-resource-link",
      metric: "largest_exact_resource_transferred_bytes",
      value: 600_000,
      unit: "bytes",
      sourceRefs: exactRefs,
      rule: "max(known transferredBytes for exactly linked resources)",
    }];
    rebindHero(bytes);
    expect(posterModelFor(bytes).headline).toBe("600 KB");

    const currentRequests = clone(fixtures["third-party-heavy"]);
    currentRequests.result.hero!.evidence[1] = <EvidenceMetric>{
      role: "support",
      level: "derived",
      attributionScope: "page-level",
      metric: "party_classified_requests",
      value: 8,
      unit: "requests",
      sourceRefs: currentRequests.record.resources.map((_, index) =>
        `#/resources/${index}/party`
      ),
      rule: "count(resources where party is first or third)",
    };
    rebindHero(currentRequests);
    expect(posterModelFor(currentRequests).headline).toBe("4 OF 8");

    const hostileStatement = clone(fixtures["image-heavy"]);
    hostileStatement.result.hero!.statement = "This prose contains 12% and 999 MB but is not parsed.";
    rebindHero(hostileStatement);
    expect(posterModelFor(hostileStatement).headline).toBe("87.5%");
  });

  it("fails closed for link-only, unsafe, classified, and mismatched evidence", () => {
    expectPosterError(() => posterModelFor(fixtures.clean), "ineligible-result");

    const unsafe = clone(fixtures["image-heavy"]);
    unsafe.result.hero!.statement = "<script>not text</script>";
    rebindHero(unsafe);
    expectPosterError(() => posterModelFor(unsafe), "unsafe-text");

    const classified = clone(fixtures["image-heavy"]);
    classified.result.hero!.evidence[0]!.level = "classified";
    rebindHero(classified);
    expectPosterError(() => posterModelFor(classified), "invalid-evidence");

    const wrongUnit = clone(fixtures["image-heavy"]);
    wrongUnit.result.hero!.evidence[0]!.unit = "bytes";
    rebindHero(wrongUnit);
    expectPosterError(() => posterModelFor(wrongUnit), "invalid-evidence");

    const multiplePrimary = clone(fixtures["image-heavy"]);
    multiplePrimary.result.hero!.evidence.push({
      ...multiplePrimary.result.hero!.evidence[0]!,
    });
    rebindHero(multiplePrimary);
    expectPosterError(() => posterModelFor(multiplePrimary), "invalid-evidence");

    const detachedEvidence = clone(fixtures["image-heavy"]);
    detachedEvidence.result.hero!.evidence[0]!.sourceRefs = ["#/resources/0/type"];
    expectPosterError(() => posterModelFor(detachedEvidence), "invalid-binding");

    const inventedRule = clone(fixtures["image-heavy"]);
    inventedRule.result.hero!.evidence[0]!.rule = "trust this derived number";
    rebindHero(inventedRule);
    expectPosterError(() => posterModelFor(inventedRule), "invalid-evidence");

    const inventedScope = clone(fixtures["image-heavy"]);
    inventedScope.result.hero!.evidence[0]!.attributionScope = "exact-element";
    rebindHero(inventedScope);
    expectPosterError(() => posterModelFor(inventedScope), "invalid-evidence");

    const mismatchedStatus = clone(fixtures["image-heavy"]);
    mismatchedStatus.result.statusPresentation.label = "PARTIAL CAPTURE";
    expectPosterError(() => posterModelFor(mismatchedStatus), "invalid-binding");

    const incompleteDominantInputs = clone(fixtures["image-heavy"]);
    incompleteDominantInputs.result.hero!.evidence[0]!.sourceRefs.pop();
    rebindHero(incompleteDominantInputs);
    expectPosterError(() => posterModelFor(incompleteDominantInputs), "invalid-evidence");

    const misboundDominantType = clone(fixtures["image-heavy"]);
    misboundDominantType.result.hero!.evidence[0]!.metric = "script_transfer_share";
    misboundDominantType.result.hero!.evidence[0]!.rule =
      "round(scriptBytes * 1000 / totalBytes) / 10";
    rebindHero(misboundDominantType);
    expectPosterError(() => posterModelFor(misboundDominantType), "invalid-evidence");

    const incompleteThirdPartyInputs = thirdPartyByteBundle();
    incompleteThirdPartyInputs.result.hero!.evidence[0]!.sourceRefs.pop();
    rebindHero(incompleteThirdPartyInputs);
    expectPosterError(() => posterModelFor(incompleteThirdPartyInputs), "invalid-evidence");

    const inventedThirdPartyShare = thirdPartyByteBundle();
    inventedThirdPartyShare.result.hero!.evidence[0]!.value = 66.7;
    rebindHero(inventedThirdPartyShare);
    expectPosterError(() => posterModelFor(inventedThirdPartyShare), "invalid-evidence");

    const incompleteClassifiedCoverage = clone(fixtures["third-party-heavy"]);
    incompleteClassifiedCoverage.record.resources[0]!.party = "unknown";
    incompleteClassifiedCoverage.result.hero!.evidence[1] = <EvidenceMetric>{
      role: "support",
      level: "derived",
      attributionScope: "page-level",
      metric: "party_classified_requests",
      value: 7,
      unit: "requests",
      sourceRefs: [0, 2, 3, 4, 5, 6, 7].map((index) => `#/resources/${index}/party`),
      rule: "count(resources where party is first or third)",
    };
    rebindHero(incompleteClassifiedCoverage);
    expectPosterError(() => posterModelFor(incompleteClassifiedCoverage), "invalid-evidence");
  });

  it("copies only a stable result route and disables overlong X captions", () => {
    const bundle = clone<ViewerBundle>(fixtures["image-heavy"]);
    const resultOrigin = "https://dom-x-ray.example";
    const stable = `${resultOrigin}${bundle.result.resultPath}`;
    expect(shareLinkFor(bundle, stable, resultOrigin)).toBe(stable);
    expectPosterError(
      () => shareLinkFor(bundle, `${stable}?secret=1`, resultOrigin),
      "invalid-binding",
    );
    expectPosterError(
      () => shareLinkFor(bundle, `https://lookalike.example${bundle.result.resultPath}`, resultOrigin),
      "invalid-binding",
    );

    bundle.result.hero!.statement = "x".repeat(270);
    rebindHero(bundle);
    const caption = shareCaptionFor(bundle, stable, resultOrigin);
    expect(caption.tooLong).toBe(true);
    expect(caption.effectiveLength).toBe(295);
    expect(caption.text).not.toContain(bundle.record.page.title);
    expect(caption.text).not.toContain(bundle.record.requestedUrl);
  });
});
