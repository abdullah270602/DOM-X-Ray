---
name: DOM X-Ray
description: A measured public page load turned into an explorable architectural cutaway.
colors:
  paper: "#e9e1d2"
  paper-light: "#f3ede3"
  graphite: "#20251f"
  soft: "#565b51"
  inspection-red: "#d9492f"
  inspection-red-dark: "#a92e1b"
  external-teal: "#2d6571"
  model-board: "#b8aa8b"
  brass: "#9b772f"
  line: "rgba(32, 37, 31, 0.31)"
typography:
  display:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "clamp(5rem, 7.25vw, 6.8rem)"
    fontWeight: 800
    lineHeight: 0.68
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "clamp(1.6rem, 2.05vw, 2.2rem)"
    fontWeight: 700
    lineHeight: 0.98
    letterSpacing: "-0.018em"
  body:
    fontFamily: "Archivo Variable, Arial, sans-serif"
    fontSize: "0.96rem"
    fontWeight: 400
    lineHeight: 1.4
  label:
    fontFamily: "Courier New, monospace"
    fontSize: "0.68rem"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "0.14em"
rounded:
  hairline: "0"
  instrument: "2px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  xl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.inspection-red}"
    textColor: "#fffaf2"
    rounded: "{rounded.instrument}"
    height: "50px"
    padding: "0 16px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.graphite}"
    rounded: "{rounded.instrument}"
    height: "50px"
    padding: "0 16px"
  field-url:
    backgroundColor: "rgba(243, 237, 227, 0.46)"
    textColor: "{colors.graphite}"
    rounded: "{rounded.hairline}"
    height: "55px"
    padding: "0 16px"
  job-readout:
    backgroundColor: "transparent"
    textColor: "{colors.external-teal}"
    rounded: "{rounded.hairline}"
    height: "39px"
    padding: "9px 0"
  button-owner-delete:
    backgroundColor: "transparent"
    textColor: "{colors.inspection-red-dark}"
    rounded: "{rounded.hairline}"
    height: "38px"
    padding: "0 12px"

# Design System: DOM X-Ray

## Overview

**Creative North Star: "The Measured Inspection Table"**

DOM X-Ray is a public visual instrument: a captured page is laid out like a physical architectural model, then separated into structure, weight, and external-origin relationships. The visual world is warm paper and graphite with a small amount of inspection red for the consequential finding and external teal for machinery outside the page boundary. It is editorial and tactile, but remains precise enough to expose the evidence behind every emphasized object.

The first viewport uses a quiet instrument column beside a dominant 3D cutaway. The left column carries identity, URL input, capture status, and one hero fact; the model owns the right side; a continuous rail anchors modes and playback at the bottom. The build is intentionally flat and material-led: no gradients, glassmorphism, neon cyberpunk, dashboard card grid, or decorative 3D particles.

**Key Characteristics:**

- Warm paper, board, drafting-film, graphite-line, and brass-registration materials.
- One red finding language; teal is reserved for external-origin topology and focus.
- A 3D architectural cutaway paired with a complete text/object-index fallback.
- Evidence is a first-class path, not decorative annotation.
- Deliberate reveal, bounded orbit, and reduced-motion stage stepping.
- A compact worker-status readout that keeps scan progress and recovery in the instrument column.

## Colors

The palette treats color as instrumentation: paper establishes the field, graphite carries most text and line work, red marks inspection and consequence, and teal identifies external-origin semantics and accessible focus.

### Primary

- **Inspection red** (`{colors.inspection-red}`): The X-RAY action, hero finding marker, selected objects, active mode indicator, and measured emphasis.
- **Inspection red dark** (`{colors.inspection-red-dark}`): Stronger text and status contrast where red is used on paper.

### Secondary

- **External teal** (`{colors.external-teal}`): Third-party hubs, origin connections, selection focus rings, and external-origin semantics. It does not mean “tracker.”

### Neutral

- **Warm paper** (`{colors.paper}`): The global canvas and primary shell surface.
- **Paper light** (`{colors.paper-light}`): Rail, evidence drawer, and lighter instrument surfaces.
- **Graphite** (`{colors.graphite}`): Primary text, rules, model outlines, and dark evidence blocks.
- **Soft graphite** (`{colors.soft}`): Supporting labels and secondary copy.
- **Model board** (`{colors.model-board}`): The physical inspection-table plinth and model caption.
- **Brass** (`{colors.brass}`): Registration hardware and model caption borders.
- **Instrument line** (`{colors.line}`): Low-contrast dividers and drafting rules.

**The Sparse Accent Rule.** Red and teal are measurement signals. Keep them rare and purposeful; do not turn the whole surface into an accent field.

## Typography

**Display Font:** Barlow Condensed (with Arial Narrow, sans-serif fallback)

**Body Font:** Archivo Variable (with Arial, sans-serif fallback)

**Label/Mono Font:** Courier New, monospace

**Character:** Barlow Condensed gives the wordmark and hero finding a tall, compressed editorial voice. Archivo keeps controls and supporting copy legible, while Courier New makes capture metadata, stage IDs, and raw evidence feel like instrument readouts.

### Hierarchy

- **Display** (800, `clamp(5rem, 7.25vw, 6.8rem)`, `0.68`): The stacked DOM X-RAY wordmark, with tight negative tracking and a graphite underline.
- **Headline** (700, `clamp(1.6rem, 2.05vw, 2.2rem)`, `0.98`): The single dynamic hero statement in the instrument column and evidence drawer headings.
- **Title** (750, approximately `0.67rem`–`0.76rem`, normal): Instrument actions, mode labels, and compact control names.
- **Body** (400, `0.96rem`, `1.4`): URL input and explanatory copy; keep supporting text short and readable.
- **Label** (700, `0.68rem`, `0.14em`, uppercase): Measurement labels, status, stage IDs, and provenance metadata.

**The One Finding Rule.** The title is the strongest typographic object; the dynamic hero statement is second. Supporting metrics must not compete with the causal statement.

## Layout

The desktop shell is a 28/72 editorial split: the instrument column is `clamp(330px, 28.5vw, 430px)` and the model stage owns the remaining space. The main viewport occupies `calc(100dvh - 78px)` with a continuous `78px` instrument rail across the bottom. The left column is vertically scrollable and uses inset drafting rules; the model stage is clipped and visually dominant rather than surrounded by cards.

At widths below `1080px`, the column settles to `320px` and secondary capture/performance plates are hidden. At `800px` and below, the shell becomes a vertical composition: identity and hero first, a minimum `560px` model stage second, then mode/playback rows and the evidence surface. The evidence drawer is a right-side panel up to `min(410px, 54vw)` on desktop and a bottom sheet up to `min(72dvh, 650px)` on mobile. This preserves the hero and model together before exposing deeper evidence.

## Elevation & Depth

Depth is conveyed primarily through tonal layering, translucent drafting-film planes, board material, outlines, brass registration details, and physically separated scene objects. The base shell is flat and paper-like. The only meaningful UI shadow is the evidence drawer's ambient offset (`-18px 10px 42px`); controls use borders and tonal change instead of floating-card elevation.

**The Flat Instrument Rule.** Surfaces rest on the paper field. Physical depth belongs to the cutaway model and evidence drawer, not to a dashboard-like stack of cards.

## Shapes

The form language is rectangular and lightly mechanical. Most controls use a restrained `2px` corner radius; fields and select controls can be square. One-pixel graphite or low-contrast rules establish boundaries, while the model uses flat plates, lightly chamfered-looking separations, thin seams, cylinders, rings, and registration hardware. There are no inflated pills, rounded glass panels, or soft blob silhouettes.

## Components

### Buttons

- **Shape:** Rectangular instrument controls with a `2px` radius and a minimum `50px` primary action height.
- **Primary:** Inspection red fill, light text, bold uppercase label with moderate tracking, and a directional arrow. Hover deepens the red and lifts the button by `1px`.
- **Secondary / Ghost:** Transparent paper surfaces with graphite border and text; hover inverts to graphite with light text. Evidence, copy, drawer, and icon actions share this language.
- **Owner deletion:** A low-priority, borderless red-dark text action appears only when the active published result has a valid browser-held deletion key. It requires native confirmation, shows an in-place deleting state, and never appears for fixtures, reused submissions without the original key, or shared browsers.
- **Focus:** A visible `3px` teal outline with `3px` offset is the keyboard focus treatment.

### Inputs / Fields

- **Style:** The URL field is a `55px` tall, square-cornered, graphite-stroked field with a lightly translucent paper-light fill and a globe icon.
- **Focus:** Teal border plus an inset teal keyline.
- **Error / Disabled:** Error uses inspection-red-dark; disabled controls lower opacity to `0.56` and retain the instrument geometry.

### Scan-job Status Readout

- **Style:** A compact, two-line Courier New status strip sits inline below the URL help text, bounded by one-pixel rules rather than a modal or progress card. The first line is the stage label; the second is the opaque job ID or published result ID.
- **States:** Use the implemented labels **CHECKING TARGET**, **SCAN QUEUED**, **ADMITTING CAPTURE**, **MAPPING MEASUREMENTS**, **PUBLISHING RESULT**, **IMMUTABLE RESULT READY**, **SCAN NOT ADMITTED**, and **SCAN INCOMPLETE** for admission, queued, capturing, mapping, publishing, ready, rejected, and failed progress.
- **Motion and color:** Running states use a small teal mark with a restrained pulse; ready fills the mark; rejected and failed use inspection-red-dark. The loading action may show a small spinner, but the readout remains the durable status source.
- **Recovery:** Inline errors remain adjacent to the field and preserve the last valid current bundle/model. A failed or rejected request must not erase a previously valid result.
- **Publication boundary:** Seeded fixture previews are explicitly labeled `FIXTURE` and do not expose a share/copy action. Copy/share appears only when a published result is active (`fixtureName === null`) and its finding is share-eligible.
- **Owner boundary:** Deletion authority is browser-local and is never shown in job IDs, result URLs, copy text, or evidence. Successful deletion returns the viewer to a seeded capture with a terse live status; failed deletion preserves the current result and names recovery inline.

### Navigation / Instrument Rail

- **Style:** One continuous paper-light rail across the bottom, divided by vertical rules rather than individual cards.
- **Modes:** Structure, Weight, and Origins are text-plus-icon controls. The active mode uses red text and a red underline.
- **Playback:** Replay, play/pause or reduced-motion “NEXT STAGE,” a red-accented timeline, and an orbit hint for “DRAG TO INSPECT DEPTH.”
- **Responsive:** The rail becomes stacked full-width rows on phone layouts.

### Cards / Containers

- **Style:** Do not use generic cards. The capture plate, performance plate, model caption, and evidence drawer are named instrument surfaces with thin rules, metadata typography, and clear provenance purpose.
- **Capture plate:** Compact Courier New metadata block for captured date, URL, method, and viewer version.
- **Performance plate:** Teal-outlined readout for object budget, draw calls, frame time, FPS, and renderer.

### Evidence Drawer

- **Character:** A provenance ledger attached to the model edge, not a separate analytics page.
- **Content:** Selected object label, selectable ID, raw summary fields, isolation action, and expandable raw-source records.
- **Behavior:** Opens from selection, focuses its close control, supports isolate/show-complete-model, and becomes a bottom sheet on mobile.

### Signature Component: Architectural Cutaway

The 3D scene is a bounded inspection table: a board plinth, layered region plates, page-level bus, external-origin hubs, measured connections, selection reticle, and a brass model caption. Structure, Weight, and Origins alter emphasis and separation while consuming the same scene manifest. The text “MODEL INDEX” path exposes the same selectable objects and evidence when WebGL is unavailable or intentionally bypassed.

## Do's and Don'ts

### Do:

- **Do** preserve the warm paper / graphite field and use red only for inspection findings, selection, and active state.
- **Do** keep the 28/72 split and the model as the dominant visual subject on desktop.
- **Do** make every emphasized object traceable to raw evidence and its mapping rule.
- **Do** retain the hero statement and evidence in reduced-motion, text-only, and no-WebGL paths.
- **Do** use thin rules, board/drafting-film layering, brass registration, and compact mono readouts to create depth.
- **Do** keep scan admission/progress, terminal status, and recovery visible inline without displacing a valid current result.

### Don't:

- **Don't** turn the viewer into a scorecard, bento dashboard, generic monitoring workspace, or roast interface.
- **Don't** use gradients, glassmorphism, neon cyberpunk, ambient particles, liquid blobs, perpetual bobbing, or decorative wire motion.
- **Don't** make third-party origin teal imply “tracker”; preserve the external-origin meaning.
- **Don't** replace the continuous bottom rail with a row of floating cards.
- **Don't** let a spectacular 3D object outrun its evidence, or let essential facts depend on WebGL.
- **Don't** show share/copy affordances for unpublished fixture-only previews.
