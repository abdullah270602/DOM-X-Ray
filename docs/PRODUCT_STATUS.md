# Product status — 2026-10-11

The original goal is not achieved: a public, no-login visitor cannot yet paste a
real public URL and reliably obtain a truthful 3D cutaway and shareable result.
Infrastructure checkpoints are not equivalent to a usable release.

## What can be tried now

The [public interactive preview](https://abdullah270602.github.io/DOM-X-Ray/)
is deployed on GitHub Pages. Deployment run
[38147592859](https://github.com/abdullah270602/DOM-X-Ray/actions/runs/38147592859)
passed build, all 74 viewer tests at that checkpoint, and deployment. The actual
public page was opened and rendered in the app; Weight mode changed the live
scene. Mobile CSS width/scroll width were both 365 pixels (no horizontal overflow).
The static build removes URL submission and result-fetching, clearly discloses
prepared examples and unavailable live scanning, and copies example links rather
than fabricated immutable result links. It publishes only static viewer assets.
No scanner backend, credentials, local results or recovery journals are uploaded.
This is an intermediate public preview, not completion of the scanning goal.

The local React/Three.js viewer provides three measured, prepared captures,
Structure/Weight/Origins modes, an authored reveal, replay, timeline scrubbing,
object selection and evidence. Fixture routes work without the scanner API.
The seeded local API can queue the three exact example URLs and publish result
routes; it does not fetch those example hosts or arbitrary websites. Local
poster/video functionality exists, but representative video reliability and
current X playback are unproven. A local result link is not a public share link.

Preview commands (separate terminals, initially from repository root):

```powershell
cd viewer
npm run dev
```

In the second terminal, from repository root:

```powershell
python -m scanner.local_scan_api --result-backend filesystem --data-dir .dom-xray-data/product-preview
```

The
interactive prepared image-heavy result is available at
`http://127.0.0.1:5173/?fixture=image-heavy&time=5000&mode=weight` while Vite runs.
Public scanning remains disabled; the interface must continue to say so.

Live browser check on 2026-10-11: the prepared image-heavy view rendered, then
**Start X-Ray** queued the seeded worker and reached an immutable `/r/` route.
The share dialog verified both PNG and MP4 against their immutable manifests;
replay changed the scene to the initial stage and resumed the reveal. The viewer
was left open in the app for the user. This is an actual local seeded-flow check,
not real public-page scanning, public hosting, social posting or representative
export reliability. The loopback development servers must remain running to use
the preview. Screenshot evidence is local, under the ignored preview data folder.

## Latest scanner experiment, not a release pass

`scripts/verify_pair_read_batch.py` selects a test-only serial-create/batched-read
candidate. It binds engine identity to the durable journal and sends both
consumer rows through unchanged full role preflight before either starts.
Production imports and behavior are unchanged.

Final normal and optimized direct-candidate and mocked full-run controls passed.
They cover durable intent/ID ordering, commit-then-raise tracking, engine/missing/
resource faults, read timeout, consumer-start prevention, cleanup callbacks and
appropriate journal retention. Mocked lifecycle controls are not kernel proof.

One native network-none pinned-image trial ran a stricter 13-second pair lease
inside an owned 15-second worker. All three real container preflights passed,
including batched broker/worker reads. Capture timed out: no result was admitted.
Pair duration was 11.137476 seconds; the outer worker completed in 14.199253
seconds. The persistent journal `pair-read-journal-25ef02b0a78eb9c03f4fc1ea35b94d9e`
was empty and scoped container/volume inventories were restored. Overall verifier
exit was 1 because admission failed. This proves native readback for this trial,
not scanner publication, a baseline speedup, host cgroup binding or reliability.

## Execution focus

1. Put the existing interactive experience in front of the user and collect
   visual/product feedback. Do not wait for scanner release to review the UI.
2. Establish one reliable real-public-page → truthful result → share artifact
   journey under the reviewed scanner boundary. Keep unsupported URLs honest.
3. Deploy the anonymous experience with explicit supported scope, stable public
   result links and operational protections, then verify the real end-to-end
   path from a browser outside the development machine.
4. Expand the representative corpus, reliability and share/playback evidence
   required by the original release gates. Limited scope is an intermediate
   milestone, not a replacement definition of completion.

No further control-channel microbenchmarks are the default next task. Remaining
containment and egress safety obligations are preserved, not waived. Deployment
credentials, new paid resources and unapproved host namespace access must not be
assumed. Human comprehension and sharing studies remain open.
