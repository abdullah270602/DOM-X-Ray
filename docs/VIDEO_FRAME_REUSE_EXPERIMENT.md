# Static-frame reuse: unverified encoding candidate

The production encoder is unchanged. This checkpoint did **not** fix the video
timeouts, prove visual equivalence, or close the export reliability/latency gate.

`scripts/verify_video_frame_reuse.py` isolates a candidate from production: keep
the five storyboard PNGs and original scale/crop/transitions, but replace
per-input repeated image decoding with a single scaled-frame buffer per stage.
Its test-only command transform inserts `loop=size=1` and a 30 fps timestamp
expression after each scale and before the animated crop. FFmpeg documents the
single-frame looping mechanism in its [loop filter reference](https://ffmpeg.org/ffmpeg-filters.html#loop).
That documentation supports the mechanism, not measured performance or visual
equivalence in this application.

The harness generates five deterministic product-sized synthetic PNGs containing
color bands, sharp geometry and text. It invokes the production encoder for the
baseline and the transformed command for the candidate. Every encoding worker
uses the existing owned process supervisor, 15-second wall-time ceiling and
10-second internal encoding timeout. Inspection runs in a separate owned
15-second worker with a four-second decoder timeout, never by extending the
encoder deadline.

If all workers complete, it validates the MP4 contract, compares all 150 decoded
frame hashes **and timestamp/duration fields**, compares format/timebase headers,
and checks repeated candidate byte hashes/evidence. Any failed worker or mismatch
aborts the test. The fixed 150-frame framemd5 output is captured before its
64 KiB post-capture size check; this is not a generic pre-allocation output cap.
Even a future passing comparison would cover these synthetic inputs, not actual
browser raster output or end-to-end API reliability.

## Evidence from this checkpoint

- A candidate actual-gallery phase run stopped before video rendering because
  the unchanged poster worker timed out. It provides no candidate encoding result.
- Two candidate fixed-fixture phase runs timed out with encoding unfinished;
  their raster durations were approximately 7.80 and 8.52 seconds.
- The initial synthetic baseline encoding/inspection worker timed out. After
  splitting encoding and inspection, the baseline encoding worker also timed out
  at about 14.55 seconds. Running the candidate first likewise timed out at about
  14.54 seconds. **No complete decoded-frame comparison was obtained.**
- An aggregate host snapshot showed 16,174 MiB available out of 32,370 MiB and
  another snapshot showed 5% aggregate CPU use. They were not synchronized with
  a render, do not measure individual core pressure and do not explain the failures.
- The experimental production filter change was removed. The final harness
  transforms only its test candidate; it has not subsequently passed natively.

```powershell
python scripts/verify_video_frame_reuse.py --verify-command
python -O scripts/verify_video_frame_reuse.py --verify-command
python scripts/verify_video_frame_reuse.py
```

Final normal and optimized portable command controls passed. They check that
only the five loop mechanisms change,
preserving the original crop/scene/transitions, codec/output options and encoding
timeout. Those controls do not substitute for native decoded-frame equivalence,
repeatability, actual-gallery latency, full API regression or X playback testing.
The next change needs a complete comparison and representative successful renders
before adoption. Public scanning remains disabled; the truthful poster fallback
and all production safety deadlines remain intact.
