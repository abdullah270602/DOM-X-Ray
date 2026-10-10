# Local video timeout phase observations

The latest broad seeded API rerun again failed the required gallery video GET:
HTTP 404, eligible/not-generated manifest, and the existing log reports a video
worker timeout. This does not change the verified poster-only fallback contract
or establish video reliability. An independent uninstrumented
`verify_video_renderer.py` run produced only one successful render in two
attempts and failed its reliability check; it is not a pass.

`scripts/verify_video_phase_probe.py` is a test-only diagnostic shim. It invokes
the same video worker main through the original process supervisor, passing
through the original nonce-bearing environment, result path, cwd and 15-second
wall-time ceiling (which includes a reserved cleanup tail). No timeout,
validator, encoding profile, frame count, image dimensions or scene is changed.
The shim adds fixed phase labels and monotonic offsets to a private temporary
file; the parent reads at most 4096 bytes and checks an ordered prefix of the
known phases before printing. No page text, SVG, URL, bundle or artifact path is
logged. The normal renderer removes its temporary directory afterward.

This replaces the worker entry point and introduces imports and filesystem
writes. Measurements are instrumented observations, not exact uninstrumented
performance or a causal proof about host scheduling. An exit code of zero means
the diagnostic completed, **not** that any render succeeded.

## Observed runs

```powershell
python scripts/verify_video_phase_probe.py
python scripts/verify_video_renderer.py
python scripts/verify_video_phase_probe.py --seeded-gallery --attempts 4
python scripts/verify_video_phase_probe.py --verify-observations
python -O scripts/verify_video_phase_probe.py --verify-observations
```

The final observation-reader controls passed normally and optimized: all valid
prefixes are accepted, and oversize/malformed observations, unknown labels,
nonfinite/boolean/negative/backwards clocks are rejected. These portable checks
validate diagnostic output handling, not video performance.

Two instrumented generated image-heavy fixture attempts completed and validated
1,085,010-byte videos, with supervised times 8.583 and 8.955 seconds. Their
raster stages took approximately 3.56 and 3.15 seconds, and encoding approximately
3.96 and 4.20 seconds. These two successes do not establish a 95% reliability
rate, representative latency or the seeded API path.

Seeded mode instead calls the real supervised gallery fixture executor and real
poster renderer. A test callback captures exactly the eligible input passed to
the video renderer after poster creation, then deliberately raises its expected
optional-render exception. That setup is not itself a successful video run.
Four subsequent renders of this input all timed out after approximately
14.54–14.57 supervised seconds, with `encode-start` as the last recorded phase.
Raster durations were approximately 5.66, 5.11, 4.88 and 4.75 seconds. Encoding
had begun but no completion marker was observed when the supervisor returned.
The evidence localizes these timeouts to an unfinished encoding stage; it does
not show encoding is the sole bottleneck or explain host variability.

An experimental per-input decoder `-threads:v 1` trial also timed out twice;
its raster stages took approximately 8.42 and 9.46 seconds. No speed improvement
was demonstrated, and the experimental production change was removed. FFmpeg's
[codec options](https://ffmpeg.org/ffmpeg-all.html#Codec-Options) document automatic
thread selection, and its [option rules](https://ffmpeg.org/ffmpeg.html#Description)
explain per-file scope; those rules motivated the experiment, not a causal claim.

## Next proof required

Repeat phase observations under a recorded host/load/runtime configuration;
profile encoding with the actual seeded input, then verify a targeted change
against decoded visual frames, MP4 validation, repeatability, export latency and
the full API publication/restart/deletion regression. Keep the existing safety
limits and truthful fallback. Current X playback/upload, representative public
pages and production worker reliability remain unproven. Public scanning stays
disabled.
