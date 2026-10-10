# Actual seeded video input and complete attempt accounting

Production rendering is unchanged. The verifier can now exercise the exact
bundle passed to video rendering after the real seeded gallery transport,
mapping and poster generation, rather than only a generated image-heavy bundle.
The setup deliberately defers its optional video call; subsequent exports invoke
the uninstrumented production video renderer. This is a repeated single-input
export benchmark, not repeated complete scans, API publication or public pages.

```powershell
python scripts/verify_video_renderer.py --seeded-gallery --attempts 5
python scripts/verify_video_benchmark_contract.py
python -O scripts/verify_video_benchmark_contract.py
```

Every attempted export now has a fixed outcome and elapsed time, including
expected renderer failures and invalid artifacts. JSON is printed before gate
assertions. Unexpected operational/validator exceptions retain a redacted
failure and abort further attempts: another worker must not launch when cleanup
may be unproven. The gate rejects any aborted run, preserving planned versus
attempted counts. Exception text, input URLs and page content are not serialized.
Setup failures remain fatal before the export sample; they are not video passes.
Clock or report-serialization faults also remain fatal and do not guarantee a
summary; the redacted abort path covers renderer and artifact-validator faults.

Only the first successful artifact and the current artifact are retained, plus
bounded per-attempt metadata. Successful repeatability uses SHA-256 comparisons.
The original 95% *sample* rule, under-ten-second bound, MP4 contract and ineligible
clean-fixture refusal remain. A small passing sample does not statistically
establish 95% population reliability. Timing includes renderer validation and
the verifier's additional MP4 validation, so it conservatively overcounts the
renderer call alone; transport/poster setup and queueing are outside this clock.

## Native evidence, 2026-10-11

Two sequential five-export seeded-gallery runs passed on this Windows host.
The second used the final aborted-run handling code:

| Run | Success | Median | Maximum | Bytes per export |
| --- | --- | --- | --- | --- |
| Initial accounting version | 5/5 | 7.451 s | 7.617 s | 1,085,010 |
| Final accounting version | 5/5 | 7.263 s | 7.875 s | 1,085,010 |

All successful artifacts had SHA-256
`556dec368f0f05318099f9f3ea2591bf85883b78a0ef818a6bf1f73b2753265d`.
The final individual export durations were 7.875, 7.602, 7.263, 6.843 and
6.723 seconds. These are fresh local fixture successes; earlier timeout failures
in `VIDEO_PHASE_DIAGNOSTIC.md` and `VIDEO_FRAME_REUSE_EXPERIMENT.md` remain failures.
No production filter, runtime pin, resource policy or timeout was changed.
This evidence does not identify the cause of host variability or prove the
static-frame candidate, optimized native child modes or current X playback.

Final portable normal/optimized accounting tests cover expected failure timing,
no exception-text leakage, invalid cadence/MP4, unexpected render/validator
abort without retry, summary emission before gate refusal, deterministic-byte
checks, exact ten-second refusal, strict attempt counts and the 19/20 sample
boundary. Mocks prove accounting only, not native performance.

Representative corpus/load/runtime benchmarks, full release reliability,
end-to-end latency and social playback remain open. Public scanning is disabled.
