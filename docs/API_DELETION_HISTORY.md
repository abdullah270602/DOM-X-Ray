# Bounded local deletion-failure history

`LocalScanJobService` accepts `deletion_failure_history_limit` (default 1024,
positive integer, not boolean). Each tracked result retains at most five
wrong-token timestamps, the existing threshold. Expired timestamps/IDs are
pruned on the next deletion request, at the existing 60-second boundary.
Further throttled guesses do not append timestamps or extend that window.

If the map is full, a forbidden attempt against a new result ID returns the
existing rate-limited outcome with a Retry-After based on the earliest retained
expiry. It allocates no new history and evicts no existing counter. This is
global local-process backpressure, not a promise of fairness per result.

Backend authorization still happens before throttling: valid owner deletion,
pending/retryable deletion and missing-result outcomes retain their behavior.
Successful deletion clears its failure record. An attacker cannot use this
history cap to prevent a valid owner from deleting a result.

## Evidence and limitations

`scripts/verify_api_deletion_history.py` tests controlled backend outcomes,
per-ID/global saturation, capacity recovery, unchanged fifth-failure threshold,
no window extension, exact expiry and strict configuration validation. Its
separate loopback check uses the real memory backend's HMAC capability checks:
wrong tokens hit 403/429, an untracked result hits saturation, and both original
owners still delete with empty no-store 204 responses and unavailable results.
This is not deployed/distributed capability or storage proof.

Final normal and optimized runs passed outside the sandbox with owned loopback
HTTP access. Initial expanded harness runs failed on an incorrect fixture name,
then on sandbox socket denial; neither is counted as a pass. The final fixture
names are `clean` and `image-heavy`, with no scan or video render needed.

```powershell
python scripts/verify_api_deletion_history.py
python -O scripts/verify_api_deletion_history.py
```

The broad seeded API regression failed during this checkpoint at its required
video GET. A diagnostic rerun identified a video-worker timeout at the unchanged
15-second safety limit, with HTTP 404 and an eligible/not-generated manifest.
The API retained its poster-only fallback as designed. Neither failed run is a
pass; the narrower deletion test does not replace that regression or establish
video reliability. No renderer deadline or validator was relaxed.

The cap bounds retained timestamp/ID counts, not request cost or aggregate
memory. Pruning scans the bounded map and temporarily creates replacement
lists. Backend I/O still runs before throttling under the service lock; this
does not cap backend calls, establish a total request deadline, provide
distributed abuse controls or fix video performance. Public scanning remains
disabled.
