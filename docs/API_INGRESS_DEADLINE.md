# Absolute local HTTP read deadline

The local HTTP server now accepts `http_ingress_timeout_seconds` (engineering
default 30 seconds, positive finite int/float, not boolean). A monotonic deadline
starts when each handler begins `handle_one_request`, before the request line.
One deadline spans the request line, headers and any body the route reads.

A raw socket reader under `io.BufferedReader` recomputes the remaining budget
before every underlying `recv_into`, setting the socket timeout to the smaller
of remaining ingress time and the existing idle-I/O timeout. This also covers
the standard library's buffered header `readline`, not only explicit body reads.
Bytes returned at or after the deadline are rejected by a post-receive check.
The idle timeout is restored after each receive for independent response writes.
The deadline is cleared on handler exit; it is never extended by arriving bytes.
Normal handler/socket cleanup and capacity-permit release remain in place.

This is an absolute **network-read budget**, not a hard whole-request deadline.
Buffered bytes may be consumed without another receive; computation, backend
I/O, parser hashing, response writes, renderer work, thread scheduling and time
before handler entry are not preempted by this reader. A production edge proxy,
aggregate memory/connection controls, backend deadlines and distributed abuse
enforcement remain separate requirements. No hard real-time scheduling guarantee
or public scanner activation is claimed.

## Verification

```powershell
python scripts/verify_api_ingress_deadline.py
python -O scripts/verify_api_ingress_deadline.py
python scripts/verify_api_http_capacity.py
python -O scripts/verify_api_http_capacity.py
python scripts/verify_api_deletion_history.py
python -O scripts/verify_api_deletion_history.py
```

Final normal/optimized slow-drip tests passed with real owned loopback sockets:
partial headers and partial JSON bodies receive bytes every 50 ms but close
under a 0.5-second ingress budget, before the independent two-second idle limit.
They create no admission/rejection jobs, release the sole handler permit and
allow ordinary health requests afterward. Owned senders/handlers/server threads
are joined. EOF and connection-reset/aborted close races are accepted, but any
response byte or a receive timeout fails the test. This proves observed local
close/recovery, not guaranteed TCP response delivery or production edge behavior.

Controlled reader checks prove the exact exhausted boundary refuses another
receive, a read completing at expiry is rejected, and a 0.2-second remaining
budget restores the independent idle timeout.
Invalid limits fail before listener binding. Existing capacity controls passed
normally and optimized after this change.
Final normal/optimized owner-deletion and parser-concurrency regressions also
passed, retaining real HMAC owner authorization and parser overflow/recovery.

The broad seeded API rerun failed before result publication with fixed
`internal-error`; it is not a pass or proof of the cause. The broad verifier
now reports only `timeout`/`failed` for its required seeded poster seam while
rethrowing the original error, preserving production response privacy. Its next
diagnostic rerun passed publication, poster/video routes, restart and deletion,
so that run did not trigger the poster diagnostic. The initial failure's cause
remains unproven. That pass preceded the final post-receive expiry check. The
subsequent full seeded API run on the final code also passed publication,
poster/video GET/HEAD/ETag routes, byte-identical restart recovery, owner deletion,
target/reuse controls and the deliberately injected video-failure fallback.
This is fixture regression coverage, not representative export reliability or
production safety proof. Narrow controls do not replace the broad suite.

The separate two-filter-thread video experiment produced zero successful renders
in two attempts and was removed. Production encoder, video validation, poster
fallback and renderer deadlines are unchanged. Export reliability remains open.
