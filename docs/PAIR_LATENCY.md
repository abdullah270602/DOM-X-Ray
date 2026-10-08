# Gate 3 — Native pair latency investigation

## Evidence, 2026-10-08

Fresh reserved HTTPS capture still times out on Windows Docker Desktop. The
absolute lease remains 15 seconds including setup and cleanup, with five seconds
reserved for teardown. No security, TLS, resource or measurement limits changed.

Content-free `--trace` output locates the execution timeout at approximately ten
seconds. One baseline trace reached broker readiness at 5,399 ms and finished
cleanup around 14,423 ms. After setup overlap another trace reached readiness at
4,923 ms and finished cleanup around 14,128 ms, but still timed out. Individual
observations are not a controlled benchmark or demonstrated SLA improvement.

Stopped broker/worker creation and preflight now overlap initializer startup.
Neither consumer starts until attach and engine state prove successful zero exit,
no OOM and stopped/PID-zero status. Durable intents/IDs stay serialized in dependency
order. Contract tests require overlap and prove initializer failure starts neither
consumer while cleaning all three created roles. Pair and journal-fault regressions
pass.

## Diagnostic worker, not a result

`containers/pair-profile.Dockerfile` overlays code on the verified local candidate
without refreshing dependencies or replacing its tag. Original base ID:

`sha256:6f898cbcaa93d174ed62795ef10187009777d2b2f8c7580bcde7bc83fe5fc408`

Fixed operator-only `worker-profile` mode reports static stage names and integer
milliseconds, never requests, grants, nonces, credentials, certificates, paths,
container IDs or provider errors. Prefixed stdout is intentionally invalid as a
scan envelope. The harness requires actual Chromium launch/navigation markers
and rejects admission.

Two diagnostic observations showed issuer setup at 17 ms, private NSS trust setup
at 41–51 ms, bridge construction below one millisecond at this precision, and
sandboxed Chromium launch at 894–993 ms. Navigation to DOM-content-loaded took
489 ms in the second observation. Probe began but did not complete before the
execution deadline. Total startup-through-cleanup was 14,897 ms and 14,524 ms;
both journal snapshots were empty.

Navigation completes; the unresolved interval is inside post-navigation probe
settling/measurement. This does not prove quiet-state tracking is the sole cause.
Next gather bounded quiet-state/network-event evidence, preserving actual service
worker observation and capture semantics. Do not shorten settling to obtain a pass.

Later observations refine that provisional diagnosis: probe returned in about
1,818–2,001 ms and browser close in 289–369 ms. Bridge cleanup began but its
listener `shutdown()` had not returned before the worker execution cutoff; the
handler-stop phase had not begun. The current target is bridge listener teardown,
not a demonstrated permanent page-settling stall. Why shutdown waits is still
unproven. One late diagnostic run also returned `supervisor-failed`; no labeled
containers or volumes remained in the subsequent direct engine inventory, but
that does not establish successful journal completion or independent emptiness.

The new verifier initially compared byte labels with text labels and falsely
rejected launch/navigation markers. It now normalizes ASCII and has a portable
regression test, including rejection of unknown labels, extra fields, oversized
numbers and arbitrary envelope content. A subsequent diagnostic run passed as
`worker-timeout` at 13,712 ms; this is truthful timeout/no-admission evidence,
not successful capture. Timing wrappers now emit a separate static error marker
so an exception exit cannot be mistaken for successful stage completion.

## Reproduction

Check the base tag matches the ID above before building:

```powershell
docker --context desktop-linux image inspect dom-x-ray-runtime-candidate:gate3 --format '{{.Id}}'
docker --context desktop-linux build --file containers/pair-profile.Dockerfile --tag dom-x-ray-runtime-candidate:gate3-profile .
python scripts/verify_pair_transport.py --journal --case profile --trace --image dom-x-ray-runtime-candidate:gate3-profile
```

An initial full-candidate build lacked cache and began refreshing OS layers. Its
exact task-owned build CLI was stopped before it replaced the original tag. The
small overlay uses existing dependencies. No unrelated resources were stopped
or pruned. No successful native capture or controller-death recovery is claimed.

Public arbitrary-URL scanning, watchdog deployment, real controller-death recovery
and independent cgroup-empty proof remain gated.
