# Bounded local terminal-job history

The local job service previously retained every completed/rejected job forever.
It now accepts `terminal_job_history_limit` (engineering default 1024, positive
integer only). All job registrations and terminal transitions run through one
helper under the service lock. An ordered terminal index records **terminal
registration**, not original submission, so an old active job becomes recent
history when it completes. Oldest terminal metadata is evicted on overflow.

Queued/running jobs never enter the eviction index. With configured active-job
limit A and terminal-history limit H, the retained job map is at most A+H after
locked mutations. This is a count of retained polling records, not a total
allocation/byte bound. Detached response snapshots and other service/backend
state are outside this count. Missing late progress/failure callbacks are ignored
rather than recreating an expired terminal job.

Eviction affects only in-memory polling metadata. It never deletes a stored
result/artifact, clears an admission reservation or changes a deletion capability.
An evicted job ID returns the existing generic 404 with `Cache-Control: no-store`.
The new test also exposed that this header was missing on job misses; that route
was corrected without changing job schemas. Stable result URLs have their own
separate retention/deletion authority.

## Evidence

```powershell
python scripts/verify_api_job_history.py
python -O scripts/verify_api_job_history.py
python scripts/verify_local_scan_api.py
```

Both final history checks passed. One running and one queued job survive 64
terminal rejections with history limit three; retained counts stay within five,
old terminal records expire, and old active jobs become recently retained
failures after release. Further churn evicts those completed jobs, and late
callbacks do not recreate them. Invalid limit types/ranges fail before pool
creation.

A separate real supervised seeded gallery execution publishes into the memory
result backend with history limit one. Rejection churn evicts its ready job;
actual loopback polling returns a no-store generic miss, but backend retrieval
still yields byte-identical bundle/poster and ETags. Exact-target reuse returns
the same result while maintaining the history cap, and the original browser
capability still deletes it after eviction/reuse. This tests independent result
authority, not deployed distributed storage or CDN behavior.

The initial run failed because job 404 responses lacked the no-store header;
it is not a pass. Final normal/optimized runs passed after the header fix. The
full existing seeded API suite separately passed publication, artifact routes,
restart/deletion, target correlation and availability controls. The optimized
history harness covers its service process, not propagation into render/fixture
children. Public scanning remains disabled.

## Remaining launch requirements

This cap promises no minimum terminal polling window or TTL: under churn,
terminal metadata can expire before a visitor receives it. Clients must handle
expired polling IDs; production retention/availability policy and rate controls
still require explicit decisions and representative load proof. Active jobs
are preserved, but result discovery and deletion usability under that churn are
not proven by the direct backend/capability checks.

Admission/origin maps, deletion-failure history, backend objects, aggregate
memory, whole-request/backend deadlines and distributed abuse controls remain
separate requirements. Local caps are not shared across instances or durable
job orchestration. This checkpoint does not close the public API safety or
product latency gate, and no stored user result is deleted merely to enforce
the terminal metadata cap.
