---
id: TODO-419
title: Fix CI linux-fastpath-gates — uring_batch stale CQE drain
severity: HIGH
phase: legacy
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-23
commit: 1dd8a3b
---

# TODO-419: Fix CI `linux-fastpath-gates` — `uring_batch` stale CQE drain

## Problem

The `linux-fastpath-gates` CI job was failing with:

```
assertion `left == right` failed: all 8 datagrams should be sent across chunks
  left: 4
 right: 8
```

`UringBatchSender::send_batch` with queue depth 4 was returning 4 instead of 8 when sending 8 datagrams. The second chunk was reported as `sent=0`, causing `send_batch` to return early with `total_sent=4`.

## Root Cause

`send_batch` uses `submit_and_wait(queued)` to wait for completion of each chunk. On the zero-copy path (`submit_chunk_zc`), every `SendMsgZc` SQE produces **two** CQEs:

1. Primary CQE: data accepted into socket buffer.
2. Notification CQE (`CQE_F_NOTIF`): kernel released the buffer.

After the first chunk, the primary CQEs were consumed by the reap loop, but notification CQEs from the first chunk could still be in the CQ ring. When the second chunk called `submit_and_wait(queued)`, the kernel considered the old notification CQEs as satisfying the wait condition and returned immediately — before the second chunk's SQEs were actually completed. The subsequent reap loop then saw only stale notification CQEs and no primary CQEs, leaving `send_success` all `false` and reporting `sent=0`.

## Fix

Drain the completion queue before pushing new SQEs in both `submit_chunk` and `submit_chunk_zc`. This ensures `submit_and_wait(queued)` waits for the correct (new) CQEs.

## Acceptance

- [x] `linux-fastpath-gates` CI job is green.
- [x] `uring_batch_handles_large_batch_beyond_queue_depth` test passes.
- [x] All other CI jobs remain green.

## Files

- `src/optimize/uring_batch.rs`
- `scripts/tests/rust/rt-transport-uring.rs` (test case, unchanged)

## Notes

The job was `continue-on-error: true`, so it did not block CI status, but a red job is still a red job and needed fixing before continuous loop work.
