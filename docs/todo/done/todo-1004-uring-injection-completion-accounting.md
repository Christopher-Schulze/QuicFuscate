---
id: TODO-1004
title: io_uring SendMsg injected-partial-failure completion accounting fails on kernel 6.17
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-09-19
depends_on: []
---

# TODO-1004: io_uring Injected-Partial-Failure Completion Accounting on Kernel 6.17

## Objective
`uring_sendmsg_partial_send_retry_subsets_deliver_exactly_once` fails deterministically on Omega (aarch64, kernel 6.17) with `io_uring SendMsg completion set incomplete: 2/3, cq_overflow=0`. The SendMsgZc twin (`uring_sendmsg_zc_partial_send_retry_subset_delivers_exactly_once`) passes on the same host. Determine whether the injected-failure submission path miscounts queued vs completed SQEs on this kernel or the kernel genuinely completes a differently-shaped submission.

## Root Cause (verified 2026-09-19, strace on Omega)
`io_uring_enter(fd, to_submit=3, min_complete=3, GETEVENTS)` returns **2**: kernel 6.17 imports the `msghdr` at SQE *prep* time, so an SQE whose iovec is invalid aborts the submission loop - the kernel consumes the SQEs in order, executes slot 0, fails slot 1 at prep, and leaves slot 2 **unconsumed in the SQ ring**. That pending SQE still references sender-owned storage and would execute with stale pointers on any later submission, so quarantining the sender is the only safe response; the io-uring crate offers no SQE retraction API.

Older kernels imported the msghdr at issue time, where the invalid slot produced a regular `-EFAULT` error CQE and the batch completed 3/3 with a partial disposition - which is also why the SendMsgZc twin still passes (different prep path).

## Fix
- `submit_and_wait`/`submit_and_poll` now compare the kernel-consumed SQE count against `queued` and quarantine immediately with a precise `InvalidData` error ("kernel consumed only N/M SendMsg SQEs; pending SQEs make the ring unsafe") instead of misattributing the outcome to completion accounting - and, on the worker poll path, without burning the 250 ms operation deadline.
- The test now encodes both kernel contracts: `Ok` partial dispositions + fallback exactly-once (issue-time import), or `Err(InvalidData)` quarantine where only the pre-failure prefix reaches the wire, the pending SQE never fires, and the dead sender rejects further batches.

## Verified Evidence (original failure)
- `scripts/tests/rust/rt-transport-uring.rs` — `send_batch_with_injected_iovec_failures(fd, payloads, &[1])` returned `BatchSendError { quarantined, dispositions: [Quarantined; 3] }` instead of the expected partial disposition.
- Reproduced 3/3 runs on Omega **and** on a tree with the TODO-902 `ToFlat` changes stashed - pre-existing, not a regression of the flat-adoption work.
- strace evidence: `io_uring_enter(3, 3, 3, IORING_ENTER_GETEVENTS, NULL, 128) = 2`.

## Acceptance
- The injected-partial test passes on Omega, or the accounting is proven kernel-version-dependent and the test documents/skips the affected kernel range with evidence. **Met**: `rt-transport-uring` 22/22 on Omega kernel 6.17.
