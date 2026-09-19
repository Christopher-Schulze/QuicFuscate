---
id: TODO-1004
title: io_uring SendMsg injected-partial-failure completion accounting fails on kernel 6.17
severity: LOW
phase: S
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1004: io_uring Injected-Partial-Failure Completion Accounting on Kernel 6.17

## Objective
`uring_sendmsg_partial_send_retry_subsets_deliver_exactly_once` fails deterministically on Omega (aarch64, kernel 6.17) with `io_uring SendMsg completion set incomplete: 2/3, cq_overflow=0`. The SendMsgZc twin (`uring_sendmsg_zc_partial_send_retry_subset_delivers_exactly_once`) passes on the same host. Determine whether the injected-failure submission path miscounts queued vs completed SQEs on this kernel or the kernel genuinely completes a differently-shaped submission.

## Verified Evidence
- `scripts/tests/rust/rt-transport-uring.rs:180` — `send_batch_with_injected_iovec_failures(fd, payloads, &[1])` returns `BatchSendError { quarantined, dispositions: [Quarantined; 3] }` instead of the expected partial disposition.
- Reproduces 3/3 runs on Omega **and** on a tree with the TODO-902 `ToFlat` changes stashed — pre-existing, not a regression of the flat-adoption work (verified 2026-09-19).
- The zc twin test with identical injection shape passes, so the discrepancy is specific to the plain `SendMsg` completion accounting in `finish_with_wait`/`finish_to_with_wait` (`uring_batch.rs` ~line 1062).
- Failure message: `io_uring SendMsg completion set incomplete: 2/3, cq_overflow=0` — the ring returned 2 CQEs for a 3-packet submission where one slot's iovec was injected-invalid.

## Hypotheses
- The injected-invalid SQE may be rejected at submission time on kernel 6.17 (no CQE at all) while the accounting still expects one completion per queued slot.
- Alternatively the failing slot produces a CQE that is consumed by a different reaping pass than expected.

## Acceptance
- The injected-partial test passes on Omega, or the accounting is proven kernel-version-dependent and the test documents/skips the affected kernel range with evidence.

## Out of Scope
- Production-path correctness: real (non-injected) partial sends take the same completion accounting and the live `tun-e2e-netns.sh` path passes with the io_uring worker active; this concerns the injection proof path only unless evidence shows otherwise.
