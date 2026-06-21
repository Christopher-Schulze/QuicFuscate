# TODO 94: Linux Send-Path Final Simplification After Zerocopy Removal

## Scope
- Linux transport send-path simplification
- `io_uring` plus UDP/sendmmsg fallback
- removal of retained `MSG_ZEROCOPY` runtime story

## Problem Statement
- The previous plan kept a retained specialized `MSG_ZEROCOPY` path pending hard Linux evidence.
- The repository direction is now stronger and simpler:
  - `MSG_ZEROCOPY` should be removed entirely from the productive runtime story
- That makes the remaining Linux send path easier to explain, review, and defend:
  - `io_uring` for the high-end path
  - UDP/sendmmsg as fallback
  - no second zerocopy send story

## Desired End State
- One final Linux send-path ladder:
  - `io_uring` is the canonical Linux high-end path when available
  - normal UDP/sendmmsg is the fallback
  - no retained `MSG_ZEROCOPY` policy, env knob, or productive send-path branch remains
- Any historical benchmark harness is optional supporting evidence, not a blocker for the runtime decision.

## Current Truth Snapshot
- `io_uring` is already the canonical high-end path in docs.
- Broad batch-send zerocopy was already removed.
- Retained zerocopy is already constrained to specialized Linux send paths.
- The architectural decision has now changed:
  - no final retained zerocopy path should remain
- What is missing is now code/doc removal, not benchmark-backed retention logic.
- A dedicated Linux send-path harness now exists at `scripts/benchmarks/suites/bench-linux-send-path-decision.sh` and reuses:
  - `scripts/benchmarks/suites/bench-profile-transport-fastpaths.sh`
  - `scripts/benchmarks/micro/micro-udpfast-throughput.sh`
  to compare baseline transport profiling and the old retained specialized zerocopy loopback micro-runs under explicit opt-in.
- The harness now also writes the old top-level decision artifacts after a real Linux run:
  - `summary.txt`
  - `decision.json`
  and can now serve as historical support or archival evidence rather than an open runtime-policy blocker.

## Architecture Gap
- We still have code and truth surfaces that assume a retained specialized zerocopy send path exists.
- The final architecture no longer wants that.
- The gap is now:
  - remove the retained path cleanly
  - simplify completion/accounting where zerocopy was only supporting the deleted path
  - collapse docs and guardrails onto the simpler final send ladder

## Execution Plan

### Phase 1: Productive Path Removal
- Remove retained `MSG_ZEROCOPY` send policy, env-gating, and productive transport branches.
- Delete or reduce any errqueue/completion support logic that only existed to serve the removed send path.

### Phase 2: Fallback Ladder Tightening
- Make the Linux send story explicit and singular:
  - `io_uring`
  - otherwise UDP/sendmmsg fallback
- Remove stale comments, docs, and helper wording that still implies retained productive zerocopy.

### Phase 3: Historical Evidence Handling
- Decide whether the existing benchmark harness stays:
  - as archived historical support
  - or as a generic Linux send-path benchmark without zerocopy retention semantics
- It must no longer define the product/runtime decision.

### Phase 4: Final Truth Sync
- Update canonical docs and review material so the final story is:
  - `io_uring` first
  - UDP/sendmmsg fallback
  - no retained `MSG_ZEROCOPY`
- Tighten guardrails so the deleted path cannot quietly return.

## Acceptance Criteria
- [x] No retained productive `MSG_ZEROCOPY` path remains.
- [x] Linux send-path docs and review materials describe only `io_uring` plus fallback UDP/sendmmsg.
- [x] Any retained benchmark harness no longer acts as runtime-policy truth.
- [x] Guardrails fail if zerocopy send-path policy quietly returns.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash -n scripts/benchmarks/suites/bench-linux-send-path-decision.sh` if the harness is retained
- `bash scripts/benchmarks/suites/bench-linux-send-path-decision.sh --dry-run --fast` if the harness is retained
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Current Progress
- [x] Runtime code no longer carries retained `MSG_ZEROCOPY` policy, env knobs, send branches, completion/accounting scaffolding, or zerocopy telemetry.
- [x] The Linux send ladder in productive code is now:
  - `io_uring` when available
  - otherwise UDP/sendmmsg fallback
- [x] The retained benchmark harness was rewritten as generic Linux send-path evidence and now emits `benchmark-only` decision artifacts instead of runtime-policy truth.
- [x] Canonical docs and parent backlog wording are synced to the new runtime truth.
- [x] Final validation was rerun after the truth-sync pass.

## Notes
- This is no longer an evidence-gathering retention task.
- This is a simplification/removal task driven by an explicit architectural decision.
- Real Linux measurement can remain as historical support, but it is no longer the blocker that decides product policy.
