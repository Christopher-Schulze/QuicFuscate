# TODO 100: BusyPoll Removal and Socket-Tuning Surface Cleanup

## Scope
- remove retained `SO_BUSY_POLL` code
- remove unexplained socket-tuning experiment residue
- tighten transport/runtime truth and guardrails

## Problem Statement
- `SO_BUSY_POLL` is no longer part of the intended product or runtime story, but its code presence still reads like unexplained low-level tuning baggage.
- Even when test-scoped, it creates reviewer drag because it suggests there may still be an unproved alternative socket-tuning strategy hidden in the transport stack.

## Desired End State
- No retained busy-poll code in runtime-owned modules.
- No docs or review material that imply busy-poll is a meaningful supported transport knob.
- Guardrails fail if busy-poll quietly returns outside a clearly justified lab-only scope.

## Current Truth Snapshot
- Busy-poll is already out of the normal product story.
- The remaining runtime-owned code and canonical doc references have now been removed.
- Guardrails enforce that no busy-poll surface quietly returns.

## Architecture Gap
- The code still says "we experimented here and kept the mechanism around."
- The desired architecture is stricter:
  - `io_uring` canonical Linux high-end path
  - UDP/sendmmsg fallback
  - no retained busy-poll side story

## Execution Plan

### Phase 1: Socket-Tuning Inventory
- Enumerate all remaining busy-poll-related code, comments, env hooks, and docs references.
- Confirm there is no productive runtime owner that would break if the code disappears.

### Phase 2: Removal
- Delete the remaining busy-poll helper structures and any now-dead support code.
- Remove stale imports, comments, and test-only shims that only existed for this branch.

### Phase 3: Truth Sync
- Ensure canonical docs and review materials no longer mention busy-poll as a retained tuning story.
- Add or tighten guardrails so unexplained busy-poll code cannot return.

## Acceptance Criteria
- [x] No retained busy-poll helper remains in runtime-owned modules.
- [x] Docs no longer imply busy-poll is a supported or meaningful transport tuning option.
- [x] Guardrails fail if busy-poll code quietly returns.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- This is removal and trust cleanup, not a performance feature effort.
- Validation completed with:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
  - `bash scripts/tests/audits/audit-runtime-guardrails.sh`
