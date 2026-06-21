# TODO 102: Final Prefetch Evidence and Owner Policy Tightening

## Scope
- retained owner-local prefetch usage
- low-level prefetch primitive policy
- final keep/remove pass over transport, crypto, FEC, and compat machine room

## Problem Statement
- Prefetch usage is already much cleaner than before, but retained callsites still need one final hard justification pass.
- Without that pass, the repo still looks like it carries a broad "prefetch because it might help" culture.

## Desired End State
- The retained prefetch primitive is just a low-level internal building block.
- Productive callsites are few, named by owner intent, and clearly tied to real hot paths.
- Unjustified or weakly justified prefetches are removed.

## Current Truth Snapshot
- Broad generic prefetch wrappers are already gone.
- Retained productive prefetch names are already owner-local across:
  - transport
  - crypto
  - FEC
- Unsafe at the prefetch owner boundary has already been localized.

## Architecture Gap
- The remaining question is no longer "is prefetch broad API surface?".
- The remaining question is:
  - which retained callsites really earn their existence
  - which should be deleted to reduce complexity and reviewer skepticism

## Execution Plan

### Phase 1: Retained Callsite Audit
- Inventory all retained prefetch callsites in:
  - `src/crypto.rs`
  - `src/fec.rs`
  - `src/transport/connection.rs`
  - `src/transport/uring.rs`
  - `src/transport/udpfast.rs`
  - `src/transport/xdp.rs`
- Classify them as:
  - clearly justified
  - likely removable
  - benchmark-needed

### Phase 2: Narrowing
- Remove prefetches with weak or unclear value.
- Keep only the retained hot-path callsites that still make technical sense.

### Phase 3: Final Truth Sync
- Ensure canonical docs do not overstate prefetch as a major runtime story.
- Tighten guardrails if any broad prefetch wording or helper resurfacing risk remains.

## Acceptance Criteria
- [x] Every retained prefetch callsite has an explicit owner-local reason.
- [x] Weak or unjustified retained prefetches are removed.
- [x] Docs and review language present prefetch as narrow internal machine room, not broad optimization posture.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted hot-path tests affected by the retained callsites

## Notes
- The aim is not to ban prefetch.
- The aim is to make every remaining prefetch defensible.
- Validation completed with:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
