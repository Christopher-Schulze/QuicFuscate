# TODO-166: Global Atomic Coupling Audit and Reduction

## Status
**DONE** (audit and documentation phase; refactoring deferred)

## Severity
**MEDIUM**

## Context
The codebase contains approximately 99 global `AtomicU64`/`AtomicU32` instances spread across multiple modules. These globals create tight implicit coupling between subsystems, making the data flow hard to trace and reason about. Cross-subsystem coordination happens via shared mutable global state rather than explicit interfaces.

Key hotspots:
- `src/brain.rs`: Brain/optimizer hint atomics
- `src/fec.rs`: `FEC_INTERVAL_HINT_PKTS`, `FEC_REDUNDANCY_PPM` and related FEC tuning globals
- `src/stealth.rs`: `INTELLIGENT_STEALTH_LEVEL_HINT` and stealth coordination globals
- `src/optimize.rs`: `TIMING_JITTER_HINT_US` and optimization hint globals
- Various other modules with scattered atomic state

## Root Cause
Subsystem coordination was implemented via the simplest possible mechanism (global atomics) during rapid development. No structured hint/message passing architecture was designed upfront.

## Fix Plan
1. Inventory all global `AtomicU64`/`AtomicU32`/`AtomicBool` instances across the codebase
2. Categorize each atomic by purpose:
   - **Metrics/counters**: May remain as globals (read-only observation)
   - **Hint channels**: Should be consolidated into structured hint types
   - **Configuration**: Should move to config structs
   - **Cross-subsystem coordination**: Should use message passing or shared state objects
3. Design a `HintChannel<T>` or similar abstraction for subsystem coordination
4. Migrate hint atomics into structured channels grouped by subsystem
5. For atomics that must remain global: add documentation explaining why
6. Update all read/write sites to use new abstractions
7. Run full test suite to verify behavioral equivalence

## Acceptance Criteria
- Global atomic count reduced by 50% or more
- Remaining globals documented with justification
- Subsystem coordination uses structured hint channels where appropriate
- No behavioral regression (all tests pass)
- Data flow between subsystems traceable via explicit interfaces

## Dependencies
- None (but should coordinate with any ongoing refactoring in brain.rs, fec.rs, stealth.rs)

## Affected Files
- `src/brain.rs`
- `src/fec.rs`
- `src/stealth.rs`
- `src/optimize.rs`
- `src/optimize/brain.rs`
- `src/optimize/stealth.rs`
- `src/optimize/transport.rs`
- `src/optimize/crypto/mod.rs`
- Any other files with global atomic declarations
