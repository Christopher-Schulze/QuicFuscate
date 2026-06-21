# Release Probe Detection Validation Plan

## Goal
Validate active-probe detection and fallback behavior against false-positive and false-negative risks under realistic traffic patterns.

## Validation Matrix
- [x] Baseline clean traffic (no probe) across representative RTT/loss profiles.
- [x] Synthetic active probe patterns against detection logic.
- [x] Boundary cases with high jitter, burst loss, packet reordering.
- [x] Long-lived sessions with mixed benign and suspicious patterns.

## Assertions
- [x] Legitimate traffic is not incorrectly escalated or blocked.
- [x] Suspicious traffic triggers expected detection and fallback.
- [x] Detection transitions are observable in logs/metrics.
- [x] Recovery path after false trigger is stable.

## Instrumentation and Telemetry
- [x] Document all probe-related counters and logs.
- [x] Add missing counters where behavior is currently opaque.
- [x] Define alert thresholds for production observability.

## Tests
- [x] Add deterministic tests for known probe signatures.
- [x] Add regression tests for previously observed edge cases.
- [x] Add soak test script for extended runtime validation.

## Acceptance Criteria
- [x] Detection logic has documented test coverage and outcomes.
- [x] False-positive risk is measured and bounded.
- [x] Fallback behavior is deterministic and documented.

## Progress Snapshot (2026-02-12)
- Added deterministic Rust probe suite: `scripts/tests/rust/rt-probe-detection.rs`.
- Added dedicated suite runner: `scripts/tests/suites/test-probe-detection.sh`.
- Wired probe suite into full-suite orchestration via `scripts/tests/utils/util-run-full-suite.sh`.
- Fast validation run completed: `./scripts/tests/suites/test-probe-detection.sh --fast` (pass).
- Added telemetry counters for detected/switch/fake/block/escalated probe paths and wired them in `StealthManager`.
- Added soak mode (`--soak-iters`) and verified `--fast --soak-iters 2` pass.
- Verified `test-stealth-brain.sh --fast` pass after command-wrapper fix.
