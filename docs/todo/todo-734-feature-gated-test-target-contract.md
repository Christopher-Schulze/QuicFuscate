---
id: TODO-734
title: Make feature-gated test targets prove the requested feature lane
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-734: Make Feature-Gated Test Targets Prove the Requested Feature Lane

## Current execution gate (2026-09-23)

This task is OPEN for the current local target/feature inventory and negative
fixtures; unavailable native or hosted lanes block closure, not that step.
The zero-test target defects listed below are historical implementation
motivation; the current Cargo metadata and runner fixtures already enforce
non-vacuous feature execution locally. Re-inventory current `[[test]]`
targets, `required-features`, crate-level `cfg`, and runner arguments at one
revision. Run the negative disabled-feature fixtures, then execute real named
tests on native Linux io_uring/kernel-hotpath and AF_XDP-capable hosts, plus
the matching hosted feature matrix. Every requested target must report a
positive executed count and expected test identity; unsupported hardware is
`SKIP`/`UNAVAILABLE`, not PASS. Preserve the unrelated root runtime-reload
failures as separate owners. Close only when all claimed feature lanes have
same-revision native or explicit unsupported-surface evidence.

## Why

Several integration targets use crate-level feature gates without declaring matching Cargo `required-features`. A direct target invocation can therefore compile an empty test crate and exit successfully, while shared runners can omit the feature needed for the real test body. A green command is not proof that the target's intended lane executed.

## Findings

### 1. Orchestrator integration falls back to a vacuous test
- **Files:** `Cargo.toml:503-505`, `scripts/tests/rust/integration/orchestrator_runtime_activation.rs:1-71`, `scripts/tests/suites/test-desktop-webadmin-rust-integration.sh:48`.
- **Problem:** The target has no `required-features`, all real tests require `feature = "orchestrator"`, and the runner passes only `rust-tests`. The disabled branch contains only `test_orchestrator_feature_disabled_compiles_clean`, so the target can pass without exercising orchestrator behavior.
- **Impact:** The named integration gate can be green while its feature-specific runtime signal and trigger-matrix tests never compile.

### 2. XDP integration can run with its required feature disabled
- **Files:** `scripts/tests/rust/rt-transport-xdp.rs:1-6`, `scripts/tests/suites/test-transport.sh:50-57`, `scripts/tests/lib/lib-common.sh:166-190`.
- **Problem:** The target requires both `rust-tests` and `internal_af_xdp_experimental`, but the Linux runner invokes it without the extra feature. The crate-level `cfg` then removes the actual test body and the command can still exit zero.
- **Impact:** The advertised XDP fast-path check does not prove the XDP probe on Linux.

### 3. Cargo metadata does not encode the feature contract for many gated targets
- **Files:** `Cargo.toml` test target declarations; `scripts/tests/rust/rt-*.rs` and `scripts/tests/rust/integration/*.rs` crate-level `cfg` gates.
- **Problem:** The current static inventory finds 60 declared test targets whose source has a crate-level feature gate but whose Cargo declaration has no `required-features`. Direct `cargo test --test <target>` and broad target runs can therefore produce zero-test success instead of an explicit skip or failure.
- **Boundary:** The shared `run_cargo` helper adds `rust-tests` for test commands, but it does not infer target-specific features and Cargo itself cannot report the intended test count from a crate-level `cfg`.

### 4. CI SIMD self-check lane omits the feature required by its test crate

- **Files:** `.github/workflows/ci.yml:337-338`, `scripts/tests/rust/rt-simd-selfcheck.rs:1-2`.
- **Problem:** The named CI command passes `simd-selfcheck` but not `rust-tests`, while the target source requires both features. The command can therefore compile a crate with its real tests removed and still exit successfully.
- **Impact:** The dedicated SIMD self-check lane can report green without executing the SIMD parity and boundary tests it claims to cover.
- **Boundary:** The lane must pass the complete feature set and assert non-vacuous execution rather than relying on a zero-test success.

### 5. Direct io_uring target invocation reports a passing no-op on unsupported hosts
- **Files:** `scripts/tests/rust/rt-transport-uring.rs:1-16`; `scripts/tests/suites/test-transport.sh:36-42`.
- **Current:** The target has one unconditional test under `#[cfg(not(target_os = "linux"))]` whose body is empty, while all real tests are Linux-only. The shared transport suite correctly skips the target on non-Linux hosts, so the suite itself does not currently claim macOS io_uring evidence. A direct `cargo test --test rt-transport-uring` on an unsupported host can nevertheless report success after running only the empty test.
- **Impact:** Direct target output remains ambiguous and can be mistaken for an io_uring proof outside the guarded suite. This is a narrower platform-contract issue, not a confirmed shared-suite skip failure.
- **Boundary:** Report an explicit platform skip with prerequisites, or make unsupported direct invocations fail/skip distinctly and assert that the Linux body executed.

### 6. Linux kernel hotpath target omits its crate-level test feature
- **Files:** `Cargo.toml:457-459`, `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:1-20`, `scripts/tests/suites/test-transport.sh:45-50`.
- **Problem:** The kernel hotpath target source is crate-gated on `feature = "rust-tests"`, but the Cargo target has no matching `required-features`. A direct `cargo test --test rt-io-hotpath-kernel-integration` can therefore compile with its real `zc_batch` test removed and still exit successfully. The shared suite currently calls `run_cargo`, whose test wrapper adds `rust-tests`, so this specific zero-test behavior is not claimed for that suite path.
- **Impact:** Direct target output does not prove that the `sendmmsg` path executed, and the feature contract remains implicit rather than enforced by Cargo metadata.
- **Boundary:** The target must declare its exact feature contract, while the shared runner must retain explicit feature propagation and non-vacuity checks.

### 7. Transport integration bundle relies on implicit wrapper feature injection
- **Files:** `Cargo.toml:400-459`, `scripts/tests/suites/test-transport.sh:67-80`, `scripts/tests/rust/rt-transport-batch-processor.rs:1`, `rt-transport-connection.rs:1`, `rt-transport-config.rs:1`, `rt-transport-frames-roundtrip.rs:1`, `rt-transport-packet-headers.rs:1`, `rt-transport-recovery.rs:1`, `rt-transport-h3.rs:1`, `rt-transport-udpfast.rs:1`, `rt-udp-batch-send.rs:1`.
- **Problem:** Every listed target starts with `#![cfg(feature = "rust-tests")]`, while its Cargo declaration omits `required-features = ["rust-tests"]`. The shared bundle invokes them without an explicit feature flag, but `run_cargo` currently injects `rust-tests` for every `test` command. The current suite therefore has wrapper-based feature coverage, while direct target calls and any future runner that bypasses the helper can still produce zero-test success. The same bundle also includes `rt-pnspace-ack-policy` and `rt-harness-udpfast`, which remain part of the target-feature inventory.
- **Impact:** The test contract is split between Cargo metadata and shell-wrapper behavior. A change to the wrapper, a direct invocation, or a copied command can silently stop executing the core connection, configuration, frame, packet-header, recovery, H3, UDP-fastpath, or batch-send tests named in the bundle.
- **Boundary:** Cargo declarations and runners must agree on the complete feature matrix, and the bundle must assert non-vacuous execution for every named target instead of relying only on implicit wrapper injection.

### 8. CI default feature-matrix lane compiles gated targets without `rust-tests`
- **Files:** `.github/workflows/ci.yml:336-342`; the crate-gated targets listed by the source inventory above.
- **Problem:** The empty CI matrix entry invokes `cargo test --workspace --all-targets` without `rust-tests`. Because most integration targets are crate-gated on that feature but do not declare `required-features`, Cargo can build them with their real tests removed while the overall command remains green. The `simd-selfcheck` branch is covered separately by Finding 4 and has the same missing `rust-tests` input.
- **Impact:** The default all-target CI result does not establish that the feature-gated integration inventory ran; it establishes only that the ungated/default targets completed.
- **Boundary:** The lane must either pass the intended feature set and verify non-vacuity, or label feature-gated targets as explicit skips and keep the default lane's coverage claim limited to default-feature tests.

## Acceptance

- Every feature-gated test target declares the exact Cargo `required-features` needed by its source gate.
- Each runner passes target-specific features explicitly, including `rust-tests,orchestrator` and `rust-tests,internal_af_xdp_experimental` where those lanes are intended.
- The CI SIMD self-check lane passes `rust-tests,simd-selfcheck` and proves that the expected test body executed.
- The Linux kernel hotpath target passes `rust-tests` together with `io_uring` or declares an explicit platform/feature skip.
- The transport integration bundle passes `rust-tests` explicitly or through a tested wrapper contract to every crate-gated target and verifies that each target executes at least one intended test.
- The CI default all-target lane either passes `rust-tests` or reports feature-gated targets as explicit skips without treating the aggregate as their execution proof.
- Runners assert expected test names or counts; a disabled feature is reported as an explicit SKIP and never as PASS.
- Platform-inapplicable targets produce explicit SKIP results rather than empty passing tests.
- Negative fixtures prove that removing an expected feature cannot produce a green run with zero real tests.
- No production or protected UI code changes are required.

## Sub-Tasks

- [x] Inventory every test target against its crate-level `cfg` and Cargo feature declaration, including the kernel hotpath and transport integration bundle.
- [x] Add exact `required-features` metadata and target-specific runner feature propagation.
- [x] Add non-vacuity assertions for the named integration suites.
- [x] Add negative feature-disabled fixtures and verify status handling.
- [ ] Re-inventory targets and execute the named native Linux io_uring,
      kernel-hotpath, AF_XDP, and hosted feature-matrix lanes at one revision.

## Notes

- TODO-709 owns strict Clippy invocation coverage; this task owns target-level test execution truth.

## Implementation Evidence

- `Cargo.toml` now declares matching `required-features` for all 64 test sources with crate-level feature cfgs. The exact target contracts are `rust-tests,orchestrator`, `rust-tests,simd-selfcheck`, `rust-tests,io_uring`, and `rust-tests,internal_af_xdp_experimental` for the specialized lanes.
- `scripts/tests/lib/lib-common.sh` provides `qf_cargo_test_run_expect()`, which requires a positive executed-test count, a successful libtest result, and a named test marker.
- The desktop/web-admin Rust runner invokes five targets separately and passes `rust-tests,orchestrator` to the Orchestrator target. The transport runner verifies one named body in each transport target, passes target-specific features, and emits structured Linux-only `SKIP` results on macOS. The full-suite Linux calls use the same explicit feature sets.
- `.github/workflows/ci.yml` passes `rust-tests,simd-selfcheck` to the SIMD lane, requires `varint_roundtrip_and_consistency`, and enables `rust-tests` in the default all-target matrix lane.
- `scripts/tests/fast/test-dynamic-discovery-fail-closed.sh` proves missing `rust-tests` and missing `orchestrator` fail in Cargo before a zero-test result can become green.
- Local verification: `cargo metadata --no-deps` reports zero crate-feature-gated targets without metadata; `bash -n` and `git diff --check` pass; `cargo check --all-targets` passes with three unchanged dead-code warnings; SIMD passes 14/14; Orchestrator passes 2/2; the dynamic-discovery contract passes; and the macOS transport suite passes all local target checks while recording explicit Linux-only skips.
- The combined desktop/web-admin validation suite passes: desktop check 0 errors/0 warnings, desktop unit 31 files and 370 tests, web-admin check 0 errors/0 warnings, web-admin unit 25 files and 285 tests, and Rust integration targets 5/3/2/1/7 tests with named-body verification. The broad `cargo test --workspace --all-targets --features rust-tests` gate reaches 2,308/2,308 library tests and 41/43 binary tests; its exit remains blocked only by the two unchanged runtime-reload assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`.
- Architecture boundary: the five architecture-specific test targets no longer compile as empty crates. On this arm64 host, `rt-random-aes-ctr` executes 1/1, while the four x86_64-only targets emit one ignored test each with an explicit `SKIP: target requires x86_64` reason.
- Resource boundary: after the broad gate the filesystem reports 11 GiB free and `target/` is 11 GiB, remaining within the requested 13 GiB target ceiling.
- Commit and remote proof: `562c2cadf7931c94af189a18107e8f21b2551dd0` is `HEAD` and matches `origin/main`.

## Closure Boundary

- Native Linux io_uring and kernel-hotpath execution, AF_XDP execution, and the CI-hosted feature matrix remain external evidence gates. This task is locally implemented and pushed, but remains `BLOCKED` until those platform-specific proofs are available.

## Deviations

None.
