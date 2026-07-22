---
id: TODO-546
title: Restore Windows SIMD dispatch and native core gate
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-519, TODO-521]
---

# TODO-546: Restore Windows SIMD Dispatch and Native Core Gate

## Why

Native Windows CI run `29885372108`, job `88814739708`, contradicted the prior native-readiness claim. After isolating the FEC GF8 polynomial mismatch under TODO-524, the remaining failures are an AVX-512 Berlekamp subtraction underflow, corrupt x86 u32 sorting helpers, and best-effort override assertions that omit the valid `avx512vbmi2` automatic policy.

## Acceptance

- Fix the AVX-512 Berlekamp path without subtraction underflow and prove scalar parity across boundary lengths.
- Fix or fail closed on the corrupt AVX-512 sort dispatch and prove exact parity with Rust's canonical sort for adversarial inputs.
- Keep feature and kernel overrides thread-local, and make best-effort assertions cover every valid automatic policy.
- Align Windows workflow documentation with its supported parallel execution contract.
- Pass native Windows check, test, and Clippy gates plus the complete CI workflow with no failed jobs.
- Pass local and Linux regression gates, update documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [x] Reproduce and map every remaining Windows failure to its exact dispatch path.
- [x] Repair Berlekamp and sort correctness with adversarial parity tests.
- [x] Verify thread-local override state and align the documented workflow contract.
- [ ] Run local, Windows-native, and Linux regression evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Discovery evidence: CI `29885372108`, Windows job `88814739708`; all other CI jobs, Clippy Matrix `29885372123`, and Release Build `29885372141` passed at commit `c7f672a`.
- TODO-524 owns the separately proven GF8 mismatch between the FEC 0x11D wire field and Intel GFNI's fixed 0x11B field.
- Source verification corrected the initial race hypothesis: `PROFILE_OVERRIDE` and `TEST_FEC_KERNEL_OVERRIDE` are thread-local and have explicit concurrent isolation tests. The failed best-effort assertions omitted the valid `avx512vbmi2` auto-selection tag.
- The removed x86 u32 small-sort kernels used per-element bit shifts instead of cross-lane permutations. The AVX-512 partition path also overwrote unselected elements while compacting in place. `sort_u32` is parity/test-only, so the smallest correct surface is Rust's canonical `sort_unstable`, not another unproven private sorter.
- Local evidence: eight u32 sort tests pass, including adversarial lengths 0 through 128 and 255/256/257/1023/1024/1025; Berlekamp-Massey parity passes at 0/1/2/31/48/63/64/65/127/128; the Wiedemann telemetry regression passes; workspace all-target Clippy with `rust-tests` and warnings denied passes; the complete workspace all-target `rust-tests` suite passes with 1,693 library tests plus every integration and example target. A local MSVC cross-check is blocked before project compilation because `ring` cannot find the Windows CRT `assert.h` from macOS, so native `windows-latest` remains authoritative.

## Deviations

None.
