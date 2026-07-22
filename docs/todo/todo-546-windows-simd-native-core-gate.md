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

Native Windows CI run `29885372108`, job `88814739708`, contradicted the prior native-readiness claim. After isolating the FEC GF8 polynomial mismatch under TODO-524, the remaining failures are an AVX-512 Berlekamp subtraction underflow, corrupt AVX-512 sort output, and process-global feature-override tests that are not safe under the workflow's parallel test execution.

## Acceptance

- Fix the AVX-512 Berlekamp path without subtraction underflow and prove scalar parity across boundary lengths.
- Fix or fail closed on the corrupt AVX-512 sort dispatch and prove exact parity with Rust's canonical sort for adversarial inputs.
- Make feature-override and process-global dispatch tests deterministic under their supported execution model without hiding product defects behind serialization.
- Align the Windows workflow command and documentation, including explicit serialization only where process-global test state requires it.
- Pass native Windows check, test, and Clippy gates plus the complete CI workflow with no failed jobs.
- Pass local and Linux regression gates, update documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Reproduce and map every remaining Windows failure to its exact dispatch path.
- [ ] Repair Berlekamp and sort correctness with adversarial parity tests.
- [ ] Isolate process-global override state and align the workflow contract.
- [ ] Run local, Windows-native, and Linux regression evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Discovery evidence: CI `29885372108`, Windows job `88814739708`; all other CI jobs, Clippy Matrix `29885372123`, and Release Build `29885372141` passed at commit `c7f672a`.
- TODO-524 owns the separately proven GF8 mismatch between the FEC 0x11D wire field and Intel GFNI's fixed 0x11B field.

## Deviations

None.
