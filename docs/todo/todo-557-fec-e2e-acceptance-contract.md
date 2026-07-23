---
id: TODO-557
title: Make specialized FEC E2E acceptance executable and truthful
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-423, TODO-425, TODO-427, TODO-524, TODO-547, TODO-555]
---

# TODO-557: Make Specialized FEC E2E Acceptance Executable and Truthful

## Why

The specialized Linux FEC harnesses contain acceptance prose that is not fully enforced by their executable assertions. The uniform-loss harness advertises substantially tighter residual-loss thresholds than it applies, the transition harness claims zero loss while allowing wider phase bounds, and the adversity harness claims throughput, overhead, mode-stability, recovery-latency, 60-second stability, and de-escalation evidence that its ping-only decisions do not establish. A green shell exit therefore does not yet prove the contract described to operators or later agents.

## Acceptance

- Define one explicit, scenario-specific production contract for uniform loss, correlated burst loss, live FEC transitions, jitter, bandwidth pressure, high RTT, combined adversity, and recovery.
- Make every documented claim executable. Remove or qualify any claim that cannot be measured from the current runtime, and never infer FEC recovery, mode behavior, throughput, or overhead from ping liveness alone.
- Separate hard correctness gates from statistical performance gates: handshake and authenticated MASQUE establishment, zero panic/decrypt failure, byte-integrity where applicable, residual packet loss, useful throughput, FEC wire overhead, mode escalation/de-escalation, transition stability, and bounded recovery time.
- Establish sample sizes, repetitions, warm-up, timeout, and pass bounds that are strong enough to reject regressions without turning random netem variance into a flaky gate. Record the exact inputs and measured outputs for every scenario.
- Compare Auto FEC with a controlled FEC-off baseline where the acceptance claim is recovery benefit, overhead, or latency improvement. Clean-link Auto must remain effectively free; severe-loss Fountain rescue may prioritize recoverability over efficiency.
- Fail closed when required telemetry or measurement tools are unavailable. Optional informational measurements must be labeled as such and must not satisfy a required gate.
- Add failable regressions that detect header/assertion drift, missing scenario execution, silently skipped required measurements, relaxed thresholds, missing panic/decrypt checks, and false green summaries.
- Preserve the exact ownership and isolation contract from TODO-555 and leave the protected Svelte/Tauri UI byte-identical.
- Pass full local Rust and shell gates, exact-commit native CI/Clippy/Release gates, and exact ARM64 Omega matrices with zero owned residue.

## Completion Gates

- Contract gate: each specialized harness has one machine-readable or single-source scenario contract consumed by both execution and human-readable output; no duplicate threshold truth remains in comments.
- Failability gate: targeted negative tests prove that threshold violations, missing telemetry, skipped required tools, mode flapping, integrity errors, panics/decrypt failures, and incomplete scenarios produce nonzero results.
- Comparative gate: claims about FEC benefit or cost include the matching FEC-off control and report absolute plus relative results.
- Statistical gate: production sample counts and repetitions are explicit, recorded, and stable across repeated isolated runs.
- Local gate: Bash syntax, ShellCheck, specialized harness regressions, runtime guardrails, TODO consistency, formatting, strict Clippy, and the full `rust-tests` workspace pass.
- Native gate: exact-commit CI, Clippy Matrix, required Release Build jobs, and SHA-256 artifact identity pass.
- Live gate: the exact ARM64 artifact passes all uniform, burst, transition, and adversity scenarios on Omega and leaves no process, namespace, link, qdisc, firewall, route, lock, or temporary-runtime residue.
- Truth gate: `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, this detail file, and all affected harness descriptions agree with the measured contract before closure.

## Sub-Tasks

- [ ] Inventory every prose claim, executable assertion, required input, measured output, skip path, and summary path in the four specialized harnesses.
- [ ] Design the minimal single-source scenario contract and statistical acceptance model.
- [ ] Implement exact measurements, controlled baselines, fail-closed required-tool handling, and machine-readable evidence.
- [ ] Add drift, failure, skip, telemetry, threshold, and summary regressions.
- [ ] Run local shell and full Rust gates.
- [ ] Run exact-commit native CI/Clippy/Release gates and identify artifacts by SHA-256.
- [ ] Run repeated exact-artifact Omega matrices and prove zero residue.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Primary files: `scripts/tests/tun-e2e-fec-netns.sh`, `scripts/tests/tun-e2e-fec-burst-netns.sh`, `scripts/tests/tun-e2e-fec-transition-netns.sh`, and `scripts/tests/tun-e2e-fec-netem-adversity.sh`.
- The current uniform-loss header claims residual loss below 2%, 5%, and 15% at 5%, 10%, and 25% netem loss, while the executable thresholds are 15%, 20%, and 40%.
- The current transition header claims zero loss during transitions, while the executable phase limits are 5%, 35%, and 10%.
- The adversity header claims throughput degradation, mode monotonicity and flapping, sub-30% overhead, recovery-vs-retransmission latency, 60-second combined stability, and five-second de-escalation. Its current pass/fail paths primarily evaluate ping loss and panic absence.
- TODO-547 and TODO-524 provide valid wire-integrity and historical 1,000-packet loss evidence, but they do not make the remaining specialized harness descriptions executable.
- This is a direct production-evidence task, not a production-readiness umbrella.

## Deviations

None.
