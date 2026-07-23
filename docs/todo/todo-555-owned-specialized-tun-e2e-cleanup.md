---
id: TODO-555
title: Replace broad process reapers in specialized TUN E2E harnesses
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-554]
---

# TODO-555: Replace Broad Process Reapers in Specialized TUN E2E Harnesses

## Why

The base harness defect isolated by TODO-554 also exists in the specialized FEC netns, FEC burst, FEC transition, and FEC netem-adversity harnesses. Their global name-based cleanup can terminate the runner itself or an unrelated QuicFuscate runtime, so later loss and recovery proofs cannot be considered safely isolated.

## Acceptance

- Inventory every process, namespace, link, qdisc, firewall, configuration, certificate, lock, and temporary-file owner in the four affected harnesses.
- Replace every `pkill`/`killall` product-name cleanup with exact child PID capture, kill, and reap semantics.
- Refuse to delete or terminate pre-existing unowned runtime resources.
- Preserve failure diagnostics and explicit keep-on-failure modes without weakening FEC, loss, transition, burst, or adversity acceptance.
- Add failable guardrails covering all specialized harnesses and an unrelated-process survival regression.
- Prove the affected exact-artifact Omega matrices and clean teardown without touching unrelated server state or protected UI files.

## Completion Gates

- Inventory gate: all four harnesses and every created resource have one explicit lifecycle owner.
- Static gate: shell syntax, runtime guardrails, TODO consistency, and exact source review reject broad product-name process cleanup.
- Isolation gate: unrelated matching processes and namespaces survive, while owned child processes and resources are removed on success, injected failure, and signal exit.
- Live gate: specialized FEC netns, burst, transition, and netem-adversity gates pass with the exact ARM64 artifact and leave zero owned residue.
- Native and truth gate: exact-commit CI, Clippy Matrix, required Release Build jobs, SHA-256 evidence, documentation/MAP/TODO truth, and protected UI diff pass before closure.

## Sub-Tasks

- [ ] Read and map all four harness lifecycle surfaces.
- [ ] Reuse the proven TODO-554 ownership pattern without shared global cleanup.
- [ ] Add static and failure-path regression coverage.
- [ ] Run the exact-artifact specialized Omega matrices.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Affected files: `scripts/tests/tun-e2e-fec-netns.sh`, `scripts/tests/tun-e2e-fec-burst-netns.sh`, `scripts/tests/tun-e2e-fec-transition-netns.sh`, and `scripts/tests/tun-e2e-fec-netem-adversity.sh`.
- This task is split from TODO-554 because the four specialized harnesses add independent network-emulation and FEC resource lifecycles beyond the base gate.

## Deviations

None.
