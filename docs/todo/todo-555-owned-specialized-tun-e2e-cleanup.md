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

- [x] Read and map all four harness lifecycle surfaces.
- [x] Reuse the proven TODO-554 ownership pattern without shared global cleanup.
- [x] Add static and failure-path regression coverage.
- [~] Run the exact-artifact specialized Omega matrices.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Affected files: `scripts/tests/tun-e2e-fec-netns.sh`, `scripts/tests/tun-e2e-fec-burst-netns.sh`, `scripts/tests/tun-e2e-fec-transition-netns.sh`, and `scripts/tests/tun-e2e-fec-netem-adversity.sh`.
- This task is split from TODO-554 because the four specialized harnesses add independent network-emulation and FEC resource lifecycles beyond the base gate.
- Lifecycle inventory: each harness owns its server and client child PID, `ns-srv`, `ns-cli`, the veth pair, and the client-namespace qdisc through explicit state; `tun-e2e-fec-netns.sh` additionally owns the optional iperf3 server PID. The shared lock is owned only through file descriptor 9 and is never deleted.
- Runtime inventory: one guarded `mktemp` root owns the generated server key, CSR, leaf certificate, CA serial, certificate chain, and per-scenario directories. Each scenario owns unique server/client logs, admin socket, QKey store, and optional iperf3 log. The repository CA certificate and key are read-only inputs; no source-tree certificate, QKey, log, socket, or temporary file is mutated.
- Network inventory: the harnesses create no host firewall rules or routes. TUN, route, and any product-owned firewall state remain inside owned namespaces, and namespace deletion closes that ownership boundary.
- Cleanup contract: exact child PIDs receive TERM, a bounded reap window, and KILL only if still alive; qdisc, namespaces, links, and guarded runtime directories are removed only when their ownership flags are set. Pre-existing product processes, namespace names, and veth names cause an exit-2 refusal before runtime mutation.
- Failure contract: EXIT, TERM, and INT traps clean exact resources by default. `QF_E2E_KEEP_ON_FAIL=1` preserves only resources owned by the failed harness for inspection. `scripts/tests/test-specialized-tun-e2e-ownership.sh` exercises normal exit, signal exit, keep-on-failure, and unrelated process/namespace/link survival.
- Local syntax, ShellCheck, runtime guardrails, and TODO consistency pass; the runtime audit reports zero critical findings and zero warnings.
- The local full Rust gate passes on the implementation state: 1,795 library tests plus every `rust-tests` target and doc-test target, strict all-target/all-feature Clippy with warnings denied, and `cargo fmt --all -- --check`. A policy-triggered `cargo clean` removed 2.4 GiB before Clippy; the rebuilt target is 338 MiB with 4.6 GiB free.
- The Linux lifecycle regression passes on Omega from `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo555-ownership-preflight-376f347`. The unrelated `quicfuscate-sentinel` process, unowned namespace, and unowned veth refusal paths pass, and the regression leaves no sentinel process, `ns-srv`, `ns-cli`, `veth-srv`, or `veth-cli` residue.
- Acceptance review found pre-existing divergence between several harness header claims and their executable thresholds or measurements. That independent evidence-contract gap is registered directly as TODO-557; TODO-555 remains limited to exact resource ownership and does not silently weaken or overclaim FEC behavior.
- The first exact-artifact matrix on `cac98367aa292b52b4c82deda58b5903d5d050b3` failed before QKey issuance because each specialized server namespace lacked the default route already present in the proven base harness. The current server correctly rejected the nonexistent default `eth0` and could not auto-detect a WAN interface. All four specialized namespace setups now add the owned `default dev veth-srv` route and fail closed if it cannot be installed; namespace teardown owns its removal.
- The isolated route-correction preflight under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo555-route-preflight-candidate` passes TLS, MASQUE, 20/20 clean-link pings, both retained iperf sub-runs, unrelated-sentinel survival, exact sentinel stop, and zero owned process, namespace, link, qdisc, or temporary-runtime residue. Exact-commit native and full-matrix proof remains pending.

## Deviations

None.
