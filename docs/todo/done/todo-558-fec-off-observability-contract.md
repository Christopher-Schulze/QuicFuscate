---
id: TODO-558
title: Make FEC-off control and live observability truthful
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-23
depends_on: [TODO-424, TODO-547, TODO-555]
---

# TODO-558: Make FEC-Off Control and Live Observability Truthful

## Why

The production `--fec-mode off` path currently selects `FecMode::Zero` only as the initial mode while every `AdaptiveFec` instance retains automatic control. Loss reports can therefore escalate an explicitly disabled client into repair modes. The exact TODO-555 ARM64 artifact reproduced this under 20% netem loss: the control reached Streaming mode with 75 switches. Runtime FEC acceptance also lacks trustworthy producer ownership for loss, encoded/decoded/recovered packet counts, and an exact exported mode mapping. TODO-557 cannot compare Auto against a controlled baseline or fail closed on live FEC behavior until these contracts are real.

## Acceptance

- Represent operator policy independently from the active codec mode: Off is a stable no-repair policy, Auto owns adaptation, and future explicit policies cannot be silently collapsed into initial-state hints.
- Make `--fec-mode off` remain Zero for the full connection lifetime under loss reports, ECN, ACK feedback, disturbance detection, observer updates, transition requests, and streaming hints.
- In Off mode, emit no repair symbols, create no recovery-only retention, perform no automatic mode switches, and preserve the allocation-free or minimal-overhead Zero fast path.
- Keep Auto behavior adaptive, including bounded escalation under loss and a return to Zero within the 35-second clean recovery phase, without changing Fountain's recovery-first role under catastrophic loss.
- Define one exact public mapping from exported numeric mode values to `Zero`, `Light`, `Normal`, `Medium`, `Strong`, `Extreme`, `Ultra`, `Fountain`, and `Streaming`; remove stale aliases and comments.
- Give every required FEC acceptance metric one real producer and one declared scope. At minimum, expose active mode, mode transitions by reason, effective window, observed loss, source/repair packet counts, decoded/recovered packet counts, and wire-byte overhead.
- Keep process-global telemetry only where the aggregate scope is explicit. Add connection-local evidence or identifiers where a client/server aggregate could otherwise make a scenario ambiguous.
- Remove or explicitly mark metrics that cannot be produced truthfully. A zero-valued dead counter must never satisfy an acceptance gate.
- Add failable deterministic tests for Off immutability, zero repair output, Auto adaptation, metric producer ownership, exact mode mapping, transition accounting, and concurrent client/server telemetry isolation.
- Preserve the specialized harness ownership contract from TODO-555 and leave every protected Svelte/Tauri UI path byte-identical.

## Completion Gates

- Policy gate: typed tests exercise every control input and prove Off stays Zero with zero repairs and zero switches while Auto still escalates and de-escalates.
- Fast-path gate: hard Off under total reported loss is no slower than clean Auto/Zero for the same persistent 1,400-byte send workload, and the 4,096-packet regression shows zero repairs, zero encoder-window state, and zero recovery-retention growth.
- Telemetry gate: every required metric changes under a deterministic positive producer test, remains unchanged under its negative control, documents its scope and unit, and exports a stable name plus exact mode mapping.
- Isolation gate: simultaneous isolated client and server runtimes expose distinguishable, scenario-owned evidence without port collision or cross-process inference.
- Live gate: the exact ARM64 artifact passes repeated Off and Auto Omega matrices at clean, moderate, severe, and recovery phases; Off emits zero repairs/switches, Auto commits non-Zero protection under loss, and Auto returns to Zero within the 10-second settle plus 250-ping recovery bound.
- Release gate: local formatting, strict Clippy, full `rust-tests`, telemetry regressions, native CI/Clippy/Release jobs, artifact SHA-256, teardown inspection, and protected UI diff pass.
- Truth gate: CLI help, `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, telemetry comments, and the specialized harness consumers agree before closure.

## Sub-Tasks

- [x] Map engine policy, active mode, observers, transition requests, repair emission, and every exported FEC metric producer.
- [x] Design the typed operator-policy and per-runtime observability contract.
- [x] Implement immutable Off semantics and preserve adaptive Auto behavior.
- [x] Wire or retire every required FEC telemetry producer and publish exact units, scope, and mode mapping.
- [x] Add deterministic policy, telemetry, concurrency, and performance regressions.
- [x] Run local Rust and telemetry gates.
- [x] Correct the live-proven Auto bootstrap and loss-observation cascade defects without weakening severe-loss recovery.
- [x] Make the live Auto gate phase-aware without weakening its clean-link, adaptation, repair, or Fountain assertions.
- [x] Make bounded Auto de-escalation an explicit live gate instead of inferring it from recovered tunnel liveness.
- [x] Complete the full local `CARGO_BUILD_JOBS=1 cargo test --features rust-tests` gate on the exact candidate source.
- [x] Run exact-commit native CI/Clippy/Release gates and repeated exact-artifact Omega Off/Auto matrices.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Primary policy paths: `src/main.rs`, `src/implementations/server/mod.rs`, and `src/fec/mod.rs`.
- Pre-implementation probe: `FecConfig::apply_engine_mode(Off)` set only `initial_mode=Zero` and `force_on=false`; `AdaptiveFec::new()` still installed automatic control.
- Pre-implementation probe: telemetry exported an undocumented numeric `quicfuscate_fec_mode`, incomplete loss state, and dead packet counters.
- The implementation contract separates `FecControlPolicy::{Off, Auto}` from the nine codec modes. Off rejects every non-Zero transition request; Auto retains the current adaptive cascade.
- Process telemetry owns only explicit aggregates: active-connection counts for every stable mode ID, active-window sum, cumulative lost/observed samples, committed transitions by reason, and actual source/repair/decoded/recovered wire counters. `AdaptiveFec` additionally owns a connection-local snapshot.
- Send metrics are produced only after `OutgoingFecPacket::write_to()` serializes the complete datagram into the network-facing output buffer. Receive metrics are produced only after `WireFecReceiver` accepts a framed datagram and reports original versus recovered output. Generated, queued, dropped, malformed, and duplicate symbols cannot masquerade as serialized or recovered work.
- The native performance matrix now has an explicit `fec_off_policy_fast_path` Criterion group comparing lossy hard-Off against the clean Auto/Zero baseline with persistent state and reusable output. The 4,096-packet regression separately proves zero repairs, zero encoder window state, and zero repair-retention growth under sustained total loss.
- Current local candidate evidence is green: `cargo fmt --all -- --check`, `git diff --check`, strict all-target Clippy with `rust-tests` and warnings denied, the complete one-job `cargo test --features rust-tests` suite with 1,811 library tests plus every binary/integration/runtime/doc target, and Bash syntax plus warning-severity ShellCheck for the specialized harness. TODO consistency passes across 198 detail files with zero violations and runtime guardrails pass with zero critical findings and zero warnings. The first TODO audit exposed one unrelated legacy frontmatter value, `TODO-532 status: SCRAPPED`; it was normalized to the repository's canonical `SCRAP` status without changing the owner-scrapped scope. `cargo clean` removed 3.8 GiB before the fresh Clippy build and the filesystem stayed above the mandatory 2 GiB free-space floor.
- Native macOS ARM64 Criterion evidence for `fec_off_policy_fast_path` measures clean Auto/Zero at `1.3240 us` and hard Off under total reported loss at `179.15 ns`, making Off approximately 7.39 times faster for the identical persistent 1,400-byte workload.
- The specialized transition harness now exposes canonical moderate (20%) and severe (40%) loss profiles and can retain a collision-safe manifest plus six client/server phase telemetry snapshots in an explicitly new `QF_E2E_ARTIFACT_DIR`. This closes TODO-558's live policy-evidence path without taking over TODO-557's comparative or statistical acceptance scope.
- Exact artifact `57788b1e98d47ba918756de45f5baed73e5852f68bfd4125bb441e7d0beb4714` passed two Off and two Auto repetitions at both 20% and 40% netem with zero tunnel loss in every clean/recovery phase and no teardown residue. The evidence also rejected closure: both Auto clients had already switched to Fountain during the nominally clean phase, including a run with only 2 lost observations among 167 sent observations. Root cause is product Auto bootstrapping in `Normal` plus temporally independent send/loss callbacks being treated as self-contained loss batches, allowing a delayed `1/1` loss callback to drive an immediate Fountain transition.
- Product Auto now bootstraps in Zero, exact sent and lost callback counts remain independent telemetry producers, adaptation consumes the congestion controller's smoothed loss signal, fallback stat baselines advance on every sample, and Fountain requires at least 32 observations plus agreement between the estimator EMA and populated recent-loss window. Deterministic regressions prove an isolated delayed loss cannot select Fountain while sustained 50% loss still does.
- Repeated live failures isolated a second controller defect: the former 2,048-source Fountain window emitted 8,192 repairs synchronously when the block completed, stalled live I/O, inflated transport loss, and triggered DPLPMTUD black-hole recovery. The same exact pre-fix ARM64 binary passed both moderate and severe diagnostics when `QUICFUSCATE_FEC_FOUNTAIN_WINDOW=128`; the severe run entered Fountain and returned to Zero without a black-hole event. Product Fountain now defaults to and clamps at 128 sources, bounding the current completion burst to 512 repairs. A deterministic regression rejects a requested 2,048-source override and proves the emitted burst remains bounded.
- Transport ACK classification now owns exact clean-delivery evidence. `FecCallbackFeedback` transfers independently reset send, ACK, and loss packet counts into Core; sends cannot increment the clean streak, any actual loss resets it, and 32 consecutive loss-free classified ACKs clear stale burst/disturbance state. That proof also permits a pending return to Zero to retire an incomplete repair-only encoder window instead of remaining stuck in a protected mode behind an unfillable block boundary.
- Exact intermediate artifact `8576559656` for commit `3a1da485e484b2a53cd513580d9492012a92de95`, binary SHA-256 `fc7a7d762ae2480c82e2f6fc51568304592e010cdc8776e16867952d4e168e76`, passed the ownership regression and all four repeated Off matrices in `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo558-3a1da48`. Its first Auto/moderate run correctly remained Zero while clean, committed `Strong` under loss, and sent 69 repairs by recovery, but exposed a false-negative harness assertion that demanded a repair before the 128-source Strong window could fill. The phase-aware correction requires clean Zero/no-work, a committed non-Zero lossy mode, repairs by run end, and no moderate Fountain transition; the corrected candidate passed the same exact binary with 0% clean loss, 22% impaired tunnel loss, and 0% recovery loss.
- Exact ARM64 artifact `8577161787` for commit `6361280c413f89e90c6b6e5669e51b469c3cf3cd`, bundle SHA-256 `dbfb3120ec24375cdca097db0317ad4c36d91289ae86d32bbd36f7bcdedd10ce`, and binary SHA-256 `fc7a7d762ae2480c82e2f6fc51568304592e010cdc8776e16867952d4e168e76` passed the ownership regression plus repeated Off and Auto moderate/severe matrices in `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo558-6361280`. All eight runs had 0% clean/recovered tunnel loss, one client and server handshake, no panic, and clean teardown; Off stayed Zero with zero repairs and switches, while Auto stayed Zero while clean, committed protection under loss, emitted repairs, and never selected Fountain under moderate loss. Two short recovery snapshots still observed Streaming, so a supplemental 10-second-settle plus 250-ping probe was run against the same exact artifact. Both profiles returned to Zero with 0% recovered tunnel loss and six or seven committed switches. The specialized harness now enforces that proven 35-second bound; a final exact-commit artifact rerun remains required before closure.
- Handoff commit `931aaa43a6f1e0243f2971eb3f8701692bf0eb0c` is pushed on `main`. It records `RECOVERY_SETTLE_SECONDS=10`, `RECOVERY_PING_COUNT=250`, persists both values in the evidence manifest, and fails Auto unless the recovered client snapshot has exactly one Zero connection and no non-Zero connection. Bash syntax, ShellCheck, diff integrity, protected-path diff, TODO consistency across 196 detail files, runtime guardrails with zero critical findings and warnings, formatting, and strict all-target Clippy with `rust-tests` and denied warnings passed on this exact commit.
- The previously stopped full Rust gate is complete on the exact candidate source. The one-job suite exited successfully after all library, binary, integration, runtime, and doc targets; the prior two-job `dyld` stall was a host resource/concurrency problem rather than a product failure.
- Exact pre-commit candidate: base commit `7c8907e2f9817390fa87a3e8e2eef56cc8ac0263`, working-diff SHA-256 `d3d0ffea77517c22a474d3aff33e58b34eb10f137389ae8f01d32f24c52b2272`, canonical 1,343-member source archive SHA-256 `18ccc15dff53420a2e875aba2895ec6479bae7081d3b1a3cd4c6361e8a1f0e6c`, and AArch64 binary SHA-256 `5dbbdf670464408e895c86977ad3e015924212c57e7cdc20ab7f592c5ba4b129`. The source archive contains no AppleDouble members or PAX xattrs. The isolated Omega root is `/home/ubuntu/SOFTWARE/QuicFuscate/candidate-todo558-7c8907e-d3d0ffea7751`; the exact retained evidence is under `evidence-final/`.
- The exact candidate passed the specialized ownership regression plus all eight repeated Omega matrices with the 150-ping loss phase and bounded recovery. Off moderate recorded `18%` and `22%` impaired tunnel loss; Off severe recorded `38%` and `37%`. Auto moderate recorded `16%` and `2%`; Auto severe recorded `38%` and `37%`. Every run recorded `0%` clean and recovery loss, one client and server handshake, zero panic, zero crypto/decrypt match, and the same binary SHA-256. All 24 Off client/server snapshots stayed Zero with zero effective window, repairs, and switches. Auto clean and recovered client snapshots stayed or returned to Zero; lossy client modes were Extreme, Streaming, Extreme, and Extreme with final repair counts `45`, `142`, `18`, and `18`, and no moderate Fountain or extreme-reason transition.
- Omega teardown is exact: IPv4/IPv6 routes, host qdiscs, namespaces, links, product processes, and temporary runtimes are byte-identical before/after; the generated TUN lock is absent; iptables, ip6tables, and nftables are structurally identical after normalizing counters and snapshot timestamps. The retained AArch64 binary and canonical source archive were re-hashed after the matrix, `cargo clean` removed the 494 MiB remote target, and only the isolated candidate/evidence root remains.
- Final implementation commit `b7db20443bb070d97686975034ebd9656ca3f98e` is on `main`. CI run `30155084370`, all eight jobs in Clippy Matrix run `30155084377`, and every required job in Release Build run `30155084369` completed successfully.
- GitHub source archive SHA-256 is `64a8fae24a1143ab9715b78c0075dfcf570c51432682f5c1383077d5309be678`. Release artifact `8618780323` contains the x86_64 server bundle with SHA-256 `a66c13296ad045e1011c12e62e02728c23101e45b525b0618df0e2bcd950110e` and packaged binary SHA-256 `a235ffa4617008d1badda9e11e62d242767320a522891d32b7ea951d12b05ec5`. Native ARM64 artifact `8618776310` contains the server bundle with SHA-256 `0fb66cb66b48475cb578eccadeb1d9f8da17273f98939ab60931b0dd8ebdeecb` and packaged binary SHA-256 `ea93bc10af7fc205da41b2acf02b5b6a0b25702113c7d8900390c12e99e516fb`.
- Both server manifests match their downloaded bundles. The x86_64 and ARM64 server archives, macOS application archive, Linux Debian package, Linux AppImage, Windows MSI, and macOS DMG are structurally valid; `hdiutil verify` reports a valid DMG checksum. The exact-commit protected Svelte/Tauri diff is empty.
- `Engine::set_fec_mode()` and server runtime reload still do not prove policy changes on already-active connections. That separate active-control contract is registered as TODO-560 and does not weaken this task's connection-construction and lifetime-Off scope.
- Exact probe source commit: `222ebdc0c91a887e480dc6697f82e45e4c9d417c`; ARM64 binary SHA-256: `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`.
- This task owns control and observability correctness. Scenario thresholds and comparative acceptance remain TODO-557.

## Deviations

None.
