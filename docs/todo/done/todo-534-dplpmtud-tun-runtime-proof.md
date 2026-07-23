---
id: TODO-534
title: Complete DPLPMTUD bounds, TUN coupling, and runtime proof
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-22
depends_on: [TODO-451, TODO-521]
---

# TODO-534: Complete DPLPMTUD Bounds, TUN Coupling, and Runtime Proof

## Why

Production sends are clamped by confirmed PMTU and ACK/loss logic drives padded probes, but discovery is fixed to 1280-1400, disabled-mode semantics are ambiguous, TUN MTU never follows the path, and no privileged black-hole or 1500-byte evidence exists. TODO-523 additionally proved that the configured 1280-byte TUN MTU can exceed the effective MASQUE payload, while the HTTP/3 body fallback has no explicit raw-IP packet framing or reassembly contract.

## Acceptance

- Expose validated minimum, maximum, probe interval, and black-hole timeout policy while retaining safe protocol floors and peer maximum UDP payload clamping.
- Reach and prove 1400 within five probes and 1500 within three probes on matching paths; keep disabled behavior explicitly fixed and regression-tested.
- Make probe ACK/loss attribution robust to unrelated ACK traffic and prove all search, complete, black-hole, recovery, and periodic re-probe transitions.
- Propagate effective MTU changes through the client TUN lifecycle without transient oversized packets or route disruption.
- Define one effective tunnel payload contract shared by client ingress, server forwarding, MASQUE datagrams, and ICMP generation.
- Return correct local IPv4 Fragmentation Needed or IPv6 Packet Too Big when a TUN packet cannot fit the current effective tunnel payload.
- Frame HTTP/3 fallback packets with explicit bounded lengths and reassemble arbitrary body-read segmentation without concatenating, truncating, or splitting IP packets.
- Retransmit lost QUIC STREAM ranges from bounded payload ownership until ACK retirement so the reliable HTTP/3 fallback cannot retain permanent offset holes.
- Prove transfer recovery after dropping packets above 1280 and measure the retained 1500-versus-1280 throughput criterion.
- Re-run the TODO-523 three-client PTB boundary on the exact artifact and preserve packet captures, metrics, logs, and cleanup proof.
- Pass local Rust gates, native CI, privileged Omega netem/TUN proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [x] Audit config, packet sizing, ACK/loss attribution, TUN ownership, and HTTP/3 body semantics.
- [x] Define bounded policy, packet framing, and MTU-change propagation.
- [x] Implement state-machine, integration, and property tests.
- [x] Implement bounded STREAM-range retransmission and ACK/loss retirement.
- [x] Execute privileged black-hole, re-probe, and throughput proof.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-451 reconciliation. Binary search remains canonical; a parallel common-MTU table is outside scope.
- Activated as the approved hot-switch from TODO-523. The retained Omega artifact `a86dcbf921fd304af22ab1d43c7a0aa357850362231421d9cc450e993f3f6e86` proves three-client dual-stack, isolation, spoof rejection, and fan-out, but three distinct PTB attempts exposed the payload mismatch and unframed fallback boundary.
- The closure bundle is serial: finish TODO-534, then restore TODO-523 as active and complete its remaining live PTB and documentation evidence.
- Audit found that the old probe target was unreachable: `Connection::send()` sliced the output buffer to the confirmed MTU before testing whether the larger probe fit. The 1400 ceiling, 60-second interval, and 10-second timeout were compile-time constants, while the client runtime separately forced a 1200-byte send maximum.
- The new contract distinguishes the confirmed MASQUE datagram payload from the effective inner tunnel MTU. The datagram path remains the allocation-free fast path; an explicit `QFT1 + u16 length` HTTP/3 frame carries IPv6-minimum packets that cannot fit one datagram, with bounded per-stream reassembly and fail-closed magic/IP validation. Packets above the effective tunnel MTU receive local IPv4 Fragmentation Needed or IPv6 Packet Too Big.
- Live TUN MTU ownership now has an explicit backend update contract. The client opens at `min(configured ceiling, effective tunnel MTU)` and synchronizes later DPLPMTUD changes; Linux uses `ip link`, macOS uses `ifconfig`, and Wintun uses active `netsh` subinterface state.
- DPLPMTUD policy is now validated configuration with a 1280 floor, 1500 ceiling, probe interval, and black-hole timeout. Dedicated probes receive the probe-sized output budget before normal application/control frames, fixing the previous confirmed-MTU clamp dead path.
- Black-hole liveness no longer refreshes from arbitrary small ACKs. Only an acknowledged packet at the confirmed MTU clears the confirmed-MTU watchdog, while probe ACK ownership remains tied to the exact recorded probe packet number.
- The exact ARM64 live path now passes three-client dual-stack routing, framed H3 fallback, client-local IPv4/IPv6 PTB, server-emitted IPv4/IPv6 PTB, isolation, spoof rejection, fan-out, and the complete routing metric matrix. IPv4 PTB encoding was corrected to RFC 1191 bytes 26-27, and authenticated traffic to the server TUN addresses is now typed as `local` instead of `internet`.
- Sustained IPv6 TCP reaches roughly 1-2 MiB before a permanent stream offset hole stalls the inner TCP flow. Fair 64-datagram flush bursts, 2 MiB UDP socket buffers, and bounded 1024-packet TUN queues keep runtimes and heartbeats responsive but cannot repair the hole. `sent_packets_by_pn` owns only byte counts and timestamps, while loss accounting never requeues the associated STREAM bytes; real QUIC STREAM retransmission is therefore required before throughput acceptance can pass honestly.
- STREAM payload ownership is now staged as immutable, byte-bounded ranges before packet sealing can fail. Compact packet-number references drive packet-threshold loss, tail-PTO requeue, exact active ACK retirement, and bounded late-ACK retirement without duplicating payload storage; retransmissions are scheduled before new stream bytes. Verification remains open until the new deterministic loss, late-ACK, PTO, local gate, ARM64, and Omega throughput proofs pass.
- Immutable ARM64 run16 passes strict clippy, all 69 transport connection tests, and release build with artifact SHA-256 `ab672c874e1a97963cff09c98a5b7057398d77edcba0ffa4d67e0f44fd5ce788`. Its live run preserves every pre-throughput gate and advances sustained IPv6 TCP from roughly 1-2 MiB to 3.40 MiB before exposing the next exact boundary: retransmission-driven FEC activation calls `force_streaming_mode()` inside an unfinished 1024-source Extreme block, prematurely labels the old encoder as Streaming, and makes `wire_profile()` reject block size 256 with `CodecSourceLimit`. The transition now keeps the old mode/profile until the source-block boundary and has a dedicated large-block regression test; run17 proof remains pending.
- ARM64 run18 passes the forced-transition regression, all three wire-profile tests, all 69 connection tests, strict all-target Clippy, and release build. Live phase 1 completes every retained boundary and sustains IPv6 TCP at 6.925 Mbit/s without a STREAM stall or `CodecSourceLimit`. Phase 2 then exposes an independent server-only ceiling: the standalone runtime still used a 1460-byte output scratch buffer, while a 1500-byte DPLPMTUD probe wrapped by the FEC wire envelope requires the full configured outer datagram budget. All three clients confirmed 1500, but each server probe failed `BufferTooShort`. The server now uses the same 65,535-byte live UDP buffer capacity as the client and receive path; repeated native and live proof remains pending.
- Final local gates pass strict all-target/all-feature Clippy and the complete `cargo test --features rust-tests` workspace: 1,768 library tests, 19 binary tests, all integration/runtime targets, and documentation tests. Deterministic regressions cover exact PMTU packetization, 1500-to-1280 retransmission splitting, loss/PTO requeue, and a late original ACK retiring every derived segment exactly once.
- Immutable ARM64 run35 passes the targeted split regression, full native tests, strict all-target/all-feature Clippy, and release build from source archive SHA-256 `b3140e9c14300af3416d021de6e81476ec41e3b57b775c7b1605a9fcaaf2ce3e`. The exact AArch64 binary is `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo534/build-run35/release/quicfuscate`, SHA-256 `d985c254fb55792afc9d2e1bc88d14b68b8737a3bfcb7507961fc8b1a1c09888`.
- Run35 retained evidence at `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo534/evidence/run35` proves three simultaneous isolated clients, dual-stack routing/NAT, source ownership, spoof rejection, default-deny and explicit opt-in client traffic, authenticated fan-out, local/server IPv4 and IPv6 PTB, and the complete routing metric matrix. Every client and the server confirm 1500.
- Every regular five-second throughput trial contains exactly five positive intervals. The 1280-floor runs measure 5.861, 6.758, and 6.454 Mbit/s, median 6.454; confirmed-1500 runs measure 8.961, 7.890, and 9.386 Mbit/s, median 8.961. The measured median gain is 38.85%, exceeding the 15% criterion.
- The 20-second `tc` egress black-hole trial detects the 1500-byte failure in 3 seconds, falls back to 1280, transfers 17,039,360 bytes, and re-confirms 1500 through bounded probes. Cleanup leaves no QuicFuscate process, heartbeat failure, or network namespace.

## Deviations

- The inherited 1200-byte comparator conflicted with the IPv6 minimum link MTU. The closure uses the protocol-safe 1280-byte floor while retaining the original 15% performance threshold; run35 achieved 38.85%.
