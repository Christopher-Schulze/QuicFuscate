---
id: TODO-547
title: Restore FEC wire framing and live 1-RTT integrity
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-22
depends_on: [TODO-422, TODO-473, TODO-524, TODO-521]
---

# TODO-547: Restore FEC Wire Framing and Live 1-RTT Integrity

## Why

The exact ARM64 release artifact reaches a completed rustls handshake on Omega, then both peers fail when opening live 1-RTT packets. Core emits every `FecPacket` through payload-only `to_raw()` and reconstructs every received UDP datagram as systematic. Repair payloads therefore enter QUIC decryption as ciphertext, while source IDs and repair coefficients never cross the wire. Disabling FEC makes the same TUN/MASQUE path complete the handshake and exchange 1-RTT application traffic without an AEAD error.

## Acceptance

- Keep Initial and Handshake datagrams raw, keep stable Zero mode payload-only, and frame every active-FEC 1-RTT source and repair packet with exact source ID, sequence, deterministically reconstructable coefficients, and payload.
- Parse framed FEC datagrams before decoder dispatch and never feed repair payloads directly into QUIC decryption.
- Carry a versioned decoder epoch, codec/mode, effective window, and interleave mapping so asymmetric loss cannot make the receiver apply an unrelated local decoder state.
- Keep every outer UDP datagram within the configured path MTU in every adaptive mode; repair metadata must not depend on transmitting an unbounded coefficient vector.
- Drop malformed or unsupported FEC envelopes without terminating the authenticated QUIC connection.
- Add a real bidirectional rustls client/server transport test with a generated trusted hierarchy plus focused raw/framed wire regressions.
- Preserve packet authentication, certificate verification, header protection, and key-update behavior.
- Prove local full Rust gates and native CI/Clippy/Release gates with protected UI files unchanged.
- Deploy the exact native ARM64 artifact into a new Omega runtime directory and pass the original uniform-loss and burst-loss TUN/FEC netns gates without touching historical runtime directories.
- Reconcile TODO-423, TODO-473, TODO-524, and production-readiness claims against the new runtime truth.

## Sub-Tasks

- [x] Reproduce the failure with the exact current ARM64 release artifact and preserve logs.
- [x] Exclude TLS Cover, TUN ownership, and rustls directional keys as root causes.
- [x] Trace the live 1-RTT boundary and prove FEC-off success on the otherwise identical Omega path.
- [x] Replace the insufficient legacy envelope with a versioned, MTU-bounded FEC wire contract and adversarial regression coverage.
- [x] Run local, native, and Omega end-to-end evidence.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Current artifact commit: `f85f63bb3709bde340c7e5f568add3ffe043d4e8`; ARM64 binary SHA-256: `11aca352d82fef143a95c616e87f0b5ff5bb5d5e76543822f14e8e9f999dbf56`.
- Current Omega evidence is under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-f85f63b/evidence/`. Historical comparison evidence is under the separately created `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-compare-7e335d3/evidence/`; existing runtime directories were not modified.
- Both sides report a completed TLS handshake before `quic open error: cannot decrypt peer's message`. The client also reports an H3 `BufferTooShort` before shutdown.
- With `--fec-mode off` on both peers, the same isolated TUN/MASQUE topology completes the handshake, opens the MASQUE stream, and sends the HTTP/3 request without an AEAD error.
- `FecPacket::to_stream_raw()` and `from_stream_raw()` already define and test the required transport envelope, but Core did not call either method.
- The real-rustls integration fixture now generates and trusts its own CA hierarchy, so release tests no longer depend on the debug-only invalid-certificate bypass.
- A focused Core patch now keeps handshake/Zero datagrams raw, frames active-FEC packets, parses the existing envelope before decoder dispatch, and exercises a real generated-CA handshake plus an emitted repair packet. Targeted Core, FEC stream, FEC end-to-end, and current debug rustls repair-path tests pass. The generated-CA release test passed before the repair assertion was added. The patch remains uncommitted because the legacy envelope is not a production contract.
- The legacy envelope adds 21 bytes plus the full coefficient vector. With the 1400-byte transport MTU, Strong mode uses `k=128`, interleave depth 4, and 64 coefficient bytes per GF16 repair, producing up to 1485 bytes. This exceeds both the configured MTU and the standalone server's 1460-byte send buffer. Extreme mode reaches 1677 bytes before UDP/IP overhead.
- The legacy envelope carries source/sequence/coefficient data but no protocol version, FEC mode, effective window, interleave depth, or transition epoch. Sender and receiver adaptation is locally driven, so asymmetric loss can select incompatible encoders and decoders even when serialization succeeds.
- Production correction therefore requires a compact versioned envelope, deterministic coefficient regeneration from a transmitted repair seed/ordinal, explicit decoder epoch parameters, bounded inner QUIC payload sizing, and dual-epoch transition acceptance. Merely wiring `to_stream_raw()` into Core would fix the current Normal-mode Omega reproduction while leaving higher modes and asymmetric links broken.
- Architecture expansion approved on 2026-07-22: optimize the active cascade for minimum wire and compute cost, reserve Fountain codes for severe-loss rescue, and continue through implementation and live proof without reducing the acceptance contract.
- The replacement wire v1 contract uses a fixed 32-byte header plus a two-byte FEC-protected source-length prefix. Core reserves exactly 34 bytes from the confirmed transport datagram budget, so raw Initial/Handshake and Zero remain unchanged while every active source and repair stays MTU-bounded.
- Repair coefficient vectors are no longer transmitted. GF4, GF8, GF16, and streaming GF8 rows are reconstructed from codec, block width, and repair ordinal; Fountain source sets are reconstructed from the repair seed. The receiver owns bounded per-epoch/per-window decoder state and never derives inbound codec state from local loss estimates.
- Adaptive field/window changes now commit only between complete source blocks. The hidden AdaptiveRS encoder-only mutation and packet-level cross-fade were removed from the production path; the active cascade selects GF4 only for blocks up to 15 sources, GF8 up to 255, GF16 above 255, and Fountain only for rescue mode.
- The architecture pass exposed and fixed two independent data-integrity defects: GF16 truncated odd source bytes, and the AArch64 NEON GF16 kernel performed integer rather than polynomial multiplication. Odd-length GF16 recovery now preserves the protected source length and final byte with a correct eight-lane carryless NEON kernel.
- The 1-RTT envelope gate now polls rustls before deciding readiness and checks the actual Initial/Handshake CRYPTO send queues. TLS completion alone can no longer cause a pending client Finished flight to be wrapped as application FEC; focused transport and CryptoStream regressions pass.
- Wire validation bounds source blocks to 2,048 symbols, total codeword capacity to 12,288 symbols, repair ordinals to the advertised capacity, retained decoder windows to four, and rejects profile mutation inside a retained epoch before allocation. Duplicate repairs are suppressed per receive window.
- Streaming wire recovery now transmits the real partial coverage anchor, maps coefficients against a stable full-block decoder anchor, zeros coefficients outside the covered prefix, and wakes the heavy decoder only when the wire receiver proves a missing source inside that coverage. This fixes the previous partial-window source-ID ambiguity without charging clean streaming traffic for decode work.
- Dynamic block repairs now use distinct ordinals instead of repeating existing repair rows. Streaming ordinals reset at block boundaries, and advertised repair capacity covers both configured and adaptive emissions.
- GF4 product mode is mathematically bounded to a 15-source/16-total MDS block with exactly one repair, matching the 16 elements available in GF(2^4). Adaptive extra repairs are disabled in this tier because a second all-source repair cannot extend a length-16 MDS code; rising loss instead promotes the codec. A compile-time multiplication table plus fused scalar/AVX2/NEON multiply-XOR removes the temporary repair buffer. Apple Silicon Criterion measures about `6.69 us` median and `199.45 MiB/s`, a further 22% median-time improvement over the preceding two-repair GF4 policy and about 43% lower median time than the measured GF8 k=16 baseline.
- The FEC Criterion surface now measures the production v1 envelope directly: 1,400-byte wire write about `29.73 ns`, parse about `12.83 ns`, and deterministic GF8 k=16 repair-row derivation about `22.75 ns` on Apple Silicon.
- `scripts/tests/suites/test-fec-simulation.sh` still carries legacy environment axes that the production controller does not read. It is excluded from TODO-547 evidence; the failable wire, codec, rustls, full-workspace, native, and Omega gates own acceptance instead.
- Focused evidence passes: 17 wire tests cover framing, validation/resource bounds, MTU bounds, retained-epoch consistency, coefficient regeneration, the exact GF4 field row, exact variable-length GF4/GF8/GF16 recovery, partial-window streaming recovery, and multi-loss Fountain rescue; the full 206-test FEC scope passes after the fused GF4 SIMD and single-repair policy changes. Earlier focused evidence also includes 23 internal FEC tests, 21 Fountain tests, the block-boundary profile test, the pending-handshake-flight regressions, and the generated-CA QKey/rustls test with authenticated HTTP/3 plus observed source and repair envelopes. The integration test rejects any emitted datagram larger than the active transport path-MTU cap.
- Final local deterministic gates pass after the one-repair policy: `cargo test --workspace --all-targets --features rust-tests -- --test-threads=1` runs 1,717 library tests plus every integration/binary target with zero failures; strict workspace/all-target Clippy with `-D warnings`, formatting, `git diff --check`, runtime-guardrail audit, and TODO-consistency audit are green.
- Native CI exposed two independent gate defects after the FEC implementation commit: the production-only acceleration re-export still exposed test-only `iter`, and the client integration harness dropped its ephemeral UDP reservation before the server task rebound it. The re-export is now exact for production, while the harness binds once and hands the already-ready socket to the spawned echo task; the focused echo test passes 50 consecutive local runs and production-feature Clippy remains warning-free.
- Final proof commit `15570abf772766c76959f6aae6ba16b2b9c26fd7` passes the complete local workspace/all-target `rust-tests` gate with 1,717 library tests plus every integration, binary, and example target green. GitHub CI `29915916296` and Clippy Matrix `29915916332` are green; Release Build `29915916301` produced the exact native ARM64 artifact used below.
- The native ARM64 bundle SHA-256 is `5406170b4175d91722d2169c8c21adc9721e61fe995a513299fc4f52eff9d8fe`; its stripped AArch64 binary SHA-256 is `9b4144a85e452ef37102ac255b0c8c976f1145ad04941c594d07d4fc6130cf5b`. Omega verification is isolated under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-15570ab`; historical runtime directories are untouched.
- The final 1,000-packet uniform matrix passes `4 passed, 0 failed`: residual tunnel loss is 0% at 0% netem, 9% at 5%, 11% at 10%, and 26% at 25%. The final correlated-burst matrix passes `2 passed, 0 failed`: residual loss is 2% for both 10%/25% correlation and 20%/50% correlation. Both retained peer-log pairs prove completed TLS, H3/MASQUE flow establishment, and NEON FEC with no AEAD, decrypt, or panic error. An earlier isolated 10% anomaly did not recur in the full final matrix, the isolated retry, or five consecutive 1,000-packet stress repetitions.

## Deviations

None.
