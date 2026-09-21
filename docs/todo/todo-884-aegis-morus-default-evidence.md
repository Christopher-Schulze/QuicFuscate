---
id: TODO-884
title: Produce decision-grade AEGIS versus MORUS default evidence
severity: CRITICAL
phase: S
priority: P0
status: ACTIVE
created: 2026-08-11
depends_on: [TODO-883]
---

# TODO-884: Produce Decision-Grade AEGIS Versus MORUS Default Evidence

## Objective

Give AEGIS-128L and MORUS-1280-128 equal, rigorous treatment and select exactly one qualified family as the QuicFuscate advanced product default. The decision must be based on current-revision correctness, cryptanalysis provenance, implementation auditability, native side-channel posture, portability, and real VPN performance.

MORUS is not a second-class compatibility option. If MORUS clears every mandatory security and correctness gate and wins the decision-grade performance matrix, MORUS becomes the advanced product default. AEGIS receives the same opportunity. No winner is predetermined.

The selected family becomes a QuicFuscate product default through TODO-885. This task cannot make either family an IETF TLS or QUIC standard and must never describe it that way.

## Current Local Evidence

Local correctness reconciliation proceeds while TODO-883 retains its external native-host and packet-capture blocker. The current revision is tested against the pinned CFRG AEGIS-128L vectors and the official CAESAR MORUS-1280-128 reference artifacts before any performance or default-selection claim. This task does not promote either family as the universal product default and does not change the standard AES-GCM live baseline; authenticated private activation and its packet owner are implemented and tested under TODO-885.

The current qf-crypto gate passes `146/146` all-feature unit tests. It includes the five valid CFRG AEGIS-128L 128-bit-tag vectors, all four CFRG verification-failure vectors, AEGIS L/X4/X8 byte identity, the ARM AESENC ordering regression, and six official MORUS v2 reference cases covering empty, partial, exact, and multi-block payloads with authentication-failure checks. The correction removed a non-conformant AEGIS update/finalization path, corrected ARM AESE key ordering, corrected MORUS word rotations and keystream word order, and does not promote a winner.

The root `rt-baseline-oracles` target passes `6/6`; root `cargo check --lib --features rust-tests` and strict all-feature Clippy pass; `cargo fmt --all -- --check` and `git diff --check` pass. The existing release `scripts/tests/suites/test-crypto.sh --fast` also passes its AEGIS, MORUS, AES-GCM, TLS-Cover, and integration fixture lanes; its x86-only GHASH parity test is correctly `SKIP` on this ARM64 host. These are local correctness and build gates only, not native cross-ISA, side-channel, packet-path, or VPN-performance promotion evidence.

The complete root `cargo test --all-features --lib` gate executes `1,750` tests: `1,749` pass, `0` fail, and `1` is ignored. This broad pass includes the live rustls persona-handshake, packet-key, QUIC transport, H3/MASQUE, FEC, TUN, and circuit regression surfaces, including the authenticated private packet epoch transition; it still cannot substitute for the unavailable hosted native Linux/Windows and side-channel lanes.

The repaired `scripts/tests/suites/test-crypto.sh` now targets the qf-crypto leaf and rejects zero-test filters before execution. Its full release mode passes AEGIS `18/18`, MORUS `21/21`, AES-GCM `8/8`, GHASH/PMULL `4/4`, ChaCha `1/1`, AES header protection `6/6`, SIMD `11/11`, root baseline oracles `6/6`, TLS-Cover `3/3`, and the failable integration fixtures; x86-only parity targets are explicitly skipped on this ARM64 host. The JSON result artifact validates successfully. The runner correction closes a real prior false-green path and still does not close the external promotion gates.

A fresh current-revision Criterion run on ARM64 macOS 15.6.1 (`arm64`, rustc `1.97.1`, dirty working tree at `60a67c9065e52c04dd2292ee50739c240c442ff`) completed with exit code `0` using release profile, `RUSTFLAGS='-C debuginfo=0'`, ten samples, 200 ms warm-up, 500 ms measurement, and 1,000 resamples. The private `data_aead_single` groups covered 64, 1024, 1400, and 8192-byte payloads for AEGIS-128L, AEGIS-X4, AEGIS-X8, and MORUS; the standard `rustls_standard_packet_key` groups covered the same sizes for AES-128-GCM-SHA-256 and AES-256-GCM-SHA-384. The 1400-byte mean point estimates persisted in `target/criterion` are:

| 1400-byte single-packet primitive | Seal | Open |
|---|---:|---:|
| AEGIS-128L | 7.361 us | 8.472 us |
| AEGIS-X4 | 7.038 us | 8.423 us |
| AEGIS-X8 | 7.443 us | 8.642 us |
| MORUS-1280-128 | 0.816 us | 0.883 us |
| rustls AES-128-GCM-SHA-256 | 0.320 us | 0.318 us |
| rustls AES-256-GCM-SHA-384 | 0.368 us | 0.350 us |

The active `connection_rustls_standard_1rtt` paired send/receive group also completed with exit code `0`; its latest 1400-byte mean point estimates were `38.659 us` for AES-128-GCM-SHA-256 and `35.367 us` for AES-256-GCM-SHA-384. This is a current local signal only: MORUS is approximately 8.6 to 9.5 times faster than the retained AEGIS implementations on this host at the primitive boundary, but is approximately 2.6 to 2.8 times slower than the live standard packet-key measurements. The earlier same-host run was materially slower, so repeated controlled native runs remain mandatory. The authenticated private packet path now has direct local owner-installation and epoch-transition coverage, but no privileged native live VPN path has been proven. These measurements therefore do not select a winner, close TODO-883, or satisfy native cross-platform, side-channel, packet-capture, TUN/MASQUE, or multi-hop promotion gates.

The retained `bench-retained-crypto-backends.sh --fast` suite initially produced a false `ok=0` on all three MORUS sizes because the runner passed the alias `morus` while the real backend emitted its canonical identity `morus1280_128`; no MORUS measurement was accepted in that run. The runner now uses the canonical identity, retains the input alias for the example CLI, and passes `bash -n` plus ShellCheck. The corrected suite exits `0` with all twelve backend/size cells valid and reports MORUS as the throughput winner in repeated spot checks. The final pinned-toolchain run (`1.97.1`) reported MORUS at `38.717`, `303.933`, and `769.953 MB/s` for 1200 B, 16 KiB, and 64 KiB. The standalone 200-iteration fast values varied materially across consecutive runs, including MORUS at 64 KiB (`1,037.787 MB/s` then `430.402 MB/s`), so this runner is status and wiring evidence only; Criterion with confidence intervals remains authoritative and no winner is selected from these spot checks.

A fresh current-revision local evidence pass on 2026-08-13 completed with exit code `0`: `test-crypto.sh` passed AEGIS `18/18`, MORUS `21/21`, AES-GCM `8/8`, GHASH/PMULL `4/4`, ChaCha `1/1`, AES header protection `6/6`, SIMD `11/11`, baseline oracles `6/6`, and TLS-Cover `3/3` in `scripts/out/tests/tests-crypto-20260813_014439/`; `test-security.sh` passed the security suite `27/27` and property suite `12/12` in `scripts/out/tests/tests-security-20260813_014730/`. The retained-backend fast benchmark in `scripts/out/benchmarks/bench-retained-crypto-backends-20260813_014544/` produced twelve valid cells with `ok=1` and `failed=0`; MORUS led the three ARM64 spot sizes at `74.310`, `635.444`, and `1,143.639 MB/s`, but this remains primitive/retained-backend evidence only. The short security/fuzz wrapper passed four deterministic cases and recorded twenty-two bounded platform/toolchain skips in `scripts/out/tests/test-security-fuzzing-20260813_014823/`; it did not provide fuzz, sanitizer, or side-channel promotion evidence. Full root and workspace all-feature library tests remain green, while native Linux/Windows, packet-capture, privileged multi-hop, and algorithm-relevant unsafe/side-channel gates remain open.

The current post-refactor local gate pass on 2026-08-13 is also green: `cargo check --all-features`, `cargo fmt --all -- --check`, root strict `cargo clippy --all-features --lib --bins --examples -- -D warnings`, and `RUSTFLAGS='-C debuginfo=0' CARGO_INCREMENTAL=0 cargo test --all-features --lib -- --test-threads=1` all exited `0`; the root library matrix reported `1,749` passed, `0` failed, and `1` ignored out of `1,750` tests. The qf-crypto release wrapper completed with AEGIS `18/18`, MORUS `21/21`, AES-GCM `8/8`, TLS-Cover `3/3`, and the ARM64 GHASH parity target explicitly skipped as non-x86. `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml`, the admin and desktop Svelte checks, and the runtime guardrail audit also exited `0`; the latter reported `Critical: 0` and `Warnings: 0` at the current audit artifact. The structural audit reports `388` Rust files, no file above `2,000` lines, and no textual `include!` assembly. These local gates validate the refactor and authenticated private activation path only; private-family promotion and external Linux/Windows, packet-capture, side-channel, and privileged multi-hop evidence remain open.

Fresh current-revision evidence on 2026-08-14 preserves that boundary. The fast crypto runner passes AEGIS `18/18`, MORUS `21/21`, AES-GCM `8/8`, and TLS-Cover `3/3`; the x86-only GHASH parity target is explicitly ignored on this ARM64 host. The security suite passes `27/27` and the property suite `12/12`. Artifacts are `scripts/out/tests/tests-crypto-20260814-final/` and `scripts/out/tests/tests-security-20260814-final/`. The retained-backend runner passes all twelve backend/size cells in `scripts/out/benchmarks/bench-retained-crypto-backends-20260814-final/` (`ok=1`); its ARM64 spot results select `morus1280_128` for 1200 B (`57.666 MB/s`), 16 KiB (`121.580 MB/s`), and 64 KiB (`282.972 MB/s`). These are status-bearing primitive spot checks, not decision-grade performance evidence. The final local root library matrix remains `1,749` passed, `0` failed, and `1` ignored out of `1,750`; Tauri checking, structure (`405` Rust files, zero oversized, zero source-assembly), documentation truth, feature taxonomy, formatting, diff hygiene, and zero-finding runtime guardrails pass. The server inline test monolith is now split into four responsibility modules, with the focused all-feature server surface passing `163/163`; the server metrics HTTP adapter is separated into `src/implementations/server/metrics/server.rs`, with focused metrics coverage passing `22/22`; firewall rule generation is separated into `src/implementations/server/routing/firewall_rules.rs`, with focused routing coverage passing `24/24`; no frontend visual surface changed. The comprehensive audit has zero critical and zero check failures but remains `UNAVAILABLE` for AMX proof on ARM64 macOS, native dialect parsers, and Linux-only kernel test targets; browser Chromium launch is also unavailable locally. No advanced family is promoted.

The differential harness is now symmetrized between AEGIS and MORUS as of 2026-08-19. Three new unit tests close the AEGIS-MORUS coverage gap from implementation-plan step 3: `morus_wrong_ad_fails_authentication` mirrors `aegis128l_wrong_ad_fails_authentication` and verifies the same tag bound to one AD does not authenticate under a different AD; `morus_failure_vectors_matrix` mirrors `aegis128l_rejects_pinned_cfrg_failure_vectors` and asserts each of the four canonical AEAD inputs (key, ciphertext, associated data, tag) independently causes authentication failure when mutated; `aegis_morus_differential_invariants` runs the same five-invariant check (roundtrip, ciphertext differs from plaintext when non-empty, wrong-AD rejection, tag-bit-flip rejection, alternate-nonce sensitivity) on both AEGIS-128L and MORUS-1280-128 with the same (key, iv/nonce, ad, plaintext) tuple across 64 deterministic splitmix64 scenarios. The qf-crypto unit test count moves from `146` to `149`, all green; `cargo fmt --all -- --check` and `cargo clippy -p qf-crypto --features rust-tests --lib --tests -- -D warnings` are clean. The standard AES-GCM baseline, the wire negotiation, and the runtime product policy are unchanged. No advanced family is promoted.

The differential harness is extended to the QUIC packet-path trait layer on the same date. `aegis_morus_aead_trait_differential` exercises `Aegis128LAead` and `MorusAead` through the public `AeadSeal::seal_with_u64_counter` and `AeadOpen::open_with_u64_counter` trait methods (the surface the transport actually consumes) across 32 splitmix64 scenarios, asserting the same three invariants (roundtrip, single bit-flip forgery rejection, wrong-AD forgery rejection) on both candidates. The qf-crypto unit test count moves from `149` to `150`, all green; the same fmt and clippy lanes remain clean. The trait-layer coverage closes the wrapper-only divergence gap between AEGIS and MORUS that the low-level differential test could not detect. No advanced family is promoted.

The differential harness is extended to the QUIC payload-size boundary on the same date. `aegis_morus_quic_payload_boundary_differential` covers the 1200, 1400, and 1500-byte payload sizes that the QUIC transport actually uses, with a fixed reproducible key/IV/AD/counter triple. Both `Aegis128LAead` and `MorusAead` are exercised through the public `AeadSeal/AeadOpen` trait at every payload size and must satisfy the same three invariants (seal reports `plaintext_len + 16`, open recovers the plaintext, single bit-flip or wrong-AD fails authentication). The qf-crypto unit test count moves from `150` to `151`, all green; the same fmt and clippy lanes remain clean. Together with the previous two additions, the AEGIS-MORUS symmetric correctness matrix now covers the small-payload (splitmix64 sweep), large-payload (1200/1400/1500), failure-vectors, and wrong-AD categories at every layer the QUIC transport actually consumes. No advanced family is promoted.

## Existing Evidence That Must Be Preserved

TODO-500 recorded a strong native AArch64 result on Omega through the retained packet trait benchmark:

| 1400-byte operation | AEGIS-L | AEGIS-X4 | AEGIS-X8 | MORUS |
|---|---:|---:|---:|---:|
| Single seal | 2.0736 us | 2.1367 us | 2.1067 us | 1.1944 us |
| Single open | 2.1307 us | 2.1725 us | 2.1760 us | 1.1885 us |
| Batch-8 seal | 16.979 us | 17.394 us | 16.699 us | 9.3550 us |
| Batch-8 open | 17.115 us | 17.221 us | 17.010 us | 9.4560 us |

The same task recorded MORUS winning every tested retained-backend AArch64 case from 64 to 8192 bytes and changed the AArch64 planner to MORUS.

This is valuable evidence, not a default decision, because:

- the benchmark did not compare against the actual rustls ring AES-GCM packet owner;
- normal live TLS installation currently replaces the private packet owner;
- the measurement does not cover the current revision, all supported architectures, multi-hop amplification, side-channel behavior, or independent implementation parity;
- the connection benchmark after the planner change does not prove that a live rustls-authenticated session retained MORUS after OneRtt key installation.

## Candidate Contract

| Candidate | Product family | Internal implementation latitude |
|---|---|---|
| AEGIS | AEGIS-128L | AEGIS-L, X4, and X8 may remain internal planner-selected backends only if byte-identical and independently justified |
| MORUS | MORUS-1280-128 | ISA-specific MORUS backends may be selected internally only if byte-identical and independently justified |

AES-GCM is the mandatory standards baseline and rollback path, not a candidate for the advanced-family winner. ChaCha20-Poly1305 may be measured as a portable reference but is not silently reintroduced into the current product policy.

## Mandatory Promotion Gates

Performance scoring begins only after a candidate passes every mandatory gate.

### Specification and Independent Provenance

- Pin the exact public algorithm specification, parameter set, test vectors, security claims, and known cryptanalysis for each candidate from primary sources current at execution time.
- For AEGIS, reconcile the exact CFRG/RFC publication state and use its normative vectors. Publication status alone must not be presented as a registered TLS/QUIC cipher suite.
- For MORUS, pin the CAESAR submission/reference artifacts, final parameter set, official known-answer vectors, and current public cryptanalysis.
- Inventory at least one implementation independent of the QuicFuscate code for each candidate.
- Prefer a maintained upstream implementation as the production provider when it is constant-time, portable, license-compatible, allocation-free on the packet path, and not measurably worse.
- If a candidate lacks a suitable upstream Rust provider, retain an independent reference oracle and make the custom runtime boundary explicit.

### Correctness and Differential Proof

- Execute every normative known-answer vector for empty, partial-block, exact-block, multi-block, large-message, empty-AAD, non-empty-AAD, and tag-failure cases.
- Differential-test QuicFuscate against the pinned independent implementation over randomized keys, nonces, AAD lengths, payload lengths, packet numbers, batch shapes, and in-place aliasing cases.
- Prove scalar and every SIMD backend byte-identical to the canonical implementation.
- Prove AEGIS L/X4/X8 output identity where width backends claim one product family.
- Prove forgery rejection after mutations in ciphertext, tag, AAD, nonce, key, packet number, and length.
- Prove exact key, nonce, tag, counter, and buffer-length bounds in debug and release.
- Run property tests, corpus regression, fuzzing, sanitizer lanes, Miri-compatible safe boundaries, and native ISA negative tests without vacuous feature skips.

### Security and Side-Channel Gate

- TODO-681 must close the algorithm-relevant unsafe, native ISA, sanitizer, erasure, and side-channel boundaries before promotion.
- No open Critical or High finding may remain in the selected algorithm, key schedule, nonce derivation, tag verification, dispatch, or packet binding.
- Secret-dependent table lookup, branch, address, allocation, log, panic, or error-class behavior is disqualifying unless removed or isolated outside the selected production path.
- Measure timing distributions for valid packets and controlled failures using a statistically defensible constant-time harness on every native target class.
- Verify zeroization ownership for retained keys and states without claiming compiler-level erasure beyond the evidence.
- Verify nonce uniqueness and the QUIC 62-bit packet-number boundary under key updates, migration, reordering, retransmission, and circuit reuse.
- Keep authentication-failure behavior algorithm-independent enough that negotiation does not create a remote oracle.

### Auditability and Supply Chain Gate

- Record production lines of code, unsafe function count, architecture-specific backend count, transitive dependencies, build scripts, native code, licenses, maintenance cadence, and independent review coverage for each candidate.
- Minimize the public contract to two product-family identifiers. Internal width or ISA variants must not leak into protocol or operator configuration.
- Pin all external implementation versions and source provenance reproducibly.
- Add SBOM, dependency-policy, and source-release coverage for any new provider.
- Reject an upstream dependency that requires an uncontrolled native download, opaque generated binary, unsupported license, or unreproducible build.

## Performance Evidence Program

### Measured Paths

1. Canonical primitive seal/open.
2. Static `PacketAeadSeal` and `PacketAeadOpen` dispatch.
3. Dynamic rustls `PacketKey` standards baseline.
4. Complete packet encode, header protection, seal, unprotect, and open.
5. Complete `QuicFuscateConnection` send/receive with stealth off and each product stealth profile.
6. TUN to H3/MASQUE to TUN single-hop traffic.
7. TODO-886 one-hop, two-hop, and three-hop circuits when that harness is available.
8. Key construction, key update, batch seal/open, and authentication-failure cost.

### Payload and Batch Matrix

- Payload bytes: 0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 128, 256, 512, 1024, 1200, 1280, 1350, 1400, confirmed-PMTU maximum, 4096, 8192, 16384, and 65536 where the path supports it.
- Batch counts: 1, 2, 4, 8, 16, 32, 64, and the actual UDP batch sizes used by the runtime.
- AAD shapes: minimum short header, long-header reference, maximal supported header, and boundary variations.
- Traffic mixes: 64-byte interactive, 512-byte mixed, 1200 to 1400-byte VPN saturation, and realistic bidirectional application traces.

### Native Hardware Matrix

- Apple ARM64 with AES and NEON.
- Linux ARM64 server hardware matching the supported deployment class.
- x86_64 AES-NI without VAES.
- x86_64 AVX2 plus AES-NI.
- x86_64 VAES/VPCLMUL and wide-vector backend where supported.
- Windows x86_64 native execution.
- Portable fallback behavior on a target without the preferred acceleration, if that target remains supported.

Cross-compilation proves compilation only. It never substitutes for native correctness, dispatch, timing, or performance evidence.

### Metrics and Experimental Control

- Median, p95, p99, standard deviation, coefficient of variation, and confidence interval.
- Nanoseconds per packet, cycles per byte, packets per second, GiB/s, CPU time, wall time, allocations, copied bytes, instructions, branches, cache misses, and binary-size delta.
- End-to-end goodput, latency, jitter, packet loss, retransmission, FEC overhead, CPU percentage, memory pressure, and energy where the host exposes a stable counter.
- Exact commit, dirty-state hash, compiler, target, features, optimization flags, CPU model, microcode, OS, governor/power mode, affinity, sample size, warmup, measurement duration, and background-load check.
- Interleaved candidate order, repeated independent runs, bounded noise thresholds, and raw status-bearing artifacts for every requested matrix cell.
- A benchmark cell that cannot run is `UNAVAILABLE` or `SKIP` with a bounded reason, never PASS.

## Winner Decision Rule

1. Disqualify any candidate that misses a mandatory correctness, security, side-channel, portability, or reproducibility gate.
2. Compare the remaining candidates first on complete live packet and VPN paths at 1200 to 1400 bytes, then on tail latency and interactive traffic, then on primitive throughput.
3. A performance winner must improve the cross-platform production-path geometric mean by at least 10 percent over the other candidate and must not regress any Tier-1 accelerated platform by more than 5 percent.
4. The winner must also improve or remain within 5 percent of the standard AES-GCM VPN path on every Tier-1 platform. A primitive win cannot excuse an end-to-end loss.
5. If candidates are within the decision margin, choose the candidate with the smaller audited runtime surface, stronger independent implementation ecosystem, clearer public specification, simpler dispatch, and lower supply-chain cost.
6. Publish one decision with exact evidence, rejected-alternative rationale, limitations, and rollback criteria in the existing canonical documentation and completed task detail.
7. If neither candidate clears every mandatory gate, keep standard AES-GCM as the effective default and leave this task BLOCKED. Never force the requested outcome by weakening a gate.

## Implementation Plan

1. Reconcile TODO-104, TODO-112, TODO-393, TODO-395, TODO-500, TODO-582, TODO-681, current source, current benchmark scripts, and current documentation.
2. Pin primary specifications, vectors, independent implementations, and cryptanalysis references.
3. Make the correctness/differential harness symmetric across AEGIS and MORUS.
4. Add the actual rustls standard baseline from TODO-883 to every relevant benchmark group.
5. Extend artifacts so every candidate/path/payload/batch/platform cell has identity, status, command, environment, and metrics.
6. Execute native correctness and performance matrices with controlled repeated runs.
7. Execute side-channel and unsafe proof lanes.
8. Apply the winner decision rule without changing the rule after seeing results.
9. Freeze exactly one advanced product-default family identifier for TODO-885.
10. Update canonical docs and task evidence in one pass.

## Acceptance Criteria

- AEGIS and MORUS use symmetric correctness, security, auditability, and performance gates.
- Historical Omega MORUS evidence is retained, reproduced or explicitly invalidated on the current revision, and no longer overstated as live-path proof.
- Both candidates have normative vectors and an independent differential oracle.
- Every retained SIMD backend has native execution evidence or is excluded from the selected runtime policy.
- TODO-681 has no selected-algorithm Critical/High blocker at promotion time.
- The actual rustls AES-GCM path is present in the comparison.
- Complete packet, connection, TUN/MASQUE, and available multi-hop paths are measured.
- Raw artifacts are reproducible and status-bearing.
- Exactly one qualified family is selected, or the task remains honestly blocked with standards mode unchanged.
- The selected name is a QuicFuscate advanced product default, never misrepresented as a TLS/QUIC standard.
- TODO-885 receives a frozen algorithm identifier, exact key/nonce/tag sizes, selected provider/backend policy, hardware fallback policy, and measured rollback thresholds.

## Primary Files and Owners

- `crates/qf-crypto/src/lib.rs`
- `crates/qf-crypto/src/aegis.rs`
- `crates/qf-crypto/src/morus.rs`
- `crates/qf-crypto/src/aead.rs`
- `crates/qf-crypto/src/tests.rs`
- `crates/qf-cpu/src/planner.rs`
- `src/qftls.rs`
- `src/transport/packet.rs`
- `examples/crypto_backend_bench.rs`
- `scripts/benchmarks/ci_regression.rs`
- `scripts/benchmarks/suites/bench-retained-crypto-backends.sh`
- `scripts/tests/rust/rt-baseline-oracles.rs`
- `scripts/tests/rust/rt-property-suite.rs`
- `scripts/tests/rust/rt-security-suite.rs`
- `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`

## Out of Scope

- Wire negotiation and runtime promotion, owned by TODO-885.
- Claiming IETF standardization.
- Choosing a winner from architecture preference or one host.
- Removing the non-winning family before compatibility and evidence-retention policy is decided.

## Deviations

- **Miri full qf-crypto suite on Omega (2026-08-23):** after fixing the MORUS scalar-path Round 3 message-XOR bug (commit `39e0578`), the complete qf-crypto test suite passes under Miri on Omega (aarch64 Linux, nightly): **151/151 passed, 0 failed, 0 UB findings**. The previous 33/33 subset (TODO-898) did not include the CAESAR MORUS-1280-128 official test vectors that exposed the scalar-path mismatch. Miri also exposed the brain-histogram NEON dispatch issue (fixed with `cfg!(miri)` guards). Native `cargo test --all-features --lib` on Omega: **1793/1793 passed**. Strict Clippy `-D warnings` under both `--features rust-tests` and `--all-features` passes clean. Fuzz contract and 7/7 fuzz targets pass.
- **Latent MORUS scalar-path bug found and fixed (2026-08-23, commit `39e0578`):** the scalar fallback in `Morus1280State::update()` Round 3 omitted the message-block XOR (`^m`) present in all SIMD backends. This produced wrong ciphertext and tags on any scalar-fallback platform. Native tests never caught it because aarch64 always dispatches to NEON and x86_64 always dispatches to SSE2+. This is a correctness regression that would have affected any future CPU without SIMD or any `cfg(miri)` build.

## ARM64 (aarch64) Criterion Cell — Omega, 2026-09-19

Single-core ARM64 Linux (NEON), `cargo bench --bench ci_regression --features benches`,
warm-up 3 s, measurement 10 s, 100 samples. Data-AEAD throughput (steady-state):

| Workload | MORUS-1280-128 | AEGIS-128L | AEGIS-128X4 | AEGIS-128X8 |
|---|---|---|---|---|
| seal 64B | 133.7 MiB/s | 91.0 | 88.6 | 86.7 |
| seal 1024B | 494.5 | 288.9 | 283.9 | 278.5 |
| seal 8192B | 1.574 GiB/s | 834.3 | 844.4 | 838.1 |
| open 64B | 127.5 | 87.5 | 87.4 | 87.6 |
| open 1024B | 478.7 | 280.7 | 280.8 | 281.9 |
| open 8192B | 1.562 GiB/s | 861.9 | 836.3 | 838.8 |

Baseline packet protection (full rustls standard 1-RTT path incl. header):
AES-128-GCM 63.3/80.5 MiB/s (1024B/1400B), AES-256-GCM 63.2/78.7 MiB/s.

Observations:

- MORUS leads AEGIS by ~1.7-1.9x across packet-relevant sizes on this ARM64 core; both
  families exceed the standard AES-GCM packet path by ~4.4x at 1024B.
- Small-payload batch-open outliers observed: `aegis128x8 batch8_open 64B` at 43.6 MiB/s
  (~half of siblings) and `morus1280 batch8_open 64B` at 63.3 vs 133.3 seal. Worth a
  micro-check whether batch-open has a per-call penalty for short payloads.
  RESOLVED 2026-09-19: re-measurement on the same Omega binary shows
  `aegis128x8 batch8_open 64B` at 90.1 MiB/s (criterion reports +106% vs the
  stale baseline); a second ARM64 witness (Apple Silicon) shows open/seal
  symmetry within ~7% (193.4 vs 208.0 MiB/s). The outlier was measurement
  noise on the single-core VM, not a code defect - the batch-open wrapper and
  X8 decrypt loop are structurally symmetric with their seal counterparts.
- Single-core VM; numbers are relative evidence, not absolute production rates.

This fills the aarch64 cell. Cross-platform matrix now has ARM64 data; remaining gates
(x86_64 second witness, side-channel, packet-capture, interop) still open per plan.

## Split remaining work (2026-09-21, no implementation)

- Winner freeze from the existing ARM cells is blocked. TODO-1028 must not
  freeze a family from those cells. The same-API bakeoff is TODO-1032 through
  TODO-1044. The freeze is TODO-1044.
- The Omega rustls row is a full 1-RTT packet path including header
  protection; the AEGIS/MORUS rows are data-AEAD primitives. Those two rows
  must not be treated as a same-API speed verdict.
- TODO-885 packet-capture wire evidence is TODO-1029.
- Product default is rustls AES-GCM (TODO-1033), independent of the bakeoff.
- TODO-1028 refuse is recorded. TODO-1044 picks opt-in S-AEGIS behind `advanced-aead` and does not promote a universal default from these cells.
