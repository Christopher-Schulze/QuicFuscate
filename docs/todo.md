# QuicFuscate Task Tracker

## Active

### TODO-884 - Produce decision-grade AEGIS versus MORUS default evidence
- Local correctness reconciliation is active against the pinned CFRG AEGIS-128L vectors and the official CAESAR MORUS-1280-128 reference. No advanced family is promoted or enabled by this work. The standard AES-GCM baseline remains the live rollback path.
- Detail: `docs/todo/todo-884-aegis-morus-default-evidence.md`

## Blocked

### TODO-884 - Produce decision-grade AEGIS versus MORUS default evidence [!] paused for TODO-893
- Local correctness reconciliation is active against the pinned CFRG AEGIS-128L vectors and the official CAESAR MORUS-1280-128 reference. No advanced family is promoted or enabled by this work. The standard AES-GCM baseline remains the live rollback path. Paused for TODO-893 per TASK lifecycle - exactly one Active.
- Detail: `docs/todo/todo-884-aegis-morus-default-evidence.md`

## Blocked


### TODO-883 - Prove and reconcile the live standard QUIC packet-protection baseline
- The local runtime baseline is implemented and verified: typed per-level owners, actual rustls suite capture, persona-ordered provider projection, fail-closed 0-RTT, low-cardinality telemetry, diagnostics, live ClientHello/handshake coverage, and ring benchmarks. Final acceptance is blocked only by native hosted Linux x86_64 and Windows execution plus packet-capture evidence unavailable on this macOS host. No advanced family is promoted by TODO-883; authenticated private activation is separately owned by TODO-885 and is locally covered after its control-boundary gates.
- Detail: `docs/todo/todo-883-live-quic-packet-protection-baseline.md`

### TODO-886 - Implement bounded N-hop MASQUE VPN circuits
- Local implementation, deterministic tests, documentation, desktop checks without visual changes, Tauri validation, and the complete all-feature library suite are green. The two-hop MTU repair now advertises each hop's configured QUIC payload ceiling and clamps outgoing packetization to the authenticated peer ceiling, with focused parser and version-restart regressions. Final acceptance is blocked only by the fresh privileged Linux 1/2/3-hop namespace, chaos, packet-capture and performance execution plus native macOS/Windows-to-Linux proof, which this macOS host cannot provide. The existing approved Rotate control remains unchanged.
- Detail: `docs/todo/todo-886-n-hop-masque-vpn-circuits.md`

### TODO-804 - Make Omega proof checkout ownership singular and inspectable
- Read-only preflight infrastructure is complete in commit `47905c3`. Historical evidence `scripts/out/audits/omega-proof-ownership-20260808T195315Z/ownership.json` was fail-closed `UNAVAILABLE`: two checkouts, 43,722 untracked paths in SOFTWARE, 20 tracked mods + missing object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1` in CODE, PID `1363976`. **2026-08-20 authorized cleanup (user: nur auf Omega):** service `quicfuscate-todo528-dc72c84` stopped, TUN `qf528srv` removed, `candidate-*`/`runtime-*`/`*.tar.gz`/`QuicFuscate-verify-dc4de71` deleted (6.5G freed), `CODE/QuicFuscate` re-cloned as singular `~/TESTING/QuicFuscate` `main 2afac5ca` clean, no backups. Current `ownership.json` is stale; fresh proof requires re-running `verify-omega-proof-ownership` against new TESTING path. No local doc history rewritten.
- Detail: `docs/todo/todo-804-omega-proof-checkout-ownership.md`
### TODO-548 - Install and prove the managed macOS PF kill-switch anchor
- Source implementation, installer ownership, hermetic fixture gates, local Rust gates, and docs are complete. Blocked only by the required authorized root macOS PF packet/coexistence/crash/uninstall proof; no privileged PF state was mutated on this ARM64 session. Frontend paths remain untouched.
- Detail: `docs/todo/todo-548-macos-pf-killswitch-native-proof.md`

### TODO-562 - Refactor single-crate monolith into Cargo workspace sub-crates
- Blocked only for final acceptance and external platform/CI gates. The original 16-module SCC is fully eliminated: QFTLS owns outgoing CRYPTO streams, transport installs complete TLS packet-key bundles through `QuicTlsKeyInstaller`, and the only TLS module direction is `transport -> qftls`. The workspace contains thirty-five independently buildable backend leaves plus the root package. Published post-push evidence at `c379057f7e9b63a5254c3a40b72c87a56664e0b0` records `36` packages, `336` Rust files, `207,678` source lines, `106` module edges, `123` workspace dependency edges, zero strongly connected components, and no protected frontend/Tauri changes; the complete serial root all-feature library passes `1,657/1,657`.
- Current CI acceptance repair clears all eight qf-cpu x86_64 diagnostics and the separate root `CompressionStrategy::BtOpt` feature-ownership warning. The exact workspace `unsafe_rust` all-target Clippy lane now passes; qf-cpu passes `87/87`, the root fallback suite `1,646/1,646`, and the root all-feature suite `1,657/1,657`.
- The Linux TUN provisioning negative harness combines its network namespace with a private mount namespace and isolated `/run`. After the owned nftables verifier was corrected, both ordinary setup failure and the adversarial missing-interface race now prove complete rollback with no durable firewall-owner residue; private runtime isolation still prevents a failed proof from contaminating later native traffic checks.
- The ChaCha20 x16 AVX-512 parity target now iterates returned blocks directly while preserving wrapping counter coverage. The exact workspace all-target `rust-tests` Clippy lane passes with warnings denied, closing hosted Clippy job `93609917539` without suppressions.
- The `io_uring` profile's seven hosted Clippy diagnostics are structurally closed without suppressions: client/server disposition loops iterate exact slots, inbound receive/event ownership is bundled, server match/teardown control flow is direct, and `BatchSendResult` now provides the standard `is_empty` companion to `len`. The exact local profile is warning-clean; native Linux confirmation is delegated to hosted CI because the installed cross target lacks `x86_64-linux-gnu-gcc`.
- The engine reload regression now uses a stable PID-scoped fixture name instead of embedding Rust's `::`-delimited test thread name in a file path. The focused reload test passes locally; hosted Windows remains the authoritative confirmation for the previously observed error 123.
- The x86 ACK-merge parity target now pins both inference boundaries explicitly: its scalar output is `Vec<(u64, u64)>` and the AVX-512 generator is `StdRng`. The exact local `tun-tests,rust-tests` profile is warning-clean; hosted x86 remains the authoritative cfg-gated confirmation.
- Windows resolver fixtures now identify file objects by volume serial plus 64-bit file index, matching Unix `dev+ino` semantics, instead of treating legitimate size and timestamp changes as object replacement. The portable resolver suite passes `15/15`; the Windows-specific kernel boundary type-checks, while hosted Windows owns runtime confirmation.
- The ChaCha20 x4 parity target now addresses the canonical `optimize::simd::crypto` owner for both dispatch override and block generation. The compatibility `optimize::crypto` surface remains intentionally narrow; hosted x86 owns execution confirmation.
- The runtime-owned io_uring worker now observes ready completion depth with the non-consuming `CompletionQueue::len` contract. Its former `count` call acknowledged every ready CQE before disposition reaping, which made the worker quarantine a successful batch as `0/N`; direct sender semantics and the Linux kernel regression remain unchanged. The exact local io_uring Clippy profile, formatting, documentation truth, and runtime guardrails pass, while hosted Linux owns kernel-backed confirmation.
- The x86 AVX2 TLS-padding helper now owns its intrinsic imports at the same test, rust-tests, and benches feature boundary as the helper itself. This closes the benches-only missing-symbol failure without widening production exports or changing dispatch and padding behavior; the exact local benches Clippy profile passes, while hosted x86 owns cfg-gated confirmation.
- The nftables set-rule verifier now preserves exact prefix, set-member, and action matching while admitting legitimate trailing rule metadata such as QuicFuscate's mandatory owner comment. Native PTB evidence proved that the former exact suffix comparison rejected the runtime's own correctly owned rule; focused qf-firewall regressions and strict leaf Clippy pass.
- The native Linux traffic job now normalizes ownership of every retained TUN provisioning evidence tree immediately after the privileged harness, including failure paths. The upload action can traverse root-created routing records without weakening the harness's runtime permissions or discarding fail-closed evidence.
- The multi-client native harness now honors the authenticated client-assignment contract: only the server receives address, prefix, and MTU flags, while each standalone client opens its TUN from the validated assignment and still proves the exact `.2/.3/.4` dual-stack allocation. The PTB phase preserves its 1472-byte carrier and temporarily raises only the client TUN to 1500 around the split-boundary probe; the server TUN remains 1280. Bash syntax, ShellCheck, documentation truth, runtime guardrails, diff hygiene, and protected-path isolation pass; hosted Linux owns the privileged rerun.
- Core now binds the client connection generation to the same authenticated CONNECT-UDP request as the QKey in pushed commit `0afb88a`. A Core header-contract regression and a paired late-server-init H3 full-drain regression pass, exact default workspace Clippy is warning-clean, and hosted Linux owns the process-level assignment rerun.
- qf-transport-udp now owns its Linux-only logging and socket-address dependencies. Native x86_64-Linux leaf Clippy, `11/11` leaf tests, feature taxonomy, and strict workspace Clippy pass; this removes the shared undeclared-dependency blocker from Linux, fuzz, AMX, and hosted feature lanes.
- qf-memory-pool's Winsock calls now have complete windows-sys feature ownership and explicit error-reading safety. Windows-MSVC all-target/all-feature Clippy, `23/23` executable leaf tests, and strict workspace Clippy pass; native Windows execution remains external.
- qf-crypto now clears all ten x86_64 diagnostics from hosted Clippy job `93544957297` without lint suppression. Native x86_64-Linux leaf Clippy, `140/140` leaf tests, the exact workspace default and `unsafe_rust,rust-tests` all-target lanes, and strict all-feature workspace Clippy pass.
- qf-transport-batch now gives its Linux receive-timeout conversion an explicit `std::io::Result<libc::timespec>` boundary, keeps seconds checked against `time_t`, and casts bounded nanoseconds infallibly into signed Linux `c_long`. Focused Linux-x86 leaf Clippy, the exact default and `unsafe_rust,rust-tests` workspace lanes, `7/7` leaf tests, and strict all-feature workspace Clippy pass.
- qf-simd removes eight unreferenced duplicate x86 implementations, limits the retained SSE4.2 safety regression to tests, corrects the AArch64 SVE2 fallback gate, and makes the active x86 owners warning-clean. Linux-x86 and Windows-x86 all-target/all-feature leaf Clippy, `61/61` executable leaf tests, the exact default and `unsafe_rust,rust-tests` workspace lanes, and strict all-feature workspace Clippy pass. Native x86 execution remains hosted.
- The five atomic retry loops now use Rust's current `try_update` API in qf-telemetry, qf-instrumentation, qf-memory-pool, and the two root Stealth owners. Nightly 1.99 checks pass with warnings denied, affected leaf tests pass `44/44`, the serial root all-feature suite passes `1,657/1,657`, and all three workspace Clippy contracts pass.
- qf-fec's AVX2 nibble-table setup is warning-clean on Linux x86_64 after removing two type-redundant casts. Native Linux-x86 all-target/all-feature leaf Clippy, qf-fec tests `82/82`, all five feature-taxonomy profiles, and all three workspace Clippy contracts pass.
- qf-transport-batch now compiles its test-only Linux metrics and platform acceleration alias only where their BatchProcessor callers exist. The exact warning-denied Linux installer profile, Windows all-target/all-feature Clippy, `7/7` leaf tests, and all three workspace Clippy contracts pass.
- Root AES-NI, VAES, AVX2/FMA, and AVX-512/FMA helpers no longer combine `#[target_feature]` with the compiler-forbidden `#[inline(always)]`. The serial root suite passes `1,657/1,657`, all three workspace Clippy contracts pass, and the complete local Windows cross-build remains blocked before product code by the missing C sysroot.
- Root x86 pattern injectors now share the test/rust-tests boundary of their only caller, checked-range helper, and AArch64 peers. The Linux missing-helper failure is structurally removed; `1,657/1,657` root tests and all three workspace Clippy contracts pass.
- Client `batch_refs` now compiles only with its `io_uring` consumer. Linux profiles without io_uring retain the sendmmsg/socket fallback without the warning; `1,657/1,657` root tests and all three workspace Clippy contracts pass.
- Wintun startup resources now transfer out of the Drop owner through `Option::take`, restore completely before incomplete-owner rollback, and clone locked cleanup snapshots. The Windows `E0509`, `E0507`, and unnecessary-mut diagnostics are structurally closed; hosted Windows compilation remains pending publication.
- The three remaining Windows warning owners from CI job `93565626522` now share their real target surfaces: privilege transition formatting is Unix/test-only, the root GF(2^8) table compatibility export is test-only, and the shared TUN `IpAddr` import is Linux/macOS-only. qf-privilege passes `23/23`, the root suite passes `1,657/1,657`, and all three workspace Clippy contracts pass; hosted Windows confirmation remains pending publication.
- The separate fuzz lock now records qf-transport-udp's direct `log` and `socket2` edges without package-version churn. Locked Nightly metadata, the Nightly fuzz-workspace all-target check, and the complete six-target fuzz contract audit pass; hosted Ubuntu sanitizer execution remains pending publication.
- The `unsafe_rust` optimize surface now limits its x86 intrinsic import to the test-owned injector and removes a stale Linux call to the eliminated root NUMA module from the test-only UnsafeMemoryPool. Exact local `unsafe_rust` all-target Clippy and `1,657/1,657` root tests pass; hosted Linux x86 confirmation remains pending publication.
- The root VBMI2 compatibility wrapper now compiles only for x86 unit tests, matching both of its callers while qf-fec retains the production kernel and runtime dispatch. Focused GF16 tests pass `6/6` and exact local `unsafe_rust` all-target Clippy is green; hosted Linux x86 confirmation remains pending publication.
- Root firewall compatibility now exposes only the live owner-verifying nftables API. Routing's unowned ruleset adapter is unit-test-only, and iptables setup uses direct typed error propagation. Focused routing tests pass `24/24`, exact local `unsafe_rust` all-target Clippy is green, and runtime guardrails report zero findings; hosted Linux x86 confirmation remains pending publication.
- ChaCha20 SIMD counter lanes now use warning-clean indexed iteration and consistent wrapping arithmetic across AVX-512, x86 x4, NEON, and scalar paths. Four focused tests cover x4 and x16 wraparound parity, exact local `unsafe_rust` all-target Clippy is green, and runtime guardrails report zero findings; hosted Linux x86 confirmation remains pending publication.
- The generated PF ruleset helper now compiles only for macOS unit tests, matching its sole caller instead of leaking dead test code into Linux feature profiles. Focused routing tests pass `24/24` and exact local `unsafe_rust` all-target Clippy is green; hosted Linux x86 confirmation remains pending publication.
- The test/rust-tests matrix transpose now uses one flat AVX2 eligibility guard and direct vector iteration for 8x8 loads/stores. Exact local `internal_wiedemann,unsafe_rust` and `test-suite` all-target Clippy profiles pass, and runtime guardrails report zero findings; hosted Linux x86 confirmation remains pending publication.
- The root test-only unsafe module no longer carries orphan duplicate GF(2^8), XOR, and entropy SIMD implementations. qf-simd and qf-cpu remain the sole runtime owners; focused Unsafe tests pass `31/31`, both affected all-target feature profiles, strict all-feature workspace Clippy, documentation truth, and zero-finding runtime guardrails pass. Hosted Linux x86 confirmation remains pending publication.
- The Linux io_uring aggregate payload helper now gives `Iterator::try_fold` its required mutable iterator binding. Its four callers, checked overflow, admission bounds, and send semantics are unchanged; local exact-profile Clippy, strict workspace Clippy, documentation truth, and zero-finding runtime guardrails pass, while hosted Ubuntu owns authoritative compilation of the cfg-gated line.
- qf-simd now restores the omitted x86 GF backend counters: AVX-512 GFNI increments `FEC_GFNI_OPS`, AVX2 increments `FEC_AVX2_OPS`, and the Ubuntu self-check follows the actual dispatcher instead of expecting a nonexistent SSSE3 path. Leaf tests pass `61/61`; Linux-x86 leaf Clippy, strict workspace Clippy, documentation truth, and zero-finding runtime guardrails pass. Hosted Ubuntu owns runtime confirmation after the local disk guard stopped the root integration rebuild.
- The fuzz Nightly preflight no longer pipes `rustup` into early-exit `grep -q` under `pipefail`, which produced status `141` and falsely reported the installed compiler as unavailable. The runner captures the complete version output before validation, and the fuzz contract audit rejects the former SIGPIPE-prone probe. Bash syntax, the corrected preflight, the six-target fuzz contract, and diff hygiene pass; hosted sanitizer execution remains the authoritative runtime gate.
- The x86 GHASH deterministic override now shares the `rust-tests` feature boundary of its registered integration test, and the ChaCha20 x16 parity target calls the canonical SIMD owner instead of a namespace that exports only x4. The exact `tun-tests,rust-tests` all-target profile, Linux-x86 qf-crypto Clippy, qf-crypto `140/140`, and strict workspace Clippy pass; the full local Linux-x86 root check remains blocked before product code by the missing C sysroot.
- The Linux installer service and disposable nspawn proof now retain `CAP_IPC_LOCK` through both outer bounding sets while `LimitMEMLOCK=infinity` authorizes the deferred post-drop `mlockall`. A static contract rejects either missing boundary, generated systemd defaults stay aligned with the shipped unit, and focused systemd tests pass `8/8`; the native AlmaLinux/Debian lifecycle remains hosted Linux evidence.
- Detail: `docs/todo/todo-562-workspace-crate-refactoring.md`

### TODO-681 - Audit all unsafe code in crypto primitives
- Local lifecycle implementation, 101-function safety inventory, static guardrails, checked seal lengths, the primitive QUIC 62-bit packet-number boundary, release-safe MORUS loader, and the AEGIS non-Copy/Drop state boundary are complete. Blocked only on compiler-level erasure, release/native GHASH proof, native cross-ISA/sanitizer/Miri lanes, and external platform evidence. The current continuation passes qf-crypto `137/137` under `--all-features`, strict qf-crypto Clippy, the AEAD property suite `12/12`, the workspace `rust-tests` matrix, strict check/Clippy, and release verification; no storage-floor blocker remains on this host. Historical commit `3ebb84d96eb6f050682ca6a513704d2c1ac14f5f` remains the prior pushed checkpoint.
- Detail: `docs/todo/todo-681-crypto-unsafe-audit.md`

### TODO-680 - Audit unsafe blocks in optimize/brain, optimize/transport, optimize/stealth, and related hot paths
- Source remediation and static guardrail wiring are complete for bitmap ranges, pattern positions and lengths, SVE2 Base64 bounds, packet-number lengths, VNNI chunking, percentile validation, test-only Linux RPS inputs, and local safety contracts. The guarded Optimize release suite now passes `5/5` suite records with `43` executed tests and `0` failures in `scripts/out/tests/test-optimization-20260810T-backend-continuation-fast/results.json`; the previous storage-floor gap is closed. TODO-837, TODO-836, and TODO-689 are archived; native x86/BMI2, AVX10/VNNI, SVE2, Linux, sanitizer, and Miri evidence remains unavailable and unclaimed.
- Detail: `docs/todo/todo-680-optimize-brain-transport-stealth-unsafe.md`

### TODO-678 - Audit and harden all unsafe code in optimize/unsafe.rs and optimize/parts/memory_pool.rs
- All implementation boundaries are closed by TODO-826 through TODO-833 on ARM64 macOS, with their focused tests, library checks, strict Clippy, formatting, and diff evidence recorded in completed details. The umbrella parent remains blocked only because the pinned Rust `1.97.1-aarch64-apple-darwin` toolchain has no Miri component and native Linux/Windows/ISA evidence is unavailable; no external proof is inferred. Boundary documentation is pushed as `15838f9f1c06706debf87dae183e59145998b062` with exact local/remote parity.
- Detail: `docs/todo/todo-678-optimize-unsafe-memory-pool-audit.md`

### TODO-759 - Make Graphify extraction and relationship evidence complete or fail closed
- Audit tooling and evidence contract are implemented and locally verified, but the result is explicitly `BLOCKED`: semantic extraction is unavailable, raw AST identity has dangling/duplicate relationships, 6 detected files have no AST nodes, normalized evidence retains 350 ambiguous and 1,465 unresolved endpoints, and the legacy client-scoped Graphify output is stale. The latest post-push fail-closed manifest is `scripts/out/audits/graphify-20260805T080752Z/graphify-evidence.json`; the completeness validator reports `graphify=BLOCKED` and the current detection scope is 728 files / 1,263,324 words. Commit `a5f1896` and the subsequent scope-refresh commit `940e252` remain pushed to `origin/main`; the current audit refresh is evidence-only and does not close TODO-759.
- Detail: `docs/todo/todo-759-graphify-extraction-relationship-contract.md`

### TODO-756 - Make frontend E2E browser prerequisites explicit and fail closed
- Local implementation is complete and pushed in commit `9a5e3c6`: exact Playwright `1.58.2` ownership, shared fail-fast preflight, package-owned install path, CI alignment, and full Admin/Desktop browser execution pass 70/70 plus 23/23. Empty-cache entrypoints return one actionable `UNAVAILABLE` result before preview-server startup. Hosted CI execution and the normal installer path on this Node 26.6 host remain external/open evidence.
- Detail: `docs/todo/todo-756-frontend-e2e-browser-prerequisites.md`

### TODO-805 - Reconcile frontend dependency security advisories
- Local implementation is complete and pushed in commit `e6e0684`: the current 35-advisory Bun baseline is mapped and resolved, the locked graph is reproducible, the frontend security gate is fail-closed and wired into CI/release, Admin/Desktop checks/builds/unit tests and bounded dev-server probes pass, and the locked ARM64 macOS Tauri host lane passes 41/41. Hosted CI, full Chromium E2E, Linux/Windows packaging, updater signing, and tagged publication remain external gates.
- Detail: `docs/todo/todo-805-frontend-dependency-advisories.md`

### TODO-755 - Remediate Tauri dependency advisories and lockfile drift
- Local implementation is complete and pushed in commit `1048f7e`: the separately locked Tauri graph has zero vulnerabilities, an exact 19-warning reverse-path inventory, a dedicated locked Cargo Deny policy, CI/release gates, and ARM64 macOS Tauri check/Clippy/tests pass with 41/41 tests. Hosted CI, Linux/Windows packaging, updater signing, and tagged publication remain external release gates.
- Detail: `docs/todo/todo-755-tauri-dependency-advisories.md`

### TODO-749 - Make CI and release dependency resolution reproducible
- Local implementation is complete in pushed commit `cba058e`: source-owned Bun/Rust/tool versions, frozen Bun installs, locked Cargo/Tauri operations, exact release-tool versions, reconciled Tauri lockfile, and a passing two-run dependency reproducibility gate. Local ARM64 macOS Tauri check/Clippy/tests pass with 41/41 tests. GitHub-hosted CI, Linux/Windows packaging, updater signing, and tagged publication remain external gates.
- Detail: `docs/todo/todo-749-reproducible-dependency-resolution.md`

### TODO-734 - Make feature-gated test targets prove the requested feature lane
- Local implementation is complete and pushed in commit `562c2ca`: all 64 crate-level feature-gated test sources have exact Cargo requirements, target-specific runner propagation, named non-vacuity checks, explicit Linux-only and architecture skips, and negative missing-feature fixtures. Native Linux io_uring/kernel-hotpath, AF_XDP, and CI-hosted matrix evidence remain open, so the task is blocked at the external gate.
- Detail: `docs/todo/todo-734-feature-gated-test-target-contract.md`

### TODO-624 - macOS pf anchor activation and kill-switch rollback contract
- Blocked after the client rollback implementation, focused tests, script syntax/help checks, format, diff, and all-target validation pass; the read-only privileged macOS PF proof cannot run in this session because the process is not root, and no shared PF mutation is authorized.
- Detail: `docs/todo/todo-624-macos-pf-anchor-never-referenced.md`

### TODO-623 - Linux DNS restore leaves written resolv.conf behind when no original file existed
- Blocked after the local implementation, focused tests, all-target check, and strict Clippy passed; the native Linux platform gate cannot run because the macOS host lacks a Linux C sysroot and the configured Omega SSH path is unavailable.
- Detail: `docs/todo/todo-623-linux-dns-restore-leaves-resolv-conf.md`

### TODO-516 - Implement mlock/mlockall for key material and memory pools
- Local MemoryPool lock ownership, zeroization, and munlock release paths are implemented and focused gates pass; the post-change native Omega proof, complete workspace gates, and remote push remain blocked by the recorded external and baseline failures.
- Detail: `docs/todo/todo-516-memory-locking-mlock-mlockall.md`

### TODO-607 - Routing teardown leaves host forwarding state and platform-owned routing state behind
- Paused after TODO-687's build prerequisite: commit `cec9c9c` reached the native Linux lifecycle gate, but graceful `RoutingManager::teardown()` reuses stale-owner recovery and rejects its own active PID `3272`, leaving `/run/quicfuscate/routing/7174756e30.json`. The harness now adds direct forwarding, TUN-link, durable-owner, and selected-firewall residue assertions before namespace cleanup; execution of the privileged Linux lifecycle gate remains open.
- Detail: `docs/todo/todo-607-routing-teardown-incomplete.md`

### TODO-754 - Make exhaustive audit coverage and TODO register truth machine-checkable
- Current detail-corpus reconciliation refreshed 2026-08-07: the post-push validator at `ea528d9` accounts for 777 tracker entries, 371/371 current details, 441 archived details, 36 explicit archive exceptions, 991 tracked paths, 35,527 ignored paths, and zero unexpected untracked paths. Graphify remains explicitly BLOCKED; native, live, Omega, and strict non-pass findings remain open. The legacy `audit-todo-consistency.sh` scanned all 371 details but returned 75 obsolete-status violations; the canonical completeness validator is the passing structural gate.
- Paused for TODO-730 and TODO-759: the final register/path validator passes structural integrity with tracker `776`, current details `375/375`, archived details `436`, `991` tracked, `26,183` ignored, `0` unexpected untracked, and `27,174` accounted paths; Graphify is retained as explicit `BLOCKED`, not promoted to green. The strict comprehensive runner at `/tmp/quicfuscate-audit-current-20260806.8UshkJ` completed all 38 result objects but returned `FAIL` with 5 critical classifications, 10 warnings, 3 failed checks, and 2 unavailable checks. Strict runtime Clippy, all-target quality Clippy, runtime guardrails, native PowerShell parsing, and the AMX host lane remain explicit non-pass boundaries. The broader target, feature, Graphify, native, frontend, external-evidence, and Omega boundaries remain open.
- Detail: `docs/todo/todo-754-exhaustive-audit-coverage-register.md`

### TODO-730 - Make the comprehensive audit runner fail closed and measure real scope
- Blocked after local implementation and commit `92a05ac`; the remaining Omega checkout attribution gate is unavailable because the local SSH client fails with `No user exists for uid 501`, and GitHub push currently fails DNS resolution.
- Detail: `docs/todo/todo-730-comprehensive-audit-fail-closed.md`

## Queue
### TODO-894 - Cap EnvSnapshot per ACK in Brain send path
- EnvSnapshot::capture() per ACK (brain.rs:606) causes millions of allocs; cache one snapshot per update_state (64 pkts/10ms).
- Detail: `docs/todo/todo-894-brain-envsnapshot-per-ack.md`

### TODO-895 - Remove AesBlock Drop from hot loop
- AesBlock Drop volatile memset per temp (aegis_aes_block.rs:7-11) and HP schedule per packet (qf-crypto/lib.rs:242) - 2-4x privat-mode overhead.
- Detail: `docs/todo/todo-895-aesblock-drop-hotloop.md`

### TODO-896 - Graceful TUN EAGAIN handling
- TUN WouldBlock currently treated as hard fault (live_auth.rs:1290, runtime.rs:970) - transient backpressure kills tunnel.
- Detail: `docs/todo/todo-896-tun-eagain-graceful.md`

### TODO-897 - Fix LazyDecoder seen_seqs leak and fastpath death
- has_gaps() stays true forever after first loss (lazy.rs:136), seen_seqs never clears, ~0.5MB/s leak.
- Detail: `docs/todo/todo-897-lazydecoder-leak.md`

### TODO-898 - Fix AVX512 and SVE2 GF16 carry-less reduction
- AVX512 single fold vs 4 (galois.rs:417) and SVE2 0x000B vs 0x100B (gf16.rs:360) - dormant landmine.
- Detail: `docs/todo/todo-898-avx512-sve2-gf16-fix.md`

### TODO-899 - Multi-RHS Gauss for FEC decode under loss
- Per-byte clone (decoder8.rs:432) and matrix rebuild (decoder16.rs:327) - 10x speedup via incremental rank update.
- Detail: `docs/todo/todo-899-fec-gauss-per-byte.md`

### TODO-900 - Global lazy MTU pool, no zeroize-on-free
- Per-conn 16-64M eager pool with 64K zeroize per free (lib.rs:1019) and global mutex ledger - 99% RAM waste.
- Detail: `docs/todo/todo-900-per-connection-pool.md`

### TODO-901 - Server RX batching drain and sharding
- Single Tokio task for all clients (runtime_loop.rs:155) with single recvmsg per wakeup - 150k pps ceiling.
- Detail: `docs/todo/todo-901-server-rx-sharding.md`

### TODO-902 - io_uring TX triple-copy and channel1 fix
- Triple-copy + channel(1) + Sleep(1ms) poll (uring_batch.rs:543) - 2x throughput via zero-copy and submit_and_wait.
- Detail: `docs/todo/todo-902-iouring-tx-triple-copy.md`

### TODO-903 - Brain jitter gate and FlowShaper tuning
- Jitter gate hits ACK-only (send.rs:206) and FlowShaper uniform 1500-3000us (manager.rs:649) - adaptive tuning.
- Detail: `docs/todo/todo-903-brain-jitter-flowshaper.md`

### TODO-885 - Implement authenticated private AEAD negotiation and promote the proven default
- Keep Initial, Handshake, unauthenticated probes, and fallback traffic standards-compatible, then negotiate the TODO-884 winner only inside the authenticated encrypted control plane. Derive independent directional keys through the existing TLS exporter, bind the selection against downgrade and cross-connection reuse, switch at deterministic packet-number boundaries, and make the winner the automatic QuicFuscate-to-QuicFuscate post-auth default while retaining explicit standard-only and advanced-required modes.
- Detail: `docs/todo/todo-885-authenticated-private-aead-default.md`

## Completed

### TODO-893 - Modularize the Performance regression runner and artifact report path
- DONE. `test-performance-regression.sh` now validates `throughput,latency,memory,cpu,hotpath,simd,scalability,report` with `--only`, gates `qf_bench_preflight` and native build to `throughput/latency/hotpath/simd` only, splits the former combined `memory_cpu` into separate `memory` and `cpu` scopes with distinct `fast_profile_omits_scope` handling, implements `write_current_snapshot` as the sole `performance_current.json` writer and `run_report_scope` with explicit `PASS/SKIP/FAIL`, and emits one selection record plus one pre-execution record per canonical scope with `not_selected_by_scope` reasons. `scripts/tests/fast/test-performance-scope-contract.sh` covers help, unknown/empty/malformed/duplicate/conflict, default, each scope, combinations, and failure propagation; `CURRENT_FILE` gap is closed.
- Detail: `docs/todo/todo-893-performance-runner-granularity.md`


### TODO-892 - Modularize the FEC internal runner without collapsing proof boundaries
- DONE. `test-fec.sh` now exposes `modes,gf16,refactor,all` with legacy `--refactor`/`--refactor-only` normalization, seven ordered mode commands (`zero,light,normal,medium,strong,extreme,streaming`) with `QUICFUSCATE_FEC_INITIAL_MODE`, single GF16 command with both `QUICFUSCATE_GF16_SIMD=1`+`NIBBLE=1`, and nine lib filters + three `rg` checks under `refactor`; each scope emits explicit `PASS`/`SKIP` with `reason=not_selected_by_scope` and every selected Cargo filter proves positive test count; conflicting selectors and unknown/empty/malformed/duplicate scopes fail closed with `2`; `test-fec-all.sh --mode` vocabulary unchanged and `util-run-full-suite.sh` still invokes `test-fec.sh --refactor` once; `scripts/tests/fast/test-fec-scope-contract.sh` covers help, validation, default, each scope, combinations, legacy aliases, and failure propagation. All shells pass `bash -n` and warning-level ShellCheck.
- Detail: `docs/todo/done/todo-892-fec-runner-granularity.md`

### TODO-891 - Modularize the Optimization test runner by explicit execution scope
- DONE. `test-optimization.sh` now validates `--only batch,memory,simd,cpu,zero-copy,telemetry,integration,stress`, writes one selection record plus one pre-execution record per canonical scope, preserves unscoped full/fast command order, honors `--fast --only` as an explicit override, and fail-closes unknown/empty/malformed selections with status `2` before artifacts. `scripts/tests/fast/test-optimization-scope-contract.sh` inspects the real JSON artifact for help, skip reasons, telemetry/zero-copy/memory selection, fast omissions, and injected failure without `[OK]`. Full-suite still has exactly one scoped owner and one default invocation. Frontend/Tauri paths were not touched. Native x86/Linux/SVE2 execution remains unclaimed.
- Detail: `docs/todo/done/todo-891-optimization-runner-granularity.md`

### TODO-887 - Remove the obsolete XOR obfuscation surface
- DONE. The callerless repeating-key XOR obfuscation layer is fully removed: SIMD kernels and all architecture backends, the standalone `src/optimize/x86_sse2.rs`, three parity test targets with Cargo/suite/guardrail registrations, the dead `STEALTH_XOR` counter, test-only obfuscation-key helpers, the `CryptoMode::Xor` bench mode, and every current-truth documentation claim. Retained XOR in AEADs, header protection, FEC/Galois math, and STUN/TURN is byte-for-byte unchanged. Closure proof: serial all-feature library `1,754/1,754`, strict Clippy, formatting, guardrails `0/0`, audits green, CLI rejects `--mode xor`; two pre-existing HEAD guardrail drifts (renamed `linux-platform-gates` job, centralized memory-lock invocation) were reconciled in the same pass.
- Detail: `docs/todo/done/todo-887-remove-obsolete-xor-obfuscation.md`

### TODO-890 - Decompose remaining large Rust owners below the monolith ceiling
- DONE. Every Rust source above 1,500 physical lines was split through responsibility-owned real modules across transport, runtime, crypto, FEC, engine, server, client, interface, and the qf-cpu/qf-memory-pool/qf-audit/qf-dns/qf-telemetry/qf-simd/qf-fec/qf-privilege/qf-engine-types leaves, with stable public paths, preserved test inventories, and synchronized scripts, audits, tools, benchmarks, and canonical docs. Closure evidence: final inventory 442 Rust files with zero at or above 1,500 lines (current committed tree peaks at 1,497) and zero source-assembly `include!` calls; the serial root all-feature library passed `1,749/1,749` with one intentionally ignored native mlock test; strict root library Clippy, formatting, diff hygiene, runtime guardrails (`Critical: 0`, `Warnings: 0`), the full `rust-tests` integration matrix, and the post-authentication control-bootstrap repair with its dedicated guardrail all pass. Hosted Linux-only integration-target execution remains explicitly unclaimed.
- Detail: `docs/todo/done/todo-890-large-rust-owner-decomposition.md`

### TODO-889 - Eliminate remaining monolithic Rust files and textual module assembly
- DONE. All 29 oversized Rust files and all 48 textual `include!` assemblies were replaced by real responsibility-owned modules with narrow visibility and stable public paths. At task closure the verified tree had 370 Rust files, no file above 2,000 physical lines, zero source assembly, unchanged test inventory, green structural/API/feature/runtime/audit/release-Stealth gates, unchanged protected frontend/Tauri paths, and a final clean workspace with 12 GiB free. The current follow-on worktree contains 384 Rust files, still no file above 2,000 lines and no source assembly; current dirty and untracked paths are retained as active multi-hop/crypto work rather than retroactively folded into this historical completion snapshot.
- Detail: `docs/todo/done/todo-889-complete-rust-module-decomposition.md`

### TODO-888 - Recover local task truth after the aborted include-to-mod refactor
- DONE. The exact 457,443-byte pre-corruption tracker was reconstructed from a verified loose Git blob plus the original TODO-883 through TODO-887 patch, installed without overwrite, normalized to repository punctuation, and reconciled with the clean tracked source at `aa4e03b`. Documentation truth, audit completeness with fresh fail-closed Graphify evidence, runtime guardrails, formatting, all-feature check and strict Clippy, the 1,703-test all-feature library suite, and the complete `rust-tests` matrix pass. The failed OMP session remains intact as forensic history and no live OMP process remains.
- Detail: `docs/todo/done/todo-888-task-truth-recovery.md`

### TODO-748 - Restore the bounded `serve:codex` contract
- DONE. Admin and Desktop now build and serve their static applications through one shared Bun-owned Vite preview lifecycle with loopback-only host validation, strict ports, HTTP readiness, a 30-second bound, deterministic failure statuses, and SIGTERM-to-SIGKILL cleanup. Tauri delegates to Desktop; five real process tests and both production package paths pass without listener residue.
- Detail: `docs/todo/done/todo-748-serve-codex-contract.md`

### TODO-878 - Validate admin API responses with runtime schemas
- DONE. Web Admin now requires one of 19 named runtime schemas for every consumed JSON method/endpoint and rejects non-JSON, missing, mistyped, malformed-list, and raw-QKey-list responses before state publication. The complete suite passes 27/385, Svelte checking is clean, and the production build passes.
- Detail: `docs/todo/done/todo-878-admin-api-runtime-schemas.md`

### TODO-707 - Align CUBIC across Rust, TOML, admin, and desktop contracts
- DONE. The exact Reno/CUBIC/BBR2/BBR3 contract now spans Rust/TOML validation, one shared frontend projection, Web Admin selection and serialization, and Desktop display. qf-engine-types passes 58/58 plus strict Clippy; Shared UI passes 12/95; Web Admin passes 26/309; Desktop passes 36/442; both Svelte checks are clean.
- Detail: `docs/todo/done/todo-707-cubic-ui-config-contract.md`

### TODO-705 - Expose desktop persistence failures and provide retry semantics
- DONE. Desktop persistence now exposes typed load/save failure state, preserves dirty data until native success, serializes revisions, bounds startup and close flushes, and keeps the window visible on failed close persistence with explicit retries. The complete bounded Desktop gate passes 36/441, Svelte checking is clean, and the changed native host path passes isolated checking.
- Detail: `docs/todo/done/todo-705-desktop-persistence-error-state.md`

### TODO-753 - Make frontend unit test execution bounded and deterministic
- DONE. Both frontend package gates now use one Bun-owned 600-second process deadline around an explicit single-worker `threads` pool, preserve live diagnostics, emit heartbeats, fail with status `124`, and enforce the current inventories. Web Admin passes 26/307 in 120.45 seconds; Desktop passes 36/441 in 321.29 seconds; the real timeout negative contract and both Svelte checks pass.
- Detail: `docs/todo/done/todo-753-frontend-unit-runner-boundedness.md`

### TODO-471 - Complete WebTransport negotiation and bidirectional stream state
- DONE. Connection-local policy advertises and validates the bounded draft-16 H3 settings used by the internal cover profile; client-initiated `webtransport-h3` sessions become ready only after a final 2xx response; both roles exchange bounded opaque unidirectional and bidirectional streams with fragmented-prefix retention and fail-closed invalid transitions. Core H3/MASQUE remains the sole VPN/TUN carrier, and external draft-16 interoperability is explicitly unclaimed until the required QUIC transport parameters and reset semantics exist. Clippy Matrix run `31518610863` passes all 23 jobs; Main CI macOS feature-matrix job `93870588204` passes the complete workspace all-target `rust-tests` surface with root library `1,661/1,661` and all seven new WebTransport regressions.
- Detail: `docs/todo/done/todo-471-stealth-webtransport-cover-profile.md`

### TODO-882 - Implement RFC 9204 QPACK instruction synchronization
- DONE. RFC 9204 static and byte-bounded dynamic tables, encoder/decoder instruction streams, Required Insert Count/Base reconstruction, blocked-stream release, acknowledgement, cancellation, eviction, malformed-input typing, lazy zero-capacity behavior, and transport reset propagation are implemented. Final commit `6dba2a3` passes all 23 Clippy Matrix jobs in run `31516652440` and the macOS feature matrix with the complete root test surface in Main CI job `93863449188`.
- Detail: `docs/todo/done/todo-882-qpack-instruction-synchronization.md`

### TODO-758 - Restore the fuzz manifest, CI coverage, and seed-corpus contract
- DONE. Commit `10c1559` adds the single missing `qf-crypto -> subtle` edge to the isolated fuzz lock with no package-version churn. Nightly locked metadata resolves `308/308` packages/nodes, the six-target static contract passes, and all `48` curated seeds remain unique. Clippy Matrix run `31510890429` is fully green; Main CI job `93844215976` passes all six AddressSanitizer targets with two workers and `1,000` runs per worker, totaling `12,000` executions without a crash artifact. Frontend and protected Tauri paths remain unchanged.
- Detail: `docs/todo/done/todo-758-fuzz-contract-reconciliation.md`

### TODO-692 - Implement HTTP/3 varint frame and stream state validation
- DONE. Commit `21ca2e8` implements complete QUIC-varint frame and stream-prefix parsing, endpoint-owned stream classification, critical-stream lifecycle, SETTINGS and frame-placement validation, request/push message sequencing, bounded and unique push IDs, correct Server Push wiring, and typed unidirectional WebTransport data handling. Focused H3 coverage passed `77/77` before the final fail-closed self-review additions; hosted job `93836990319` compiled the final source and passed Clippy, release compilation, the complete workspace test execution, and `1,642` root library tests with zero failures. Clippy Matrix run `31508779282` is fully green. TODO-882 owns QPACK instruction synchronization and TODO-471 owns complete WebTransport negotiation. Frontend and Tauri paths remain unchanged.
- Detail: `docs/todo/done/todo-692-h3-frame-stream-state-machine.md`

### TODO-660 - Own Blacklist Synchronizer Task Lifecycle and Concurrency
- DONE. `BlacklistSyncOwner` provides atomic single-flight ownership, bounded retry, cancellation, hard resource caps, and typed freshness/outcome telemetry. Closure review additionally made cache rename and active-list replacement one cancellation-aware commit, retains graceful ownership past the 500 ms reporting deadline for an admitted publication, and prevents direct stop/drop from allowing a late commit. Blacklist tests pass 21/21, atomic commit rejection 1/1, the complete server surface 539/539, all-target checking, strict library Clippy, formatting, and diff gates.
- Detail: `docs/todo/done/todo-660-blacklist-sync-detached.md`

### TODO-633 - Validate QUIC KDF Secret Lengths
- DONE. Every QUIC traffic-secret derivation validates exactly 32 bytes before HKDF and returns `KeyMaterialError::Length` for malformed input; the DCID-based Initial extract remains intentionally separate. Packet helpers map the error to `ConnectionError::CryptoError`, and Initial, Retry, Handshake, 0-RTT, 1-RTT, key-update, lifecycle, and `KeyScheduleHooks` edges propagate failure before mutating the affected slot. The complete 0/4/31/33-byte rejection matrix and exact-32-byte acceptance pass across all KDF functions; KDF 26/26, packet 29/29, connection key-update 4/4, local checking, and strict library Clippy pass. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `06de1cd`.
- Detail: `docs/todo/done/todo-633-quic-kdf-input-validation.md`

### TODO-634 - Bound Fountain Decoder Symbol Storage
- DONE. `LTDecoder` enforces explicit repair-symbol, retained-byte, degree-one queue, and cumulative propagation-work budgets. The wire path binds each validated per-window repair ordinal to one global Fountain symbol ID before payload allocation; duplicate IDs and ordinal reuse fail closed. FIFO eviction updates all coupled maps, order, queue, and byte accounting while dedicated counters expose evictions, rejections, and propagation work. The 100,000-unique-symbol adversarial regression stays within every limit. Fountain 25/25, wire 22/22, FEC 241/241, workspace all-target checking, and strict library Clippy pass. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `827bd3c`.
- Detail: `docs/todo/done/todo-634-fountain-decoder-unbounded-storage.md`

### TODO-636 - Remove Quadratic Equation Peeling in FEC Decoder
- DONE. GF8, GF4, and GF16 retain equations in `VecDeque`; each peeling pass processes every queued equation exactly once, preserves unresolved-equation order, and performs no `Vec::remove`/`Vec::insert` shifts. Direct decoder, interleaved, lazy, wire, and E2E recovery regressions are covered by the passing FEC 241/241 surface. The isolated `k=256` Criterion case improves from 17.598 ms to 16.080 ms, approximately 8.6%, while workspace checking, strict library Clippy, format, and diff gates pass. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `3a73209`.
- Detail: `docs/todo/done/todo-636-fec-decoder-quadratic-peeling.md`

### TODO-637 - Reuse Wiedemann Solver Buffers
- DONE. `WiedemannScratch` owns producer-local, decoder-bounded column and SpMV storage reused across payload-byte solves; no mutable scratch crosses Rayon producers. Telemetry distinguishes column, accumulator, matrix/RHS, Krylov, iteration, candidate, and reserved AMX allocation classes. High-loss `k=128/256` Criterion coverage records 75% fewer logical column-buffer and accumulator events with latency stable within approximately +2.2% and +0.6%. Focused Wiedemann 2/2, FEC 242/242, telemetry 1/1, benchmark execution, all-target checking, and strict library Clippy pass. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `56f088a`.
- Detail: `docs/todo/done/todo-637-wiedemann-repeated-allocations.md`

### TODO-638 - Remove Avoidable Receive-Side Retry Token and Destination-CID Allocations
- DONE. The authenticated client Retry path moves the parsed token after integrity verification while preserving Retry SCID adoption, Initial key derivation, and packet-number reset. Destination-CID tracking stores fixed-size inline `ConnectionId` values without per-insert `Vec` conversion, and the normal 1-RTT path retains its pre-parsed-header move. Authenticated Retry/CID tests, transport 538/538, focused Criterion coverage, workspace all-target checking, and strict library Clippy pass. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `2b8c56a`.
- Detail: `docs/todo/done/todo-638-transport-connid-clone-hotpath.md`

### TODO-639 - Define StealthShaper RNG Failure and Seed Lifecycle Semantics
- DONE. Fresh non-cryptographic shaper seeds are fallible with no deterministic fallback; failed BBR2/BBR3/CUBIC activation restores the original controller and returns an operator-visible typed error through Recovery, Connection, and Brain runtime activation. Reno uses an RNG-free wrapper because it has no randomized pacing path. Stealth-focused coverage passes 266/266 and CC/Recovery integration passes 20/20 plus 2/2. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `e172069`.
- Detail: `docs/todo/done/todo-639-stealthshaper-rng-fallback.md`

### TODO-640 - Route HTTP/3 Masquerade Cookie Timestamps Through the Canonical Time Source
- DONE. The production H3 masquerade cookie reads the canonical injectable wall clock, delegates valid epochs to the unchanged deterministic formatter, and omits only the optional cookie for pre-Epoch values instead of emitting timestamp zero. Fixed-clock regressions exercise the real header path while cover-scheduler routing stays separate. H3 passes 9/9, persona headers 13/13, and complete stealth 268/268. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `557f619`.
- Detail: `docs/todo/done/todo-640-h3-masquerade-time-source.md`

### TODO-641 - Define Domain Fronting Selection Semantics
- DONE. `get_fronted_domain()` uses strict atomic round-robin with deterministic serial order and balanced concurrent slot coverage; `random_domain()` remains an explicit opt-in, empty managers return the documented Cloudflare fallback, and MASQUE intentionally retains a stable first-domain authority. Focused domain-fronting tests pass 9/9, complete stealth 269/269, stealth config 9/9, and stealth mode 7/7. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `7e53d15`.
- Detail: `docs/todo/done/todo-641-domain-fronting-jitter.md`

### TODO-650 - Own DNS Intercept Blocking-Task Outcomes and Shutdown
- DONE. `DnsInterceptWorkerOwner` owns every accepted blocking task, closes admission and response publication before teardown, reaps completion and panic outcomes, distinguishes queued cancellation from started-operation shutdown expiry, and exposes terminal response/queue, join, cancellation, panic, late-publication, and expiry telemetry without changing TODO-611 admission limits. Real single-thread blocking-pool lifecycle tests pass 3/3 and the complete server suite passes 458/458. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `3273178`.
- Detail: `docs/todo/done/todo-650-dns-intercept-spawn-ignored.md`

### TODO-645 - Define Generic Engine Configuration Reload and Propagation
- DONE. Generic file and in-memory candidates are fully validated before publication; stopped engines replace complete state, running clients update only the explicit next-connection projection while preserving active non-FEC sessions, and running generic servers reject unsupported mutation. Focused Engine/config/QKey tests pass 61/61, ClientRuntime 6/6, and control-plane integration 5/5. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `1e0be5d`. TODO-724 and TODO-876 separately close standalone transactional generation publication.
- Detail: `docs/todo/done/todo-645-engine-config-no-reload.md`

### TODO-647 - Bound Admin HTTP Admission and Configure Connection Capacity
- DONE. The CLI-only owner defaults to 16 and validates `1..=1024`; admission occurs before task creation, excess sockets are dropped without a user-space pending queue, diagnostics expose active/admitted/rejected state, and shutdown aborts and joins accepted tasks. Focused coverage passes 68/68 and the real contract target 2/2. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `ed29a0a`.
- Detail: `docs/todo/done/todo-647-admin-http-conn-limit.md`

### TODO-661 - Define Admin HTTP Operation Deadline and Cancellation Ownership
- DONE. Admin HTTP owns a bounded `50..=120000` ms operation deadline, bounded worker protocol, timeout/close response contract, panic/cancellation/late-result telemetry, and a one-second shutdown drain. Focused coverage passes 72/72 and the server filter 467/467. Clippy Matrix run `31471819294` is fully green, and Main CI run `31471819318`, macOS feature-matrix job `93716959602`, passes the default all-target Rust lane at a revision containing implementation commit `a1b2498`.
- Detail: `docs/todo/done/todo-661-admin-http-per-op-timeout.md`

### TODO-649 - Define Linux DNS Resolver Path, Symlink, and Backup Ownership
- DONE. Typed standard/alternate paths, schema-3 resolver identity, create-only backup/state publication, symlink-safe restore, target-replacement refusal, and fail-closed rollback are implemented. Main CI run `31471819318`, Linux job `93716959582`, passes the unprivileged native proof with restore fixtures 15/15, path/lock fixtures 3/3, and the exact terminal marker at revision `3e242d3c49aba65d3e2919370aa5021098411c94`.
- Detail: `docs/todo/done/todo-649-dns-backup-hardcoded-path.md`

### TODO-646 - Bound io_uring Batch Admission and Executor Ownership
- DONE. Sender/worker admission is bounded before copies, runtime paths use one joined worker with deadline, quarantine, shutdown, and no-replay failure, and generic TUN read ownership is explicit. Main CI run `31463107578`, Linux job `93690492040`, passes `rt-transport-uring` 20/20 plus kernel integration 1/1 at a revision containing implementation commit `a7acd21`; artifact `9090960274` retains the Linux proof.
- Detail: `docs/todo/done/todo-646-uring-batch-unbounded-queue.md`

### TODO-850 - Complete privilege post-drop state and failure proof
- DONE. Linux verifies real/effective/saved/filesystem IDs, groups, capabilities, and no-new-privileges for every live thread; partial transitions fail closed; standard and Tokio probes deny both UID and GID root regain. Main CI run `31469067924`, Linux job `93708224053`, proves one and nine verified threads with parent-root preservation; artifact `9093181072` reports native status `PASS` and zero failures.
- Detail: `docs/todo/done/todo-850-privilege-post-drop-proof.md`

### TODO-849 - Close privilege identity and cross-platform FFI contracts
- DONE. `ResolvedIdentity` is opaque and revalidated, `CurrentIds` compiles cross-platform, malformed `getgroups()` counts fail closed, and every privilege FFI block has a local safety contract. Main CI run `31463107578` passes qf-privilege `23/23` plus the privilege integration target `3/3` on macOS job `93690492100`; Windows job `93690492145` checks the core and compiles the Rust test library with `tun-windows,rust-tests`. Native Linux post-drop/root-regain proof remains TODO-850.
- Detail: `docs/todo/done/todo-849-privilege-identity-ffi-portability.md`

### TODO-802 - Bind Server Firewall Resources to Durable Ownership
- DONE. One durable server firewall owner is enforced per Linux network namespace. Main CI run `31467150282` passes the exact nftables and iptables collision, policy-preservation, process-loss recovery, graceful teardown, unrelated-resource, and zero-residue markers at revision `4a7dae10f9228248fcfcf7962d7dcdd39d80e202`; Clippy Matrix run `31467150276` also passes.
- Detail: `docs/todo/done/todo-802-server-firewall-global-ownership.md`

### TODO-798 - Make io_uring partial-send accounting duplicate-safe
- DONE. Exact per-slot disposition flows through sender/worker APIs and client/server retry subsets. Main CI run `31463107578`, Linux fastpath job `93690492040`, passes both real middle-slot `EFAULT` proofs at revision `20ae52561eea425f8675ae6be4fc1df5525fb422`: connected and unconnected SendMsg each deliver exactly once after retrying only slot 1, while opt-in SendMsgZc reports two kernel sends, one fallback, three deliveries, zero duplicates, and three notifications. The complete Clippy matrix and macOS build/test job `93690492100` also pass.
- Detail: `docs/todo/done/todo-798-uring-partial-send-accounting.md`

### TODO-643 - Define Ownership and Cleanup for Preloaded TLS Key Locks
- DONE. Individually locked Unix keys use page-exclusive anonymous mappings; rejected duplicate/conflict owners zeroize before their own `munlock` and `munmap`, while the accepted identity remains process-lifetime-owned. Main CI run `31461410134` at revision `c3432072b9066febd2a7d64227a35894ef8c7eea` passes macOS strict Clippy, release compilation, the root library `1,620/1,620`, the dedicated native cleanup test `1/1`, and Linux's exact native key-lock ownership step. Windows core checking and test compilation also pass for the non-Unix branch. TODO-516/TODO-678 remain the separate pooled-block lock owners.
- Detail: `docs/todo/done/todo-643-qftls-mlock-missing-munlock.md`

### TODO-808 - Bound EscalationState probe timestamp history
- Closed with current hosted execution. `ProbeHistory` aggregates same-millisecond probes, maintains independent 60-/120-second counters, and enforces a fixed 120,001-bucket cap. Main CI macOS job `93669407470` executes all three named regressions and passes qf-stealth 127/127 plus the root library 1,619/1,619 at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`; implementation commit `45d5266036a493d886f9049a355616cf37c80476` is included.
- Detail: `docs/todo/done/todo-808-escalation-state-history-unbounded.md`

### TODO-644 - Bound ActiveProbeDetector event history without changing escalation semantics
- Closed with current hosted execution. The qf-stealth owner enforces timestamp-only `VecDeque` storage, `max(threshold, 1)` FIFO eviction, and independent 60-second pruning. Main CI macOS job `93669407470` passes qf-stealth 127/127 and the root library 1,619/1,619 at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`; implementation commit `036d040370202fe77fb03219313cdfc179a34b7e` is included. TODO-808 remains the separate escalation-state owner.
- Detail: `docs/todo/done/todo-644-probe-detector-history-unbounded.md`

### TODO-662 - Make Client Profile Persistence Atomic and Crash-Safe
- Closed with current hosted execution. Main CI macOS job `93669407470` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f` passes the root library 1,619/1,619 and binary 47/47, including all six atomic-publication acceptance tests. Implementation commit `1197eb9c40b5eca9ca44705576825cbe43255893` is included. The standalone API has no current production runtime caller, which remains an explicit non-claim.
- Detail: `docs/todo/done/todo-662-profile-save-atomic.md`

### TODO-658 - Client profile IDs use 32-bit nanosecond truncation, risking collisions
- DONE. `ProfileManager` remains standalone; new IDs use 128-bit fallible OS-CSPRNG output as lowercase hexadecimal, `add()` and `load()` reject empty or duplicate IDs without replacement, and non-empty legacy IDs remain unchanged. Main CI macOS job `93669407470` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f` passes all current profile tests `14/14` and the formerly unrelated `quicfuscate` baseline `47/47`; implementation commit `251dcf31c79e61c26d02628fe5ec584cdadc762b` is included.
- Detail: `docs/todo/done/todo-658-client-profile-id-collision.md`

### TODO-656 - Use a checked time source for PKI generation
- DONE. `crates/qf-pki/src/lib.rs` captures one checked/injectable `PkiTime` for generation, existing-PKI validation, quarantine naming, and fixed-time regeneration. Main CI macOS job `93669407470` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f` passes the extracted qf-pki crate `19/19` and the formerly unrelated `quicfuscate` baseline `47/47`; implementation commit `860b958af544be8aa86e74214adbbf54c6028f36` is included.
- Detail: `docs/todo/done/todo-656-pki-timestamp-unwrap.md`

### TODO-657 - E2E CLI probes default silently on timeout parse errors
- DONE. Both probe binaries fail explicitly on malformed or missing timeout/hold values while preserving absent defaults, zero values, and duplicate last-value-wins semantics. Main CI macOS job `93669407470` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f` passes `qf-e2e-client` `8/8`, `qf-e2e-desktop` `3/3`, and the formerly unrelated `quicfuscate` baseline `47/47`; implementation commit `e791bc0` is included.
- Detail: `docs/todo/done/todo-657-cli-probe-parse-errors.md`

### TODO-845 - Harden Unix TUN syscall progress, lengths, and rollback
- DONE. Raw Linux and macOS syscall-result, progress, bounded-name, rollback, and terminal close contracts are implemented. Main CI run `31459436098` at revision `d0dca375d934bfad7d8adfe02ed4cd1f939ad0f2` passes the exact macOS job `93679888152` and Linux job `93679888252` platform tests; Linux native job `93679888172` additionally proves process-real provisioning rollback with zero owned residue and artifact `9089352187`. No live privileged macOS utun packet-I/O claim is inferred.
- Detail: `docs/todo/done/todo-845-unix-tun-io-boundaries.md`

### TODO-843 - Align interface BMI2 dispatch with CPU profile proof
- Closed backend/native x86 proof. Main CI run `31458252191`, Windows job `93676432308`, executes the deterministic dispatch matrix and direct native unaligned BMI2 parser at revision `bd159d2762ad2c242da165718d33ba1e7d064015`; both pass exactly once, the native `SIMD_SKIP` count is zero, and the root suite passes `1,601/1,601`.
- Detail: `docs/todo/done/todo-843-interface-bmi2-dispatch-proof.md`

### TODO-830 - Define ZeroCopyBuffer platform FFI and raw-count contracts
- Closed backend/cross-platform. Local Unix and portable memory-pool tests pass `23/23`. Main CI run `31458252191`, Windows job `93676432308`, executes the complete `qf-memory-pool` leaf at revision `bd159d2762ad2c242da165718d33ba1e7d064015`, including `windows_zero_copy_checks_u32_abi_bounds`; the result is `23` passed, `0` failed, `0` ignored.
- Detail: `docs/todo/done/todo-830-zero-copy-buffer-ffi-contract.md`

### TODO-682 - Audit unsafe code in transport layer
- Closed backend/audit-parent. TODO-837 through TODO-842 are complete. Main CI run `31455640097`, Linux fastpath job `93669407582`, supplies the final native Linux kernel/syscall and x86_64 AVX2 proof at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`; all findings retain exact implemented owners.
- Detail: `docs/todo/done/todo-682-transport-unsafe-audit.md`

### TODO-654 - Fix Unaligned u32 Read in TUN Packet Parsing
- Closed backend/cross-architecture. Main CI run `31455010980` executes the intentionally unaligned portable write on macOS job `93666880395` and both portable plus direct BMI2 unaligned paths on Windows x64 job `93666880422` at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-654-tun-unaligned-read.md`

### TODO-653 - Privilege drop builds CStr from raw pointers without NUL guarantee
- Closed backend/FFI-boundary. Main CI run `31455010980`, macOS job `93666880395`, executes normal in-buffer NUL handling and rejects null, outside-buffer, and unterminated account-name fields in both the workspace matrix and dedicated privilege proof suite at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-653-privilege-cstr-from-ptr.md`

### TODO-652 - Keep Privilege Lookup Extraction Checked
- Closed backend/FFI-boundary. Main CI run `31455010980`, macOS job `93666880395`, executes nonzero status, null result, pointer mismatch, `ERANGE` growth, and real unknown-account lookup regressions in the complete workspace matrix and dedicated privilege proof suite at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-652-privilege-assume-init.md`

### TODO-651 - Make the SecretString UTF-8 Invariant Explicit and Safe
- Closed backend/safe-secret. Main CI run `31455010980`, macOS job `93666880395`, executes all four `SecretString` invariant/erasure tests and the real invalid-UTF-8 QKey regression inside the complete passing workspace matrix at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`; Windows independently executes the parser rejection.
- Detail: `docs/todo/done/todo-651-secretstring-utf8-unchecked.md`

### TODO-867 - Reconcile generic client DATAGRAMs with the authenticated MASQUE carrier
- Closed backend/authenticated-native. Main CI run `31455010980`, Linux traffic job `93666880449`, passes the framed H3 fallback phase and the live authenticated MASQUE Flow-ID `0` bidirectional carrier at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-867-generic-datagram-masque-carrier.md`

### TODO-866 - Propagate server-assigned client IPv6 through an authenticated control plane
- Closed backend/authenticated-native. Main CI run `31455010980`, Linux traffic job `93666880449`, applies authenticated dual-stack assignment `10.0.1.2/24` plus `fd00::2/64` before successful bidirectional TUN traffic; Windows job `93666880422` executes pre-open projection and disabled-assignment rejection at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-866-client-ipv6-assignment-control-plane.md`

### TODO-831 - Return generic pooled buffers on every failure path
- Closed backend/ownership. Main CI run `31455010980`, macOS job `93666880395`, executes compression/decompression failure returns, pooled-guard drop/transfer accounting, and TUN read-failure recycling inside the complete passing workspace matrix at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-831-pooled-buffer-failure-cleanup.md`

### TODO-874 - Align stale XDP interface configuration with actual runtime support
- Closed backend/configuration. Main CI run `31455010980`, macOS job `93666880395`, executes the legacy non-TUN validation and removed-XDP-field schema regressions inside the complete passing workspace matrix at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-874-xdp-config-surface-truth.md`

### TODO-844 - Define generic TUN read and write result contracts
- Closed backend/cross-platform. Main CI run `31455010980` executes the external-factory read/write, MTU-misreport, and client short-write regressions on Windows job `93666880422` and macOS job `93666880395`; both complete root suites pass at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`.
- Detail: `docs/todo/done/todo-844-generic-tun-io-result-contract.md`

### TODO-841 - Close PMTU validation and portable prefetch contracts
- Closed backend/deterministic. The guarded release PMTU/prefetch target passes `1/1`, and Main CI run `31455640097` passes the Linux recovery integration target `2/2` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`. No privileged network probe is part of this contract.
- Detail: `docs/todo/done/todo-841-pmtu-prefetch-contract.md`

### TODO-840 - Harden frame malformed-input and batch-serialization boundaries
- Closed backend/cross-architecture. Main CI run `31455640097`, Linux fastpath job `93669407582`, passes the frame target `8/8` at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`; the guarded ARM64 matrix separately executes the bounded AArch64 cursor regression.
- Detail: `docs/todo/done/todo-840-transport-frame-boundaries.md`

### TODO-842 - Add transport malformed-boundary and native ISA proof coverage
- Closed backend/native-Linux. Main CI run `31455640097`, Linux fastpath job `93669407582`, passes the native AVX2 lane, io_uring rearm and SendMsgZc kernel proofs, real kernel hotpath, Linux invalid-fd, malformed metadata, and the full transport target set at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`. The AArch64-only rerun remains an explicit x86 host skip and is covered by the prior ARM64 execution.
- Detail: `docs/todo/done/todo-842-transport-proof-coverage.md`

### TODO-839 - Repair transport packet-number and public length contracts
- Closed backend/native-ISA. Main CI run `31455640097`, Linux fastpath job `93669407582`, executes the exact AVX2/scalar packet-number parity regression under `-C target-feature=+avx2`; the target passes `9/9`, including intentionally unaligned output and sentinel preservation, at revision `abb9c8149ee5d4e46983e129720fc2d88698a45f`.
- Detail: `docs/todo/done/todo-839-transport-packet-boundaries.md`

### TODO-848 - Add interface and platform negative proof guardrails
- Closed backend/Windows-evidence. Main CI run `31455010980`, job `93666880422`, passes the Windows library, deterministic Wintun/WFP boundaries, privileged lifecycle/policy gates, and zero-residue assertions. The versioned manifest binds the proof to revision `3dd681d510778b6d72bc4bf086b37ae443f13aac` and keeps Unix, ISA-conditional, Win32-fault, and BFE-fault limitations explicit instead of converting skips into passes.
- Detail: `docs/todo/done/todo-848-interface-platform-negative-proof.md`

### TODO-847 - Preserve Windows WFP engine and transaction ownership
- Closed backend/Windows-native. Main CI run `31455010980`, job `93666880422`, passes the exact deterministic WFP failure/retry tests (`2/2`), the privileged IPv4/IPv6 packet-policy and process-exit cleanup target, and the managed-object absence target with `managed_object_residue=0` at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`. Direct BFE/Fwpm native failure injection remains explicitly `UNAVAILABLE`, not falsely green.
- Detail: `docs/todo/done/todo-847-wfp-engine-transaction-ownership.md`

### TODO-846 - Preserve Wintun native cleanup ownership and concurrency proof
- Closed backend/Windows-native. Main CI run `31455010980`, job `93666880422`, passes the complete Windows library plus `2/2` privileged verified-DLL Wintun lifecycle targets with bidirectional I/O, bounded close, repeated open/close, and `adapter_residue=0` at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`. Native Win32 cleanup fault injection remains explicitly `UNAVAILABLE`, not falsely green.
- Detail: `docs/todo/done/todo-846-wintun-cleanup-ownership.md`

### TODO-760 - Make Cargo SIMD feature declarations truthful
- Closed backend/CI-only. Hardware-named Cargo selectors and `simd-all` are removed, the fail-closed metadata gate separates Cargo features from target features and runtime dispatch, and Main CI run `31455010980` passes the contract plus macOS/Ubuntu SIMD self-checks. Clippy Matrix run `31455010971` passes every declared profile at revision `3dd681d510778b6d72bc4bf086b37ae443f13aac`. Native ISA execution remains a separate proof surface.
- Detail: `docs/todo/done/todo-760-cargo-simd-feature-contract.md`

### TODO-881 - Extract the common workspace contract crate
- Closed backend-only. `qf-common` owns the environment, protocol-time, secure-randomness, and zeroizing-secret leaf contracts with exactly three dependencies; the root compatibility paths and test-only parity remain intact. The workspace edge is `quicfuscate -> qf-common` with no reverse edge.
- qf-common tests pass `28/28`; root default and `rust-tests` library suites pass `2,663/2,663`; root/qf-common checks and strict library Clippy pass; formatting and protected-path gates are clean. No frontend field was required and no frontend/Tauri path changed.
- Completion commit: `a5fc3f2` (`TASK 881: Extract common workspace contract crate`).
- Detail: `docs/todo/done/todo-881-common-contract-crate.md`

### TODO-880 - Freeze workspace seam graph and migration contract
- Closed backend-only audit/documentation task. The deterministic seam inventory records 50 dependencies (48 normal and 2 dev), 29 features, 95 targets, 234 Rust files, 203,361 lines, 159 cross-module edges, and one 16-module SCC. Protected Svelte/Tauri paths are clean; the staged migration contract assigns the first leaf extraction to TODO-881 and rejects a one-shot workspace move. Commit `f18730ab87f2cd7890a9a83614a33230f0c2bf30`; Graphify remains explicitly `BLOCKED`.
- Detail: `docs/todo/done/todo-880-workspace-seam-contract.md`

### TODO-561 - Reconcile canonical documentation and evidence-state truth
- Closed backend/documentation-only. Canonical task status now points to `docs/todo.md` and detail frontmatter; current versus historical evidence boundaries are explicit. The deterministic documentation validator passes `tasks=783 references=1755 links=54 canonical_docs=5` with negative fixtures for stale status, broken links, version drift, and duplicate anchors. Runtime guardrails pass with `Critical: 0` and `Warnings: 0`; the completeness validator passes with Graphify explicitly `BLOCKED`. No Rust product/runtime or frontend path changed.
- Detail: `docs/todo/done/todo-561-canonical-documentation-evidence-truth.md`

### TODO-757 - Close the all-feature strict Clippy panic and invariant contract
- Closed backend-only. All 42 pre-remediation library diagnostics and four binary diagnostics are now either typed-error repairs or narrow, documented compatibility/test dispositions. The production, benchmark, and all-feature strict Clippy lanes pass; the default library suite passes 2,659/2,659 and the all-feature library suite passes 2,701/2,701. The comprehensive audit's unrelated web-admin, Linux-only integration, runtime-guardrail, and native-host boundaries remain explicit. The completeness validator reaches coverage but is blocked by stale Graphify provenance. Frontend paths were untouched.
- Detail: `docs/todo/done/todo-757-all-feature-strict-clippy-panic-contract.md`

### TODO-782 - Make shared verification artifact writers valid and non-destructive
- Closed backend/test-infrastructure-only. The shared writer and all three named suite consumers use structured JSON fields; populated-environment contract runs parse `items[0].environment` correctly for optimization, performance-regression, and security-fuzzing. The shared writer fixture, Bash syntax checks, create-new/backup protections, and malformed-input checks pass. Foreign Cargo/curl/iperf/probe JSON remains explicitly separate; no frontend path changed.
- Detail: `docs/todo/done/todo-782-shared-artifact-writer-contract.md`

### TODO-807 - DoH client cache unit test requires external DNS resolution
- Closed backend-only. The cache test now uses a numeric loopback endpoint and an empty cache, proves first-build population, and proves `DnsProxyConfig` clones share the cached client without host resolution or network I/O. The focused DNS module passes 41/41 and strict library Clippy, formatting, and diff hygiene pass.
- Detail: `docs/todo/done/todo-807-doh-cache-test-requires-external-dns.md`

### TODO-800 - Reconcile runtime reload fixtures with strict PMTU validation
- Closed backend-only. The valid reload fixture now supplies a PMTU ceiling compatible with its reduced MTU, and the invalid fixture asserts the complete validator's canonical field-specific diagnostic. Default and all-feature focused runtime-reload tests pass 2/2 each; strict binary Clippy, formatting, and diff hygiene pass. The intentional Linux-only all-target fixture remains a hosted Linux boundary.
- Detail: `docs/todo/done/todo-800-runtime-reload-pmtu-fixtures.md`

### TODO-803 - Remove two redundant clone sites surfaced by the comprehensive audit
- Closed backend-only. The validated QKey token is moved into client construction and the standalone TUN setup moves its owned memory-pool handle into `TunInterface::open`, removing both redundant clones without changing failure or ownership behavior. Strict all-feature library/bin/example Clippy, backend check, formatting, and diff hygiene pass on ARM64 macOS.
- Detail: `docs/todo/done/todo-803-redundant-clone-sites.md`

### TODO-752 - Remove crate-wide warning suppression from strict lint lanes
- Closed backend-only. The crate-root `allow(warnings)` attributes are removed; checked division, slice comparisons, and unsafe-pool alignment diagnostics exposed by strict lanes are fixed; the x86 ACK module-level dead-code allowance is gone and its scalar parity helper is test/rust-tests scoped. Runtime guardrails now fail critically if either broad suppression returns. ARM64 macOS passes strict all-feature Clippy, strict all-target `rust-tests` Clippy, all-feature library/bin/example Clippy, all-feature check, 2,656/2,656 default tests, 2,698/2,698 all-feature tests, formatting, and diff hygiene. The Linux-only io_uring all-target fixture and x86_64 cross-lane remain explicit platform/toolchain boundaries; frontend paths were untouched.
- Detail: `docs/todo/done/todo-752-crate-warning-suppression-lint-truth.md`

### TODO-751 - Make fingerprint rotation configuration and runtime semantics truthful
- Backend-only closure is complete. Engine TOML, AppConfig, embedded client, standalone client/server CLI, and runtime owner now share strict `browser@os` parsing, typed slots, Fixed/Slots/All semantics, and fail-closed invalid/unsupported profiles. The manager keeps established personas frozen and exposes a bounded next-session cursor; the owner snapshot is consumed on reconnect; the old no-op rotation API is removed; running embedded clients explicitly reject rotation-policy changes until restart. Focused rotation/client/server tests, 2,656/2,656 default library tests, 2,698/2,698 all-feature library tests, all-feature check, strict Clippy, format, and diff checks pass. The macOS all-target no-run lane remains inapplicable because the existing Linux-only io_uring test target intentionally emits `compile_error!`. Frontend/admin field exposure is explicitly deferred and no frontend path changed.
- Detail: `docs/todo/done/todo-751-fingerprint-rotation-contract-truth.md`

### TODO-741 - Make release updater publication require complete signed artifacts
- Archived after current workflow, manifest, negative-fixture, Git-history, and live-release-shape revalidation on 2026-08-11. All three desktop updater platforms are required; failures, missing files, empty signatures, disabled native activation, and incomplete manifests block publication. The negative contract passes, prior native Tauri evidence remains 48/48, and protected Tauri/frontend sources remain untouched. Live `v0.4.4` has three signed updater entries but predates the fail-closed implementation, so it is not claimed as execution proof of the newer workflow.
- Detail: `docs/todo/done/todo-741-release-updater-artifact-completeness.md`

### TODO-877 - Give every benchmark cell a status-bearing, identified result record
- Archived after current shared-runner, suite-consumer, selection, shell-syntax, and fixture revalidation on 2026-08-11. Every requested cell carries identity, exact command/environment, status, bounded reason, command status, and validated metric or explicit platform skip. Benchmark-cell, fast/full-mode, and shared-artifact fixtures pass; prior real FEC 4/4 and Stealth/Brain 1/1 evidence remains recorded. Frontend sources remain untouched and future presentation fields stay deferred.
- Detail: `docs/todo/done/todo-877-benchmark-artifact-cell-truth.md`

### TODO-876 - Validate the complete EngineConfig surface and publish one reload generation
- Archived after current source, ownership, regression, ancestry, and hosted-Clippy revalidation on 2026-08-11. TODO-794 retains complete `EngineConfig` validation and typed projection; this backend-only slice retains one shared `RuntimePolicyGeneration` publication gate, generation-tagged `RuntimePolicySnapshot`, profile-rotation serialization, and reload-result visibility. Historical focused 1/1, server 160/160, and all-feature 2,691/2,691 execution evidence remains recorded; current Clippy Matrix run `31500690078` is green. Frontend and Tauri sources remain untouched and future UI fields stay deferred.
- Detail: `docs/todo/done/todo-876-engine-config-validation-and-generation.md`

### TODO-750 - Make QUIC frame parsing and DATAGRAM wire handling fail closed
- Archived after current canonical-leaf, compatibility-adapter, receive-preflight, regression-wiring, and ancestry revalidation on 2026-08-11. Transactional receive parsing, the RFC packet-space matrix, DATAGRAM `0x30`/`0x31`, no-LEN STREAM, checked 64 KiB length handling, exact DATAGRAM reservation, and New Connection ID invariants remain intact. The runtime guardrail passes with Critical 0 and Warnings 0, and current Clippy Matrix run `31501355668` is green; historical frame 21/21, default 131/131, `zero_copy_dgram` 134/134, and all-feature 2,690/2,690 evidence remains recorded. Frontend and Tauri sources remain untouched.
- Detail: `docs/todo/done/todo-750-quic-frame-datagram-wire-contract.md`

### TODO-698 - Make FEC and DATAGRAM send ownership transactional
- Archived after current Core/FEC/transport source, regression, telemetry, ownership, and ancestry revalidation on 2026-08-11. FEC and DATAGRAM queues retain exact FIFO ownership through their complete write/seal boundary and commit one item plus sealed-DATAGRAM telemetry only after success. Runtime guardrails pass with Critical 0 and Warnings 0, and current Clippy Matrix run `31501777499` is green; historical FEC library 2,565/2,565 plus owned 129/129 and zero-copy 132/132 connection evidence remains recorded. Frontend and Tauri sources remain untouched; TODO-559 retains sustained native throughput.
- Detail: `docs/todo/done/todo-698-fec-datagram-send-ownership.md`

### TODO-879 - Reconcile Claude handoff and establish the backend-only continuation baseline
- Archived after current ancestry, H3/transport source, task-truth, scope, and gate revalidation on 2026-08-11. Baseline commit `3a50234` immediately follows `a96bef9` and remains in `main`; the original all-feature backend gates, H3 `62/62`, and transport-connection `127/127` evidence remains valid, current runtime guardrails pass with Critical 0 and Warnings 0, and Clippy Matrix run `31501777499` is green. This archive pass leaves frontend and Tauri paths unchanged.
- Detail: `docs/todo/done/todo-879-claude-handoff-reconciliation.md`

### TODO-691 - Emit a real HTTP/3 control stream and SETTINGS frame
- Archived after current control-stream, peer-ownership, writable-queue, local-setting, regression, and ancestry revalidation on 2026-08-11. Implementation commit `3a50234` and follow-up `c2b891c` remain in `main`; every local SETTINGS value is now bounded before QPACK construction or wire emission. Clippy Matrix run `31503056901`, the release build, and the complete workspace all-target `rust-tests` step in CI job `93818015386` pass. Frontend and Tauri paths remain untouched.
- Detail: `docs/todo/done/todo-691-h3-control-stream-wire-init.md`

### TODO-747 - Make local UI process helpers own children and prove readiness
- Implementation complete and verified on ARM64 macOS. A PID is not ownership, and the helper treated it as both identity and reach. Records now carry the PID, the process group, and an identity built from the process start time and command line; start runs the child under job control so it leads its own process group, which is the portable way to get one because macOS has no `setsid`. Stop signals the group rather than the wrapper shell, refuses to act on a PID whose identity no longer matches, and reports surviving descendants as a failure with a nonzero exit instead of printing success. For the tmux launchers, `send-keys` only queues text into a pane, so both scripts printed started URLs while the build had not run; each service is now probed until it accepts a TCP connection, with a bounded timeout reported as a distinct non-pass state and the session left running for inspection.
- Verification: proven by running real processes, not by reading. A fixture parent that spawns a long-lived grandchild, mirroring how `bun run dev` spawns Vite, was started through the new path: the grandchild died with the group kill. The same fixture under the old form, a background job with no dedicated group signalled by PID alone, left the grandchild running, which is the defect stated verbatim. A record pointing at an unrelated live `sleep` with a mismatched identity made stop refuse, print both identities, exit nonzero, and leave that process alive. The readiness probe was exercised in all three states: a closed port times out and reports not ready, an open port is detected immediately, and a port that opens two seconds late is still detected. `bash -n` and `/bin/bash -n` pass for all four scripts and the portability gate still passes at 152 scripts. No tmux session was launched end to end, so full build-to-ready timing for the real services is not claimed.
- Detail: `docs/todo/done/todo-747-local-ui-process-readiness.md`

### TODO-746 - Validate frontend API and remote endpoint contracts at runtime
- Implementation complete and verified on ARM64 macOS, reduced in scope and split. The unifying defect is that a TypeScript type parameter is a claim about a value, not a check of it, so `apps/svelte-desktop/src/lib/ipc-contracts.ts` now validates everything crossing the Tauri boundary and rejects rather than coerces: a malformed field means the two sides disagree, and repairing it silently hides exactly that. `engine_stats` was the sharpest case, because `?? 0` only substitutes for null and undefined, so a present `NaN`, `Infinity`, negative counter, or string passed into store state and then into the throughput calculation and produced a figure that looks measured and is not; a sample with any invalid field is now dropped whole rather than partially trusted. `engine_status` requires a usable state but nulls malformed optional fields, so a bad error string cannot suppress a real transition. The updater result must carry both versions and a callable installer before it can be offered as an available update.
- Writing the endpoint tests surfaced a second defect the finding did not name: `[::1]:` with an empty port after the colon was also accepted and defaulted to 4433. An explicit colon with nothing after it is malformed, not "no port given", and only an absent suffix now takes the default.
- Scope: findings 2, 3, and 4 are closed here. Finding 1, the admin `getJson`/`postJson` casts, is a per-endpoint schema project rather than a call-site fix and was split into TODO-878; it is not claimed as done.
- Verification: svelte-desktop passes `431/431`, up from 418, with 13 new cases covering every primitive against the exact values that survive `?? 0`, status parsing, statistics rejection per invalid field, SNI handling, updater validation, and the four newly rejected IPv6 suffix forms. svelte-admin passes `307/307` and `bun run check` is clean for both apps. The gate was proven failable by removing the `Number.isFinite` guard, observing three tests fail, and restoring.
- Detail: `docs/todo/done/todo-746-frontend-runtime-contracts.md`

### TODO-745 - Make macOS utility scripts portable
- Implementation complete and verified on ARM64 macOS, with one finding corrected. Finding 1 is real: `/bin/bash` here is 3.2.57 and has no `mapfile`, so both utilities aborted before doing any work on a stock macOS host; both now use portable read loops. Finding 2 is stale: BSD `find` on this macOS does support `-mindepth` and `-delete`, verified by running `/usr/bin/find` with both directly rather than assuming, so nothing was changed there and no fix is claimed.
- Two adjacent instances were found by the new gate rather than by the finding. `scripts/tests/suites/test-e2e-admin-web.sh` used `mapfile` and is not platform-specific, so it is fixed too; `test-linux-installer.sh` also uses it but is Linux-only by definition and is explicitly exempted. More uncomfortably, `scripts/install/setup-netfilter-fastpath.sh`, which I rewrote earlier in this same session for TODO-744, introduced a fresh `mapfile`. That is exactly the regression this gate exists to catch, and it caught it.
- Verification: the new `scripts/tests/smoke/smoke-shell-portability.sh` scans 152 scripts for Bash 4 builtins outside comments and additionally executes the utilities under `/bin/bash` 3.2 itself, because parsing clean is not the same as running. `util-cleanup-workspace.sh --safe --dry-run` completes under 3.2 and still emits its documented release-preserving `find` command. The gate was proven failable by restoring `mapfile` in `util-check-quality.sh`, observing the named failure, and restoring. `bash -n` and `/bin/bash -n` pass for every modified script, and the TODO-744 fixture still passes after its rewrite.
- Detail: `docs/todo/done/todo-745-macos-utility-portability.md`

### TODO-744 - Make the netfilter fast path own only its rules
- Implementation complete and verified on ARM64 macOS. The helper deleted every rule matching `-p udp --dport PORT -j ACCEPT`, a spec with no owner information, so an identical rule created by an operator or a distribution was indistinguishable from its own and was removed by a cleanup run. Every rule now carries `-m comment --comment quicfuscate-fastpath`, and one `rule_spec` is used for the check, the insert, and the delete, so the helper can only remove what it created. The port is validated before any mutation and bounded to 1024..65535: inserting an unconditional top-of-chain ACCEPT is a firewall-precedence change, and a typo that opens 22 or 53 ahead of every preceding rule is exactly the damage the bound exists to prevent. Two smaller gaps were closed along the way: `--remove` ran before the root check, and unknown options were silently treated as a port. The helper also refuses to run when the iptables `comment` match is unavailable, because creating an unowned rule would reintroduce the original defect quietly.
- Verification: the new `scripts/tests/smoke/smoke-netfilter-fastpath.sh` passes, proving that every emitted iptables command carries the owner comment, that no delete command could match an unowned rule, that `0`, `22`, `53`, `1023`, `65536`, `99999`, a non-numeric value, and an unknown option are all refused, and that a supported custom port still produces an owned rule. Both gates were proven failable by dropping the comment from the rule spec and by disabling the range check, observing the expected failures, and restoring. `bash -n` passes for both scripts. No live firewall was modified: this host has no iptables, so the evidence is the exact command set the helper emits under `--dry-run`, and privileged insert, remove, and repeated-run behaviour against a real chain is not claimed.
- Detail: `docs/todo/done/todo-744-netfilter-fastpath-rule-ownership.md`

### TODO-743 - Synchronize the generated systemd helper with the shipped CLI
- Implementation complete and verified on ARM64 macOS. The generator emitted `--mode server`, a CLI form the binary no longer accepts, and pointed `Documentation` at `your-org`, so any unit built from it could not start while the separately shipped installer unit worked. Both defaults now describe the same invocation as the shipped template, the `server` subcommand with `--listen`, `--cert`, `--key`, and `--config`, built from named constants, and the client default uses the `client` subcommand. The acceptance allowed deleting the generator instead; it has no in-tree callers, but it is public API and removing it silently would break an external user for no gain, so it was aligned rather than deleted. The duplication between generator and shipped template is real and is now guarded rather than hidden.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2968/2968` with three new tests. The drift test includes `scripts/install/quicfuscate-server.service` at compile time and asserts that both use the same executable and subcommand, that every required argument appears in both, and that `--mode` cannot reappear; the metadata test rejects the `your-org` placeholder; the client test pins its subcommand. All were proven failable by restoring the old `--mode server` string and the placeholder URL, observing two tests fail, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. `systemd-analyze verify` was not run: this host has no systemd, so unit validation by systemd tooling is not claimed.
- Detail: `docs/todo/done/todo-743-systemd-helper-cli-contract.md`

### TODO-742 - Make Tauri persisted-state limits UTF-8 safe
- Implementation complete and verified on ARM64 macOS. Constants named `_CHARS` were compared against `String::len()` and the resulting byte index was passed to `String::truncate`, which panics when it lands inside a code point, so any non-English persisted state could abort the host during startup sanitization. All limits are now measured and applied in Unicode scalars through `char_count` and `truncate_chars`. The truncate-versus-reject split is a decision the finding did not make and is the substantive part: only `name` and `location` are shortened, because a display string keeps its meaning when abbreviated, while an over-long `id`, `remote`, or `sni` drops the tunnel and an over-long `qkey` is cleared. Silently shortening an identifier produces a different tunnel that can collide or orphan the selection, a shortened endpoint points somewhere else entirely, and a shortened credential is invalid rather than shorter, so truncating any of them would be exactly the silent data corruption the acceptance forbids. Clearing the credential also makes the derived `has_token` report the truth.
- Verification: the Tauri crate passes `48/48` with three new tests covering 2-, 3-, and 4-byte encodings plus a combining sequence for both truncated fields, over-long identity fields rejected while the credential case keeps the tunnel and drops only the key, and values sitting exactly at each limit accepted unchanged, which catches an off-by-one that would reject multibyte values far below the documented size. The gate was proven failable by restoring the byte-index truncation, observing two tests panic at the old call site, and restoring. `cargo clippy --all-targets -- -D warnings` is clean for the Tauri crate; `cargo test --workspace --all-targets --features rust-tests` still passes `2965/2965`. Running `cargo fmt` in that crate also reformatted `state_store.rs`, which is pure formatting with no logic change and makes the crate's own `fmt --check` gate green; it is unrelated to this task and is called out rather than left unmentioned.
- Detail: `docs/todo/done/todo-742-tauri-state-utf8-boundaries.md`

### TODO-739 - Exclude local secrets from source release archives
- Implementation complete and verified on ARM64 macOS. The archive is built from the filesystem, so gitignoring keeps nothing out of it, and this workspace really did hold `config/local/admin-auth.json` at mode 0600 plus a QKey store and dev certificates that the old exclusion list would have shipped. Those paths and the usual credential and key filename classes are now excluded. Exclusion alone was not accepted as the deliverable, because a mistyped or newly missing pattern fails silently and a published secret cannot be recalled: the archive is now verified after it is built, its member list checked against the same sensitive patterns and its decompressed contents grepped for private-key PEM headers so a key under an innocuous filename is caught too. Any hit deletes the archive and exits nonzero while retaining the manifest. An approved-fixture allowlist exists and is deliberately empty.
- Adjacent finding fixed: the archive also contained `docs/todo` and `docs/todo.md`, the internal task registry that commit `ac9068a` deliberately removed from the public tree. Gitignored, present on disk, and therefore republished by a filesystem tar. Excluding it dropped the archive from 2,369 to 1,534 members.
- Verification: a real archive builds and passes the gate, reporting `1534 members, no sensitive paths or key material`, and the manifest confirms no `config/local`, `docs/todo`, or key members; the only near-matches are `config/admin-auth.json.example`, a placeholder template, and a docs filename, both correctly not matched by the anchored patterns. The gate was proven failable twice on throwaway fixture trees: with the `config/local` exclusion removed it refused to publish and deleted the archive, and a private-key PEM written to `src/innocuous_name.txt` was caught by the content scan under a name no pattern covers. `bash -n` passes and `--dry-run` still prints its command. No archive was uploaded or published.
- Detail: `docs/todo/done/todo-739-source-archive-secret-exclusion.md`

### TODO-738 - Validate benchmark and probe example CLI inputs and exit status
- Implementation complete and verified on ARM64 macOS. Seven examples each had their own argument handling, and between them a typo could panic, an unknown option could be ignored while a different workload ran, a unit multiplication or a bytes-times-iterations product could wrap, and a zero-iteration run could emit a record containing no measurement and exit zero. Rather than patch seven parsers, the contract is one shared `examples/bench_cli/mod.rs` included with `#[path]`: typed messages instead of `unwrap`, a 1 GiB buffer budget and a 10^9 iteration budget applied before anything is allocated, a checked workload product because every throughput figure is computed from it, and zero rejected outright. Each example now fails on unknown options instead of skipping them. Beyond the findings, `shuffle_bench` dropped unparseable entries from `--lengths` through `filter_map(.. .ok())`, so `4,oops` silently measured a different set; that is now an error, and a run where every requested length was skipped exits nonzero instead of printing a header. `fec_sim` environment overrides fell back to defaults on a malformed value, so an exported typo ran a different model without saying so.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2965/2965`; `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` and `cargo clippy --examples --features "benches rust-tests"` are clean; `cargo fmt --all -- --check` and `git diff --check` pass. The new `scripts/tests/smoke/smoke-bench-example-cli.sh` runs 14 negative cases across all seven examples and asserts three things per case: a nonzero exit, no panic, and a diagnostic. It was proven failable by restoring `microbench`'s silent `_ => print_help()` arm, observing `[FAIL] microbench rejects an unknown benchmark: exited zero`, and restoring. Valid invocations were re-run by hand and still produce their measurements.
- Detail: `docs/todo/done/todo-738-benchmark-cli-input-contract.md`

### TODO-737 - Make the engine basic example safe and truthful
- Implementation complete and verified on ARM64 macOS. The example is the copy-paste entry point for embedding the engine, and it disabled peer verification by default and called `engine.connect()` under a comment claiming it did not connect. Both defaults are inverted: verification stays on, and the run is offline unless `--connect` is passed. Each weakening is now an explicit flag that announces itself, `--insecure-no-verify` printing a warning that names what it accepts, and an explicitly requested connection that fails is returned as an error rather than printed as an expected demo outcome, because the caller asked for it. Unknown options fail instead of being ignored.
- Adjacent defect found by making the offline run actually work: the example's `update_config` batch set `transport.mtu = 1350` and was rejected, because `from_toml` normalizes before validating while `apply_config_candidate` only validated. The same document was therefore accepted from a file and rejected programmatically. That asymmetry came from TODO-875's clamp and is fixed at its source, `apply_config_candidate` now normalizes first, rather than papered over in the example.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2965/2965`; `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean, as is `cargo clippy --examples`; `cargo fmt --all -- --check` and `git diff --check` pass. The new `scripts/tests/smoke/smoke-engine-example.sh` proves the default run completes with no server, says it skipped the connection, reports `Verify peer: true`, and never reports a connection; that `--insecure-no-verify` both warns and disables; and that an unknown option fails. It was proven failable by restoring `.verify_peer(false)`, observing `[FAIL] peer verification must stay enabled by default`, and restoring. All four command paths were also run by hand, including `--connect`, which fails with a connection-refused error and a nonzero exit as intended.
- Detail: `docs/todo/done/todo-737-engine-basic-example-safety.md`

### TODO-740 - Make the build-check runner fail closed
- Implementation complete and verified on ARM64 macOS. The runner caught `cargo fmt --check`, `cargo clippy`, and `cargo bench --no-run` failures, passed them to `warn`, and then printed `[OK] Compilation checks passed` regardless, so its exit status was evidence of nothing. Every check now runs through one `run_check` site that records the exact command status and accumulates failures, and the runner exits 1 if any required check failed. Low disk and `--skip-clippy` are recorded as SKIP with a named reason rather than PASS, and the final line lists every skipped check, so a run with Clippy skipped cannot read as a full quality pass. The `results.json` artifact carries one record per check plus an aggregate.
- Verification: proven by failure injection. A deliberately misformatted function added to `src/lib.rs` made the runner exit 1 with `[FAIL] Build check failed: formatting` and a `results.json` whose formatting record is `FAIL` with `command_status: 1`, where it previously warned and exited 0. After restoring the file the same invocation exits 0 with `[OK] Build check passed with skipped checks: clippy test-compilation benchmark-compilation`, the skips coming from `--skip-clippy` and from this machine having 6.8 GiB free against the runner's 10 GiB threshold. The injected file was restored and verified against git. Writing the aggregate record surfaced a defect in my own first version: it appended itself to the failure list it was reporting, so the summary read `formatting aggregate`; the lists are now snapshotted before the aggregate is written. `bash -n` passes.
- Detail: `docs/todo/done/todo-740-build-check-fail-closed.md`

### TODO-735 - Make benchmark suites fail closed and emit valid result status
- Implementation complete and verified on ARM64 macOS, reduced in scope and split. Six suites and the CI gate ran `cargo bench --no-run` and reported every nonzero result as "no benches detected", so a compile error, a dependency failure, or an unsupported feature was indistinguishable from a repository that declares no benchmarks, and the lane exited zero. `qf_bench_preflight` now reads the declared targets from `cargo metadata` and answers the two questions separately: absence is a legitimate skip, a declared target that fails to build is a failure carrying the build output. The CI gate additionally dropped `|| true` from baseline creation, which had allowed a failed creation to be reported as a created baseline that the next run would compare against and call a pass; it also now sources the shared library explicitly and refuses to run without it, since losing that would silently restore the old guessing. The orchestrator's empty selection returns 2 instead of 0.
- Scope: findings 3, 4, and 7 are closed here. Findings 1, 2, 5, 6, 8, and 9 are one artifact-schema problem across the suites rather than separate defects and were split into TODO-877. Reality check on finding 7: its main claim is stale, `FAILED_SUITES` already drives a nonzero exit; only the empty-selection path was still wrong.
- Verification: proven by failure injection rather than by reading. A `compile_error!` added to `benches/fec_pipeline.rs` made `qf_bench_preflight benches` return 1 with the build output and `bench-transport.sh` exit 1 with `[FAIL] declared benchmark targets did not build; refusing to report a skip`, where it previously printed a skip and exited 0. The same injection in `scripts/benchmarks/ci_regression.rs` made the gate's `ci_regression`-scoped preflight return 1. An undeclared target name classifies as `absent` with exit 0, so the skip path still works. Both injected files were restored and verified byte-identical against git. `bash -n` passes for every modified script and `bench-ci-regression.sh --help` and `bench-transport.sh --fast --dry-run` still run. A full benchmark execution was not completed; the 10-minute run was cut short deliberately and no timing result is claimed.
- Detail: `docs/todo/done/todo-735-benchmark-suite-fail-closed.md`

### TODO-733 - Make persisted blocked-IP policy fail closed and report durability errors
- Implementation complete and verified on ARM64 macOS. The loader collapsed a missing file, an unreadable file, and malformed JSON into one empty set, so a corrupt or inaccessible policy readmitted every address the operator had denied. It now returns a typed `PersistedBlockedIpsState` mirroring the `load_persisted_logging_mode` precedent already in the same module rather than inventing a second shape, and bootstrap propagates the error, so the server refuses to start instead of starting allow-all. `Absent` and an explicitly empty policy are kept apart and both logged, because they are identical in memory and only the log distinguishes them. Entry validation was added beyond the finding: an entry that `normalize_admin_ip` cannot match is a rule that would be loaded and never enforced, which is the same silent-ineffectiveness class, so it is rejected. On the mutation side the live set is deliberately not rolled back when persistence fails, because rolling back a block would readmit the address just denied and rolling back an unblock would keep denying one just released; the requested state is the safer one. What changed is the report: the response now fails and states that the change applies to the running server only and will be lost on restart, so success means durable.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2965/2965` covering absent versus explicitly empty kept distinct, a valid IPv4 and IPv6 policy round-tripping through the shared atomic writer, malformed JSON and a JSON object and a non-string entry and a non-address entry and an empty entry each rejected as `InvalidData` with the file named, an unreadable file reported as a read failure with the empty-set outcome excluded on either branch, an unpersistable block and unblock reported as failures that name the address and the live consequence while the requested live state stands, and a durable block and unblock reporting success with the file reflecting each change. Both gates were proven failable by swallowing the persistence error and by defaulting malformed JSON to an empty list, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Concurrent admin mutations were not exercised as a timing test; the live set is behind an `RwLock` and each persist writes the full set under it, which is stated rather than claimed as proven.
- Detail: `docs/todo/done/todo-733-blocked-ip-persistence-truth.md`

### TODO-732 - Derive a valid SNI for IPv6 remote endpoints
- Implementation complete and verified on ARM64 macOS. `remote.split(':').next()` is only correct for `host:port`; for the bracketed IPv6 form it yielded `[`, which travelled into the stealth headers and the TLS configuration, so the defect was invisible on IPv4 and broke exactly one half of a dual-stack deployment. Because `connection.remote` must already parse as a `SocketAddr`, the derivation had a correct source available and simply was not using it: the fallback is now `remote_addr.ip().to_string()`, extracted into `derive_sni()` so it is testable without a network, and it matches what `qf-e2e-client` already did. A configured SNI stays authoritative. The desktop display fallback uses the existing `parseRemote()`, which already handles brackets, rather than a second parser; the UI change is exactly the one derived value named by the task.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2959/2959` covering IPv4, bracketed IPv6, and IPv6 loopback fallbacks with the bracket explicitly excluded, and an explicit SNI staying authoritative for both families. `bun run test:unit` passes `416/416` for svelte-desktop and `307/307` for svelte-admin, with four new cases covering the bracketed IPv6 render, IPv4, a configured SNI, and an unparseable endpoint; `bun run check` is clean for both apps. Both gates were proven failable by restoring the split, observing the expected red, and restoring.
- Adjacent fixes required to run those gates, all pre-existing and unrelated to the SNI defect: `__RELEASE_VERSION__` was declared after `export {}` in both `app.d.ts` files, which made it module-scoped and invisible, so `bun run check` failed on `AboutView`; both vitest configs lacked the `define` that `vite.config.ts` has, so every About test failed with a `ReferenceError` instead of an assertion; and both About tests asserted the literal `v0.2.0`, the exact drift TODO-706 closed, so they now read the same workspace-version owner. The frontend suites were red before this task and are green after it.
- Detail: `docs/todo/done/todo-732-ipv6-sni-derivation.md`

### TODO-731 - Reject malformed TUN address CLI values instead of dropping them
- Implementation complete and verified on ARM64 macOS, with one finding corrected. Finding 1 is stale: the client does not parse these values at all, it rejects `--tun-mtu/--tun-ip/--tun-netmask/--tun-ip6/--tun-prefix6` outright as server-assigned, so there is no silent client parse. The task's own reconciliation of finding 2 was right, and the duplication is now removed: standalone TUN construction consumes the typed values `apply_standalone_tun_server_config()` already validated instead of reparsing the strings with `parse().ok()`, so presence still follows the flag while an error can only stop startup. Removing the duplicate parse exposed a real divergence it had been hiding: the IPv4 branch only runs when an address is supplied, so a `--tun-netmask` given alone never reached the server configuration while the construction still parsed and applied it, leaving the two describing different interfaces. That combination is now rejected rather than half-applied.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2957/2957` covering a malformed `--tun-ip`, `--tun-netmask`, and `--tun-ip6` each rejected as `InvalidInput` with the flag named and the configuration left untouched, a lone netmask rejected with the default netmask preserved, and a valid dual-stack set plus fully omitted values keeping their current meaning. The new gate was proven failable by disabling the lone-netmask check, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. No platform TUN device was opened, so interface creation itself is not claimed as runtime-proven.
- Detail: `docs/todo/done/todo-731-tun-cli-parse-fail-closed.md`

### TODO-729 - Make health and metrics reflect server lifecycle state
- Implementation complete and verified on ARM64 macOS. Prometheus hardcoded `quicfuscate_up 1`, the admin metrics JSON hardcoded the same, and the JSON health body only ever considered readiness, so a stopped runtime reported itself serviceable. The three surfaces now read one published `LifecyclePhase` on `Metrics`, and the runtime publishes on every transition through `set_state()`, so the lifecycle can no longer be assigned without being published, which is how the surfaces drifted in the first place. Health and readiness are kept as different questions: readiness decides the status only while the phase is `running`, and every other phase answers on its own, because no readiness result makes a stopped runtime healthy. Incomplete cleanup gets its own `stopped_incomplete` phase reporting `failed` rather than being folded into a clean stop, since it leaves host state behind and an operator has to act. Three existing readiness tests now set `Running` explicitly, which is the separation working rather than a regression.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2954/2954` covering all six phases agreeing across the text export, the `phase` label, and the JSON body, and a stopped, stopping, or incompletely stopped runtime never reporting `ok` even with every readiness input at its healthiest, with `stopped_incomplete` distinguished from `stopped`. Writing that surfaced a trap worth recording: the nested memory-lock object carries its own `status`, so a substring assertion reads the wrong field; the tests parse the body and read the top-level field. The gate was proven failable by removing the lifecycle override and the computed `up` value, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. No live health probe was run against a running server, so the surfaces are proven at their export boundary rather than over HTTP.
- Detail: `docs/todo/done/todo-729-lifecycle-aware-health-metrics.md`

### TODO-728 - Remove audit path check and open TOCTOU races
- Implementation complete and verified on ARM64 macOS. The startup check inspected the name and every later operation resolved that name again, so a replacement between them redirected the append, the mode change, and the ownership transfer to a different inode while the process believed it had validated the audit path. The refusal is now atomic with the open: `open_private_append_file` passes `O_NOFOLLOW` and makes the regular-file test through the returned handle, which turns the earlier `symlink_metadata` check from the security boundary into a clearer early error. Hardening was the sharper defect, because `set_permissions` and `chown` resolved the pathname separately and could tighten the mode on one inode and give ownership of another away; `secure_audit_file` now opens once with `O_NOFOLLOW` and performs both through that descriptor via `fchown`, with a newly created parent chowned through an `O_NOFOLLOW|O_DIRECTORY` handle. The checkpoint staging file also gained `O_NOFOLLOW`; its publication was already a rename, which does not follow a link at its final component.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2952/2952` covering a symlinked audit path refused by the open itself with `ELOOP`, the audit owner refusing to publish on it, the link target's bytes unchanged and the link left as found, hardening refusing a symlinked target with the target's 0644 mode untouched, and hardening refusing a directory at the audit path. Both no-follow gates were proven failable by removing the flag, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. A privileged chown path was not executed, so the ownership transfer itself is not claimed as runtime-proven; it is bound to a descriptor by construction.
- Detail: `docs/todo/done/todo-728-audit-path-toctou.md`

### TODO-727 - Bound audit startup reads for existing segments
- Implementation complete and verified on ARM64 macOS. All four startup readers loaded whole files into strings, so startup memory scaled with whatever was on disk. They now share `open_bounded_audit_segment()` and `next_audit_line()`: the segment size is checked from metadata against the existing `MAX_AUDIT_SEGMENT_BYTES` retention ceiling before any content is allocated, because reading a file to discover it is too large is the exhaustion path itself, and a single entry above the new `MAX_AUDIT_ENTRY_BYTES` (64 KiB, derived from the writer's 8 KiB encoded payload bound plus fixed-width fields and two hashes) is refused rather than read. `read_tail_state` was the worst case, reversing over a whole-file string to find one entry; it now streams forward and keeps one entry, at constant memory. The Notes forbid weakening the chain check to avoid reading the file, and it is untouched: `verify_segment` still reads and hashes every entry, only without materializing the file first.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2950/2950` covering an oversized segment rejected by all three entry points with the bound named, a file exactly at the ceiling passing the segment bound and being caught by the entry bound instead so the size check refuses only what is out of contract, an oversized single entry rejected with the entry limit named, and a bounded valid chain still verifying with its first sequence, next sequence, and full tail hash intact. Both bounds were proven failable by disabling them, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Pathname binding stays with TODO-728.
- Detail: `docs/todo/done/todo-727-bound-audit-startup-reads.md`

### TODO-726 - Reject audit events after terminal persistence failure
- Implementation complete and verified on ARM64 macOS. Reality check first: the finding's main claim was already source-closed. `log_typed` checks the terminal state before and after admission, returns the typed persistence failure, and counts terminal discards separately; the writer counts events queued before the failure; and shutdown and flush return the original failure rather than claiming durable completion. Each of those was read in the current source rather than taken from the reconciliation note. One acceptance item was genuinely open: metrics did not distinguish queue-full, worker-closing, and worker-disconnect outcomes, because all three incremented one `dropped_events` counter even though they return different errors. Those are three different operator situations, a writer that is behind, one that is shutting down, and one that is gone until restart, so each now has its own counter through a single `record_dropped_event()` site, with the aggregate kept as the total and exported as `quicfuscate_audit_dropped_events_by_cause_total` with a `cause` label.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2947/2947` covering each of the three causes counted under its own name with the other two untouched and the aggregate still totalling, and a terminal persistence failure counted as a terminal discard with every queue cause and the aggregate left at zero, so a persistence outage cannot read as a backlog. The gate was proven failable by dropping the per-cause increment, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Existing-file reads and pathname binding stay with TODO-727 and TODO-728.
- Detail: `docs/todo/done/todo-726-audit-persistence-failure-admission.md`

### TODO-725 - Reject negative transport reload values instead of clamping to zero
- Implementation complete and verified on ARM64 macOS. Nine override parsers wrote `val.max(0)`, so a negative became a legal value with different runtime semantics: zero disables the idle timeout entirely and a zero flow-control limit permits no data, and the reload reported success either way. All nine now share `transport_varint_override()` and `transport_len_override()`, which reject a negative with the field named. Zero stays accepted because an operator can mean it; only the negative that used to become zero is refused. Specifying the range also surfaced a missing upper bound the finding did not name: transport parameters are varint-encoded, so anything above 2^62-1 cannot go on the wire and is a configuration error rather than a large limit, and that bound is now enforced with the maximum itself still legal. The finding's second file reference, `src/transport/connection/parts/impl_api.rs:782,784`, is stale; no clamp exists there.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2945/2945` covering, for each of the nine fields, a negative rejected with the field and the defect named, zero still accepted, the varint maximum accepted, and one past it rejected with the field named, plus a negative aborting the whole override set with an earlier valid setter in the same file leaving transport unmutated. Both gates were proven failable by restoring the clamp, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-725-reject-negative-transport-reload.md`

### TODO-724 - Make runtime configuration reload atomic across policy domains
- Implementation complete and verified on ARM64 macOS, reduced in scope and split. The reload wrote three shared policy locks and only then applied transport, whose helper was infallible at its API boundary and logged setter failures, so a reload could publish three domains and report success with transport on the previous file. `apply_transport_overrides_from_toml()` now returns every setter failure and applies the overrides to a private copy that is committed only once all of them have succeeded, so a rejected constraint cannot leave transport half-updated either. Transport runs first and the three locks are written only after it succeeds. Reality check on the finding: every transport key is currently pre-validated by `AppConfig::validate()` and the override parser, so the masked-setter impact is not reachable through the reload path today. That is precisely the argument for the change rather than against it, because the safety depended on two validators staying in step with the setters and nothing enforced it. Startup is now fail closed: `apply_transport_overrides_from_file()` treats absence as the only acceptable reason to keep defaults, and a present but unreadable or invalid file fails instead of silently downgrading the operator's transport semantics.
- Scope: findings 1 and 2 are closed here. Finding 3 (complete `EngineConfig` validation and the silent typed-string defaults) and the generation-identifier and mixed-generation acceptance bullets are architectural rather than local to the reload ordering and were split into TODO-876 instead of being ground through here. They are not claimed as done.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2943/2943` covering a setter rejection returned rather than logged with the live config untouched and an earlier setter in the same file not surviving the later rejection, a rejected reload publishing nothing across FEC, optimization, and stealth, and a present-but-invalid override file failing at startup with the file named while a missing file keeps the defaults. The helper-level gate was proven failable by restoring the old ordering and the swallowed setter error, observing the expected red, and restoring. The reload-level test guards the publication contract rather than the ordering, because today's rejection still comes from the pre-validators; that limit is stated in the test itself. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-724-atomic-runtime-config-reload.md`

### TODO-723 - Make PKI writers reject symlinked output paths
- Implementation complete and verified on ARM64 macOS. Three writers opened pathnames three different ways, so they are now one `write_pki_file()` boundary rather than three patched call sites. The Notes explicitly rule out the tempting fix, checking `is_symlink()` and then reopening the same pathname, so the rejection and the safety are separated: an existing link is reported as `PkiError::UnsafePath` without being followed, and the write itself is made safe by staging into a sibling that cannot pre-exist (`create_new` plus `O_NOFOLLOW`) and renaming onto the target, because `rename` does not follow a symlink at its final component. A link planted after the check therefore replaces the link, not its destination. Carrying the mode on the staging file also fixed a defect the finding did not name: the old key writer reused an existing file, so replacing a key that had been widened to 0666 inherited that mode. `ensure_pki` and quarantine now use `symlink_metadata`, since `Path::exists()` resolves the link and reports a dangling one as absent, which is exactly how a planted link would have slipped past the existence check.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2940/2940` covering replacement leaving the new content and no staging file, all three writers rejecting a symlinked `server.key`, `server.crt`, and `ca-root.crt` with the victim file byte-identical and the link itself untouched, private keys created at 0600 with the caller's DER zeroized and a replacement refusing to inherit 0666, a dangling link seen as present and rejected with its target never created, and a missing parent directory reported without creating anything. The symlink and mode gates were proven failable by neutering the rejection and the creation flags, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. A concurrent planting race was not executed as a timing test; the rename boundary is what makes it safe and that boundary is what the tests exercise.
- Detail: `docs/todo/done/todo-723-pki-symlink-safe-writers.md`

### TODO-722 - Clear and verify supplementary groups on non-Linux privilege drop
- Implementation complete and verified on ARM64 macOS, which is one of the affected platforms. The non-Linux Unix branch set only the primary GID and UID, so every supplementary membership survived a transition that reported success. `clear_supplementary_groups()` was already correct and merely gated to Linux, so widening it to `cfg(unix)` was enough; no second implementation was written. It runs before `setgid`, because after `setuid` the process no longer holds the privilege to drop groups, and its failure is propagated so a drop that did not reduce anything cannot be reported as one. Verification is deliberately not a copy of the Linux empty-set rule: POSIX leaves it unspecified whether `getgroups()` reports the effective GID and the BSD-derived platforms do, so `check_supplementary_groups_cleared()` tolerates the new primary GID and nothing else. Linux's stricter contract is untouched.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2935/2935` covering an empty set accepted, the new primary GID accepted alone, and a single retained group, a group beside the primary GID, a retained root membership, and several retained groups each failing with every retained group named and the primary GID never reported as retained. A live test asserts against the observed group set on both branches: under a privileged runner the clear must genuinely empty the set, and unprivileged it must surface a real `setgroups` errno while leaving the set unmodified, which is the outcome this machine exercised. The verification gate was proven failable by neutering the retained-group check, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. A privileged end-to-end drop was not performed and is not claimed, and the Linux branch was not recompiled because no Linux linker is installed here; the only Linux-visible change is the widening of an existing `cfg`, which leaves that path with exactly one unchanged definition.
- Detail: `docs/todo/done/todo-722-nonlinux-supplementary-groups.md`

### TODO-721 - Validate DNS UDP responses against transaction and question
- Implementation complete and verified on ARM64 macOS. The UDP forwarder treated source-address equality as transaction authentication, which it is not: a stale, misdirected, or forged datagram arriving from the configured resolver's own address satisfied the query. The check DoH already performed was not DoH-specific, so rather than write a second parser it was factored into a transport-neutral `match_response_to_query()` with a `DnsResponseMismatch` enum that keeps the three cases a caller must not conflate apart, an unparseable query we sent, an unparseable response, and a well-formed answer to a different question. `receive_dns_response()` now binds every accepted datagram to the outstanding transaction ID and complete question tuple. A mismatch consumes the same bounded spoof-rejection budget and keeps waiting under the existing deadline instead of failing, because the legitimate answer may still be in flight behind the stale one; exhausting the budget fails with `InvalidData`. Parser bounds, the 4,096-byte limit, and the opacity of answer, authority, and EDNS sections are untouched.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2931/2931` covering a matching response accepted, stale transaction ID, wrong QNAME, wrong QTYPE, wrong QCLASS, a missing QR flag, and a truncated header each rejected, the real answer still accepted after an unmatched datagram, and a flood of unmatched responses terminating within the budget rather than the deadline. All three new gates were proven failable by neutering the match, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. No DNS implementation or external resolver test was performed, so live-resolver behaviour is not claimed. DoH semantic validation beyond transaction ID stays with TODO-810.
- Detail: `docs/todo/done/todo-721-dns-question-validation.md`

### TODO-720 - Wire 0-RTT key installation or remove the advertised capability
- Implementation complete and verified on ARM64 macOS. The acceptance offered two branches and the honest one was the second: full 0-RTT key installation is a protocol feature, not a task, and leaving the capability half-wired was the actual defect. The gap was worse than a no-op, because `connection.enable_0rtt` defaulted to `true`, so every default deployment already believed it had 0-RTT while `get_0rtt_keys()` returned `None` and `CryptoContext::install_0rtt_keys()` had no production caller, meaning no early-data packet protection was ever installed. Both `connection.enable_0rtt` and `transport.enable_early_data` now default to `false` and are rejected by `EngineConfig::validate()` with a message naming the missing wiring and the key, because a silently ignored setting is how a deployment comes to trust a replay posture that does not exist. The anti-replay strike register is untouched and stays in place for the point where the wiring lands.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2927/2927` covering both keys off by default, defaults validating, and each key independently rejected with the rejection naming the missing wiring. The new test was proven failable by neutering the guard, observing the expected red, and restoring. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. `config/quicfuscate.toml` and `config/server-linux.default.toml` no longer document 0-RTT as usable, and `docs/DOCUMENTATION.md` states the capability is rejected rather than ignored. Sending or accepting early data is not claimed and remains unwired.
- Detail: `docs/todo/done/todo-720-0rtt-key-wiring.md`

### TODO-719 - Propagate packet-normalize target size through the engine config path
- Implementation complete and verified on ARM64 macOS. The gap was worse than non-propagation: the engine schema had no target field at all, and the conversion rejected `padding_strategy = "normalize"` outright with a message admitting the field "is not part of the engine schema", so the strategy was selectable and documented but unconfigurable through this path. `StealthSection::normalize_target_size` now flows into `StealthConfig` and on through the manager's existing `set_stealth_normalize_target()` link to transport strategy 5; the chain was complete except for its first link. The target is bounded to `1200..=65527`, justified by the QUIC minimum datagram and the maximum UDP payload, with both exact boundaries accepted. A target set alongside any other strategy is rejected rather than ignored, because a silently unused target is how a configuration comes to claim stealth it does not perform. Every error names the key.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2926/2926` covering a valid configuration reaching the runtime with its target intact, a missing target, a target of 1, one below the minimum and one above the maximum each failing with the key named, both boundaries accepted, and a target with `adaptive` rejected while `adaptive` alone still works. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass, and `docs/DOCUMENTATION.md` documents the key, range, rejection rules, and propagation chain. An on-wire size measurement is not claimed and stays with TODO-543.
- Detail: `docs/todo/done/todo-719-packet-normalize-config-propagation.md`

### TODO-718 - Make reorder ratio a real bounded recent-window metric
- Implementation complete and verified on ARM64 macOS. The decay-and-fold step lived inline inside `apply_policy`'s write lock and could not be exercised without driving a whole brain; `decay_reorder_window()` and `reorder_ratio_from_window()` are now extracted with `REORDER_WINDOW_HALF_LIFE_SECS` naming the half-life policy actually uses. Specifying the contract surfaced two real defects: nothing clamped reordered packets to observed packets, so an over-reporting caller produced a ratio above one before the downstream clamp, and a non-finite accumulator poisoned every later ratio because the decay multiplied it forward. Both are handled, and a fresh observation now recovers the window instead of leaving it stuck. `reorder_count` and `pkt_count` carry an explicit observability-only contract: saturating, never reset, monotonic over the connection's life, not read by policy.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2923/2923` covering a 50 % burst decaying below 1 % under sustained clean traffic, idle time preserving the ratio while halving the weight per half-life, an empty window reporting zero, over-reported reorders clamped to exactly one, NaN and both infinities and a negative accumulator each sanitised with recovery to the fresh sample, and the saturating lifetime addition. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. A path-migration reset is deliberately not claimed: the brain has no migration hook and adding one reaches into TODO-584's surface; the window's decay already bounds how long pre-migration observations matter, and that bound is now documented and tested.
- Detail: `docs/todo/done/todo-718-brain-reorder-window.md`

### TODO-717 - Isolate connection-local brain and stealth actuators
- Implementation complete and verified on ARM64 macOS. The last cross-connection actuator is closed: `StealthBrain` wrote the process-global `telemetry::MASQUE_HINT` atomic and every `StealthManager` read it back to decide its own MASQUE preference, so one connection's telemetry flipped every other connection's preference. The value moved into `IntelligentLevelHints`, which is already the manager-owned per-connection channel the brain receives at construction, alongside `brain_level` and `probe_level`. `MASQUE_HINT` is still written and exported for metrics but is never read back for policy, and its documentation says so; no `MASQUE_HINT.load` remains in production code. No FEC or intelligent-level state was moved, since both were already connection-local.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2917/2917` including a test that builds two managers, asserts they do not share a hint `Arc`, and drives the preference in both directions so the isolation is not one-way by accident, plus one that interleaves 64 rounds of opposing updates and requires each connection's outcome to stay exactly what it set. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Broader Brain/Stealth correctness stays with TODO-584.
- Detail: `docs/todo/done/todo-717-brain-stealth-connection-isolation.md`

### TODO-716 - Replace AEAD length arithmetic with checked bounds
- Implementation complete and verified on ARM64 macOS. `sealed_len()` and `checked_seal_capacity()` compute plaintext-plus-tag with `checked_add` and return `BufferTooShort` on overflow, and every `len + 16` in the ChaCha20-Poly1305, AES-GCM, AEGIS, MORUS, and batch paths now routes through them: ten capacity guards and six return expressions across three modules, with no unchecked tag addition left anywhere in `src/crypto`. The overflow was reachable rather than theoretical: `len + 16` on a length near `usize::MAX` wraps to a small number in release and panics in debug, and the wrapped total is smaller than almost any buffer, so the capacity comparison passed and `split_at_mut(len)` was reached with a length no allocation can satisfy. Per-item batch guards use the same helper, so one overflowing item in an otherwise valid batch is refused.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2915/2915` including zero length, one byte, 1500 bytes, the exact `usize::MAX - 16` boundary and both lengths past it, an overflowing length refused regardless of buffer size, exact and one-byte-short capacity, a test asserting the old wrapped total really is smaller than a realistic buffer so the defect is demonstrated rather than described, and the real ChaCha seal path returning a typed error for both an overflowing and a merely oversized length while still sealing a valid one. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-716-aead-checked-lengths.md`

### TODO-715 - Correct GF16 PCLMUL reduction and differential-test dispatch
- Implementation complete and verified on ARM64 macOS. The reduction was wrong twice over: `prod ^ clmul(prod >> 16, POLY)` XORs the fold into the untruncated product so the original high-degree terms survive, and one fold cannot finish because `clmul(high, 0x100B)` is itself up to 27 bits wide and reintroduces degrees at or above 16. Modelling the field first showed the fold count must be four; one, two, and three all diverge from the scalar field, four matches it for every `a` in `0..=0xFFFF` across a spread of `b` and for 200,000 random pairs with zero mismatches. `gf16_reduce_folded()` is a scalar model of exactly what the vector kernel does and is differentially tested against `gf16_mul_single()` on every host, so the formulation is proven even where PCLMULQDQ cannot run; `gf16_fold_pclmul()` implements the same four folds in vector form. The fold count is justified by a test that reproduces the original single-fold formulation and asserts it diverges, rather than being asserted.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2911/2911`, covering exhaustive `a` for zero, identity, the reduction constant, the high bit and all ones, 200,000 deterministic random pairs, the single-fold divergence proof, and a dispatcher test over lengths `0,1,2,3,7,16,17` so the vector loop and its scalar tail are both compared against the scalar field. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Executing `gf16_mul_pclmulqdq` itself, and therefore native PCLMUL/VPCLMUL evidence, is UNAVAILABLE here and is not claimed. AVX2/GFNI Reed-Solomon stays with TODO-594.
- Detail: `docs/todo/done/todo-715-gf16-pclmul-correctness.md`

### TODO-714 - Make macOS DNS capture failure-safe and service-scoped
- Implementation complete and verified on real macOS. `capture_current_dns()` returned an empty vector for a `networksetup` spawn failure and for a genuine DHCP service alike, and never checked the exit status, so a failed capture was indistinguishable from "no DNS set" and disconnect would later set `Empty` and erase the user's explicit servers. It now returns `Result<CapturedDns, PlatformError>` with `Servers`/`Dhcp` variants and a typed error carrying the command and stderr. `set_dns()` propagates that error instead of storing an empty list, so activation fails closed rather than overwriting DNS it could not record. Restore now distinguishes three states: recorded servers are restored exactly and in order, a recorded DHCP state restores `Empty` because that is what was there, and no recorded state is a logged no-op because this process never took ownership. The cached `dns_service` is cleared alongside the captured state, so the next connection resolves the service that is actually active instead of reusing one from before an interface change.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2907/2907`. Because the host is Darwin the macOS tests execute for real: classification covers explicit servers with order preserved, whitespace and blank lines, the DHCP sentence, and empty output; the failure test actually invokes `networksetup` against a nonexistent service and asserts the error names the command; and the no-ownership restore is proven a no-op. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. A privileged live connect/disconnect and an interface-change scenario are UNAVAILABLE and not claimed. Linux cases stay with TODO-623 and TODO-649.
- Detail: `docs/todo/done/todo-714-macos-dns-capture-restore.md`

### TODO-713 - Make macOS kill-switch rule files race-safe and symlink-safe
- Implementation complete and verified on real macOS. The rule path was `/tmp/quicfuscate_killswitch_<pid>.conf` written with `std::fs::write`, which follows symlinks and reuses whatever exists, so a local attacker who could predict the PID could redirect privileged pf rule content to another file. The path now carries 16 bytes from the secure RNG, and `write_rules_exclusive()` removes any prior entry then creates the file with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`, so the handle can only refer to a regular file the call just made. Regular-file type, owning uid against `geteuid()`, and mode are verified through the open handle rather than by re-examining the path, so nothing can be swapped in between check and pfctl load. Recreating rather than truncating also stops a permissive stale file from carrying its mode into the new rules.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2904/2904`. Because the host is Darwin, the `cfg(target_os = "macos")` tests actually execute: the path is proven not PID-derived and distinct per instance, a write produces an owner-only regular file owned by the effective uid, a rewrite replaces rather than appends, a symlink planted at the path leaves its target byte-identical while the rule path ends up a regular file, and a `0666` stale file has both content and mode replaced. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. Privileged `pfctl` activation against a live pf is UNAVAILABLE and not claimed; pf anchor evaluation stays with TODO-548 and TODO-624.
- Detail: `docs/todo/done/todo-713-macos-killswitch-temp-file-race.md`

### TODO-875 - Repair the failing binary-target runtime config reload tests
- Implementation complete and verified on ARM64 macOS. Both failures had one root cause and it was a product defect: `transport.pmtu_max_mtu` defaults to `1500` while `transport.mtu` is operator-configurable and validation requires the probe ceiling not to exceed the MTU, so setting `mtu = 1400`, a completely ordinary value, failed validation even though nothing contradictory was configured. Any deployment on a sub-1500 MTU hit this. `EngineConfig::normalize()` now lowers `pmtu_max_mtu` to `min(mtu, max_udp_payload)` with a warning, and `from_toml()` runs it so every parse path including the runtime reload sees a reconciled configuration; an explicitly lower ceiling is preserved and `validate()` keeps its checks as post-normalization invariants. The second failure was an unactionable message: `MTU must be at least 1200` does not say whether it means `transport.mtu`, `pmtu_min_mtu`, or `interface.tun_mtu`, so the message now names the key, which is what the test asserted all along.
- Verification: `cargo test --workspace --all-targets --features rust-tests` passes `2902/2902` including both previously failing tests, plus new coverage that a lone `mtu = 1400` parses and validates with the ceiling following to 1400, that `max_udp_payload` participates in the same ceiling, that an explicitly lower ceiling is preserved, and that the floor error names the key and states the floor. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check`, `git diff --check`, and the release-version audit pass. The reported baseline is now this command rather than `--lib`, which does not build the binary target and is why these were invisible.
- Detail: `docs/todo/done/todo-875-binary-target-runtime-reload-tests.md`

### TODO-712 - Bound admin HTTP request body memory before collection
- Implementation complete and verified on ARM64 macOS. `Incoming::collect()` is replaced by `read_body_bounded()`, which consumes frames one at a time and checks the accumulator before each append, so peak allocation is the cap plus one frame and a chunked or lengthless request can no longer hold memory until the operation timeout. The status code was never the defect: the old post-collection check also returned 413, it just did so after allocating the whole body, so `append_bounded()` is split out to make the bound itself directly testable rather than inferred from a status. `parse_content_length()` returns `None` for an absent header, rejects an unparsable value instead of treating it as zero, and accepts duplicates only when they agree, since disagreeing values are a request-smuggling shape. A declared length only sizes the initial reservation and is never trusted. Both rejections happen during request conversion, before any handler or auth path runs.
- Verification: `cargo test --lib --features rust-tests` passes `2572/2572` including a direct bound test (chunks up to the cap accumulate exactly, the byte past it is refused and not appended, an oversized single chunk is refused without buffering any of it, and the comparison saturates), a header-shape test covering absent/valid/duplicate-equal/conflicting/unparsable/negative, and three end-to-end tests for oversized chunked without Content-Length, chunked within the cap, and the two 400 cases. `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` is clean; `cargo fmt --all -- --check` and `git diff --check` pass. An RSS or task-count stress measurement is deliberately not claimed; connection admission stays with TODO-647.
- Detail: `docs/todo/done/todo-712-admin-http-body-bound.md`

### TODO-711 - Fail closed when the server bundle binary is not executable
- Implementation complete and verified on the host. The `|| true` on the staged `chmod` was already removed while closing TODO-706; this adds the proof that the mode achieved what it was meant to guarantee. Before packaging, the staged binary must exist, carry the executable bit, and match the built binary by SHA-256, so a truncated copy or a stage modified between copy and packaging fails instead of shipping. Execution is proven on Linux via `--version` and reported as `binary_execution=unavailable` elsewhere rather than treated as success. After `tar`, the archive listing is read back and the `bin/quicfuscate` entry must exist with an executable mode; the verified hash and the packaged mode are printed so provenance sits on the build output instead of being assumed.
- Verification: executed against a real staging directory and tarball. The happy path reports `packaged_mode=-rwxr-xr-x` with the SHA-256 and exits `0`, correctly reporting execution as unavailable on this Darwin host; mode `0644` exits `1` with "staged binary is not executable"; appending a byte to the staged copy exits `1` with "staged binary does not match the built binary" and both hashes. `bash -n`, `shellcheck -S warning`, and `git diff --check` pass, and the release-version audit the bundler invokes still passes. Executing the Linux binary and running a real installer against an extracted bundle are UNAVAILABLE on this host and are reported by the script rather than passed over.
- Detail: `docs/todo/done/todo-711-server-bundle-executable-gate.md`

### TODO-710 - Stage web admin assets atomically without destroying the previous bundle
- Implementation complete and verified on the host. The publisher no longer runs `rm -rf "$DEST"` before a fallible copy. The new bundle is copied into a unique `mktemp -d` sibling, the staged tree is verified for required assets and a non-empty file count, and only then does the swap happen as two renames inside the same directory, so nothing can observe a half-copied tree at the destination. An `EXIT` trap removes only directories this script created and restores the previous tree if the process died between the two renames; the destination itself is never removed by the trap. Archiving is unchanged and stays an explicit operator choice.
- Verification: executed against real directories, a successful swap publishes the new bundle with no residue; a bundle missing `index.html`, a missing source, and an unwritable destination each exit `1` with the destination still holding the old content and no residue. `verify_atomic_asset_publish` in `test-e2e-admin-web.sh` now runs those scenarios as a permanent gate before the suite builds anything, extracting the publish boundary from the shipped script so it tracks the real code. The gate was proven failable: reintroducing `rm -rf "$DEST"` makes it exit `1` naming both destructive scenarios, and removing the regression returns it to `0`. `bash -n`, `shellcheck -S warning`, and `git diff --check` pass; three pre-existing `SC2034` warnings at lines 44 and 65 are outside this change and were left untouched.
- Detail: `docs/todo/done/todo-710-web-admin-asset-staging.md`

### TODO-709 - Run the documented strict Clippy contract in every CI gate
- Implementation complete and verified on the host. CI's workspace Clippy now runs the documented `--features rust-tests` command; without it every test-only target and `rust-tests`-gated path was linted in its disabled form, so a warning there could not fail the gate. Turning it on exposed 33 warnings that `-D warnings` would have made CI red, so they were cleared: 17 by `cargo clippy --fix`, the rest by hand. Two were real defects rather than style: `WintunCleanupState` and its methods sat outside the `target_os = "windows"` gate that contains every constructor and consumer, so they compiled on all other platforms as an unreachable type, and `MemoryPool::accounting_snapshot` was gated on `rust-tests` while every consumer is an in-crate `cfg(test)` module. The Clippy matrix grew from 8 to 21 feature entries, and a new `feature-matrix-coverage` job fails when Cargo.toml declares a feature the matrix omits or the matrix lists one Cargo.toml does not declare; `tun-windows` and `tun-ios` are excluded with a stated platform reason. Tauri host Clippy with `-D warnings` already existed and was verified, not duplicated.
- Verification: the exact CI command `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` completes clean, as does the Tauri host's. The coverage gate was proven failable in both directions and found two real omissions on first run (`test-suite`, `experimental`). Library suite `2566/2566`; both workflows parse as valid YAML; `cargo fmt --all -- --check` and `git diff --check` pass. Adjacent finding filed as TODO-875 rather than absorbed: `cargo test --workspace --all-targets` reports `2619 passed, 2 failed`, both in the binary target and both reproducing on a clean tree, invisible to the `--lib` baseline the project reports.
- Detail: `docs/todo/done/todo-709-ci-strict-clippy-contract.md`

### TODO-708 - Make CI benchmark baseline checkout fail closed
- Implementation complete and verified locally. The step now runs under `set -euo pipefail` with no `|| true` or silenced fallback left in executable code, so a missing baseline, failed checkout, failed benchmark, failed restore, or failed stash pop all fail the job instead of reporting a green comparison against an unknown tree. A missing baseline is a hard `::error::` failure rather than the previous "Baseline build skipped" success. `pr_tree`, `baseline_ref`, `baseline_commit`, `baseline_tree`, `checked_out_tree`, and `restored_tree` are all printed, and an `EXIT` trap restores the PR tree and pops the stash before propagating the original status, verifying the restored tree equals the PR tree captured before any mutation so a mixed or baseline-only checkout cannot reach later steps or the uploaded artifacts.
- Verification: all four negative fixtures were executed against a real throwaway repository with the `cargo bench` call substituted. Happy path: the benchmark saw baseline content and the PR tree plus untracked file came back exactly. Benchmark failure: exit `3` with the tree still restored. Missing baseline: exit `1` with the explicit error and no benchmark run. Stash-pop conflict: exit `1` with `failed to pop the stash`. The workflow parses as valid YAML, the step body passes `bash -n`, an automated check asserts no masked failures and the presence of the trap and all five tree-hash variables, and `git diff --check` passes. A hosted GitHub Actions run is UNAVAILABLE here and is not claimed.
- Detail: `docs/todo/done/todo-708-ci-benchmark-baseline-tree.md`

### TODO-706 - Derive visible product versions from the release version owner
- Implementation complete and verified on the host. The workspace package version in the root `Cargo.toml` is now the single owner: both Vite configs read it at build time and expose `__RELEASE_VERSION__`, declared in each app's `app.d.ts`, and both About surfaces derive from it instead of carrying the stale `v0.2.0` literal. `package.json`, both Svelte manifests, the Tauri npm wrapper, and `apps/tauri/src-tauri/Cargo.toml` moved from `0.3.0` to `0.4.4`, treated as release-owned because package metadata, dependency snapshots, and provenance all identify the artifact. `verify-release-version.sh` previously compared only the Cargo workspace and `tauri.conf.json`, so five manifests could drift while the gate stayed green; it now validates eight owners and additionally rejects any hardcoded `x.y.z` literal in the About surfaces or an About surface that does not reference `__RELEASE_VERSION__`. `build-server-bundle.sh` lost the `|| true` and the `unknown` substitution, fails when the version is unreadable or non-semantic, and runs the audit before staging.
- Verification: the gate was proven failable, not decorative. Reverting `package.json` to `0.3.0` produces `release version mismatch against Cargo.toml=0.4.4: package.json=0.3.0`; restoring the admin About literal produces a hardcoded-literal error naming `__RELEASE_VERSION__`. Both were executed and the tree restored; the audit then passes reporting all eight owners. `bash -n` and `shellcheck -S warning` pass for the bundle builder, the Tauri crate passes `45/45` after its bump, the core suite is unaffected at `2567/2567`, and `git diff --check` passes. `svelte-check` and the frontend unit suites are UNAVAILABLE here because both apps' `node_modules/.bin` entries are dangling symlinks; the injection logic was instead verified directly against the real `Cargo.toml` and against a manifest with the version removed.
- Detail: `docs/todo/done/todo-706-release-version-surface-drift.md`

### TODO-704 - Propagate failed desktop state redaction rewrites
- Implementation complete and verified. The rewrite-error propagation sub-boundary was already closed in current source; the remaining secure-intermediate-state boundary is closed here. The temporary file is now created with `create_new(true).mode(0o600)` instead of the ambient umask, so no window exists in which the desktop state file is readable by other local users; the mode is asserted on the temporary file before the rename and read back for comparison, with the result propagated instead of discarded via `let _ =`, so a permission failure aborts the write rather than leaving a permanently over-permissive state file. Every fallible step after the temporary file exists routes through a cleanup that removes it, so no stray file can survive holding content that never became the real state. The general atomic-write permission window stays with TODO-667 for other writers.
- Verification: the Tauri crate suite passes `45/45` including a test asserting the published file is mode `0600` with no surviving `.tmp-` file, and one that puts a directory at the target path so the rename fails after the temporary file already holds content, asserting the write fails and the temporary file is cleaned up. `cargo clippy` reports zero errors for that crate and `git diff --check` passes. Pre-existing `cargo fmt` drift in that crate's test helpers from line 2544 onward was left untouched; every line added here is fmt-clean.
- Detail: `docs/todo/done/todo-704-tauri-redaction-rewrite-errors.md`

### TODO-703 - Never persist QKeys in plaintext when the keychain is unavailable
- Implementation complete and verified. `redact_state_for_disk()` no longer restores `t.qkey` when `store.set()` fails; it returns a typed error naming the tunnel and the keychain failure, so a locked or missing keychain can no longer turn a protected secret into a plaintext disk credential reachable through file access, backups, and crash artifacts. Both `save_state_to_path()` and the redacting load path already propagate with `?`, so nothing is written and existing on-disk state is left intact rather than overwritten with plaintext; the operation is retryable once the keychain is reachable. The error carries the tunnel id and the keychain error but never the credential, which is asserted. The regression that explicitly encoded the downgrade as intended behaviour is now a fail-closed assertion, and a second test states the invariant directly: with a working keychain the returned state has an empty `qkey` while `has_token` stays true, and with a failing keychain no state is returned at all. Server registry encryption stays with TODO-539.
- Verification: the Tauri crate suite passes `43/43` including both tests, `cargo clippy` reports zero errors for that crate, the core library suite is unaffected at `2567/2567`, and `git diff --check` passes. The crate has pre-existing `cargo fmt` drift in test helpers at lines 2466 and beyond; no line added here is flagged and the unrelated drift was deliberately left alone.
- Detail: `docs/todo/done/todo-703-tauri-keychain-plaintext-fallback.md`

### TODO-702 - Stop installer credential disclosure and serialize systemd environment safely
- Implementation complete and verified on the host. The installer no longer prints the administrator password; it writes user and password to `/etc/quicfuscate/admin-credentials`, created under `umask 0177` and explicitly `chmod 0600` / `chown root:root` before any secret reaches it, and prints only the path. Environment values are serialized by `systemd_env_value()` as double-quoted values with backslash escapes, escaping the backslash before the quote, and any value containing a line break is rejected because a newline would terminate the assignment and the remainder would parse as a new key. The unit was expanding `${VAR}` unquoted in `ExecStart`, which systemd splits on whitespace, so a path with a space became two arguments; every expansion is now `"${VAR}"`. The environment file's `chmod`/`chown` no longer tolerate failure with `|| true`.
- Verification: three new gates in `run_static_checks` report `systemd_env_serialization=PASS`, `credential_output=PASS`, and `unit_quoted_expansions=PASS`. The serialization gate decodes with systemd's own escape rules and asserts exact round-trips for plain, spaced, quoted, backslashed, combined, `$`, `;`, and backtick values plus rejection of newline and carriage return; the unit gate was proven failable against a deliberately unquoted unit. `bash -n`, `shellcheck -S warning`, and `git diff --check` pass. Guest VM lifecycle runs against live systemd are UNAVAILABLE on this macOS host and stay with TODO-541.
- Detail: `docs/todo/done/todo-702-installer-secret-output-serialization.md`

### TODO-701 - Make the installer password fallback locale-safe and pipe-safe
- Implementation complete and verified on the host. `tr -dc ... | head -c 24` failed under `set -o pipefail` because `head` closes the pipe and `tr` takes SIGPIPE, aborting an install whose only defect was a missing OpenSSL, and `tr` character classes are locale sensitive. The fallback now reads bytes from `/dev/urandom` with `LC_ALL=C od` and maps them into an explicit alphabet with shell arithmetic, rejecting bytes above the largest multiple of the alphabet size so no character is favoured. The OpenSSL branch verifies it produced the full length instead of silently emitting a shorter credential, and the fallback fails with a diagnostic on an unreadable device, a short read, or an exhausted attempt budget; since the caller assigns under `set -e`, any of those aborts the install rather than writing a partial credential.
- Verification: `run_static_checks` gained `verify_random_password_contract`, which exercises the generator on the host across the OpenSSL path, five fallback runs with OpenSSL hidden and `LC_ALL=de_DE.UTF-8`, and a distribution check over 2,016 characters. It reports `random_password_contract=PASS distinct=62`, so all 62 alphabet characters appear. `bash -n` and `shellcheck -S warning` pass for the installer and the suite; `git diff --check` passes and the Rust suite is unaffected at `2567/2567`. Guest VM lifecycle runs are UNAVAILABLE on this macOS host and are not claimed; they stay with TODO-541.
- Detail: `docs/todo/done/todo-701-installer-random-password-fallback.md`

### TODO-700 - Make direct ServerRuntime stop own every service task
- Implementation complete and verified on ARM64 macOS. `ServerRuntime::stop()` now calls `service_signals.shutdown_all()` immediately after publishing `Stopping` and setting the shutdown flag, so admin, web, and metrics listeners are told to stand down on the same path that tears down host resources. The async drain and live-shutdown paths already did this; direct stop was the one that did not, which is how a `Stopped` runtime could leave listeners alive holding ports and serving stale state. The already-stopped fast path signals as well, so a repeated stop or a service registered after the first stop is still covered. Signalling precedes the existing TUN reader, io_uring worker, host-resource, and routing teardown, so primary cleanup errors keep their precedence. TODO-660 subsequently closed blacklist synchronization ownership.
- Verification: `cargo test --lib --features rust-tests` passes `2567/2567` including a new test that registers all three service signals, calls direct `stop()` and asserts each fired, then registers a further service and calls `stop()` again to prove the repeat stays successful and does not skip signalling. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-700-server-runtime-direct-stop-ownership.md`

### TODO-699 - Fail closed when the server loop outlives engine startup or stop
- Implementation complete and verified on ARM64 macOS. The admin sender only exists once `ServerRuntime` is constructed inside the spawned thread, so it cannot be captured before the acknowledgement; the thread now publishes it through a shared slot immediately before sending the ack and the startup-timeout branch takes it from there, so a runtime that came up just after the deadline is reachable instead of being represented by a handle the engine could only join. When the bounded stop join times out, the engine now records an `EngineError` that flows into the existing shutdown-error path, so the published state becomes `Error` rather than a `Stopped` the engine cannot substantiate while the loop may still hold listeners, sessions, and descriptors. Signal-before-join ordering and the precedence of client-runtime and kill-switch errors are unchanged.
- Verification: `cargo test --lib --features rust-tests` passes `2566/2566` including a new test that gives the engine a loop which never exits and a 50 ms budget, asserts `stop()` returns an error and publishes `Error`, then releases the loop so no live thread is left behind. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-699-server-engine-shutdown-timeout.md`

### TODO-697 - Prioritize terminal CONNECTION_CLOSE over queued control frames
- Implementation complete and verified on ARM64 macOS. `flush_pending_control_frames()` hoists any queued CONNECTION_CLOSE or APPLICATION_CLOSE to the front before walking the queue. Close frames are not ack-eliciting, so once in front they are emitted even under congestion bypass, where the walk otherwise breaks at the first ack-eliciting frame; that break is what let an earlier PING or MAX_DATA hide a later close until congestion reopened or the idle timeout fired. Hoisting is a single removal and push-front, so the relative order of the remaining frames is preserved and it is idempotent when a close is already in front. Ack-eliciting frames still stay queued under bypass, so bypass cannot inflate `bytes_in_flight` beyond `cwnd`. Admission bounds and coalescing remain with TODO-575 and duplicate close suppression with TODO-606.
- Verification: `cargo test --lib --features rust-tests` passes `2564/2564` including a bypass flush over PING, MAX_DATA, CONNECTION_CLOSE, and a second PING that asserts the close is emitted, no ack-eliciting frame is written, and the remaining three stay queued in order, plus an order-preservation and idempotency test. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-697-connection-close-priority.md`

### TODO-696 - Make terminal timeout cleanup use one recovery owner
- Implementation complete and verified on ARM64 macOS. `Recovery::discard_all_spaces()` retires all three packet-number spaces at once through the existing per-space discard path and clears `pto_count`, since PTO backoff belongs to retired state when nothing is in flight to probe for; it is idempotent by construction. `Connection::on_timeout()` now runs its state transition through that owner instead of zeroing only its own `bytes_in_flight` while the recovery spaces kept their sent maps, timers, PTO bases, and largest-acked marks. Nothing remains that could emit a loss callback, probe, or retransmission after the terminal timeout. Non-terminal PTO ownership was not modified and stays with TODO-544.
- Verification: `cargo test --lib --features rust-tests` passes `2562/2562` including three new tests: every field of every space retired plus idempotency on a second discard, an ACK after the discard resurrecting neither losses nor acknowledgements, and the connection path proving a second terminal timeout does not count another in-flight loss. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-696-connection-timeout-recovery-ownership.md`

### TODO-695 - Bound recovery loss detection scans and temporary storage
- Implementation complete and verified on ARM64 macOS. `detect_lost_packets()` no longer materializes every retained packet number up to `largest_acked` and sorts the result. The loss set is a contiguous prefix, because packet numbers ascend through the map and send times are non-decreasing in packet number, so the scan stops at the first survivor and the cost is `O(log n + k)` in the losses rather than in the in-flight window; ascending packet numbers already yield send order, so the sort is gone, and timer re-arming takes the first usable deadline for the same reason. Each space now enforces explicit budgets of `16,384` packets and `64 MiB` with an `O(1)` `retained_bytes` counter kept accurate across insert, loss removal, ACK removal, and space discard; eviction drops the oldest record so current traffic stays tracked, and every eviction increments the new `RECOVERY_SENT_RETENTION_EVICTIONS` counter. The doc comment that claimed a bound the code did not have was corrected.
- Verification: `cargo test --lib --features rust-tests` passes `2559/2559` including two new tests proving the declared losses come back in send order as a contiguous prefix, and that sending past the cap without acknowledgement keeps the retained set within budget, surfaces the eviction in telemetry, never evicts the newest packet, and keeps byte accounting exactly matching the retained set. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass. ACK-range key materialization was left in place: it is bounded by the ranges the peer sent, and the retention budget now bounds the window it walks.
- Detail: `docs/todo/done/todo-695-recovery-loss-scan-boundedness.md`

### TODO-694 - Retain pending ACK state until serialization succeeds
- Implementation complete and verified on ARM64 macOS. `PktNumSpace` now separates inspection from commit: `peek_ack_at()` reports the frame's `(ack_delay, ranges)` without touching `ack_elicited`, `recvd_since_ack`, or `ack_deadline`, and `commit_ack_at()` clears them only after the bytes are in the packet. Both the application space in `impl_recv.rs` and the Initial/Handshake space in `impl_send.rs` use that order, so an undersized output buffer or a `frames::to_bytes()` failure leaves the ACK pending with its deadline and ranges intact rather than discarding an ACK that no further inbound packet is guaranteed to re-trigger. `take_ack_at()` is retained as peek-then-commit so no existing caller changed behaviour. The observer callback, `ACK_DELAY_LAST_US`, and the policy hook already ran only on success and now share the commit, so pending state clears exactly once per emitted frame and ECN counters are untouched.
- Verification: `cargo test --lib --features rust-tests` passes `2557/2557` including three new tests proving inspection is stable and non-consuming, that a commit clears the decision while received ranges are retained and a later ack-eliciting packet schedules a fresh ACK, and that a send which inspects, fails, and retries still carries the ACK. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass. Recovery behaviour was not modified and stays with TODO-544.
- Detail: `docs/todo/done/todo-694-transport-ack-transactional-retention.md`

### TODO-693 - Count only newly accepted STREAM bytes for flow control
- Implementation complete and verified on ARM64 macOS. `conn_bytes_recvd` and `stats.stream_recv_bytes` now advance by the newly covered byte union instead of raw payload length. `Connection::newly_covered_bytes()` measures an incoming range against the contiguous delivered prefix plus every buffered out-of-order fragment, so a duplicate retransmission contributes zero and a partial overlap contributes only its extension. Reordering and ordinary loss recovery can no longer exhaust the connection window or drive MAX_DATA and MAX_STREAM_DATA thresholds without delivering new bytes. `recv_off`, fragment storage, and delivery are unchanged; control-frame coalescing was not modified and stays with TODO-575.
- Verification: `cargo test --lib --features rust-tests` passes `2554/2554` including three new tests covering the full boundary matrix (empty, inverted, below-prefix, straddling, exact duplicate, contained, left and right overlap, spanning, hole between fragments, prefix and fragments combined), a first arrival plus its exact and partial retransmissions, and six scrambled overlapping ranges whose credited total must equal the union size, with a guard asserting the fixture really contains overlap. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-693-transport-flow-control-overlap-accounting.md`

### TODO-690 - Repair the non-functional Wiedemann FEC solver
- Implementation complete and verified on ARM64 macOS. The recorded defect was real but incomplete: repairing the back-substitution alone could not have worked, because Berlekamp-Massey computed the minimal polynomial in the wrong field. `simd::scalar::berlekamp_massey` used `gf_mul_byte`, which reduces with the AES polynomial `0x11B`, while the FEC codec field is `0x11D`. Its shift bookkeeping was also wrong, so it returned polynomials that do not annihilate their own input: for `[fd,30,aa,0d,fd,30,aa,0d]` it returned `[01,00,dd,3e,cd]` where the recurrence requires `[01,00,00,00,01]`. Every dispatched lane (GFNI, AVX2, SVE2) delegates to that one scalar implementation, so the defect reached all architectures and one fix covers all of them. `solve_wiedemann_system()` now builds the Krylov sequence from the right-hand side and recovers `x = lambda[d]^-1 * XOR_j lambda[j] A^(d-1-j) b` by Horner back-substitution, failing a zero constant term rather than shortening the degree. Because scalar Wiedemann can fail on a full-rank system for an unlucky projector (a 3-cycle permutation over GF(256) is the smallest case), it retries bounded independent deterministic projectors and verifies `A x = b` before returning, so it never returns a non-solution. `try_eliminate_wiedemann()` retains full per-equation validation as the second gate.
- Verification: `cargo test --lib --features rust-tests` passes `2551/2551`; `cargo test --lib --all-features` passes `2594/2594` including `internal_wiedemann` and the previously failing `test_decoder_elimination_paths`, so the recorded red all-feature gate is green without weakening any assertion; `rt-security-suite` passes `27/27` and `rt-property-suite` `12/12`; `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass; `audit-runtime-guardrails.sh` retains exactly the known four critical findings and one warning. Native x86 GFNI/AVX2 and SVE2 execution of the dispatched Berlekamp-Massey lanes is UNAVAILABLE here and is not claimed.
- Detail: `docs/todo/done/todo-690-fec-wiedemann-solver-correctness.md`

### TODO-865 - Close the test-only ConstPacketPool capacity and zero-size contract
- Implementation complete and verified on ARM64 macOS. `ConstRingBuffer` now tracks occupancy with an explicit length instead of reserving a slot to distinguish full from empty, so `ConstPacketPool<N, SIZE>` yields exactly `N` buffers rather than `N - 1`. Full capacity was chosen over documenting the old behaviour because a fixed-capacity type whose usable capacity is one less than its name says is a trap however well documented. Both modulo operations are now reached only when the tracked length proves `N > 0`, making `ConstRingBuffer<T, 0>` a representable empty ring instead of a modulo-zero hazard; `new()` checks every free-list insertion instead of discarding the result, and `alloc()` bounds the popped index before touching `in_use` or `packets`. No production pool code was touched, so TODO-826/TODO-827/TODO-828/TODO-829 ownership is preserved.
- Verification: `cargo test --features rust-tests --test rt-security-suite` passes `27/27` with the regression that encoded the old `N - 1` behaviour rewritten to assert the full count, plus new cases for `N = 1` and `N = 2` full capacity, a zero-capacity pool that never allocates, a full free-and-reallocate cycle preserving total capacity, and a double free that must not manufacture a third slot. `cargo test --lib --features rust-tests` passes `2548/2548`; `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-865-const-packet-pool-contract.md`

### TODO-864 - Define the global MemoryPool auto-tuner lifecycle and initialization contract
- Implementation complete and verified on ARM64 macOS. `init_global_pool()` published a pool without starting the auto-tuner while `global_pool()` started one, so identical workloads tuned differently depending only on which path ran first; explicit initialization now starts the worker too. `refresh_resource_metrics()` used the creating accessor, so a metrics scrape could construct the process-global pool and its worker before the runtime initialized optimization state; telemetry now uses a new non-creating `global_pool_if_initialized()` and reports nothing when no pool exists. Shutdown ownership was documented rather than changed because the existing behaviour is correct for a process-global worker: `shutdown_auto_tuner()` is a process-final or test-teardown operation that stops and joins the single worker, leaves the published pool valid and allocatable, is a no-op when idle, permits an explicit restart, and is deliberately not called from `MemoryPool::drop` since the worker is process-global while a pool is not. No parser or snapshot semantics were touched, so TODO-670/TODO-811 authority is preserved.
- Verification: `cargo test --lib --features rust-tests` passes `2548/2548` including three new lifecycle tests covering idempotent start, shutdown joining exactly once with continued allocation afterwards and explicit restart, a disabled-auto-tune pool never claiming the slot, and a telemetry flush being unable to change pool existence. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass.
- Detail: `docs/todo/done/todo-864-memory-pool-auto-tuner-lifecycle.md`

### TODO-863 - Close the Windows NUMA FFI result and safety contract
- Implementation complete and verified on ARM64 macOS. The recorded "ignored result" finding was wrong: `GetCurrentProcessorNumberEx` is declared `fn(*mut PROCESSOR_NUMBER)` with no return type in `windows-sys-0.59.0` line 137, so there is no status to check; the call site now says so. The real defect was availability: `is_available()` returned `highest_node > 0`, but the API reports the highest node *number*, so every single-node Windows host was reported as having no NUMA support and skipped binding and node queries that would have worked. Availability now follows query success, and the node count saturates so `u32::MAX` cannot wrap to zero nodes. All three unsafe blocks gained local contracts covering the zeroed POD outputs, the `GetCurrentThread()` pseudo-handle, the null previous-affinity pointer, and the checked-return precondition for `last_os_error()`. The result classification moved into a pure `numa_classification` module so it is provable off Windows.
- Verification: `cargo test --lib --features rust-tests` passes `2545/2545` including three new tests for single-node availability, node-count saturation, and both the failure and `u16::MAX` no-node sentinel paths; `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass. Windows-target compilation and native execution of every NUMA API are UNAVAILABLE on this host and are not claimed.
- Detail: `docs/todo/done/todo-863-windows-numa-ffi-contract.md`

### TODO-862 - Close the shared portable prefetch pointer contract
- Implementation complete and verified on ARM64 macOS. The x86_64 lane passed a runtime `mode` to `_mm_prefetch`, whose locality strategy is a const generic, so any x86_64 build with the `prefetch` feature (and therefore with `throughput`) did not compile at all. Proven by targeted `rustc --target x86_64-unknown-linux-gnu` runs: the old form fails with `error[E0435]`, the new `_mm_prefetch::<_MM_HINT_T0>`/`::<_MM_HINT_T1>` match compiles. The recorded faulting `read_volatile` AArch64 lane was already gone from current source; all AArch64 targets emit `PRFM PLDL1KEEP`. Because every lane is now a genuinely non-faulting hint, the facade documents that callers owe no readable span and may pass empty-slice, one-past-the-end, or dangling pointers, while provenance discipline for the producing arithmetic stays with TODO-826/TODO-827/TODO-829 and TODO-841. No caller was modified and no ownership was absorbed.
- Verification: `cargo test --lib --features rust-tests` passes `2542/2542`; the two new prefetch contract tests also pass under `--features rust-tests,prefetch`, so the feature-enabled lane is executed rather than the no-op branch, and both are positive tests that fabricate no invalid address. `cargo clippy --lib --features rust-tests,prefetch` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass. A full `x86_64-unknown-linux-gnu` crate build is UNAVAILABLE here because `ring`'s build script needs a Linux C toolchain, and no native x86 runtime probe is claimed.
- Detail: `docs/todo/done/todo-862-shared-prefetch-pointer-contract.md`

### TODO-873 - Close QKey registry Windows replacement FFI contract
- Implementation complete and verified on ARM64 macOS. `encode_wide_nul_terminated()` defines the accepted Windows path shape as UTF-16 with no interior NUL, appends exactly one terminator, and returns `InvalidInput` naming which of source or destination was rejected; `replace_file()` applies it to both paths, so `MoveFileExW` can no longer replace a file named by a truncated prefix of the requested registry path. The unsafe block now states buffer lifetime, absence of interior NULs, read-only callee access, the durability meaning of `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, and that a zero return is the only path to `last_os_error()`. No encryption, zeroization, file-mode, atomic-recovery, or pathname-binding logic was duplicated from TODO-539/TODO-671/TODO-728.
- Verification: `cargo test --lib --features rust-tests` passes `2540/2540` with `qkey_registry_storage` at `13/13`, including a new interior-NUL rejection test that also proves source paths are checked, and a host-native replacement test proving a successful replacement consumes the source while a missing source fails without mutating the destination. `cargo clippy --lib --features rust-tests` reports zero errors; `cargo fmt --all -- --check` and `git diff --check` pass. Windows-target compilation and native `MoveFileExW` execution are UNAVAILABLE on this host and are not claimed.
- Detail: `docs/todo/done/todo-873-qkey-registry-windows-ffi-contract.md`

### TODO-861 - Close audit-file FFI, path encoding, and security-failure contracts
- Implementation complete and verified on ARM64 macOS. Audit-file hardening is now fail-closed: `secure_audit_file()` returns `Result<(), AuditError>`, a failed `set_permissions()` or `chown()` propagates instead of logging a warning, and `init_audit_log_with_options()` applies it before `AUDIT_LOG.set()`, so the global audit owner can no longer be published after required hardening failed. `init_audit_log()` returns the same status rather than swallowing it; it had no callers, so the signature change is contained. `encode_wide_nul_terminated()` rejects an interior NUL before encoding, so Windows checkpoint replacement cannot hand `MoveFileExW` a truncated prefix of the named path. The `geteuid`, `chown`, and `MoveFileExW` unsafe blocks state their pointer, lifetime, aliasing, and return-value contracts.
- Verification: `cargo test --lib --features rust-tests` passes `2538/2538` with the audit module at `34/34`, including three new tests for the Win32 encoding contract, the typed permission failure, and initialization refusing to publish an owner when the path cannot be created; the two existing `secure_audit_file` tests now assert the returned status. `cargo clippy --lib --features rust-tests` reports zero errors and the same five pre-existing warnings, none in touched files; `cargo fmt --all -- --check` and `git diff --check` pass; `audit-runtime-guardrails.sh` retains exactly the known four critical findings and one warning. Windows execution of `replace_file` and root-privileged `chown()`/`geteuid()` failure branches are UNAVAILABLE on this host and are not claimed.
- Detail: `docs/todo/done/todo-861-audit-file-ffi-path-and-failure-contract.md`

### TODO-860 - Close FEC sequence and arithmetic overflow contracts
- Implementation complete and verified on ARM64 macOS. `InterleavedEncoder::params()` now reports the shape the lanes actually represent instead of the requested one, so a non-divisible `k` can no longer reach `wire_profile()` as a `source_count` its own interleave depth fails to divide; construction logs the floored request. Interleaved repair identities gained `REPAIR_LANE_BITS`/`MAX_REPAIR_ORDINAL` and refuse an out-of-range ordinal instead of shifting out of the `u64` and aliasing another repair. `params_for_target()` no longer turns a NaN or infinite redundancy into `MAX_TOTAL_COUNT` through `f32::min`; non-finite and negative ratios fall back to systematic-only with a warning. `ReceiveWindow::source_packet()` converts the Fountain window offset with `checked_sub` plus a `source_count` bound instead of relying on the validator invariant. `DecoderVariant::take_packet()` converts Fountain source ids with `usize::try_from` so a 32-bit truncation cannot alias a valid index. Decoder16 recovery checks the `words * 2` product itself.
- Verified as already bounded and left unchanged: `Decoder8::try_peel_all()` uses `saturating_mul(4)`; the Fountain robust-soliton `i * (i - 1)` and `i * k` products run after `k` is clamped to `1..=12,288` on both constructor paths; wire-path repair identities use a `u16` ordinal with a validated `block_index < interleave_depth <= 8`.
- Verification: `cargo test --lib --features rust-tests` passes `2535/2535`; `cargo clippy --lib --features rust-tests` reports zero errors and the same five pre-existing warnings, none in touched files; `cargo fmt --all -- --check` and `git diff --check` pass; `audit-runtime-guardrails.sh` retains exactly the known four critical findings and one warning. No 32-bit, native, fuzz, or privileged gate was run; the 32-bit narrowing fixes are source-level and UNAVAILABLE for execution proof on this host.
- Detail: `docs/todo/done/todo-860-fec-sequence-arithmetic.md`

### TODO-859 - Close FEC negative proof and documentation truth gaps
- Implementation complete and verified on ARM64 macOS. Two vacuous-green defects were real: `test_streaming_dedup_across_calls` dropped source `42` while transmitting only ids `1..32`, so no recovery ever occurred and `seen_missing <= 1` held on a permanent zero; it now drops an in-range id and asserts `seen_missing == 1`. `test_fec_e2e_no_duplication_no_ordering_violation` never asserted ordering; it now bounds recovery reordering at `FEC_E2E_MAX_RECOVERY_REORDER = 64` against a deterministic worst case of 62. `test_fec_mode_transition_no_memory_leak` now performs its documented 100 transitions instead of 50. `src/fec/gf16_tests.rs` gained a `0..96` lane-boundary length matrix, an overlong-request clamping case that proves the tail stays untouched, and a host-independent `bounded_u16_len` matrix. The FEC fuzz target now drives the block path with fuzzer-declared lengths, the wire parser including truncated prefixes, and the matrix helper with ragged/mismatched/empty shapes, with its proof boundary stated. `test-fec-simulation.sh` and `tun-e2e-fec-burst-netns.sh` now state their proof boundaries in header, summary, and emitted JSON. The GF16 table's 393,214-byte construction peak is documented and bound by a test.
- Verification: `cargo test --lib --features rust-tests` passes `2532/2532`; `cargo clippy --lib --features rust-tests` reports zero errors and the same five pre-existing warnings, none in touched files; `cargo fmt --all -- --check`, `git diff --check`, and `bash -n` on both scripts pass; the fuzz workspace type-checks; `audit-runtime-guardrails.sh` retains exactly the known four critical findings and one warning. Native x86 AVX-512 VBMI2 differential/throughput proof, the AMX negative matrix, and privileged Linux netns gates are UNAVAILABLE on this host and are not claimed.
- Detail: `docs/todo/done/todo-859-fec-proof-and-doc-truth.md`

### TODO-858 - Close FEC configuration and feedback validation contracts
- Implementation complete and verified on ARM64 macOS: `FecConfig::validate()` now enforces domain maxima (burst_window, lambda, hysteresis, Kalman q/r, configured stream cadence, and window sizes including the wire and Fountain source maxima); `AdaptiveFec::new()` validates the config before runtime plan construction and falls back to `FecConfig::product_default()` on failure. `FecRuntimePolicy::detect_with_snapshot()` clamps switch dwell, extreme window, stream cadence, and interleave depth to finite ranges. `FecRuntimePlan::resolve()` enforces stream cadence in `1..=32`. Transport feedback in `report_transport_loss_inner()` caps reported loss at `sent_packets` while preserving raw `acknowledged` values for clean-ack proof, and telemetry records the unnormalized caller values. `LossEstimator::report_smoothed_rate()` rejects non-finite inputs; `KalmanFilter::new()` and `update()` clamp q/r/measurement to positive finite ranges. `ModeManager::update()` clamps loss to `0..=1`, `params_for_target()` caps total repair count at `wire::MAX_TOTAL_COUNT`, and `force_state()` clamps window to `wire::MAX_SOURCE_COUNT`. `AdaptiveFec::bandwidth_aware_overhead_adjustment()` clamps non-finite trends and the loss estimate to valid ranges.
- Verification: focused `cargo test --lib --features rust-tests -j 1 -- --test-threads=1 fec::` passes `275/275`; `cargo clippy --lib --features rust-tests` passes with only pre-existing diagnostics; `cargo fmt --all` passes. The formerly pre-existing `optimize::transport::tests::test_decode_packet_number_4byte` failure was corrected separately under TODO-839 ownership; the full library suite now passes `2530/2530`.
- Detail: `docs/todo/done/todo-858-fec-config-feedback-contract.md`

### TODO-838 - Define AF_XDP experimental UMEM and ring ownership
- Removal complete in commit `d183d0a44d4e6e4442f58add505a3c84dff9b374`: no production AF_XDP caller existed, so the incomplete AF_XDP implementation, feature, constructor probe, and integration target were removed. Test-only UDP/GSO compatibility helpers remain, reject zero MTU, and use saturating aggregate sizing. Metadata, feature taxonomy, AF_XDP-specific guardrails, shell syntax, Rust format, and diff hygiene pass. The aggregate runtime guardrail retains exactly four pre-existing critical findings and one warning; no Rust build or Linux feature-on execution is claimed because the feature was removed and the disk floor is protected. Local and remote `main` match exactly.
- Detail: `docs/todo/done/todo-838-af-xdp-ownership-contract.md`

### TODO-837 - Harden UDP batch FFI result and ownership contracts
- Implementation complete on ARM64 macOS: shared Unix batch helpers bound syscall counts, payload/address lengths, sockaddr ABI conversion, Apple partial `sendmsg_x` completion, Linux timeout/aligned arithmetic, caller-owned descriptor lifetime, and terminal malformed-result propagation at direct callers. Verification passes feature-gated library `2448/2448`, Optimize/UDP `8/8`, Unix ownership `1/1`, UDP-fastpath `3/3`, `rt-udp-batch-send` `3/3`, `rt-transport-udpfast` `2/2`, macOS BatchProcessor `1/1`, formatting, and diff hygiene. The final Linux-only error-propagation change was source-reviewed and formatted but not compiled on this macOS host. Linux-only integration cases, Windows target compilation, all-target rebuilding, and Omega execution remain unclaimed because the prior build reached the disk floor; `target/` was cleaned back to absent with 4.0 GiB free. Commit `403fb0fc710e295c1fe0d73f3951f70b09a92576` is pushed and matches `origin/main`.
- Detail: `docs/todo/done/todo-837-udp-batch-ffi-contracts.md`

### TODO-679 - Audit all unsafe SIMD code in src/simd/* and src/optimize/simd/* for missing bounds/safety docs
- Umbrella closure is complete and pushed as `9f4c31b16fbb7b1c49fddf378ef00b695f876d99`. The 31-file SIMD audit was reconciled with TODO-834, TODO-835, and TODO-836: current source has 131 unsafe declarations, 120 target-feature attributes, and 131 local Safety sections. The feature-contract and cargo metadata gates pass; successor ARM64 debug/release, malformed-input, strict Clippy, and unsupported-ISA accounting evidence is recorded. Native x86/Linux, Windows, SVE2, sanitizer, and Miri proof remains explicitly unclaimed. The aggregate runtime guardrail retains four pre-existing critical findings and one warning outside this owner and no SIMD-specific failure. Final audit completeness is PASS with Graphify explicitly `BLOCKED` at `scripts/out/audits/graphify-20260807T013748Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-679-simd-unsafe-audit.md`

### TODO-677 - Multiple modules use Instant::now or SystemTime::now instead of the canonical time_source
- Umbrella audit and reconciliation are complete. The current tracked-source inventory reports `919` clock locations with `0` unclassified: production `156`, tests `384`, benchmarks `58`, probes `31`, scripts `262`, browser `25`, and archived `3`. The earlier `962` location report is retained as the pre-TODO-868-through-TODO-872 browser-remediation baseline. TODO-820 through TODO-825 and the narrower owners classify every remaining production, runtime, wall-clock, browser, diagnostic, test, probe, script, and archive boundary; native retry/jitter delays remain explicit non-clock runtime domains.
- Verification: `bash scripts/audits/verify-time-source-inventory.sh` passes with `919/0`; `bash scripts/tests/audits/test-time-source-inventory.sh` passes; TODO-820 through TODO-825 and TODO-868 through TODO-872 are archived as completed with their scoped Rust/frontend/runtime evidence and external limits recorded. The final post-push Graphify evidence is explicitly `BLOCKED` at `scripts/out/audits/graphify-20260807T012923Z/graphify-evidence.json`; the parent audit changed no product/UI implementation.
- Detail: `docs/todo/done/todo-677-canonical-time-source.md`

### TODO-676 - AMX tile config uses a static mut global
- Implementation closure is complete and pushed as `d8a339d11177a759abe03d2cefaacf58a8e7c54b` on `origin/main` with exact local/remote parity. TODO-816 through TODO-819 removed the unsafe AMX path, made the active Wiedemann solver a checked scalar fallback, separated CPU/compiler/OS/backend eligibility, and closed the profile and proof-contract ownership. Current verification passes the AMX contract checker, Wiedemann `6/6`, AMX capability/scalar-concurrency `3/3`, and formatting/diff checks; native x86 AMX execution remains explicitly unavailable on this ARM64 host and is not inferred.
- Detail: `docs/todo/done/todo-676-amx-static-mut.md`

### TODO-675 - Make audit persistence failure handling truthful and bounded
- Implementation is complete and pushed as `67e6d8166445284e6a1e03f7d5f0d7f8313c3ddf` on `origin/main` with exact local/remote parity. Audit persistence now has a shared typed terminal state, writer-side durability watchdog, bounded shutdown reporting, sticky failure propagation, terminal-discard/slow-flush/shutdown metrics, and probe assertions for all failure counters. Focused audit tests pass `31/31`, metrics `1/1`, probe tests `3/3`, the full library passes `2443/2443`, strict library Clippy passes, and the rebuilt real probe verifies `10,000/10,000` events with all failure counters at zero. All-target Clippy retains only the five pre-existing baseline findings recorded in the archived detail.
- Detail: `docs/todo/done/todo-675-audit-blocking-flush.md`

### TODO-674 - qf-logging-probe calls logging init twice
- Implementation is complete and pushed as `4787b3eea61228283a870cc44af458de7d17bf9f` on `origin/main`: the isolated probe now calls `logging::init()` exactly once, while the process-real logging suite remains green at `3/3` for rotation, filters, admin delivery, syslog, invalid configuration, queue saturation, sink failure, and producer cost. Documentation and the archived detail record the unchanged behavior and the pre-existing strict probe/Integration-Clippy boundary in FEC/Memory-Pool code. Local and remote `main` parity is exact.
- Detail: `docs/todo/done/todo-674-duplicate-logging-init.md`

### TODO-836 - Restore SIMD safety documentation and proof guardrails
- Implementation is complete and pushed as `f83c5d61c80c3fecddc90bc87b65f5fc1cdf6a53` on `origin/main`: all current 131 unsafe SIMD declarations have local `# Safety` contracts; the module-level suppression is removed; the runtime guardrail inventories restricted visibility and exact target-feature wording; and 24 unsupported-ISA returns across nine test files emit explicit `SIMD_SKIP` accounting. Debug and release SIMD suites pass `113/113`, complete debug/release libraries pass `2,440/2,440`, strict Clippy, formatting, diff hygiene, and the new guardrail sections pass. Miri, sanitizer, native x86/Linux, Windows, and SVE2 execution remain explicitly unclaimed because the required toolchains/hosts are unavailable. Local and remote `main` parity is exact.
- Detail: `docs/todo/done/todo-836-simd-safety-proof-guardrails.md`

### TODO-835 - Harden SIMD unsafe slice, dimension, and short-load boundaries
- Implementation is complete and pushed as `64b1fd18d1015c0bcb94e54876dc253ef6fad9d5` on `origin/main`: the SSE4.2 short-needle load uses owned sixteen-byte padding; GF(256) matrix dimensions and slices, BMI2 output capacity, every local Berlekamp-Massey entry, private repeating-key helpers, and private ChaCha XOR length relations fail closed in release mode. Focused malformed-input coverage passes for accepted needle lengths, matrix dimensions/slices, BMI2 short buffers and LEB128 bytes, direct/dispatched overlong prefixes, and private length guards. ARM64 macOS debug/release focused tests, complete libraries `2,440/2,440`, strict library/all-target Clippy, formatting, and diff hygiene pass. Native x86/Linux, Windows, SVE2, sanitizer, and Miri proof remains external with exact failures recorded in the detail. Local and remote `main` parity is exact.
- Detail: `docs/todo/done/todo-835-simd-unsafe-boundaries.md`

### TODO-825 - Reconcile frontend and browser clock and timestamp contracts
- Parent audit and follow-through are complete on 2026-08-06. The corrected inventory covers 962 locations with 0 unclassified, including 65 active browser-production locations and 390 frontend-test locations. TODO-868 through TODO-872 close the timestamp, monotonic elapsed-time, timer/RAF lifecycle, identifier/CSRF, and deterministic frontend-test boundaries. Their Admin/Desktop checks, builds, Chromium 1.58.2 preflight, Admin E2E `70/70`, Desktop E2E `23/23`, and scoped unit/regression gates are recorded in the completed successor details; no visual UI composition change was introduced by the parent audit. Documentation closure is pushed as `2be5b049e21bf70cf92c4748b59b53feb0a3ad64` with exact local/remote parity.
- Detail: `docs/todo/done/todo-825-frontend-browser-clock-contract.md`

### TODO-834 - Make SIMD ISA dispatch match compiled and runtime feature intersections
- Implementation is complete on 2026-08-06 and pushed to `origin/main` as `964936a76304c2a6ec18ab60f87213f7dba22ea7`: the shared feature-intersection matrix, exact runtime/compile-time gates across SIMD, optimization, FEC, transport, and direct crypto callers, fallback reconciliation, telemetry cleanup, and packet-number network-order regression fix are implemented. ARM64 macOS verification passes locked metadata, library checking, the complete serial library suite `2,439/2,439`, strict library/all-target Clippy with `unsafe_rust`, formatting, and diff hygiene. Native x86/Linux/Windows execution remains external because the available Linux target lacks `x86_64-linux-gnu-gcc` and a Linux sysroot for the clang retry; no native ISA proof is inferred. Local and remote `main` parity is exact.
- Detail: `docs/todo/done/todo-834-simd-feature-dispatch-intersections.md`

### TODO-833 - Return zero-copy datagram buffers to MemoryPool
- Implementation is complete locally on 2026-08-06 and pushed as `83a68b6893ef350b08a90386e8af1283573c8820` on `origin/main`: feature-on `DatagramBuffer` now stores `PooledBlock`; inbound/send oversized payloads fail closed; exact feature-on/off byte-equivalence and pool-counter tests cover queue rejection, receive/send removal, serialization success/error, purge, and connection teardown; strict `zero_copy_dgram,unsafe_rust` library/all-target Clippy, formatting, diff hygiene, and locked metadata pass. The feature-on focused lane passes `5/5`; the current feature-off full debug library passes `2,437/2,437`; the feature-on full debug library passed `2,441/2,441` before the final test-only queue-rejection assertion expansion. The full Optimization Suite release execution is explicitly unclaimed because an unrelated telemetry baseline failed and a later release attempt was stopped at the mandatory disk floor; native Linux/Windows remain TODO-682/TODO-683 boundaries.
- Detail: `docs/todo/done/todo-833-datagram-buffer-pool-return.md`

### TODO-832 - Close FEC pooled-buffer failure cleanup and symbol-length propagation
- Implementation is complete and pushed as `ff1cc5081700a5fd3054f5015d6a6c370e99bba0` on `origin/main`: production FEC allocations now retain `PooledBlock` ownership through parser, wire, GF4/GF8/GF16, decoder, and Fountain failure paths; `MemoryPool::try_alloc_from_slice()` rejects oversized symbols; `FecPacket` transfer validates pool origin and declared lengths; decoder teardown returns internal blocks; and GF16 row/index arithmetic fails closed. The FEC matrix passes `252/252`, the complete debug library passes `2,436/2,436`, the complete release library passes `2,436/2,436`, strict `unsafe_rust` library/all-target Clippy, formatting, diff hygiene, and locked metadata pass. TODO-833 closes the separate zero-copy DATAGRAM ownership boundary.
- Detail: `docs/todo/done/todo-832-fec-pooled-buffer-failure-cleanup.md`

### TODO-829 - Make memory-pool allocation layouts and failure behavior recoverable
- Implementation is complete and pushed as `62a81bfd15627aa726506660df7087c9cf473da9`: checked 64-byte layouts, `isize::MAX` capacity bounds, fallible safe/raw constructors and allocation/resize paths, partial-construction cleanup, and explicit compatibility-wrapper panic policy are implemented. Safe pool release focus passes `16/16`, raw `unsafe_rust` focus passes `31/31`, the full default-feature `unsafe_rust` library passes `2453/2453`, native `unsafe_rust,compression_zstd_ffi` focus passes `32/32`, all-target checking and strict library Clippy pass, and local/remote revision parity is verified. The `--no-default-features` baseline failure remains outside this task; TODO-830 through TODO-833 remain separate boundaries.
- Detail: `docs/todo/done/todo-829-memory-pool-allocation-layout-contract.md`

### TODO-827 - Make MemoryPool capacity, origin, TLS, and ephemeral accounting coherent
- Implementation is complete and pushed as `454100a8a4115b911d1b6fda825554652a4ae1e3`: `PoolOwnershipLedger` now binds exact block addresses to accounted/ephemeral origin and queue/TLS/checked-out state; ephemeral returns, foreign/mismatched blocks, TLS-aware shrink, concurrent transitions, stale-address recovery, and pool/TLS cleanup are covered by one synchronized state model. Focused pool tests pass `13/13`, FEC E2E passes `19/19`, the full library passes `2419/2419`, and the final release-focused pool lane passes `13/13` with only unrelated `qftls.rs` warnings. Formatting and diff hygiene pass; all-target strict Clippy retains 11 unrelated baseline diagnostics. TODO-767 and TODO-831/TODO-833 remain separate boundaries.
- Detail: `docs/todo/done/todo-827-memory-pool-capacity-ephemeral-accounting.md`

### TODO-828 - Prove UnsafeCompressor zstd FFI, failure, and synchronization contracts
- Implementation is complete and pushed as `a1fdb25f92049b121876d31266a5f0be7cf24ecf`: typed native/fallback context ownership, mutex-serialized access, checked `ZSTD_compress2` parameter application, explicit dictionary and failure results, checked u32 lengths, and pool cleanup are implemented. Fallback `unsafe_rust` coverage passes `29/29`; native `unsafe_rust,compression_zstd_ffi` coverage passes `30/30`; format, diff, feature-taxonomy, and locked-metadata gates pass. A full all-library feature run was not started below the mandatory 2-GiB disk floor; no result is claimed for that gate. The module remains test-only and TODO-829 through TODO-833 remain separate boundaries.
- Detail: `docs/todo/done/todo-828-unsafe-compressor-sync-ffi-contract.md`

### TODO-826 - Prove UnsafeMemoryPool cache and raw-pointer ownership
- Implementation is complete and pushed as `dd140a30595719c18e03acbfa603035c0b40efcc`: synchronized exact-base registry, preallocated/fallback ownership separation, release packet checks, overlap-safe checked copying, bounded prefetch, checked-out drop protection, and misuse/concurrency coverage. Focused debug `unsafe_rust` `24/24`, full debug library `2437/2437`, optimized release focused `24/24`, optional zstd focused `24/24`, strict all-target Clippy, formatting, and diff hygiene pass. Miri is unavailable on the pinned toolchain; the target was cleaned afterward.
- Detail: `docs/todo/done/todo-826-unsafe-memory-pool-cache-ownership.md`

### TODO-872 - Build Deterministic Frontend Clock and Suspension Test Coverage
- Implementation is complete: `scripts/tests/frontend/test-clock.ts` provides isolated wall/monotonic/RAF/visibility/timer controls for all three frontend unit environments; timing owners use the suspension matrix; and E2E fixtures use fixed unit-labeled timestamps. Shared UI `92/92`, Admin `307/307`, Desktop `412/412`, Admin/Desktop checks, both builds, Chromium 1.58.2 preflight, Admin E2E `70/70`, Desktop E2E `23/23`, and `git diff --check` pass. No product or visual UI implementation was made.
- Detail: `docs/todo/done/todo-872-frontend-deterministic-clock-tests.md`

### TODO-871 - Separate Browser Identifier and CSRF Entropy from Wall Time
- Implementation is complete and pushed as `a5799c6`: CSRF nonce generation is secure or fail-closed, toast and Sparkline IDs are monotonic owner-scoped identities, and all frontend UUID test doubles are deterministic. Shared UI `89/89`, Admin `307/307`, Desktop `411/411`, both checks, both builds, Chromium `1.58.2` preflight, Admin E2E `70/70`, Desktop E2E `23/23`, and `git diff --check` pass.
- Detail: `docs/todo/done/todo-871-browser-identifier-csrf-entropy.md`

### TODO-870 - Close Browser Timer and RAF Lifecycle Ownership
- Implementation is complete and pushed as `c52a05d`: every production timer, interval, RAF, ResizeObserver, visibility listener, delayed action, and shared feedback handle has an explicit owner; root persistence is serialized; hidden work is invalidated; and late async clipboard/parser/login continuations stop after unmount. Shared UI `88/88`, Admin `301/301`, Desktop `411/411`, both checks, both builds, Chromium `1.58.2` preflight, Admin E2E `70/70`, Desktop E2E `23/23`, and `git diff --check` pass.
- Detail: `docs/todo/done/todo-870-browser-timer-raf-lifecycle.md`

### TODO-869 - Make Browser Elapsed Measurements Monotonic and Visibility-Aware
- Implementation complete and pushed as `0d12cbb`: shared monotonic browser elapsed/rate policy, bounded delayed-gap handling, visibility rebasing, hidden RAF/animation reset, and timer-owned QKey paste suppression are implemented. Admin/Desktop checks, full unit suites, production builds, Chromium 1.58.2 preflight, Admin E2E 70/70, and Desktop E2E 23/23 pass.
- Detail: `docs/todo/done/todo-869-browser-monotonic-elapsed-visibility.md`

### TODO-868 - Define Frontend and Tauri Timestamp Boundary Contracts
- Implementation complete and committed as `c0ee04d`: shared branded Unix-second/Unix-millisecond contracts and runtime validators cover Tauri persistence/logs, desktop-owned creation, admin QKey metadata, and admin logs. Invalid backend timestamps are fail-closed without browser repair; log messages and structurally valid QKey rows remain visible with unavailable timestamp metadata. Admin/Desktop checks, unit suites, production builds, Admin E2E 70/70, isolated Desktop E2E 23/23, and Tauri host tests 42/42 pass.
- Detail: `docs/todo/done/todo-868-frontend-tauri-timestamp-boundary.md`

### TODO-824 - Close TimeSource injection, monotonicity, and test coverage gaps
- Implementation complete and pushed in `b2ef7719b94c860446d375486f858135e12bec32`: the test override is thread-local and nested, explicit owners remain authoritative, the clock contract and negative/concurrency tests are complete, and the fail-closed inventory classifies 957 locations with zero unclassified entries. Local root/Tauri gates pass 2413/2413 and 42/42; the isolated Omega checkout passes inventory 957/0, locked test-target checking, strict feature Clippy, and 2437/2437 library tests.
- Detail: `docs/todo/done/todo-824-time-source-test-isolation.md`

### TODO-823 - Unify wall-clock producers and make pre-epoch handling explicit
- Implementation complete and pushed in `4157892d72ba4a5ab5f15fca871047ec26afa199`: checked Unix wall-clock conversion and explicit error propagation now cover the TODO-823 server security/expiry, quota, profile, logging/audit, and Tauri persistence owners. Local root library tests pass 2410/2410, Tauri host tests pass 42/42, and the clean isolated Omega checkout passes locked test-target checking, strict library Clippy, and 2434/2434 library tests. Reality/Stealth timestamp behavior, Rust test isolation, and frontend/browser clocks remain their documented owner boundaries.
- Detail: `docs/todo/done/todo-823-wall-clock-provenance.md`

### TODO-822 - Define the boundary between injected monotonic time, Tokio time, and OS watchdog clocks
- Implementation complete and pushed in commits `1d7d56f` and the subsequent verification-doc update: the clock-domain matrix is enforced across product monotonic, Tokio, OS/native, wall, and diagnostic timing. Mixed client housekeeping/diagnostic, server drain, stealth shutdown, DNS worker, DoH, and blocking-DNS conversions are closed. Local checks, strict Clippy, and the complete 2,399-test library binary pass; a redundant later relink hit macOS `errno=28` and was cleaned. Clean isolated Omega commit `1d7d56f2e039cfcf2c500fc5948c6f4933273aa7` passes locked test-target checking and strict library Clippy; its full test attempt ends with SSH `255` before a summary, so no remote test pass is claimed. Dirty Omega checkouts remain untouched.
- Detail: `docs/todo/done/todo-822-runtime-clock-domain.md`

### TODO-821 - Make server and client stateful timing deterministic and source-consistent
- Implementation complete and pushed in commits `ff0a2d3` and `e0c6cca`: one engine-owned `ProtocolClock` now propagates through server/client state, rate/quota/blacklist/session/admin/DNS/TUN/quality/backend paths, with deterministic manual-clock coverage. Local library tests pass 2398/2398, strict library Clippy and locked check lanes pass, and the clean isolated Omega checkout passes locked test-target checking and strict library Clippy. Omega full-test attempts ended with remote-host disconnect before a result summary and are not claimed.
- Detail: `docs/todo/done/todo-821-server-client-time-source.md`

### TODO-820 - Route transport, stealth, and core monotonic clocks through one explicit time contract
- Implementation complete locally: `ProtocolClock` is propagated through the scoped transport, H3, Core, engine, Stealth, and qftls protocol graph, including packet-number ACK wrappers and timestamped BBR2/BBR3 RTT updates. The final library suite passes 2,390/2,390, strict `rust-tests` library Clippy passes, and format/diff hygiene passes. The native OS Condvar handshake deadline remains an explicit TODO-822 runtime-clock boundary; TODO-821, TODO-823, TODO-824, and TODO-825 retain their separate time domains. Local generated-target cleanup removed 5.7 GiB without touching `scripts/out`.
- Detail: `docs/todo/done/todo-820-transport-stealth-time-source.md`

### TODO-819 - Reconcile AMX CPU profile and documentation claims
- Implementation complete and pushed in `528eb0c`: `X86_P3e` is documented and commented as AVX-512F + GFNI, Intel AMX remains an independent fail-closed capability contract, and `Apple_M` is documented as a NEON/crypto profile whose Apple matrix bit is metadata only. The stale Apple AMX startup log and brain matrix-completeness claim are corrected; all 32 `Apple_M` references were inspected and no active Apple AMX arithmetic caller exists. The AMX contract checker passes, targeted AMX/profile-mask tests pass 3/3 and 7/7, and format/diff checks pass. TODO-676, TODO-818, and TODO-690 retain their separate dispatch/tile, proof, and equation boundaries.
- Detail: `docs/todo/done/todo-819-amx-profile-documentation.md`

### TODO-818 - Add an explicit AMX build and runtime proof lane
- Implementation complete locally: the exact `+amx-tile,+amx-int8` target-feature lane, Linux x86 tile-state probe, fail-closed backend capability field, machine-readable `AVAILABLE`/`UNAVAILABLE` result, scalar FEC parity/concurrency/dimension/scratch/telemetry coverage, Full-Suite/Comprehensive-Audit wiring, and CI artifact validation are present. Local ARM64 evidence reports `UNAVAILABLE` with zero failures and scalar fallback proof `PASS`; focused AMX tests pass 3/3, the six Wiedemann proof tests pass 6/6, strict `rust-tests` Library Clippy passes, and the full serial `rust-tests` library run passes 2386/2387 with the independent Admin HTTP panic test passing in isolation 1/1. Native x86 AMX execution and hosted CI remain external evidence boundaries; no native backend success is claimed.
- Detail: `docs/todo/done/todo-818-amx-proof-lane.md`

### TODO-817 - Remove the unbounded external cpuid dependency from AMX detection
- Implementation complete and pushed in `5c635a9c7ecd37d3e904457e22789569f366cea7`: `FeatureDetector` no longer launches `cpuid`; `AmxCapability` separates CPU, OS, compiler, and verified backend evidence and remains fail closed. Focused detector tests pass 2/2, local strict library Clippy passes, and Omega exact-source library tests pass 2409/2409 with strict Clippy. Omega rustfmt is unavailable because its toolchain lacks `cargo-fmt`; the local aggregate library run had two unrelated timing failures that passed in isolated reruns, and the runtime guardrail aggregate retains unrelated failures. TODO-676, TODO-818, TODO-819, and TODO-760 retain their separate boundaries.
- Detail: `docs/todo/done/todo-817-amx-detector-process-contract.md`

### TODO-816 - Validate AMX kernel semantics and tile-register configuration
- Implementation complete and pushed in `afe1d17003464981ab67ca666e7e98ce55114fc6`: the production Wiedemann path uses checked scalar GF(256) SpMV on every target; the former raw AMX kernels, global tile config, compile-time-absent decoder branch, and stale audit allowlist entries are removed. Focused Wiedemann tests pass 4/4, FEC tests 80/80, local library 2383/2383, Omega exact-source library 2407/2407, local and Omega strict library Clippy pass with `-D warnings`, and local format/diff checks pass. Omega rustfmt is unavailable because its toolchain lacks `cargo-fmt`; native AMX execution remains TODO-818 evidence. TODO-676, TODO-817, TODO-818, TODO-819, and TODO-690 retain their separate boundaries. Post-push Graphify remains a separate fail-closed evidence gate.
- Detail: `docs/todo/done/todo-816-amx-kernel-semantics.md`

### TODO-815 - Close audit event admission before shutdown
- Implementation complete and pushed in `90decbc7d8543294fc57ef33a79f8fdfe3268a3c`: `AuditLog` now linearizes `Open`/`Closing`/`Closed` admission with an in-flight producer count, drains admitted producers before the final flush barrier, returns typed lifecycle rejection errors, and exposes the same outcomes through dropped-event telemetry. Focused audit coverage passes `28/28`, the metrics test `1/1`, the probe tests `3/3`, the local full library passes `2381/2381`, Omega passes `2405/2405`, and strict library Clippy passes locally and on Omega. Local format/diff checks pass; Omega lacks `rustfmt`, so its remote format check remains an environment limitation. TODO-675, TODO-726, TODO-727, TODO-728, and TODO-849 retain their separate boundaries. Post-push Graphify remains fail-closed and is refreshed separately.
- Detail: `docs/todo/done/todo-815-audit-shutdown-admission-race.md`

### TODO-814 - Bound audit event payload allocations before queue admission
- Complete and pushed: `AuditLog::log_typed()` enforces JSON-encoded UTF-8 bounds for source IP, client ID, reason, message, and the combined dynamic payload before cloning or queue admission. Typed rejections, separate counters, metrics, probe output, boundary tests, and SSOT documentation are reconciled. The exact pushed Omega source passes the full library `2403/2403`, strict library Clippy, audit probe `3/3`, focused audit `26/26`, metrics `1/1`, formatting, and diff hygiene gates. Graphify remains explicitly fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T170254Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-814-audit-event-payload-bounds.md`

### TODO-669 - DNS forwarding needs transaction validation and an overall timeout
- Local implementation is complete and pushed as `bcc68009f61d686856be844c5af571807f22d449` (`TASK 669: Bound DNS forwarding`): the shared 4,096-byte DNS message and 12-byte header limits reject unsafe public input; DoH response bodies are bounded before full collection; DoH and plain-UDP fallback share a monotonic 5-second aggregate deadline; the async plain-DNS branch owns synchronous socket work in `spawn_blocking`; UDP oversize datagrams are rejected through a 4,097-byte receive sentinel; and client/listener limits use one shared constant. The dedicated benchmark records separate allocation counts and Criterion latency for DoH request/response, UDP receive, and synthetic SERVFAIL stages. DNS tests pass 30/30, client listener 3/3, server module 145/145, full library 2,336/2,336, all-target check passes, strict library Clippy passes, and the full matrix is 2,336/2,336 library plus 41/43 binary tests with only the existing TODO-800 runtime-reload failures. Broad all-target Clippy retains the same eight unrelated baseline diagnostics. Remote `origin/main` matches the commit; post-push Graphify is fail-closed at `scripts/out/audits/graphify-20260805T084640Z/graphify-evidence.json`. TODO-810, TODO-721, TODO-770, TODO-650, and native/Omega/live proof remain separate boundaries.
- Detail: `docs/todo/done/todo-669-dns-allocs-timeout.md`

### TODO-671 - Sensitive file creation relies on umask instead of explicit mode
 - Implementation complete: Linux resolver targets now use explicit `0o644`, resolver locks/backups and audit files use `0o600`, rotating operational logs use explicit `0o640`, and profile persistence remains on TODO-662's atomic `0o600` temporary path. Existing audit reopens reassert mode through the opened handle before append; resolver restore no longer delegates destination mode to `std::fs::copy`. Local macOS library tests pass 2,339/2,339, strict library Clippy, formatting, and diff hygiene pass. The full all-target matrix retains only the two pre-existing TODO-800 runtime-reload fixture failures, and broad all-target Clippy retains eight unrelated baseline diagnostics. The Linux cross-target check is unavailable because this macOS host has no Linux C compiler/sysroot; no native Linux/Omega proof is claimed. Commit `5fa47f570105015c2ce55d8063e5e983d18da521` (`TASK 671: Make file modes umask independent`) is pushed and matches `origin/main`; post-push Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T090928Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-671-umask-file-permissions.md`

### TODO-668 - DNS proxy has no per-client query rate limiting
- Completed and pushed as `d619a2d`: one shared bounded `DnsAdmission` now owns client-listener and server MASQUE/TUN admission, with source-IP/session identity, global and per-identity budgets, in-flight cap, hard state bound, idle pruning, lifecycle cleanup, explicit public admitted helper, no-amplification drop semantics, and reasoned metrics. DNS 23/23, client listener 3/3, server admission 4/4, metrics 2/2, full library 2329/2329, all-target check, strict library Clippy, formatting, and diff hygiene pass. The full all-target matrix retains only the two existing TODO-800 runtime-reload fixture failures (41/43 in `quicfuscate`); all-target Clippy retains eight unrelated baseline diagnostics. `d619a2d8b45089ee4233dcd4302b0e1c6a9e0a96` matches `origin/main`; post-push Graphify is fail-closed `BLOCKED` in `scripts/out/audits/graphify-20260805T080752Z/graphify-evidence.json`. Detail archived at `docs/todo/done/todo-668-dns-rate-limiting.md`.
- Detail: `docs/todo/done/todo-668-dns-rate-limiting.md`

### TODO-809 - Admin HTTP session store has no explicit live-session count cap
- Local implementation is complete and pushed as `e3a6189`: one server admits at most 256 live sessions, prunes expired records before admission, rejects capacity-exceeding successful logins with HTTP 429 without evicting active sessions, exposes lifecycle counters, and clears sessions after normal shutdown drain. Admin HTTP tests pass 77/77 and the full library passes 2324/2324; workspace all-target execution retains only the two pre-existing TODO-800 runtime-reload fixture failures (41/43 in `quicfuscate`), and strict all-target Clippy retains eight unrelated baseline diagnostics. Native/deployed proof remains a separate external gate; post-push Graphify is fail-closed `BLOCKED` in `scripts/out/audits/graphify-20260805T073437Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-809-admin-session-store-live-session-cap.md`

### TODO-810 - DoH response validation stops at transaction ID
- Implementation complete and pushed as `690376a9c9c895f8422b6fcf3330d7df49c4eb30` (`TASK 810: Validate DoH response semantics`): `resolve_via_doh_with_client()` now requires response QR, standard opcode, exactly one bounded question, canonical case-insensitive QNAME, exact raw QTYPE/QCLASS, and transaction-ID match. Bounded compression pointers reject forward/reserved/looping references; answer, authority, and EDNS sections remain opaque. Deterministic local HTTP coverage passes valid compressed-answer/EDNS, wrong question fields, QR/opcode/count/name, wrong ID, HTTP status/content-type, and oversized-body cases. DNS module tests pass 33/33, full library 2,342/2,342, workspace all-target check and strict library Clippy pass. The full matrix retains only the two pre-existing TODO-800 binary failures (41/43); broad all-target Clippy retains eight unrelated baseline diagnostics. `origin/main` and `git ls-remote origin refs/heads/main` match the commit; post-push Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T092917Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-810-doh-response-semantic-validation.md`

### TODO-672 - Log rotation has no external trigger hook (e.g., SIGHUP)
- Implementation complete and pushed as `09849240f9f5677c8e66e5f1d7c06cbac9962340` (`TASK 672: add external log rotation triggers`): writer-owned FIFO `Rotate`/`Reopen` commands now provide bounded acknowledgements; authenticated `POST /api/logs/rotate` force-rotates and emits a typed audit event; SIGHUP preserves next-connection-only config reload and independently reopens the file sink. External rename and copytruncate are supported and covered by deterministic appender and writer tests. The final library matrix passes 2,355/2,355, auxiliary/integration targets pass, and the `quicfuscate` binary remains 41/43 only because of the two known TODO-800 runtime-reload/PMTU fixture assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`; broad all-target Clippy retains eight unrelated baseline diagnostics. Local `main`, `origin/main`, and `git ls-remote origin refs/heads/main` match the commit. Post-push Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T111940Z/graphify-evidence.json`; completeness is `PASS` with tracker 771, Queue 138, Completed 592, current details 401/401, done archive 405, explicit archive exceptions 36.
- Detail: `docs/todo/done/todo-672-log-rotation-sighup.md`

### TODO-811 - Environment controls bypass the canonical parser and silently fall back
- Implementation complete and pushed as `bbc73d0731fe75afc2faaf3520fb094b2b3cf55b` (`TASK 811: consolidate environment parser authorities`): direct production environment authorities now use immutable snapshots or documented validated startup exceptions; compression, memory-pool, Reality, trusted-proxy, optional zstd, metrics, CLI, NUMA, SIMD, and io_uring controls have explicit typed invalid-value contracts and regression coverage. The final library matrix passes 2,363/2,363; workspace check, default and optional strict library Clippy, formatting, and diff hygiene pass. Graphify and audit-completeness results are recorded in the archived detail; native, Omega, external-process, deployed, and live-wire proof remain separate gates.
- Detail: `docs/todo/done/todo-811-env-parser-authority.md`

### TODO-770 - DNS query admission accepts malformed wire semantics and rewrites questions
- Implementation complete and pushed as `b6979bfdd057ddd2b6a7524c93a16cf7848c990b` (`TASK 770: harden DNS query wire admission`): the shared DNS parser now enforces supported query flags, standard opcode, exactly one question, bounded RFC 1035 name/pointer semantics, and exact question/QTYPE/QCLASS wire preservation; server IPv4/IPv6 UDP/53 admission now enforces exact lengths, rejects IPv4 fragments, and validates the applicable checksums. DNS parser tests pass 36/36, the complete server module passes 147/147, the full library passes 2,368/2,368, default and optional workspace checks pass, and default/optional strict library Clippy passes. The full workspace matrix retains only the two existing TODO-800 binary fixture failures (41/43 at `src/main_parts/late_tests_and_mlock.rs:566,638`). Local `main`, `origin/main`, and `git ls-remote origin refs/heads/main` match. Post-push Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T125741Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-770-dns-query-parser-wire-semantics.md`

### TODO-673 - CLI control commands serialize unbounded and weakly validated strings
- Implementation complete and pushed as `cd73dec2490d49c40ca2074207d471e2fbc54bb5` (`TASK 673: bound admin CLI request frames`): the Unix-only CLI target is registered in Cargo, builds typed commands, enforces exact arity and shared value normalization before socket I/O, rejects unknown command fields, and emits one bounded newline-terminated JSON request frame. The serial server filter passes 490/490, the complete library passes 2,372/2,372, `quicfuscate-ctl` passes 8/8 and strict binary Clippy, default/optional workspace checks and strict library Clippy pass, and the full matrix leaves only the two existing TODO-800 runtime-reload/PMTU fixture failures in `quicfuscate` (41/43). Post-push Graphify is explicitly `BLOCKED` at `scripts/out/audits/graphify-20260805T135004Z/graphify-evidence.json`; completeness passes with tracker 771, Queue 135, Completed 595, current details 398/398, done archive 408, and zero unexpected untracked paths.
- Detail: `docs/todo/done/todo-673-cli-unbounded-strings.md`

### TODO-812 - Join the logging worker when global logger installation fails
- Implementation complete and pushed as `b4b003b03c26ec740f234d02671a499682d447e6` (`TASK 812: join logger worker on install failure`): the failed `log::set_boxed_logger()` path now sends the bounded writer shutdown command and joins the temporary worker before returning `LoggerAlreadyInstalled`. Logging unit tests pass 19/19, process integration passes 3/3, the complete library passes 2,374/2,374, default/optional workspace checks and strict library Clippy pass, and the full matrix retains only the two existing TODO-800 runtime-reload/PMTU fixture failures in `quicfuscate` (41/43). Post-push Graphify is explicitly `BLOCKED` at `scripts/out/audits/graphify-20260805T141655Z/graphify-evidence.json`; completeness passes with tracker 771, Queue 134, Completed 596, current details 397/397, done archive 409, and zero unexpected untracked paths.
- Detail: `docs/todo/done/todo-812-logger-init-failure-worker.md`

### TODO-813 - Add upper bounds to audit persistence configuration and probe inputs
- Implementation complete and pushed as `7ea5daf432265bf67fb12eb6f0ace25ef9bdf526` (`TASK 813: bound audit persistence configuration`): one shared `AuditOptions::validate()` contract now bounds queue capacity `1..=65,536`, segment bytes `1..=128 MiB`, retained segments `1..=64`, and flush timeout `1..=60,000 ms` across product configuration, direct API, global startup, and the probe. Probe event/producer ceilings are `1..=1,000,000` and `1..=64`; machine-readable output reports effective values and ceilings. Current tests are 24/24 audit, 1/1 config, 3/3 probe, and 2,377/2,377 library. The pre-final-parent-guard workspace matrix retained only the two existing TODO-800 `quicfuscate` assertions (41/43); final current-source full-matrix retry was stopped at the mandatory disk floor and is not counted. Post-push Graphify is explicitly `BLOCKED` at `scripts/out/audits/graphify-20260805T151507Z/graphify-evidence.json`; audit completeness passes with tracker 771, Queue 133, Completed 597, current details 396/396, done archive 410, and zero unexpected untracked paths. TODO-814 owns event payload bounds and TODO-727 existing-file read bounds.
- Detail: `docs/todo/done/todo-813-audit-config-upper-bounds.md`

### TODO-670 - Environment parsing silently ignores invalid values
- Implementation complete and pushed as `dad7defb61a45aa87204e2d4cdd60ac65811fe99` (`TASK 670: make environment parsing deterministic`): `EnvSnapshot` now provides one warning-producing invalid-value contract, ordered aliases skip empty or invalid canonical values, and the StealthManager, core connection, FEC, Brain, Reality, stealth, TLS Cover, recovery, and BBR2/BBR3 construction paths share one immutable environment generation. Library environment-mutating tests use one process-wide guard; direct production parsers remain explicitly owned by TODO-811. Format, diff hygiene, workspace all-target check, full library tests 2,350/2,350, strict library Clippy, and the full matrix's auxiliary targets pass. The `quicfuscate` binary remains 41/43 only because of the two known TODO-800 runtime-reload/PMTU fixture assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`; broad all-target Clippy retains eight unrelated baseline diagnostics. `origin/main` and `git ls-remote origin refs/heads/main` match the commit; post-push Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260805T105401Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-670-env-var-race-validation.md`

### TODO-665 - Admin replay protection has a fixed FIFO history without time-based expiry
- Local implementation is complete and pushed as `aaa2ec9`: per-session replay fingerprints are timestamped and pruned at the explicit five-minute window while retaining the 4,096-entry O(1)-amortized bound; duplicate-within-window, expiry, memory, and post-eviction behavior are covered. Admin HTTP coverage passes 74/74, the contract target 2/2, the full library 2321/2321, workspace checking and strict library Clippy pass. The full all-target matrix retains only the two existing TODO-800 runtime-reload fixture failures; all-target strict Clippy retains eight unrelated baseline diagnostics. External deployed HTTP proof and TODO-809 live-session count ownership remain separate; post-push Graphify is fail-closed `BLOCKED` in `scripts/out/audits/graphify-20260805T005244Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-665-session-store-replay-unbounded.md`

### TODO-769 - Embedded server TUN address and routing owner use different configuration sources
- Local implementation is complete and pushed as `1c277e9`: `ServerConfig` is the sole effective server-network authority for embedded and standalone TUN provisioning, routing/firewall subnet selection, isolation, live addresses, and IPv4/IPv6 pools. Matching embedded/standalone tests and conflicting IPv4/IPv6 pre-open rejection pass; focused server coverage passes 13/13, standalone coverage passes 2/2, the complete server module passes 145/145, the full library passes 2319/2319, workspace checking and strict library Clippy pass. The full all-target matrix retains only the two existing TODO-800 runtime-reload fixture failures; all-target strict Clippy retains eight unrelated baseline diagnostics. Native privileged Linux/Omega/live-wire proof remains external; post-push Graphify is fail-closed `BLOCKED` in `scripts/out/audits/graphify-20260805T003550Z/graphify-evidence.json`.
- Detail: `docs/todo/done/todo-769-embedded-tun-routing-config-drift.md`

### TODO-768 - Parallel library test flakes on scheduler-sensitive profile jitter wall-clock bound
- Completed in the test contract: the jitter regression now verifies future readiness/deferred frame emission without a scheduler-sensitive one-second assertion, and the ClientHello policy test disables cosmetic jitter for immediate inspection. Focused qftls passes 23/23; serial and default parallel library gates pass 2,312/2,312. Runtime guardrails retain three unrelated baseline critical findings and one known warning; no native/Omega/live-wire proof is claimed.
- Detail: `docs/todo/done/todo-768-profile-jitter-test-flake.md`

### TODO-767 - MemoryPool adaptive sizing overrides explicit body-pool block configuration
- Completed locally: `MemoryPool::new()` now has an explicit block-size contract, `new_adaptive()` owns MTU-based packet sizing, body-pool telemetry reports the effective allocation size, and compression/memory-pool regressions pass. The full library passes 2,312/2,312, workspace checking and strict library Clippy pass, and the optimization fast suite passes 5/5. Runtime guardrails retain three unrelated baseline critical findings and one known warning; no native/Omega/live-wire proof is claimed.
- Detail: `docs/todo/done/todo-767-memory-pool-explicit-block-contract.md`

### TODO-761 - Reconcile the completed sccache CI caching contract
- Archived after current workflow and owner revalidation on 2026-08-11. Commit `e399c88` retires TODO-155's unsupported sccache completion and performance claim across Rust CI, Clippy Matrix, Windows Omega, and release boundaries. Current Cargo/target caches remain directory caching only; no compiler-cache hit, invalidation, failure-propagation, or 30% improvement claim exists. TODO-754 remains separately blocked.
- Detail: `docs/todo/done/todo-761-sccache-ci-contract-reconciliation.md`

### TODO-762 - Make the MSRV and stable-toolchain support contract truthful
- Archived after current toolchain and owner revalidation on 2026-08-11. Commit `a443616` establishes Rust `1.97.1` as the exact root/CI/release baseline with no `rust-version` or MSRV promise. TODO-151 and TODO-204 remain reconciled historical archives; TODO-758 was later reopened for isolated fuzz-lock drift and is now re-archived with hosted sanitizer proof; TODO-754 remains separately blocked. Original evidence remains all-target check, 2,308/2,308 library tests, and strict library Clippy on the pinned toolchain.
- Detail: `docs/todo/done/todo-762-msrv-toolchain-contract.md`

### TODO-763 - Reconcile the completed Cargo feature consolidation claim
- Archived after current manifest, audit-script, documentation, and hosted-gate revalidation on 2026-08-11. The 26 direct and 29 effective Cargo feature selectors are classified and checked after TODO-838 removed the AF_XDP experiment; Clippy Matrix run `31498749415` passes the taxonomy gate on revision `9abb32f`. Seven TODO-176 legacy groups remain rejected, and the stale fewer-than-ten completion claim stays retired. No product or UI behavior changed.
- Detail: `docs/todo/done/todo-763-feature-consolidation-contract.md`

### TODO-764 - Reconcile the web-admin publish artifact ownership contract
- Completed in the current reconciliation: `assets/web-admin/` is explicitly generated and ignored, TODO-202's stale tracked-tree claim is retired, build/local/E2E/release/installer ordering is documented, and `scripts/audits/verify-web-admin-publish-contract.sh` passes the ownership and missing-bundle negative contract without changing UI sources.
- Detail: `docs/todo/todo-764-web-admin-publish-artifact-contract.md`

### TODO-766 - Reconcile the transport ClientHello template setter contract
- Completed in commit `c1d894f`: removed the write-only `Config::chlo_template` storage and its three setters, removed the dead transport injection helpers, renamed the remaining deterministic profile catalog, and documented rustls as the sole real-wire ClientHello owner. Focused Rust validation and the complete local audit gates remain recorded in the task detail; hosted/native proof is not claimed.
- Detail: `docs/todo/done/todo-766-write-only-chlo-template.md`

### TODO-663 - Client TUN configuration omits generic IPv6 propagation
- Archived after current-source and owner revalidation on 2026-08-11. Commit `8dfdabd` closes canonical `tun_ip6`/`tun_prefix6` schema fields, typed IPv4/IPv6/dual-stack normalization, `ClientRuntime` projection into native `TunConfig`, fail-closed malformed/MTU/source validation, and explicit single-family compatibility rejection. TODO-620, TODO-683, TODO-731, and TODO-866 are archived; native and privileged live evidence remains unclaimed where unavailable.
- Current ownership is in `crates/qf-engine-types`, `crates/qf-transport-types`, and the root client/interface integration. Original focused evidence remains config 3/3, generic projection 5/5, compatibility 6/6, library 2,295/2,295, and all-target binary 41/43 with the two then-known unrelated reload failures.
- Detail: `docs/todo/done/todo-663-tun-config-hardcoded-ipv4.md`

### TODO-799 - Align audit validator with the blocked tracker section
- Archived after current tracker, fixture, Graphify-boundary, and Git-scope revalidation on 2026-08-11. The canonical section/status contract includes `Blocked`, `AUDIT_COMPLETE`, deterministic ordering, required sections, stale-path rejection, and failable positive/negative fixtures. The live completeness gate passes with tracker `785`, current details `230/230`, archived details `590`, `36` explicit archive exceptions, `1,005` tracked paths, `30,948` ignored paths, and zero untracked paths; Graphify remains explicitly `BLOCKED` under TODO-754.
- Detail: `docs/todo/done/todo-799-audit-validator-blocked-section.md`

### TODO-689 - Audit remaining unsafe code in cpu_dispatch, telemetry, cache_and_const, lib.rs, and tests
- Archived after current-source and owner revalidation on 2026-08-11. TODO-670, TODO-752, TODO-811, TODO-826, TODO-827, TODO-834, TODO-835, TODO-836, TODO-841, TODO-843, and TODO-862 through TODO-865 are archived. Current prefetch ownership is in `crates/qf-cpu`, Windows NUMA ownership is in `crates/qf-memory-pool`, and retained global-pool/test-only constant-pool compatibility remains under `src/optimize`. Native x86, AArch64, Windows, privileged, and live network execution remains unclaimed where unavailable.
- TODO-730 and TODO-754 remain separate blocked owners for the global machine-checkable audit/register and fail-closed Graphify evidence; this archive does not close them. Audit coverage includes direct prefetch callers, SIMD intersections, Windows NUMA FFI, global-pool/auto-tuner initialization, test-only environment mutation, constant-buffer helpers, audit scripts, CI workflows, documentation, related owners, history, and the telemetry/crate-root/transport false positives. No production implementation or runtime verification was made in the audit phase.
- Detail: `docs/todo/done/todo-689-remaining-unsafe-audit.md`

### TODO-686 - Audit unsafe code in FEC
- Archived after current-source and owner revalidation on 2026-08-11. TODO-581, TODO-594, TODO-634 through TODO-637, TODO-676, TODO-679, TODO-689, TODO-690, TODO-715, TODO-811, TODO-816 through TODO-819, TODO-832, TODO-834 through TODO-842, and TODO-855 through TODO-860 are archived. Native x86 AVX-512/VBMI2 and PCLMUL execution, the native AMX negative matrix, privileged Linux netns execution, sanitizer, Miri, and unavailable cross-platform lanes remain explicitly unclaimed.
- Audit coverage includes all FEC source and test modules, unsafe SIMD/AMX sites, public decoder/matrix/wire/Fountain boundaries, direct core/runtime callers, feature gates, malformed-input tests, fuzz and shell/benchmark/netns proof, documentation, related owners, and history. No production implementation or runtime verification was made in the audit phase. Verification: commit `82c1308`; Graphify `BLOCKED` at `scripts/out/audits/graphify-20260807T025026Z/graphify-evidence.json`; completeness PASS with `tracker=777`, `current_details=371/371`, `missing_current=0`, `done_archive=441`, and `explicit_archive_exceptions=36`.
- Detail: `docs/todo/done/todo-686-fec-unsafe-audit.md`

### TODO-688 - Audit remaining audit-file FFI and Windows API boundaries
- Archived after current-source and owner revalidation on 2026-08-11. TODO-671, TODO-675, TODO-726, TODO-728, TODO-813, TODO-814, TODO-815, and TODO-861 are archived. Current ownership is in `crates/qf-audit/src/lib.rs`, where descriptor-bound Unix hardening, typed security-failure propagation, local FFI contracts, and interior-NUL Windows-path rejection are present. Native Windows `MoveFileExW` success/failure execution and privileged root `fchown` failure execution remain explicitly unclaimed.
- Audit coverage includes the full audit implementation and tests, audit probe, direct startup/runtime callers, limits false positive, audit suites and guardrails, documentation, related TODO owners, and history. No production implementation or runtime verification was made in the audit phase.
- Detail: `docs/todo/done/todo-688-audit-server-unsafe.md`

### TODO-684 - Audit unsafe code in privilege drop, mlock, and qftls/secret key handling
- Archived after current-source and owner revalidation on 2026-08-11. TODO-643, TODO-651, TODO-652, TODO-653, and TODO-849 through TODO-854 are archived; TODO-516 and TODO-678 remain explicit separate blocked pooled-lock owners and are not closed by this audit archive.
- Current-source and owner reconciliation covers privilege reduction, all-thread verification, libc lookup and identity boundaries, process and pool memory-lock callers, standalone and embedded startup, TLS identity preload, secret wrappers and key-output paths, direct callers, platform gates, tests, scripts, documentation, related TODOs, and history. No production implementation or runtime verification was made in the audit phase. Verification: commit `9430f83`; Graphify `BLOCKED` at `scripts/out/audits/graphify-20260807T022638Z/graphify-evidence.json`; completeness PASS with `tracked=991`, `ignored=32411`, `accounted=33402`, `current_details=370/370`, `missing_current=0`, `done_archive=441`, `explicit_archive_exceptions=36`.
- Detail: `docs/todo/done/todo-684-privilege-mlock-unsafe-audit.md`

### TODO-683 - Audit interface and platform unsafe boundaries
- Archived after current-source and owner revalidation on 2026-08-11. TODO-654, TODO-664, and TODO-843 through TODO-848 are archived; injected Windows Win32/BFE failures and privileged Windows residue execution remain explicit unavailable native lanes, not inferred successes.
- Current-source and owner reconciliation covers interface dispatch, generic and native TUN I/O, Wintun/WFP cleanup, direct callers, platform gates, tests, scripts, documentation, and history. No product or test implementation was made in the audit phase. Verification: commit `e7225fba058ef7015ee262c66780673a1c2ef174`; Graphify `BLOCKED` at `scripts/out/audits/graphify-20260807T021809Z/graphify-evidence.json`; completeness PASS with `tracked=991`, `ignored=31892`, `accounted=32883`, `current_details=370/370`, `missing_current=0`.
- Detail: `docs/todo/done/todo-683-interface-platform-unsafe-audit.md`

### TODO-664 - Legacy Windows PlatformBackend stale Unsupported finding
- Closed as stale after the complete source, caller, trait, history, test, and documentation audit. Commit `702b903` already made the compatibility path fail closed before host mutation and added an explicit message directing callers to native Wintun. `PlatformError::Unsupported` is the existing canonical variant; no production code changed in this audit phase.
- Detail: `docs/todo/done/todo-664-windows-create-tun-legacy.md`

### TODO-620 - Client backend ignores tun_ip/tun_netmask/tun_subnet_prefix config and hardcodes 10.8.0.2/24
- Closed: `ClientBackend::connect_inner()` now resolves the configured TUN address, CIDR prefix, gateway, and family-matched split default routes. The legacy IPv4 default remains `10.8.0.2/24` with gateway `10.8.0.1`.
- Verification: focused backend tests 11/11, full library 2,183/2,183, locked all-target checking, strict all-feature Clippy, format, and diff checks pass.
- Detail: `docs/todo/done/todo-620-client-backend-ignores-tun-ip-config.md`

### TODO-619 - ClientRuntime::connect failure path orphans connection and state
- Closed: every failure after `ClientRuntime::connect()` assigns a connection now shuts down and joins owned I/O tasks, closes and removes the QUIC connection, clears socket and driver state, and returns to `Running`.
- Verification: focused client tests 5/5, full library 2,179/2,179, locked all-target checking, strict all-feature Clippy, format, and diff checks pass.
- Detail: `docs/todo/done/todo-619-client-connect-failure-orphans-connection.md`

### TODO-618 - Retry token length constant 160 is below the worst-case encoded size 169
- Closed: `MAX_RETRY_TOKEN_LEN` is 192, and the real `issue_for_initial` plus `validate` path now accepts the exact 169-byte maximum bounded IPv6, 20-byte CID, and 64-byte credential token.
- Verification: focused DDOS tests 4/4, server module 135/135, full library 2,177/2,177, locked all-target check, strict all-feature Clippy, format, and diff checks pass.
- Detail: `docs/todo/done/todo-618-retry-token-length-capacity.md`

### TODO-659 - Retry token aggregate-length ordering claim reconciled
- Archived after current source, caller, constant, test, and owner revalidation on 2026-08-11. Current field limits cap accepted tokens at 169 bytes under `MAX_RETRY_TOKEN_LEN=192`; oversized fields fail before allocation and HMAC, and aggregate oversize fails before tag verification. TODO-618 and commit `823e327` own the real capacity correction and Rust evidence; no production code changed.
- Detail: `docs/todo/done/todo-659-retry-token-length-validation.md`

### TODO-617 - Admin Unix socket permissions and stale-path cleanup
- Closed: `AdminServer` now enforces owner-only mode 0600, an 8 KiB command-frame cap, a five-second absolute read deadline, and type-, owner-, liveness-, and identity-aware stale-path and shutdown cleanup.
- Verification: focused admin tests 13/13, server module 135/135, full library 2,176/2,176, all-target check, strict all-feature Clippy, format, and diff checks pass.
- Detail: `docs/todo/done/todo-617-admin-socket-permissions.md`

### TODO-616 - SessionManager add/rebind conflict contract
- Closed the session-index integrity gap. `SessionManager::add` rejects duplicate session IDs and IPv4/IPv6/remote keys before mutation; `remove` uses owner checks; `rebind_remote_addr` rejects a foreign remote owner without removing the old mapping; and validated path migration restores its transport key when domain rebind fails.
- Focused SessionManager tests passed 9/9, migration tests passed 2/2, the complete server module passed 135/135, the full library passed 2,170/2,170, locked all-target checking passed, strict all-feature Clippy passed, and formatting/diff hygiene passed.
- Detail: `docs/todo/done/todo-616-session-map-key-conflicts.md`

### TODO-615 - Health and MetricsServer HTTP endpoints stall on one slow connection
- Closed the sequential-read gap for HealthServer, active MetricsServer, and test-only GlobalMetricsServer. The shared reader incrementally frames headers through `\r\n\r\n`, applies a five-second per-read deadline, caps requests at 8 KiB, rejects unterminated oversized input with 413, and admits at most 32 per-connection workers. The separate telemetry endpoint remains unchanged and retains its own timeout/semaphore/bind contract.
- Shared reader passed 1/1, HealthServer half-open integration passed 1/1, MetricsServer and GlobalMetricsServer tests passed 16/16, the complete server module passed 135/135, the full library passed 2,165/2,165, and locked all-target checking passed. Strict Clippy remains blocked only by the two pre-existing `needless_borrow` diagnostics in `src/implementations/client/dns_runtime.rs`.
- Detail: `docs/todo/done/todo-615-http-endpoints-read-timeout.md`

### TODO-614 - Byte-rate burst contract is undefined relative to PPS burst policy
- Defined and implemented byte-bucket capacity as `ceil(max_bps * effective_burst / max_pps)` with checked arithmetic; `burst_size` remains packet-token capacity and `refill_interval` remains refill cadence. Overflow and zero-packet-rate cases fail closed.
- Focused limits tests passed 46/46, the exact runtime-admin lifecycle regression passed 1/1, the complete server test module passed 135/135, the full library passed 2,161/2,161, and locked all-target checking passed. Strict Clippy remains blocked only by two pre-existing `needless_borrow` diagnostics in `src/implementations/client/dns_runtime.rs`.
- Detail: `docs/todo/done/todo-614-byte-bucket-burst-mismatch.md`

### TODO-806 - Native IPv4 TTL-expiry proof fails in the multi-client harness
- Closed the source and native wire-proof gap. The corrected tunnel-ingress path preserves valid IPv4 TTL 0/1 packets until routing classification. Native run `30827540460`, job `91733001327`, artifact `server-ipv4-ptb-native` (ID `8861606310`, SHA-256 `28eaf231afd5feb1f931a276d78e98f761b35a4ee6b4a39fa83542f1569e4e3c`) contains one TTL-1 ICMP Echo request and one server-sourced TTL-128 ICMP Time Exceeded response. The fail-closed verifier proves endpoints, ICMP type/code, IPv4 and ICMP checksums, and exact 28-byte quote matching; server telemetry changes `time_exceeded=0` to `1`. Independent PTB evidence remains intact with `packet_too_big=0` to `3` and `icmpv6=0` to `1`. The later backpressure-quiescence failure is separate and remains open under the queue/runtime task set.
- Detail: `docs/todo/done/todo-806-native-ttl-expiry-proof-failure.md`

### TODO-613 - IPv4 packet larger than TUN MTU without DF has an explicit PTB disposition
- Closed the selected fail-closed PTB-for-all contract before either MASQUE or framed-H3 TUN write. Local unit coverage proves valid IPv4 PTB for DF=0 and DF=1, including checksums, quote, source/destination, MTU, and telemetry; the complete server module passed 134/134, the full library passed 2,157/2,157, all-target checking, formatting, diff hygiene, and native-harness syntax passed. Native CI run `30824438300`, job `91722362887`, passed the complete server-owned PTB gate: both 1,328-byte IPv4 probes arrived unfragmented, both returned server-sourced `Frag needed and DF set (mtu = 1280)`, IPv6 returned `Packet too big: mtu=1280`, and metric deltas were `packet_too_big=3` plus `icmpv6=1`. The overall job later failed only at the independent TTL-expiry assertion tracked by TODO-806.
- Detail: `docs/todo/done/todo-613-ipv4-mtu-non-df-drop.md`

### TODO-612 - Client fan-out queue is unbounded (memory growth under broadcast flood)
- Closed the shared MASQUE/framed-HTTP/3 fan-out queue gap with 256-entry/384 KiB global admission, 32-entry/64 KiB per-source admission, FIFO accounting, a 64-packet housekeeping drain budget, and `quicfuscate_client_fanout_dropped_total` telemetry. Rejected packets are dropped before payload cloning; housekeeping drains the queue even without new UDP input and no second unbounded backlog container is created. Four focused tests passed, the complete server module passed 133/133, and the full library gate passed 2,156/2,156. All-target check, formatting, and diff hygiene passed; local strict Clippy remains blocked only by the pre-existing `TlsCover::client_hello_custom` dead-code lint owned by TODO-709/TODO-752/TODO-787. Remote Clippy Matrix run `30815583508` passed all eight feature lanes on source revision `c216cc5`.
- Detail: `docs/todo/done/todo-612-fanout-queue-unbounded.md`

### TODO-611 - DNS intercept has no rate limit - client can flood spawn_blocking upstream queries
- Closed the server-TUN DNS flood path with one per-standalone-runtime admission guard: 128 concurrent `spawn_blocking` exchanges, a 2,000 PPS global cap with a 4,000-query burst, a 100 PPS per-source-IP cap with a 200-query burst, idle bucket pruning, and `quicfuscate_dns_intercept_dropped_total` telemetry. Admission drops consume the intercepted DNS packet and never reach generic fan-out or TUN forwarding. The optional response cache was evaluated but not added without a TTL-safe transaction-ID and wire-question contract. Admission tests passed 2/2, the metric test passed 1/1, DNS passed 22/22, the complete server module passed 131/131, and the full library gate passed 2,153/2,153. All-target check, formatting, and diff hygiene passed; Clippy Matrix run `30812779253` passed all eight feature lanes on source revision `69e3511`; local strict Clippy remains blocked only by the pre-existing `TlsCover::client_hello_custom` dead-code lint owned by TODO-709/TODO-752/TODO-787.
- Detail: `docs/todo/done/todo-611-dns-intercept-rate-limit.md`

### TODO-687 - Audit unsafe code in io_uring batch and client io_driver
- Closed the io_uring sender/receiver and client `io_driver` unsafe/lifetime audit. Commit `cec9c9c` repairs the Linux borrow boundary; sender-owned payloads, submit-failure quarantine, SendMsgZc notification tracking, receive-slot validation/rearming, ring-before-pool destruction, and exact eventfd reads are documented and covered by host gates.
- Remote Clippy passed the `io_uring` feature lane. On the exact source commit, the Linux fastpath passed `rt-transport-uring` 13/13 and `rt-io-hotpath-kernel-integration` 1/1. TODO-646 retains synchronous executor ownership and TODO-798 retains unordered partial-send disposition. The overall workflow's unrelated Windows, macOS, and native routing failures remain with their existing owners.
- Detail: `docs/todo/done/todo-687-uring-io-driver-unsafe-audit.md`

### TODO-801 - Execute opt-in io_uring zero-copy and receive rearm evidence
- Linux CI run `30807353972`, job `91665699625`, passed the full-depth zero-length receive rearm proof and the explicit SendMsgZc proof. The regular suite passed 529 library tests, `rt-transport-uring` 14/14, and `rt-io-hotpath-kernel-integration` 1/1.
- Detail: `docs/todo/done/todo-801-uring-opt-in-runtime-evidence.md`

### TODO-666 - DNS proxy returns NXDOMAIN when upstream fails, lying to clients
- Completed the shared client/server result contract: genuine upstream responses, including NXDOMAIN, pass through unchanged; upstream, configuration, endpoint, no-resolver, and parse failures produce SERVFAIL with preserved transaction/question semantics where available. DNS tests passed 22/22, the complete server test module passed 131/131, and Clippy Matrix run `30811429734` passed all eight feature lanes on revision `5b3b8c2`.
- Detail: `docs/todo/done/todo-666-dns-nxdomain-lie.md`

### TODO-771 - DNS DoH proxy primitives are not wired into the client runtime
- Completed the supported client TUN DNS owner: localhost UDP/53 proxy, pre-pinned RFC 8484 DoH endpoints, Linux/Windows TUN-name hooks, Engine and standalone lifecycle wiring, resolver restoration, and fail-closed stop behavior.
- The Linux E2E harness now separates explicit TUN DNS from OS/application resolver DNS, private resolver namespace mutation, underlay port-53 capture, and restoration. The privileged run is environment-specific and is not claimed on this macOS host.
- The server ownership boundary is documented as encrypted client-to-server transport followed by configured plain-UDP upstream forwarding; no server-side DoH HTTP/3 endpoint is claimed.
- Detail: `docs/todo/todo-771-dns-proxy-runtime-wiring-gap.md`

### TODO-606 - Second close() queues a second close frame after CONNECTION_CLOSE was already queued
- `Connection::close()` is now first-close-wins: repeated calls preserve the first terminal frame and state, and the transport serializes one close frame only. The regression covers pending-queue cardinality, first-close metadata, peer receipt, and `Done` on a later send.
- Focused proof and the full `CARGO_BUILD_JOBS=2 cargo test --locked --features rust-tests` gate passed; strict Clippy also passed. TODO-697 remains the separate terminal-close priority owner.
- Detail: `docs/todo/todo-606-double-close-redundant-frame.md`

### TODO-772 - Local transport close reports ApplicationClosed regardless of close kind
- `Connection::close()` now records structured `LocalApplicationClosed` or `LocalConnectionClosed` errors matching the emitted frame, while first-root-cause and peer-error separation remain intact. `ClientConnection::close()` is documented and exercised as application close; `close_transport()` exposes the transport branch, and public error accessors return the cloned local/remote split.
- Focused Close-/Client-, TLS-, and version-negotiation tests passed; the full `CARGO_BUILD_JOBS=2 cargo test --locked --features rust-tests` gate and strict Clippy passed. TODO-606 idempotency remains green and TODO-697 remains the separate terminal-close priority owner.
- Detail: `docs/todo/todo-772-local-close-error-type-contract.md`

### TODO-773 - Classify tracked archive paths in the exhaustive audit coverage contract
- `archive/stealth/doh.rs`, `archive/stealth/masque_manager.rs`, and `archive/tests/masque_runtime_integration.rs` are now classified as `historical-archive` evidence in the fail-closed validator and coverage manifest. They remain retired, non-compiled sources owned by the historical MASQUE/DoH record.
- The validator now passes with 899 tracked, 55,098 ignored, 0 non-ignored untracked, and 55,997 accounted paths; the archive class contains exactly 3 paths. TODO-754's remaining target/evidence boundaries stay open under their own owners.
- Detail: `docs/todo/todo-773-audit-coverage-archive-classification.md`

### TODO-774 - Remove the stale MASQUE integration target from the desktop validation suite
- The desktop/web-admin Rust validation runner now invokes five current Cargo integration targets; the archived MASQUE integration source remains evidence only and is not promoted back into the active test surface.
- The targeted suite reached its final success status after the five Rust targets executed, together with the desktop/admin checks and unit suites.
- Detail: `docs/todo/todo-774-stale-masque-integration-target.md`

### TODO-775 - Reconcile the TUN factory example feature contract
- `tun_factory_example` now has one explicit contract: Cargo and crate-level gating require `tun-tests`, and `main()` demonstrates external factory wiring only. `tun-windows` and `tun-ios` remain separate platform backend features and no longer select this example.
- Positive default-feature check and runtime execution pass; no-feature, `tun-windows`-only, and `tun-ios`-only invocations fail closed because Cargo requires `tun-tests`.
- Detail: `docs/todo/todo-775-tun-factory-example-feature-contract.md`

### TODO-776 - Serialize frontend polling and discard stale responses
- Admin and desktop polling now use per-resource serialization, generation/epoch checks, and teardown invalidation. Delayed Dashboard, Configuration, Logs, and Tauri responses are covered by 45 focused lifecycle tests; both Svelte checks pass with 0 errors and 0 warnings. The unbounded frontend `bun run test:unit` run did not return a report in the local environment and is not claimed as passing.
- Detail: `docs/todo/todo-776-frontend-polling-stale-response-contract.md`

### TODO-777 - Make the fast FEC smoke test fail closed
- `test-fast-fec.sh` now runs four separate FEC filters with explicit `benches,rust-tests`, records each command status and executed-test count, rejects zero-test or non-OK output, and records bench compilation separately. The positive local run passed 112 focused tests plus the bench smoke. The real invalid-Rust-flag fixture returned nonzero with bounded `FAIL` records and no green or bench result.
- Detail: `docs/todo/todo-777-fast-fec-smoke-fail-closed.md`

### TODO-778 - Make dynamic test discovery target-scoped and fail closed
- Shared fail-closed Cargo discovery/execution classification now covers optimization, performance regression, and security/fuzzing suites. Positive discovery found 2,104 library tests; the real negative fixture covers command failure, target mismatch, stale patterns, and zero-test execution. The three affected suites passed their bounded local gates with structured `PASS`, `FAIL`, `SKIP`, and `UNAVAILABLE` metadata.
- Detail: `docs/todo/todo-778-dynamic-test-discovery-contract.md`

### TODO-779 - Make test and benchmark harness argument propagation array-safe
- Shared Cargo/env propagation is array-safe; touched wrappers validate bounded CLI values, preserve structured command identity, and emit explicit per-cell results. The real negative fixture passed shell-metacharacter, malformed-size, invalid-numeric, path-with-space, and Admin dry-run checks without side effects. A current Fast Full Suite run re-opened the separate TODO-782 artifact-consumer boundary: `test-optimization.sh --fast` fails JSON serialization after a passing Cargo case because of an extra environment brace. TODO-735, TODO-738, and TODO-782 remain open for their broader owners.
- Detail: `docs/todo/todo-779-harness-argument-safety.md`

### TODO-780 - Reconcile profiling script truth and durable evidence
- The three profiling runners now emit versioned, unique per-scenario evidence with provenance, readiness, process, perf/flamegraph, metric, cleanup, and aggregate manifest status. Missing native prerequisites are `UNAVAILABLE`; failed setup, process, traffic, or measurement is `FAIL`; no `N/A` row can pass.
- The canonical zero-copy entrypoint is `scripts/benchmarks/profiling-zc.sh`, and the historical TODO-418 and ignored `docs/profiling/` boundary are explicitly reconciled. The local macOS run records native Linux profiling as unavailable rather than claiming remote execution.
- Detail: `docs/todo/todo-780-profiling-evidence-contract.md`

### TODO-781 - Reconcile benchmark and analysis fast-mode flags
- The five affected benchmark suites now implement distinct `--fast` and `--full` matrices, write effective-mode and selected-cell metadata, and support non-executing dry runs. The orchestrator records selected suites and propagates the matching child flag.
- Coverage analysis now records the bounded static fast proxy separately from full cargo-llvm-cov or Cargo-test-proxy execution. The positive mode fixture and existing harness argument-safety fixture pass.
- Detail: `docs/todo/todo-781-fast-mode-contract.md`

### TODO-783 - Make the admin confirmation dialog concurrency-safe
- The admin confirmation store now uses monotonic request IDs and explicit latest-wins cancellation. Superseded callers resolve `false`, stale dialog callbacks cannot resolve another request, and layout teardown cancels the active request so no confirmation Promise remains pending.
- Focused frontend evidence passed: `svelte-check` 0 errors/0 warnings; confirmation store 3/3, Sidebar 12/12, Configuration 10/10, and Logs 17/17 tests. The visible dialog presentation and shared UI component were not changed.
- Detail: `docs/todo/todo-783-admin-confirm-dialog-concurrency.md`

### TODO-784 - Make the PGO build helper isolated and evidence-complete
- The PGO helper now creates unique run-scoped evidence with parser-valid `quicfuscate.pgo-release.v1` provenance, explicit workload/profile/merge/final-build status, and a final binary SHA-256. Missing tools, no profile output, merge failure, and concurrent isolation are covered by the bounded fake-tool fixture; native PGO was not run on the disk-constrained macOS host.
- Detail: `docs/todo/todo-784-pgo-build-artifact-contract.md`

### TODO-785 - Make tray autostart synchronization fail closed on uncertain state
- Tray state now distinguishes first-run absence, loaded state, and unavailable/corrupt state. Autostart mutations read the OS first, persist after the OS change, compensate failed saves or OS operations, and report retryable partial results when compensation fails. The native tray disables and labels preference controls while state is unavailable; 37/37 desktop bin tests and Clippy passed.
- Detail: `docs/todo/todo-785-tray-autostart-state-contract.md`

### TODO-786 - Propagate desktop engine cleanup failures through the native host
- Native disconnect, replacement-connect, and tray shutdown now retain failed engine ownership and propagate bounded cleanup outcomes instead of discarding `disconnect()`/`stop()` errors. The desktop adapter test target passed 41/41 tests and Clippy passed.
- Detail: `docs/todo/todo-786-desktop-engine-cleanup-errors.md`

### TODO-787 - Make admin credential initialization and persistence fail closed
- Admin auth initialization now fails closed on hash, invalid-verifier, malformed-file, and initial-persistence errors. Credential updates durably commit before publishing in-memory state or invalidating sessions; failed writes retain the previous credential, clean temporary artifacts, and return an explicit error. Focused auth tests passed 18/18 and the startup-failure regression passed 1/1.
- Detail: `docs/todo/todo-787-admin-credential-persistence-contract.md`

### TODO-788 - Make standalone FEC file loading strict and fail closed
- Explicit `--fec-config` input now fails closed on I/O, TOML, enum, and semantic errors; unknown modes and invalid windows are rejected before runtime construction, and accepted source provenance is logged. Parser tests passed 3/3, all FEC-filtered library tests passed 281/281, and loader tests passed 5/5.
- Detail: `docs/todo/todo-788-standalone-fec-config-fail-closed.md`

### TODO-789 - Make client CA loading scoped and fail closed
- Client CA files are now fully validated before runtime publication, retained on the owning transport configuration, and passed to each connection-local rustls provider without process-global first-writer-wins state. Standalone, engine, E2E, and QKey integration callers fail closed; qftls passed 21/21, transport configuration 50/50, standalone loader 1/1, engine missing-CA 1/1, and real QKey HTTP/3/TLS integration 1/1.
- Detail: `docs/todo/todo-789-client-ca-scope-and-fail-closed.md`

### TODO-790 - Validate client URL scheme host and target semantics
- Standalone client URL handling now validates one target object before DNS or UDP setup, distinguishes omitted default input from explicit input, rejects invalid authorities and unsupported schemes, and projects the validated host, HTTP/3 authority, and request path without fallback.
- Target parsing and connection-construction tests passed 6/6; `cargo check --lib --bins`, `cargo fmt -- --check`, and `git diff --check` passed. The unchanged TLS Cover dead-code warning remains outside this task.
- Detail: `docs/todo/todo-790-client-url-validation-contract.md`

### TODO-791 - Fail closed when requested standalone client TUN cannot start
- Standalone client `--tun` activation now fails closed on open/configuration, reader-spawn, and reader-loop errors. Startup cleanup preserves the primary error, closes QUIC, retains kill-switch blocking, and shuts down the stealth runtime within its bounded timeout. Connected policy requires complete TUN ownership and a healthy reader.
- Focused client-TUN tests passed 4/4, the complete runtime reload suite passed 29/29, and the TUN library suite passed 30/30. `cargo check --lib --bins`, targeted Clippy with documented baseline suppressions, `cargo fmt -- --check`, and `git diff --check` passed; the existing TLS Cover dead-code warning remains outside this task.
- Detail: `docs/todo/todo-791-standalone-client-tun-activation.md`
### TODO-792 - Propagate initial client handshake send errors
- Standalone client startup now requires a non-empty initial QUIC datagram and complete connected-UDP delivery before any later HTTP/3 request, TUN activation, or readiness work. Construction and socket-send failures run bounded cleanup and preserve the primary error context.
- Runtime tests passed 33/33; `cargo check --lib --bins`, targeted Clippy with documented baseline suppressions, `cargo fmt -- --check`, and `git diff --check` passed. The existing TLS Cover dead-code warning remains outside this task.
- Detail: `docs/todo/todo-792-initial-handshake-send-error.md`

### TODO-793 - Propagate TUN data-plane I/O faults to runtime health
- Typed reader, channel, TUN-write, transport-send, and transport-receive faults now reach client/server runtime health and bounded cleanup. Connected/QUIC liveness is separate from TUN readiness; cooperative reader shutdown remains non-error and joins owned readers.
- Full local library gate passed 2120/2120 tests; all-target check, focused data-plane/runtime/server-health tests, formatting, diff hygiene, and targeted Clippy passed. Linux cross-compilation was not claimable on this macOS host because the local GNU cross-compiler and Linux sysroot are missing.
- Detail: `docs/todo/todo-793-tun-data-plane-fault-propagation.md`

### TODO-794 - Validate complete EngineConfig across adapter and reload boundaries
- Strict complete EngineConfig validation now runs before AppConfig projection, client/server runtime construction, generic engine transport setup, and admin write/reload validation. Unknown keys and invalid typed/range values fail closed; transport policies, FEC, stealth, optimization, and fingerprint-slot projections are canonicalized and tested.
- Local proof: canonical configuration parse/validate/roundtrip, strict fixtures for every serialized section, Engine 24/24, engine adapter 21/21, client adapter 8/8, server adapter 121/121, full library gate 2130/2130, all-target check, targeted Clippy, formatting, and diff hygiene.
- Detail: `docs/todo/todo-794-complete-engine-config-validation.md`

### TODO-795 - Validate quicfuscate-ctl response shapes and bounded framing
- `quicfuscate-ctl` now enforces typed command-specific response schemas and one bounded newline-terminated UTF-8 response frame. Missing, wrong-typed, unknown, malformed, oversized, unterminated, and overflowing values fail closed; QKeys are parsed and checksum-validated.
- Local proof: CLI 5/5, Unix admin projection 7/7, full library 2130/2130, all-target check, targeted Clippy, formatting, and diff hygiene. TODO-673 remains the request-side owner.
- Detail: `docs/todo/todo-795-quicfuscate-ctl-response-contract.md`

### TODO-796 - Make E2E migration proof fail closed on HTTP/3 finalization
- The migration proof now handles the final HTTP/3 body/FIN result before emitting `migration-proof`, records `finalization=accepted` or the explicit terminal `finalization=already-done` state, and returns nonzero without a marker for every other error. H3 `Done` now maps to the typed terminal `ConnectionError::Done` instead of a string-wrapped transport error.
- Local proof: `qf-e2e-client` tests 5/5, full library 2132/2132, release migration control-path 1/1, all-target check, targeted Clippy, formatting, and diff hygiene. The live QKey migration probe was not run because no live server/QKey fixture was available in this bounded local gate.
- Detail: `docs/todo/todo-796-e2e-migration-proof-finalization.md`

### TODO-797 - Make persisted logging mode state fail closed and durable
- Persisted logging state now distinguishes absent from valid typed state, applies `normal` only for an absent sidecar, and aborts standalone bootstrap on malformed, unreadable, missing-mode, unknown-field, or unsupported state. Configured admin updates persist before live publication; failed writes retain the previous mode, while no-config updates explicitly report live-only behavior.
- Local proof: logging-mode filter 24/24, dedicated `no-log` regression 1/1, full library 2,139/2,139, all-target check, targeted Clippy with repository baseline suppressions, formatting, and diff hygiene.
- Detail: `docs/todo/todo-797-logging-mode-persistence-contract.md`

### TODO-685 - Audit unsafe code in qkey registry storage and admin session handling
- Archived as a stale unsafe-site inventory after current-source reconciliation: no QKey registry or admin-session raw-memory issue exists. The sole inspected Rust `unsafe` block is registry storage's Windows `MoveFileExW` call; TODO-873 closes its interior-NUL path contract, safety contract, and portable replacement proof at commit `b532ecd`, and the source is unchanged. Native Windows execution remains explicitly unclaimed. TODO-861 and TODO-728 separately close audit-file FFI and pathname binding. Original verification: commit `4c6114d`; Graphify `BLOCKED` at `scripts/out/audits/graphify-20260807T023124Z/graphify-evidence.json`; completeness PASS with `tracked=991`, `ignored=32931`, `accounted=33922`, `current_details=371/371`, `missing_current=0`, `done_archive=441`, `explicit_archive_exceptions=36`.
- Detail: `docs/todo/done/todo-685-qkey-registry-unsafe-audit.md`

### TODO-610 - DNS intercept fabricates NXDOMAIN replies when upstream resolution fails
- Reconciled as a duplicate of TODO-666 after confirming the same failure contract in the shared proxy and server TUN intercept. No product code changed.
- Detail: `docs/todo/done/todo-610-dns-upstream-fail-nxdomain-lie.md`

### TODO-631 - Expanded AES round-key zeroization claim reconciled
- Closed as stale after verifying that the canonical `qf-crypto` expanded schedule exists only on x86_64 when AES-NI is available, is zeroized there, and is absent from non-x86 layouts. Key and IV fields are zeroized on every target. Native ARM64 coverage passes 140/140 and strict crate Clippy passes; no product code changed.
- Detail: `docs/todo/done/todo-631-round-key-zeroization-non-aesni.md`

### TODO-642 - TLS cover zero-key fallback claim reconciled
- Closed as stale after verifying that `fill_secure` errors map to `ConnectionError::CryptoError` before derivation; no all-zero RNG fallback exists. A forced-entropy-failure regression now executes the real root adapter and proves the typed fail-closed result.
- Detail: `docs/todo/done/todo-642-tls-cover-zero-keys.md`

### TODO-648 - Config write validation claim reconciled
- Closed as stale after tracing the active handler: `AppConfig::from_toml`, config validation, and transport-override validation all run before `fsutil::atomic_write_file`. A direct regression proves malformed and QUIC-varint-invalid candidates leave the existing target unchanged; focused coverage passes 1/1 and the server surface passes 163/163.
- Detail: `docs/todo/done/todo-648-config-write-validation.md`

### TODO-655 - TUN fcntl failure handling claim reconciled
- Closed as stale after verifying the canonical Linux/macOS rollback owners and the armed `FdGuard` in the macOS compatibility path. Interface coverage passes 28/28 and compatibility-handle close-failure coverage passes 1/1; no product code changed.
- Detail: `docs/todo/done/todo-655-tun-fcntl-ignored.md`

### TODO-621 - Profile Store Writes Non-Atomically - Superseded
- Closed as an exact duplicate of TODO-662 after source verification. The detail was true-renamed into `docs/todo/done/`; no product code changed.
- Detail: `docs/todo/done/todo-621-profile-save-not-atomic.md`

### TODO-622 - 32-Bit Profile ID Collisions - Superseded
- Closed as an exact duplicate of TODO-658 after source verification. The detail was true-renamed into `docs/todo/done/`; no product code changed.
- Detail: `docs/todo/done/todo-622-profile-id-32-bit-collision.md`

### TODO-609 - NDP neighbor solicitation answered for any target address (gratuitous NA)
- Reconciled as stale against the current builder: the NS target at `src/implementations/server/icmp.rs:324-326` must equal the server IPv6 address, and empty foreign-target responses are ignored by the TUN writer. The explicit negative regression test remains a future test-only hardening gap; no production code changed.
- Detail: `docs/todo/done/todo-609-ndp-solicitation-any-target.md`

### TODO-608 - Routing setup swallows TUN address assignment errors and reports success
- Reconciled as stale against TODO-571. Current Linux routing checks command results and exact address/prefix/link postconditions; macOS `ifconfig` failures propagate through the typed command boundary. Focused routing gate: 17 tests passed serially on 2026-08-02. No product code changed.
- Detail: `docs/todo/done/todo-608-routing-setup-swallows-addr-errors.md`

### TODO-604 - Client backend hardcodes the TUN gateway IP instead of using a configured value
- Closed as a duplicate of TODO-620 after source verification. The current backend still ignores `tun_ip`, `tun_netmask`, and `tun_subnet_prefix`; TODO-620 is the sole implementation owner. No product code changed.
- Detail: `docs/todo/done/todo-604-backend-hardcoded-tun-ip.md`

### TODO-605 - probe_detector threshold is never consulted in detection/escalation logic
- Closed as a stale finding. Current `check_packet()` prunes the 60-second history, counts matching probes, and returns `Switch` at the configured threshold; regression coverage and canonical documentation were added. No production logic change was required. The serial 2,095-test library suite passes; the separate parallel timing-test failure is tracked in TODO-768. No external or Omega proof is claimed.
- Detail: `docs/todo/done/todo-605-probe-detector-threshold-ineffective.md`

### TODO-603 - decompress_with_dict performs a partial read of the decompressed payload
- Reconciled the stale partial-read claim against the current bulk decompressor: it writes into exactly the declared-length pool slice, rejects undersized blocks, and requires the decoded length to match. Added a >64 KiB complete round-trip regression and documented the contract. Local gates pass: 2,094 library tests, all-target tests/check, strict Clippy, format/diff checks, runtime guardrails with 0 critical findings and 1 existing warning at `src/simd/x86_ack.rs:3`. TODO-767 owns the separate explicit-pool-size versus adaptive-block mismatch found during regression setup; no external or Omega proof is claimed.
- Detail: `docs/todo/done/todo-603-decompress-with-dict-partial-read.md`

### TODO-601 - Fatal TLS errors close locally without sending CONNECTION_CLOSE to the peer
- TLS provider failures now preserve the local root error and queue a `CRYPTO_ERROR`/`ConnectionClose` with the `0x0100` TLS-alert base before returning. Peer closes remain receive-only terminal events. Local gates pass: 2,093 library tests, all targets/check, strict Clippy, format/diff checks, runtime guardrails with 0 critical findings and 1 known warning at `src/simd/x86_ack.rs:3`. No external browser, Linux, Windows, or Omega proof is claimed.
- Detail: `docs/todo/done/todo-601-fatal-tls-close-without-connection-close.md`

### TODO-600 - key_update falls back to partial stack rotation on provider failure
- TLS-provider-backed write key updates now fail closed without a raw transport fallback or key-phase toggle; providerless transport-secret rotation remains supported. Bounded control admission coalesces repeated `DataBlocked` and `StreamDataBlocked` notifications per scope. Local gates pass: 2,092 library tests, all targets/check, strict Clippy, format/diff checks, runtime guardrails with 0 critical findings and 1 known warning at `src/simd/x86_ack.rs:3`. No external browser, Linux, Windows, or Omega proof is claimed.
- Detail: `docs/todo/done/todo-600-key-update-partial-stack-rotation.md`

### TODO-599 - local_error single-slot semantics lose root cause and mix remote with local errors
- `Connection` now keeps the first local root cause separate from the first peer close, with typed `CONNECTION_CLOSE`/`APPLICATION_CLOSE` details and public combined/side-specific accessors. Local tests, all-target tests, check, strict Clippy, format/diff checks, and runtime guardrails pass: 2,089 library tests, 0 critical findings, 1 known warning at `src/simd/x86_ack.rs:3`. No external browser, Linux, Windows, or Omega proof is claimed.
- Detail: `docs/todo/done/todo-599-local-error-single-slot-semantics.md`

### TODO-598 - TlsCover ClientHello production path violates ChaCha policy and contains dead advanced-builder machinery
- The active client and server rustls builders now share a filtered provider that excludes the three ChaCha suites; deterministic compatibility templates apply the same policy; the malformed advanced builder and helper-only machinery are removed. Local focused/full Rust gates, strict Clippy, format, diff, and runtime guardrails pass. No external browser capture or Omega proof is claimed.
- Detail: `docs/todo/done/todo-598-tlscover-chacha-policy-dead-builder.md`

### TODO-597 - MASQUE manager and DoH resolver are test-only or dead in production builds
- Core H3/MASQUE is the sole active CONNECT-UDP/capsule carrier; the retired manager, stealth-local DoH resolver, and obsolete integration test are archived. The active parser now handles 1/2/4/8-byte varints, split DATA tails, bounded lengths, staged events, and fail-closed FIN validation. Local gates: 2,084 library tests, all-target tests/check, strict Clippy, format/diff checks, runtime guardrails with 0 critical findings and 1 known warning. No external or Omega proof is claimed.
- Detail: `docs/todo/done/todo-597-masque-doh-production-gap.md`

### TODO-596 - TLS Cover ClientHello templates are dead code and violate the ChaCha policy
- Removed the unread TLS Cover ClientHello-template machinery and no-op cover override, kept the synthetic encrypted record path, and gave Safari a dedicated header template without `sec-fetch-*`, `upgrade-insecure-requests`, or `cache-control`. Local gates: 2,080 library tests, all-target check, strict Clippy, format/diff checks, runtime guardrails with 0 critical findings and 1 known warning. No external browser-capture or Omega proof is claimed.
- Detail: `docs/todo/done/todo-596-tls-cover-ch-template-dead-chacha.md`

### TODO-593 - SIMD unsafe functions missing debug_assert bounds, RS encode assumes aligned shards
- Scoped x86 SIMD contracts now have debug dimension/output-capacity assertions; scalar, NEON, and GFNI Reed-Solomon encoders preserve partial input through zero-padded shards; the AVX2 header validator avoids discarded SIMD work; and Windows x86/ARM SHA no-op stubs fail loudly. Native local gates (2,078 library tests, strict Clippy, all-target check, runtime guardrails) and x86_64-macOS library/test-build checks pass. Miri is unavailable on the active stable-aarch64-apple-darwin toolchain; Windows cross-check remains blocked by the pre-existing `CurrentIds` configuration error at `src/privilege/drop.rs:676`, and no external proof is claimed.
- Detail: `docs/todo/done/todo-593-simd-bounds-rs-alignment.md`

### TODO-594 - SIMD Reed-Solomon encode/decode correctness bugs (dead code, not production path)
- Standalone x86 AVX2/GFNI Reed-Solomon paths now use canonical coefficients, full matrix inversion, dynamic LUTs, safe vector tails, and runtime shard metadata validation. Rosetta x86 coverage passes; production FEC remains unchanged and the broader FEC/SIMD/GF16 reviews remain separately owned by TODO-686, TODO-679, and TODO-715.
- Detail: `docs/todo/done/todo-594-simd-reed-solomon-correctness.md`

### TODO-595 - Chrome TLS profile extension_order contains invalid and duplicate extension IDs
- Chrome-based `qftls` extension metadata now uses unique scoped IANA-registered IDs plus intentional GREASE: `renegotiation_info=0xff01`, one `compress_certificate=0x001b`, and no invalid `0x0019`. The regression and full native gates pass; the list remains test-only without a production wire consumer.
- Detail: `docs/todo/done/todo-595-tls-extension-ids-fingerprint.md`

### TODO-580 - Transport hot-path O(n) lookups and pacer burst accumulation
- Stream admission/removal uses O(1)-average membership sets, pacing burst bytes decay against elapsed rate, H3 body storage is pool-backed, datagram queue initialization is unified, and BBR3 ACK-clock ordering is regression-tested. Focused local gates and current workspace checks pass; exact Omega/Linux throughput proof remains explicitly unclaimed.
- Detail: `docs/todo/done/todo-580-transport-hotpath-lookups.md`

### TODO-579 - Remove blocking sleep in TLS profile and guard StealthManager runtime spawn
- TLS profile jitter is represented as a readiness deadline, and Stealth runtime startup is explicitly runtime-owned with a synchronous non-spawning compatibility constructor. Focused qftls/StealthRuntime regressions and current local gates pass; exact Omega/Linux proof remains explicitly unclaimed.
- Detail: `docs/todo/done/todo-579-blocking-sleep-stealth-spawn.md`

### TODO-577 - Validate PKI certificate reuse before production startup
- Existing PKI material is parsed and validated for chain, hostname, validity, and private-key match before reuse; invalid material is quarantined before regeneration, and client disconnect retains owned-handle abort/await semantics. Focused local gates pass; exact Omega proof remains explicitly unclaimed.
- Detail: `docs/todo/done/todo-577-pki-cert-validation-client-handles.md`

### TODO-575 - Eliminate hot-path lock contention and unbounded control queues
- Brain packet observation uses atomic accumulators drained by `apply_policy`; transport control admission is bounded and coalesces latest connection/per-stream flow-control updates while preserving terminal close frames. Focused local source/tests and current workspace gates pass. Exact Linux TUN/Omega acceptance remains explicitly unclaimed.
- Detail: `docs/todo/done/todo-575-hotpath-lock-contention.md`

### TODO-578 - Fix io_uring dispatch silence and replay window pruning
- io_uring fall-through now fails explicitly, and replay-window pruning advances on current time from housekeeping even during quiet periods. Focused replay/QKey tests and current local workspace gates pass; Linux io_uring runtime and Omega proof remain explicitly unclaimed due unavailable cross-target/runtime surfaces.
- Detail: `docs/todo/done/todo-578-iouring-dispatch-replay-prune.md`

### TODO-576 - Wire TUN reader shutdown and adaptive housekeeping tick
- TUN reader cancellation, owned joins, blocking/poll waits, adaptive housekeeping, and skip-on-missed-tick behavior are implemented. Focused local TUN/runtime tests and current workspace gates pass. Native Linux idle-CPU/TUN and Omega proof remain explicitly unclaimed because this Darwin session lacks the required runtime and checkout paths.
- Detail: `docs/todo/done/todo-576-tun-reader-shutdown-housekeeping.md`

### TODO-582 - Crypto hot-path performance - AEGIS mutex, GHASH scalar, redundant checks
- AEGIS hot-path wrappers now use local state, scalar GHASH uses a 4-bit table, and the redundant per-call SSE4.2 lookup is removed. Focused AEGIS tests, local benchmark comparison, formatting, and diff hygiene pass; the exact Omega/Linux throughput proof is not claimed because the required protected checkout paths are unavailable in the current session.
- Detail: `docs/todo/done/todo-582-crypto-hotpath-performance.md`

### TODO-581 - FEC production hardening - unbounded repairs, weak PRNG, hot-path overhead
- FEC repair deduplication is bounded, GF table initialization is one-time, fountain symbol selection is connection-seeded, LazyDecoder tracking is hash-based with explicit bounds, matrix setup avoids redundant clearing, and decoder solve telemetry is exported. Focused FEC tests (278), all-target check, strict Clippy, formatting, and diff hygiene pass. The exact Omega/Linux proof is not claimed because the required protected checkout paths are unavailable in the current session.
- Detail: `docs/todo/done/todo-581-fec-production-hardening.md`

### TODO-592 - Admin server std::sync poison risk, LoginRateLimiter unbounded growth, io_driver per-call allocations
- Admin auth/session locks now use `parking_lot`; login attempts are counted and bounded by a 10,000-key LRU; replay fingerprints use bounded FIFO eviction; inbound flush and outbound batch references reuse buffers; client TUN packets transfer pool-backed ownership without per-packet `Vec` copies. Existing `live_auth` staging, async blacklist sync, and `MissedTickBehavior::Skip` boundaries were verified as already bounded/non-blocking. Full local Rust/all-target tests (2,076 passed), strict Clippy, reduced server feature check, runtime guardrails, formatting, and audit completeness pass. The unqualified no-default feature probe retains a pre-existing optional-dependency gating failure.
- Detail: `docs/todo/done/todo-592-admin-iodriver-allocations.md`

### TODO-591 - Revocation retention and fsutil permission window
- Revocation records now use configurable 90-day retention with bounded housekeeping pruning and `quicfuscate_revocation_pruned_total`; atomic writes secure temporary files before rename and retain post-rename defense in depth. Local focused, full Rust, strict Clippy, feature, runtime-guardrail, and completeness gates pass. Exact Omega/Linux proof remains blocked by protected dirty remote checkouts.
- Detail: `docs/todo/done/todo-591-revocation-fsutil-hardening.md`

### TODO-667 - fsutil atomic write sets permissions after rename, creating TOCTOU race
- Closed as a duplicate of TODO-591. The shared implementation creates and secures temporary files before atomic rename, with focused intermediate and final mode regressions.
- Detail: `docs/todo/done/todo-667-fsutil-toctou.md`

### TODO-590 - Server IP pool O(n) allocation, IPv6 infinite-loop risk, and usize overflow
- IPv4 and IPv6 pools now use cursor-plus-free-list allocation, IPv6 capacity counters use `u128`, invalid ranges are safe, and out-of-range releases are ignored. Focused, full Rust, strict Clippy, feature, runtime-guardrail, and completeness gates pass. Exact Omega/Linux proof remains blocked by protected dirty remote checkouts.
- Detail: `docs/todo/done/todo-590-ip-pool-allocation.md`

### TODO-589 - H3 connection memory leaks, env-var race, and hot-path allocations
- H3 polling now releases terminal stream IDs, MASQUE flow mappings, and completed Server Push payloads; per-connection FEC environment mutation is gone; STREAM and MASQUE receive buffers are allocated once at bounded sizes; duplicate stream-type state was removed.
- Focused H3 tests (54), full workspace/all-target tests (2,066 library tests plus all discovered binary and integration suites), workspace check, strict Clippy, alternate feature check, runtime guardrails, and audit completeness pass. Exact Omega/Linux proof remains blocked by protected dirty remote checkouts.
- Detail: `docs/todo/done/todo-589-h3-memory-env-hotpath.md`

### TODO-588 - Congestion control overflow, delivery-rate corruption, and min_rtt staleness
- CC in-flight accounting is saturating across BBR2, BBR3, and Reno; BBR2 delivery accounting now advances only on ACK samples; BBR2 and BBR3 use a configurable 10-second minimum-RTT filter window, preserve samples across `set_cwnd`, and route RTT timestamps through the canonical time source; StealthShaper jitter is symmetric; RFC 9438 confirms the retained CUBIC target clamp.
- Focused CC tests (91), full workspace/all-target tests (2,063 library tests plus all discovered binary and integration suites), workspace check, strict Clippy, feature check, runtime guardrails (`Critical: 0`), and audit completeness pass. Exact Omega/Linux throughput proof remains blocked by protected dirty remote checkouts.
- Detail: `docs/todo/done/todo-588-cc-overflow-delivery-minrtt.md`

### TODO-587 - Optimize module cleanup - heap allocs, thread leaks, format overhead
- SVE2 divergence uses a bounded stack workspace; the MemoryPool auto-tuner is stoppable and joinable; metrics exporters write directly into pre-sized buffers; Engine caches the instrumentation Arc; unsafe pool copying has explicit bounds and safety invariants.
- Local full Rust, focused export, feature, Clippy, runtime-guardrail, and completeness gates pass.
- Detail: `docs/todo/done/todo-587-optimize-module-cleanup.md`

### TODO-586 - Compression path optimization - double alloc, dead MIME policy, asymmetric API
- Decompression writes directly into caller-owned pool blocks, H3 MIME allow/deny policy is centralized and tested, and dictionary compression/decompression use symmetric bulk APIs with correct pool ownership; local full Rust, feature, Clippy, runtime-guardrail, and completeness gates pass.
- Detail: `docs/todo/done/todo-586-compression-optimization.md`

### TODO-585 - Server platform hardening - UID/GID truth, iptables safety, replay sentinel
- Saved-ID reporting, iptables deletion, replay initialization, audit timestamps, PKI Base64, and audit path signatures are hardened; local Rust gates and strict Clippy pass.
- Detail: `docs/todo/done/todo-585-server-platform-hardening.md`

### TODO-584 - Brain/Stealth correctness - lost ACK samples, escalation semantics, time source
- Aggregated all ACK samples per policy tick, separated probe and Brain levels per connection, enforced probe-count escalation order and de-escalation cooldowns, routed Reality through the canonical time source, validated Brain configuration bounds, and made reorder pressure decay over a 30-second half-life.
- Detail: `docs/todo/done/todo-584-brain-stealth-correctness.md`

### TODO-583 - Remove confirmed dead code across FEC, qftls, stealth, and accelerate
- Removed incorrect GF implementations, the production-only AVX-512 no-op wrapper, duplicate qftls session storage and unread cache fields, dead SVE2 work, duplicate cfg, redundant 1-RTT state write, and test-only logging exports; retained and documented the tested legacy DPI response selector.
- Detail: `docs/todo/done/todo-583-dead-code-removal.md`

### TODO-628 - AEGIS seal/open paths unwrap Option state on the crypto hot path
- Resolved by TODO-582: AEGIS wrappers now use local non-nullable state, remove the Mutex/Option unwrap path, and pass concurrent seal/open regression coverage.
- Detail: `docs/todo/todo-628-aegis-unwrap-panics.md`

### TODO-573 - Remove inert QKey rotation and harden revocation state
- Removed the inert automatic QKey rotation scheduler and callback state, consolidated revocation/tracker ownership, preserved explicit admin revocation with peer-visible close delivery, and completed local/process gates.
- Detail: `docs/todo/done/todo-573-qkey-revocation-state-truth.md`

### TODO-572 - Make configured GeoIP enforcement fail closed
- Typed GeoIP activation, fail-closed admission, truthful readiness and telemetry, negative activation coverage, restart proof, and process-real DDoS evidence are complete.
- Detail: `docs/todo/done/todo-572-geoip-fail-closed-activation.md`

### TODO-571 - Make TUN provisioning fail closed and platform truthful
- Fail-closed client and server TUN provisioning, exact Linux postconditions, transactional rollback, explicit Linux-only server support, native namespace proof, native traffic proof, and Windows Wintun/WFP lifecycle evidence are complete.
- Detail: `docs/todo/done/todo-571-tun-provisioning-platform-truth.md`

### TODO-570 - Own stealth background tasks and Reality cover cache
- Shared Reality cover refresh, proxy cleanup, profile rotation, generation identity, cancellation, bounded joins, standalone CLI ownership, and process-real lifecycle proof are complete. All local Rust, native probe, readiness, documentation, TODO, and protected-UI gates pass.
- Detail: `docs/todo/done/todo-570-stealth-background-task-ownership.md`

### TODO-765 - Close bidirectional active fingerprint probe normalization
- The exact five-profile Omega matrix passes packet capture, p0f, active probe vectors, checksum, disabled byte-exact, enabled non-SYN transport, IP-ID, protected-process, and cleanup gates. Nmap output is retained with corrected exact-match semantics and no exact active classifier claim where Nmap reports `No exact OS matches`.
- Detail: `docs/todo/done/todo-765-bidirectional-active-probe-normalization.md`

### TODO-423 - Reconcile FEC E2E proof with the actual transport gates
- Native QUIC/TUN, model, and wire-level contracts are explicitly separated. The six-level model matrix passes 6/6 with forwarded Cargo options; the native specialized evidence remains owned by TODO-557.
- Detail: `docs/todo/done/todo-423-fec-e2e-quic-transport-tests.md`

### TODO-543 - Complete TCP and ICMP fingerprint runtime proof
- All bounded acceptance gates pass: five-profile packet/capture/p0f evidence, disabled byte-exact passthrough, checksums, allocation-free normalization, atomic TLS/network persona coupling, and retained Omega throughput at approximately 13.5 Gbit/s. Bidirectional active-probe closure is retained in completed TODO-765.
- Detail: `docs/todo/done/todo-543-fingerprint-runtime-proof.md`

### TODO-270 - Reconcile duplicate legacy archive identities
- The archive retains two historical detail files with the same legacy ID; both are explicitly retained and mapped in the TODO-754 reconciliation manifest.
- Detail: `docs/todo/done/todo-270-architecture-debt-audit.md`
- Additional legacy archive: `docs/todo/done/todo-270-cargo-dependency-cves.md`

### TODO-21 - Archived detail from todo-21-unified-engine
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-21-unified-engine.md`

### TODO-22 - Archived detail from todo-22-engine-wiring
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-22-engine-wiring.md`

### TODO-23 - Archived detail from todo-23-server-mode
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-23-server-mode.md`

### TODO-24 - Archived detail from todo-24-client-packaging
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-24-client-packaging.md`

### TODO-41 - Archived detail from todo-41-stealth-brain-realtls-hardening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-41-stealth-brain-realtls-hardening.md`

### TODO-42 - Archived detail from todo-42-fec-runtime-adaptation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-42-fec-runtime-adaptation.md`

### TODO-43 - Archived detail from todo-43-hotpath-optimization-wiring
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-43-hotpath-optimization-wiring.md`

### TODO-44 - Archived detail from todo-44-interface-control-plane-readiness
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-44-interface-control-plane-readiness.md`

### TODO-45 - Archived detail from todo-45-runtime-fastpath-consolidation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-45-runtime-fastpath-consolidation.md`

### TODO-46 - Archived detail from todo-46-linux-fastpath-correctness-gates
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-46-linux-fastpath-correctness-gates.md`

### TODO-47 - Archived detail from todo-47-xdp-product-truth-alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-47-xdp-product-truth-alignment.md`

### TODO-48 - Archived detail from todo-48-zerocopy-stack-consolidation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-48-zerocopy-stack-consolidation.md`

### TODO-49 - Archived detail from todo-49-rng-entropy-hardening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-49-rng-entropy-hardening.md`

### TODO-50 - Archived detail from todo-50-dead-acceleration-pruning
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-50-dead-acceleration-pruning.md`

### TODO-51 - Archived detail from todo-51-docs-transparency-and-feature-contract
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-51-docs-transparency-and-feature-contract.md`

### TODO-52 - Archived detail from todo-52-audit-guardrail-automation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-52-audit-guardrail-automation.md`

### TODO-53 - Archived detail from todo-53-fec-simd-deadcode-resolution
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-53-fec-simd-deadcode-resolution.md`

### TODO-54 - Archived detail from todo-54-server-runtime-unification-and-ownership
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-54-server-runtime-unification-and-ownership.md`

### TODO-55 - Archived detail from todo-55-xdp-and-fastpath-surface-collapse
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-55-xdp-and-fastpath-surface-collapse.md`

### TODO-56 - Archived detail from todo-56-runtime-owned-optimization-surface-audit
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-56-runtime-owned-optimization-surface-audit.md`

### TODO-57 - Archived detail from todo-57-secure-rng-truth-alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-57-secure-rng-truth-alignment.md`

### TODO-58 - Archived detail from todo-58-fec-determinism-and-config-purity
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-58-fec-determinism-and-config-purity.md`

### TODO-59 - Archived detail from todo-59-server-observability-and-identity-contract
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-59-server-observability-and-identity-contract.md`

### TODO-60 - Archived detail from todo-60-feature-claims-and-forked-protocol-truth-alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-60-feature-claims-and-forked-protocol-truth-alignment.md`

### TODO-61 - Archived detail from todo-61-embedded-server-runtime-truth-gap
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-61-embedded-server-runtime-truth-gap.md`

### TODO-62 - Archived detail from todo-62-standalone-server-session-model-drift
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-62-standalone-server-session-model-drift.md`

### TODO-63 - Archived detail from todo-63-engine-server-stats-dead-surface
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-63-engine-server-stats-dead-surface.md`

### TODO-64 - Archived detail from todo-64-session-timeout-runtime-wiring-gap
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-64-session-timeout-runtime-wiring-gap.md`

### TODO-65 - Archived detail from todo-65-dead-xdp-core-branch-removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-65-dead-xdp-core-branch-removal.md`

### TODO-66 - Archived detail from todo-66-dual-xdp-abstraction-collapse
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-66-dual-xdp-abstraction-collapse.md`

### TODO-67 - Archived detail from todo-67-aarch64-secure-rng-contract-mismatch
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-67-aarch64-secure-rng-contract-mismatch.md`

### TODO-68 - Archived detail from todo-68-public-enable-xdp-contract-fix
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-68-public-enable-xdp-contract-fix.md`

### TODO-69 - Archived detail from todo-69-fastpathtransport-public-surface-demotion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-69-fastpathtransport-public-surface-demotion.md`

### TODO-70 - Archived detail from todo-70-gso-gro-api-semantic-correction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-70-gso-gro-api-semantic-correction.md`

### TODO-71 - Archived detail from todo-71-batchprocessor-shadow-surface-resolution
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-71-batchprocessor-shadow-surface-resolution.md`

### TODO-72 - Archived detail from todo-72-orphan-optimize-microprimitives
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-72-orphan-optimize-microprimitives.md`

### TODO-73 - Archived detail from todo-73-fec-constructor-ambient-state-drift
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-73-fec-constructor-ambient-state-drift.md`

### TODO-74 - Archived detail from todo-74-auth-failure-metrics-rewiring
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-74-auth-failure-metrics-rewiring.md`

### TODO-75 - Archived detail from todo-75-admin-client-identity-unification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-75-admin-client-identity-unification.md`

### TODO-76 - Archived detail from todo-76-forked-aead-protocol-posture-clarification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-76-forked-aead-protocol-posture-clarification.md`

### TODO-77 - Archived detail from todo-77-feature-claims-runtime-truth-correction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-77-feature-claims-runtime-truth-correction.md`

### TODO-78 - Archived detail from todo-78-product-surface-minimization-program
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-78-product-surface-minimization-program.md`

### TODO-79 - Archived detail from todo-79-forked-aead-posture-narrowing
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-79-forked-aead-posture-narrowing.md`

### TODO-80 - Archived detail from todo-80-unsafe-surface-internalization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-80-unsafe-surface-internalization.md`

### TODO-81 - Archived detail from todo-81-stealth-capability-preservation-and-simplification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-81-stealth-capability-preservation-and-simplification.md`

### TODO-82 - Archived detail from todo-82-fec-capability-preservation-and-decoder-surface-simplification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-82-fec-capability-preservation-and-decoder-surface-simplification.md`

### TODO-83 - Archived detail from todo-83-single-server-runtime-final-convergence
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-83-single-server-runtime-final-convergence.md`

### TODO-84 - Archived detail from todo-84-data-plane-aead-ssot-and-ownership-simplification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-84-data-plane-aead-ssot-and-ownership-simplification.md`

### TODO-85 - Archived detail from todo-85-tls-cover-and-rustls-boundary-clarification
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-85-tls-cover-and-rustls-boundary-clarification.md`

### TODO-86 - Archived detail from todo-86-stealth-observable-ownership-and-mode-policy-cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-86-stealth-observable-ownership-and-mode-policy-cleanup.md`

### TODO-87 - Archived detail from todo-87-fec-public-contract-simplification-to-off-auto
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-87-fec-public-contract-simplification-to-off-auto.md`

### TODO-88 - Archived detail from todo-88-continuous-fec-auto-controller-and-mode-collapse
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-88-continuous-fec-auto-controller-and-mode-collapse.md`

### TODO-89 - Archived detail from todo-89-hardware-adaptive-aead-backend-selection-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-89-hardware-adaptive-aead-backend-selection-tightening.md`

### TODO-90 - Archived detail from todo-90-linux-send-path-collapse-around-io-uring
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-90-linux-send-path-collapse-around-io-uring.md`

### TODO-91 - Archived detail from todo-91-generic-copy-prefetch-surface-minimization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-91-generic-copy-prefetch-surface-minimization.md`

### TODO-92 - Archived detail from todo-92-crypto-simd-layer-hardening-and-internalization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-92-crypto-simd-layer-hardening-and-internalization.md`

### TODO-93 - Archived detail from todo-93-final-runtime-complexity-layer-separation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-93-final-runtime-complexity-layer-separation.md`

### TODO-94 - Archived detail from todo-94-linux-send-path-evidence-and-zerocopy-decision-program
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-94-linux-send-path-evidence-and-zerocopy-decision-program.md`

### TODO-95 - Archived detail from todo-95-fec-auto-controller-stress-stability-and-efficiency-proof
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-95-fec-auto-controller-stress-stability-and-efficiency-proof.md`

### TODO-96 - Archived detail from todo-96-crypto-simd-differential-and-unsafe-invariant-hardening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-96-crypto-simd-differential-and-unsafe-invariant-hardening.md`

### TODO-97 - Archived detail from todo-97-security-crypto-review-readiness-pack
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-97-security-crypto-review-readiness-pack.md`

### TODO-98 - Archived detail from todo-98-runtime-soak-and-chaos-validation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-98-runtime-soak-and-chaos-validation.md`

### TODO-99 - Archived detail from todo-99-quinn-udp-overlap-and-transport-divergence-audit
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-99-quinn-udp-overlap-and-transport-divergence-audit.md`

### TODO-100 - Archived detail from todo-100-busypoll-removal-and-socket-tuning-surface-cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-100-busypoll-removal-and-socket-tuning-surface-cleanup.md`

### TODO-101 - Archived detail from todo-101-generic-memcpy-removal-and-local-copy-ownership
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-101-generic-memcpy-removal-and-local-copy-ownership.md`

### TODO-102 - Archived detail from todo-102-final-prefetch-evidence-and-owner-policy-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-102-final-prefetch-evidence-and-owner-policy-tightening.md`

### TODO-103 - Archived detail from todo-103-non-security-random-simplification-and-canonical-rng-boundary
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-103-non-security-random-simplification-and-canonical-rng-boundary.md`

### TODO-104 - Archived detail from todo-104-retained-custom-data-plane-crypto-contract-and-backend-boundary
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-104-retained-custom-data-plane-crypto-contract-and-backend-boundary.md`

### TODO-105 - Archived detail from todo-105-reviewer-trust-ai-transparency-and-fork-truth-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-105-reviewer-trust-ai-transparency-and-fork-truth-tightening.md`

### TODO-106 - Archived detail from todo-106-io-uring-runtime-truth-collapse
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-106-io-uring-runtime-truth-collapse.md`

### TODO-107 - Archived detail from todo-107-canonical-doc-stale-random-and-telemetry-truth-cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-107-canonical-doc-stale-random-and-telemetry-truth-cleanup.md`

### TODO-108 - Archived detail from todo-108-crypto-backend-differential-proof-expansion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-108-crypto-backend-differential-proof-expansion.md`

### TODO-109 - Archived detail from todo-109-unsafe-invariant-annotation-and-boundary-hardening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-109-unsafe-invariant-annotation-and-boundary-hardening.md`

### TODO-110 - Archived detail from todo-110-crypto-machine-room-layer-separation-and-internalization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-110-crypto-machine-room-layer-separation-and-internalization.md`

### TODO-111 - Archived detail from todo-111-crypto-backend-runtime-evidence-telemetry
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-111-crypto-backend-runtime-evidence-telemetry.md`

### TODO-112 - Archived detail from todo-112-retained-crypto-backend-performance-evidence-program
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-112-retained-crypto-backend-performance-evidence-program.md`

### TODO-113 - Archived detail from todo-113-quinn-udp-overlap-and-fork-boundary-final-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-113-quinn-udp-overlap-and-fork-boundary-final-tightening.md`

### TODO-114 - Archived detail from todo-114-reviewer-audit-fast-path-and-repository-entry-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-114-reviewer-audit-fast-path-and-repository-entry-tightening.md`

### TODO-115 - Archived detail from todo-115-fec-auto-controller-empirical-proof-expansion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-115-fec-auto-controller-empirical-proof-expansion.md`

### TODO-116 - Archived detail from todo-116-consolidated-quality-evidence-bundle-and-trust-surface
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-116-consolidated-quality-evidence-bundle-and-trust-surface.md`

### TODO-117 - Archived detail from todo-117-xdp-compatibility-shim-io-uring-ownership-collapse
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-117-xdp-compatibility-shim-io-uring-ownership-collapse.md`

### TODO-118 - Archived detail from todo-118-public-xdp-fastpath-token-removal-and-uring-truth-tightening
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-118-public-xdp-fastpath-token-removal-and-uring-truth-tightening.md`

### TODO-119 - Kill-Switch Race Condition - Atomic Rule Application
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-119-killswitch-race-condition-atomic-apply.md`

### TODO-120 - QKey Tokens on Disk - Plaintext Removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-120-qkey-tokens-on-disk-plaintext-removal.md`

### TODO-121 - Manual HTTP Parser Replacement
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-121-manual-http-parser-replacement.md`

### TODO-122 - admin-auth.json Git Removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-122-admin-auth-json-git-removal.md`

### TODO-123 - TUN IP Hardcoded - Make Configurable
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-123-tun-ip-hardcoded-configurable.md`

### TODO-124 - DNS Servers Hardcoded - Make Configurable
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-124-dns-servers-hardcoded-configurable.md`

### TODO-125 - Session ID Predictable Counter
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-125-session-id-predictable-counter.md`

### TODO-126 - CSRF Replay Window Expansion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-126-csrf-replay-window-expansion.md`

### TODO-127 - Session TTL Reduction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-127-session-ttl-reduction.md`

### TODO-128 - Password Minimum Length Increase
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-128-password-minimum-increase.md`

### TODO-129 - DNS Restore Silent Failure
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-129-dns-restore-silent-failure.md`

### TODO-130 - X-Forwarded-For Spoofable
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-130-x-forwarded-for-spoofable.md`

### TODO-131 - macOS utun Socket Binding Not Properly Implemented
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-131-macos-utun-socket-binding.md`

### TODO-132 - Missing SAFETY Comments on Unsafe Blocks
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-132-safety-comments-unsafe-blocks.md`

### TODO-133 - BBR3 Stealth Modifications Undocumented
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-133-bbr3-stealth-modifications-documentation.md`

### TODO-134 - Float-to-u64 Cast Loses Precision in Delivery Rate Calculation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-134-float-to-u64-cast-delivery-rate.md`

### TODO-135 - io_uring Mutex Panic Poisoning Silently Ignored
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-135-io-uring-mutex-panic-poisoning.md`

### TODO-136 - Token SHA256 Hashes Hex String Instead of Binary Bytes
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-136-token-sha256-hex-string-vs-binary.md`

### TODO-137 - Rate Limiter Uses Float Arithmetic for Token Refill
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-137-rate-limiter-float-arithmetic.md`

### TODO-138 - Windows Firewall Kill-Switch Rules Accumulate Over Time
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-138-windows-firewall-rules-accumulate.md`

### TODO-139 - ECN Data Read But Discarded in ACK Frame Parsing
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-139-ecn-data-read-but-discarded.md`

### TODO-140 - Connection Migration State Machine Missing
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-140-connection-migration-state-machine.md`

### TODO-141 - 0-RTT Early Data Lacks Replay Protection
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-141-0rtt-replay-protection.md`

### TODO-142 - Flow Control MAX_DATA Lacks Upper Bound Validation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-142-flow-control-max-data-validation.md`

### TODO-143 - Packet Number Overflow and Duplicate Validation Missing
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-143-packet-number-overflow-validation.md`

### TODO-144 - XDP Skeleton Code Remains After Feature Removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-144-xdp-skeleton-code-cleanup.md`

### TODO-145 - io_uring submit_and_wait Blocks Per-Packet, Defeating Batching
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-145-io-uring-synchronous-fix.md`

### TODO-146 - Replace Deprecated lazy_static with std::sync::OnceLock
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-146-lazy-static-deprecated-replacement.md`

### TODO-147 - Replace aead RC Dependency with Stable Release
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-147-aead-rc-to-stable.md`

### TODO-148 - Audit and Review md5 Crate Usage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-148-md5-crate-usage-review.md`

### TODO-149 - Trim tokio "full" Feature to Specific Features
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-149-tokio-full-feature-trimming.md`

### TODO-150 - Add cargo audit Step to CI Pipeline
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-150-cargo-audit-ci-pipeline.md`

### TODO-151 - Define and Test Minimum Supported Rust Version (MSRV)
- Reconciled by TODO-762: no MSRV was ever declared or tested; the project uses a pinned-stable-only policy and retains this file as historical evidence.
- Detail: `docs/todo/done/todo-151-msrv-tests.md`

### TODO-152 - Integrate Frontend E2E Playwright Tests into CI
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-152-frontend-e2e-tests-ci.md`

### TODO-153 - Integrate Fuzz Tests into CI Pipeline
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-153-fuzz-tests-ci.md`

### TODO-154 - Add Performance Regression Detection to CI
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-154-performance-regression-tests.md`

### TODO-155 - Add sccache for CI Compilation Caching
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-155-sccache-ci-builds.md`

### TODO-156 - Enforce cargo-deny Multiple Versions and Raise License Confidence
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-156-cargo-deny-multiple-versions.md`

### TODO-157 - Migrate Web Admin from HeroUI to Shadcn/ui
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-157-heroui-to-shadcn-migration.md`

### TODO-158 - Split configuration.tsx Monolith into Focused Components
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-158-configuration-tsx-monolith-split.md`

### TODO-159 - Fix Focus Ring WCAG Violation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-159-focus-rings-wcag-violation.md`

### TODO-160 - Eliminate Frontend Code Duplication via Shared Package
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-160-frontend-code-duplication.md`

### TODO-161 - Theme/Tailwind Definition Duplication Across Apps
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-161-theme-duplication.md`

### TODO-162 - Shared UI Component Package
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-162-shared-ui-package.md`

### TODO-163 - TypeScript `as any` Casts Removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-163-typescript-as-any-casts.md`

### TODO-164 - Frontend Unit Test Coverage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-164-frontend-unit-tests.md`

### TODO-165 - CryptoManager Dead Code Removal
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-165-cryptomanager-dead-code.md`

### TODO-166 - Global Atomic Coupling Audit and Reduction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-166-global-atomic-coupling-audit.md`

### TODO-167 - Admin Interface Unix/HTTP Handler Redundancy
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-167-admin-unix-http-redundancy.md`

### TODO-168 - MAP.md Outdated File Tree Audit
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-168-map-md-outdated-audit.md`

### TODO-169 - Rust Public API Documentation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-169-rust-api-documentation.md`

### TODO-170 - README.md Restructure
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-170-readme-restructure.md`

### TODO-171 - Deployment Guide
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-171-deployment-guide.md`

### TODO-172 - Troubleshooting Guide
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-172-troubleshooting-guide.md`

### TODO-173 - Server Configuration Template Expansion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-173-server-config-template-expansion.md`

### TODO-174 - Scripts Redundancy Consolidation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-174-scripts-redundancy-consolidation.md`

### TODO-175 - Central Justfile for Build/Test/Bench Commands
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-175-central-justfile.md`

### TODO-176 - Feature Flags Consolidation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-176-feature-flags-consolidation.md`

### TODO-177 - Profile-Guided Optimization for Release Builds
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-177-pgo-release-builds.md`

### TODO-178 - Target-Specific Release Profiles
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-178-target-specific-optimizations.md`

### TODO-179 - Memory Pool Size Auto-Scaling
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-179-memory-pool-size-autoscale.md`

### TODO-180 - Secret Rotation Infrastructure
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-180-secret-rotation-infrastructure.md`

### TODO-181 - HashMap Stream Cache Locality at Scale
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-181-hashmap-streams-cache-misses.md`

### TODO-182 - Vec Allocation in Frame Parsing Hot Path
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-182-vec-allocation-frame-hot-path.md`

### TODO-183 - Accept Loop Timeout and Buffer Allocation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-183-accept-loop-timeout-reduction.md`

### TODO-184 - HTTP Admin Server Async Migration
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-184-http-admin-server-async.md`

### TODO-185 - Linux ioctl IfReq Uninitialized Memory
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-185-linux-ioctl-race-ifreq.md`

### TODO-186 - macOS pfctl Enable Race Condition
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-186-macos-pfctl-enable-race.md`

### TODO-187 - macOS Kill-Switch Hardcoded /tmp Path
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-187-macos-tmp-hardcoded-killswitch.md`

### TODO-188 - Windows WinTUN Adapter Prerequisite
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-188-windows-wintun-prerequisite.md`

### TODO-189 - macOS DNS Reset DHCP Leak
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-189-macos-dns-reset-dhcp-leak.md`

### TODO-190 - Full UI Revamp - Web Admin and Desktop
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-190-full-ui-revamp.md`

### TODO-191 - Svelte Cutover and React Retirement
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-191-svelte-cutover-and-react-retirement.md`

### TODO-192 - Svelte Build, CI, and Release Pipeline Truth Alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-192-svelte-build-ci-release-cutover.md`

### TODO-193 - QKey Issuance, Reveal, and Import Contract Repair
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-193-qkey-issuance-reveal-import-contract-repair.md`

### TODO-194 - Admin Credential Policy Reconciliation to 6 Characters
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-194-admin-credential-policy-reconciliation.md`

### TODO-195 - Canonical UI Documentation and Backlog Truth Alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-195-canonical-ui-doc-and-backlog-truth-alignment.md`

### TODO-196 - XOR Product-Surface Demotion
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-196-xor-product-surface-demotion.md`

### TODO-197 - Svelte Admin/Desktop Contract and End-to-End Coverage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-197-svelte-admin-desktop-contract-and-e2e-coverage.md`

### TODO-198 - Stealth, Brain, and FEC Control Ownership Audit
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-198-stealth-brain-fec-control-ownership-audit.md`

### TODO-199 - Unsafe ROI Audit and Selective Safe Replacement
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-199-unsafe-roi-audit-and-selective-safe-replacement.md`

### TODO-200 - Local Repository Truth and Staging Alignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-200-local-repository-truth-and-staging-alignment.md`

### TODO-201 - Active Svelte Workspace Source Tracking and Workspace Manifest Truth
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-201-active-svelte-workspace-source-tracking-and-manifest-truth.md`

### TODO-202 - Admin Publish Asset Tree Index Reconciliation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-202-admin-publish-asset-tree-index-reconciliation.md`

### TODO-203 - Local Worktree Hygiene and Artifact Guardrail Closure
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-203-local-worktree-hygiene-and-artifact-guardrail-closure.md`

### TODO-204 - Toolchain Baseline Upgrade to Current Stable Rust
- Reconciled by TODO-762: the pinned Rust `1.97.1` baseline remains current, while the historical `rust-version = "1.80"` premise is not current manifest evidence.
- Detail: `docs/todo/done/todo-204-toolchain-baseline-upgrade-to-current-stable-rust.md`

### TODO-205 - Workspace Build, Test, and Clippy Excellence Restoration
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-205-workspace-build-test-and-clippy-excellence-restoration.md`

### TODO-206 - Clippy Debt and Code-Hygiene Elimination
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-206-clippy-debt-and-code-hygiene-elimination.md`

### TODO-207 - Connection Migration Path Validation State Machine
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-207-connection-migration-path-validation-state-machine.md`

### TODO-208 - Anti-Amplification, Path Cooldown, and Validation Guards
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-208-anti-amplification-path-cooldown-and-validation-guards.md`

### TODO-209 - Migration Event and Telemetry Truth Correction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-209-migration-event-and-telemetry-truth-correction.md`

### TODO-210 - Migration Test Truth Rebuild and Adversarial Coverage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-210-migration-test-truth-rebuild-and-adversarial-coverage.md`

### TODO-211 - Migration Suite and Runtime Contract Realignment
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-211-migration-suite-and-runtime-contract-realignment.md`

### TODO-212 - Migration Documentation and Product-Surface Truth Rewrite
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-212-migration-documentation-and-product-surface-truth-rewrite.md`

### TODO-213 - Admin Credential Policy Reconciliation to 4 Characters
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-213-admin-credential-policy-reconciliation-to-4-characters.md`

### TODO-214 - Weak Local Admin Defaults Documentation and Operator Override Guide
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-214-weak-local-admin-defaults-documentation-and-operator-override-guide.md`

### TODO-215 - Script, Smoke, Audit, and CI Svelte-Truth Harmonization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-215-script-smoke-audit-and-ci-svelte-truth-harmonization.md`

### TODO-216 - Frontend Svelte Truth Revalidation After Repository and Toolchain Cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-216-frontend-svelte-truth-revalidation-after-repository-and-toolchain-cleanup.md`

### TODO-217 - End-to-End Validation Matrix and Release-Readiness Gate
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-217-end-to-end-validation-matrix-and-release-readiness-gate.md`

### TODO-218 - Final Local Index Consolidation and Pre-Commit Stabilization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-218-final-local-index-consolidation-and-pre-commit-stabilization.md`

### TODO-219 - Backlog and Canonical Documentation Final Synchronization
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-219-backlog-changelog-context-and-canonical-documentation-final-synchronization.md`

### TODO-220 - FEC AVX2 GF(256) Null Multiplication Table
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-220-fec-avx2-gf256-null-table.md`

### TODO-221 - Unused morus External Dependency
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-221-unused-morus-external-dependency.md`

### TODO-222 - ConnectionError Enum 44-Variant Bloat and Duplicates
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-222-connection-error-enum-bloat.md`

### TODO-223 - Dead SIMD Backends Behind #[allow(dead_code)] in fec.rs
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-223-dead-simd-backends-fec.md`

### TODO-224 - env_flag_enabled and env_parse Utility Deduplication
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-224-env-flag-parse-utility-dedup.md`

### TODO-225 - InsecureAcceptAllVerifier Missing Runtime Safety Guard
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-225-insecure-accept-all-verifier-guard.md`

### TODO-226 - std::env::set_var After Tokio Runtime Start
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-226-set-var-after-tokio-runtime.md`

### TODO-227 - Password Dialog Minimum Chars UI/Code Mismatch
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-227-password-dialog-min-chars-mismatch.md`

### TODO-228 - Frontend Utility Deduplication Sweep
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-228-frontend-utility-deduplication.md`

### TODO-229 - Dead UI Components Removal (PillToggle, Segmented)
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-229-dead-ui-components-removal.md`

### TODO-230 - svelte-desktop Build Artifacts Committed in Git
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-230-svelte-desktop-build-artifacts-in-git.md`

### TODO-231 - Desktop Polish - Favicon, Poll Redundancy, Updater Config
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-231-desktop-polish-favicon-polls-updater.md`

### TODO-232 - Hot Path Allocation and Init Redundancy
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-232-hot-path-allocation-cleanup.md`

### TODO-233 - Frontend Cosmetic Debt Sweep
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-233-frontend-cosmetic-debt.md`

### TODO-234 - Documentation Accuracy Drift
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-234-documentation-accuracy-drift.md`

### TODO-235 - std::thread::sleep in Production Synchronous Code Paths
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-235-thread-sleep-production-code.md`

### TODO-236 - FEC Telemetry Atomic Contention in Hot Path
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-236-fec-telemetry-atomic-contention.md`

### TODO-237 - Barrel Exports in server/mod.rs
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-237-barrel-exports-server-mod.md`

### TODO-238 - Admin Shared Constants Deduplication
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-238-admin-shared-constants-dedup.md`

### TODO-239 - Desktop Duplication Sweep - Magic Numbers, Styles, Utilities
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-239-desktop-duplication-sweep.md`

### TODO-240 - UI Component Divergence Desktop vs Admin
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-240-ui-component-divergence-desktop-admin.md`

### TODO-241 - Frontend README Boilerplate Replacement
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-241-frontend-readme-boilerplate.md`

### TODO-242 - todo.md Status Label Inconsistencies
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-242-todo-md-status-label-inconsistencies.md`

### TODO-243 - Frontend Dead Code and Scaffolding Cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-243-frontend-dead-code-scaffolding.md`

### TODO-244 - Frontend Naming and Label Cosmetics
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-244-frontend-naming-label-cosmetics.md`

### TODO-245 - Desktop Runtime Bugs - logCursor and throughputSamples
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-245-desktop-runtime-bugs-logcursor-throughput.md`

### TODO-246 - Replace std::process::exit() in Library Code
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-246-process-exit-in-library-code.md`

### TODO-247 - Deterministic Session Cleanup in Reality Proxy
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-247-probabilistic-session-cleanup.md`

### TODO-248 - Consolidate Triple PacketType Enum Definition
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-248-packet-type-enum-triple-definition.md`

### TODO-249 - Audit and Remove .expect() Calls in Production Code
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-249-expect-calls-audit-and-removal.md`

### TODO-250 - Remove Unimplemented Congestion Control Variants
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-250-congestion-control-dead-variants.md`

### TODO-251 - Deduplicate Aegis128L/X4/X8 Constructors
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-251-aegis-constructor-deduplication.md`

### TODO-252 - Remove Duplicate runtime_cc_algorithm() Function
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-252-runtime-cc-algorithm-from-impl-overlap.md`

### TODO-253 - Deduplicate Hex Encoding Logic
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-253-hex-encoding-logic-deduplication.md`

### TODO-254 - Fix Instant::now().elapsed() Always-Zero Anti-Fingerprinting Seed
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-254-instant-now-elapsed-zero-ns.md`

### TODO-255 - Fix //? Doc Comment Typo in stealth.rs
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-255-doc-comment-typo-question-mark.md`

### TODO-256 - Audit Crate-Level Clippy Suppressions
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-256-crate-level-clippy-suppressions.md`

### TODO-257 - Audit and Reduce recursion_limit = "1024"
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-257-recursion-limit-1024-audit.md`

### TODO-258 - Replace ConnectionId Heap Allocation with Fixed-Size Buffer
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-258-connection-id-heap-allocation.md`

### TODO-259 - Comment Hygiene - Remove Remnants and Fix Language Inconsistency
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-259-comment-hygiene-cleanup.md`

### TODO-260 - Split Monolithic Source Files into Focused Submodules
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-260-monolithic-file-split.md`

### TODO-261 - Deduplicate CLI Argument Fields Between Client and Server
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-261-cli-argument-field-deduplication.md`

### TODO-262 - Upgrade rand Crate and Consolidate RNG Usage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-262-rand-crate-upgrade-and-rng-consolidation.md`

### TODO-263 - Reconcile License Headers Across Source Files
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-263-license-header-audit.md`

### TODO-264 - Move Fuzz Seed Corpus Out of Git Tracking
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-264-fuzz-seed-corpus-gitignore.md`

### TODO-265 - Fix .gitattributes Stale Path References
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-265-gitattributes-stale-paths.md`

### TODO-266 - Add .claude/ Directory to .gitignore
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-266-gitignore-claude-directory.md`

### TODO-267 - Reconcile TLS Version Claims Across Protocol Layers
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-267-tls-version-layer-mismatch.md`

### TODO-268 - Add Property-Based Tests for Core Algorithms
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-268-property-based-tests.md`

### TODO-269 - Audit TlsCoverProvider Cipher Suite Reinstallation
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-269-tls-cover-cipher-reinstallation-audit.md`


### TODO-271 - FEC emitted_ids HashSet Unbounded Growth
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-271-fec-emitted-ids-unbounded.md`

### TODO-272 - FEC Buffer Upsizing Silent Fallback
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-272-fec-buffer-upsizing-silent-fallback.md`

### TODO-273 - aead 0.6.0-rc.10 RC Dependency in Production
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-273-aead-rc-dependency.md`

### TODO-274 - Tauri capabilities.json Empty - No Permission Restrictions
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-274-tauri-capabilities-empty.md`

### TODO-275 - LICENSE Not in Repository Root
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-275-license-not-in-root.md`

### TODO-276 - tokio::spawn Fire-and-Forget in Reality Proxy
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-276-reality-proxy-joinhandle.md`

### TODO-277 - CI Uses Deprecated actions-rs/toolchain@v1
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-277-ci-deprecated-actions-rs.md`

### TODO-278 - .cargo/config.toml Profile Redundancy and German Comments
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-278-cargo-config-redundancy.md`

### TODO-279 - syncAnchor() Pattern Duplicated 3x in Svelte Admin
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-279-sync-anchor-duplication.md`

### TODO-280 - Config stealth.mode = "performance" Non-Canonical Value
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-280-config-stealth-mode-invalid.md`

### TODO-281 - engine.rs Polling Loop TODO
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-281-engine-polling-loop.md`

### TODO-282 - Debug eprintln! Statements in qftls.rs
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-282-qftls-debug-eprintln.md`

### TODO-283 - Replace aead 0.6.0-rc.10 Release Candidate with Stable
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-283-aead-release-candidate-in-production.md`

### TODO-284 - Update Outdated User-Agent Strings
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-284-outdated-ua-strings.md`

### TODO-285 - Document or Remove Unwired Config Keys
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-285-unwired-config-keys.md`

### TODO-286 - PQ Feature Flag Missing Crate Dependencies
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-286-pq-feature-missing-deps.md`

### TODO-287 - Fire-and-Forget tokio::spawn Calls
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-287-fire-and-forget-spawns.md`

### TODO-288 - ChaCha TLS Cover vs TLS Policy DPI Inconsistency
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-288-chacha-tls-cover-dpi-inconsistency.md`

### TODO-289 - ENV_MUTEX Duplicated 7x with Inconsistent Poisoning
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-289-env-mutex-inconsistent-poisoning.md`

### TODO-290 - deny.toml multiple-versions = "warn" Should Be "deny"
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-290-deny-toml-multiple-versions-warn.md`

### TODO-291 - Create SECURITY.md
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-291-missing-security-md.md`

### TODO-292 - password-hash/rand/rand_core Triple Version Fragility
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-292-rand-core-triple-version.md`

### TODO-293 - Hardcoded ADMIN_PASS="123" in E2E Test
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-293-hardcoded-admin-password-e2e.md`

### TODO-294 - DOCUMENTATION.md FEC_PARALLEL Override Contradiction
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-294-fec-parallel-doc-contradiction.md`

### TODO-295 - TODO-119 Marked Done but Troubleshooting Still References Race Condition
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-295-todo-119-troubleshooting-drift.md`

### TODO-296 - Browser Profile Scripts Reference Non-Existent Directory
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-296-browser-profiles-scripts-nonexistent-dir.md`

### TODO-297 - Shallow Stealth Test Coverage
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-297-stealth-test-coverage-gaps.md`

### TODO-298 - Congestion Control Refactor - Pluggable CC Trait + Real Implementations + Stealth Wrapper
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-298-cc-refactor-pluggable-trait.md`

### TODO-299 - it-qkey-auth-integration Test Failure - Missing AEAD Sealer
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-299-qkey-auth-integration-test-failure.md`

### TODO-300 - TLS Cover Post-Handshake Cover Traffic Gap
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-300-tls-cover-post-handshake-gap.md`

### TODO-301 - Port_Scan_SYN Probe Detection Pattern Too Generic
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-301-port-scan-syn-probe-pattern-generic.md`

### TODO-302 - BBR2 Proper Port from quiche
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-302-bbr2-proper-port.md`

### TODO-303 - cargo clean + Full Rebuild + Clippy Warning Elimination
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-303-cargo-clean-rebuild-clippy.md`

### TODO-304 - AEGIS Inline Tests
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-304-aegis-inline-tests.md`

### TODO-305 - Connection.rs Inline Tests
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-305-connection-inline-tests.md`

### TODO-306 - AdaptiveReedSolomon Parameter Adaptation Tests
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-306-adaptive-rs-tests.md`

### TODO-362 - Audit 8 #[allow(dead_code)] markers in fec/internal.rs
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-362-fec-internal-dead-code.md`

### TODO-523 - Complete Multi-Client Dual-Stack TUN and ICMP Runtime Contract
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-523-multi-client-dual-stack-icmp-proof.md`







### TODO-534 - Complete DPLPMTUD Bounds, TUN Coupling, and Runtime Proof
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-534-dplpmtud-tun-runtime-proof.md`

### TODO-535 - Prove CUBIC Conformance, Fairness, and Loss Performance
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-535-cubic-conformance-performance-proof.md`

### TODO-536 - Wire QUIC v2 and Version Negotiation End to End
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-536-quic-v2-version-negotiation-runtime.md`







### TODO-545 - Prove Cipher Reinstallation State Safety
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-545-cipher-reinstallation-safety-proof.md`

### TODO-553 - Make ARM64 Release Checksum Sidecars Relocatable
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-553-relocatable-arm64-release-checksum.md`

### TODO-554 - Make the Base TUN E2E Harness Own Its Process Cleanup
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-554-owned-base-tun-e2e-cleanup.md`

### TODO-555 - Replace Broad Process Reapers in Specialized TUN E2E Harnesses
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-555-owned-specialized-tun-e2e-cleanup.md`

### TODO-556 - Migrate GitHub Actions off Deprecated Node.js 20 Runtimes
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-556-github-actions-node24-runtime-migration.md`

### TODO-558 - Make FEC-Off Control and Live Observability Truthful
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-558-fec-off-observability-contract.md`

### TODO-568 - Remove Local Task Coupling and Waste from Public CI
- Reconciled from the done archive inventory; retained as a historical archived owner.
- Detail: `docs/todo/done/todo-568-public-ci-privacy-and-efficiency.md`



### TODO-851 - Propagate memory-lock policy into embedded server startup
- Reconciled from current detail frontmatter status `DONE`; shared standalone/embedded process-and-pool policy, pre-identity ordering, deferred Linux privilege boundary, startup-owned reload rejection, local tests, and both canonical TOML templates are complete. TODO-854 adds local deterministic negative-proof wiring and explicit native-unavailable reporting; native Linux `mlockall` execution remains an external boundary. Process-lock readiness/failure policy is complete under TODO-852.
- Detail: `docs/todo/done/todo-851-embedded-memory-lock-propagation.md`

### TODO-852 - Define process memory-lock readiness and failure policy
- Reconciled from current detail frontmatter status `DONE`; typed best-effort/fail-closed policy, query/syscall/platform failure causes, startup exposure propagation, deferred privilege readiness, panic-safe cleanup, Metrics/admin/systemd health, configuration templates, focused tests, and documentation are complete. The full library matrix reached 2,499/2,501 because of one isolated-pass parallel audit flush timeout and the existing TODO-839 packet-number assertion. TODO-854 adds local deterministic negative-proof wiring and explicit native-unavailable reporting; pool unlock/accounting remains TODO-516/TODO-678.
- Detail: `docs/todo/done/todo-852-process-memory-lock-policy.md`

### TODO-853 - Define TLS identity consistency and secret output ownership
- Reconciled from current detail frontmatter status `DONE`; rustls SPKI certificate/key correspondence now runs before process-global identity publication, isolated mismatch/duplicate/conflict preload coverage passes, and keying-material export returns a zeroizing owner through every qftls boundary. TODO-854 adds the dedicated local negative-proof wiring and explicit unavailable native-lane reporting; lower-level page-exclusive key lock/publication is closed by TODO-643 and pool ownership remains TODO-516/TODO-678.
- Detail: `docs/todo/done/todo-853-tls-identity-secret-output.md`

### TODO-854 - Add privilege, lock, and TLS negative-proof guardrails
- Reconciled from current detail frontmatter status `DONE`; deterministic privilege `19/19`, memory-lock `11/11`, qftls `19/19`, portable integration `1/1`, source-order checks, explicit native-unavailable manifest, and Windows compile-before-test CI guard are wired. The current ARM64 macOS host cannot provide Linux root-regain or Windows native fault execution; those remain explicit unavailable boundaries and are not counted as security proof.
- Detail: `docs/todo/done/todo-854-privilege-lock-negative-proof.md`

### TODO-855 - Reconcile FEC SIMD feature selection and unsafe preconditions
- Local implementation is complete and pushed as `4a6ac25`: exact matrix-derived FEC levels and thresholds, AVX-512 VBMI2/VBMI telemetry, release-safe slice bounds, local Safety contracts for all 12 FEC unsafe declarations, PCLMUL/SVE2/NEON policy alignment, FEC guardrail coverage, and negative/tail tests are wired. FEC tests pass 253/253, the SIMD self-check passes 15/15, the feature-contract audit passes, and the library check passes. The full library retains one unrelated packet-number baseline failure at 2504/2505; native x86/SVE2, sanitizer, and Miri proof remains explicitly external or owned by TODO-859/TODO-715.
- Detail: `docs/todo/done/todo-855-fec-simd-dispatch-contract.md`

### TODO-856 - Bound FEC decoder, matrix, and wire API inputs
- Implementation is complete and pushed as `1d8c900073af058c2bca325ba24c6fb16aeaa121`: compatibility packet lengths, decoder dimensions and exact coefficient widths, Decoder16 active-window membership, matrix shape errors, wire helper arithmetic/division, and source-only pool-block rejection are fail-closed. Focused stream/decoder, Wire FEC, and malformed matrix tests pass `17/17`, `24/24`, and `1/1`; `cargo check`, `cargo clippy`, formatting, and diff hygiene pass with only pre-existing warnings. Tests run with `--test-threads=1` to avoid environment-variable races between parallel tests. Native x86/SVE2, sanitizer/Miri, privileged, Omega, and external proof remain unclaimed and stay with their adjacent owners.
- Detail: `docs/todo/done/todo-856-fec-api-input-boundaries.md`

### TODO-857 - Validate Fountain constructor and source-index contracts
- Implementation is complete and pushed as `a6a7a6808a5dd6fce0a8e636df7d507fdac04146`: `LTEncoder` and `LTDecoder` constructors clamp `k` and `symbol_size` to bounded ranges before allocation; `add_source_symbol` rejects oversized and duplicate inputs; `add_encoded_symbol` rejects invalid source-index sets and oversized payloads; `propagate_decoded_symbol` validates index and length. The 32 `fec::fountain_codes` tests pass; `cargo check`, `cargo clippy`, formatting, and diff hygiene pass with only pre-existing warnings. Tests run with `--test-threads=1`. Native x86/SVE2, sanitizer/Miri, privileged, Omega, and external proof remain unclaimed and stay with their adjacent owners.
- Detail: `docs/todo/done/todo-857-fountain-input-contract.md`

### TODO-307 - io_uring Full Exploitation - Inbound RecvMsg, Server Send, SendMsgZc, SQPOLL
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-307-iouring-full-exploitation.md`

### TODO-356 - "Update stale test counts in retired local worklog and todo.md"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-356-context-todo-stale-counts.md`

### TODO-357 - "CONTRIBUTING.md says "Rust stable (latest)" instead of pinned version"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-357-contributing-rust-version.md`

### TODO-358 - "Remove 4 dead PQ trait methods from qftls.rs"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-358-stale-pq-trait-methods.md`

### TODO-359 - "Add SAFETY comments to ~25 unsafe blocks"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-359-unsafe-missing-safety-comments.md`

### TODO-360 - "Replace eprintln! with log::warn! in transport hot path"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-360-eprintln-transport-hotpath.md`

### TODO-361 - "hkdf_expand panics on large out_len instead of returning Result"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-361-hkdf-expand-panic.md`

### TODO-363 - "Stealth mode env var rejects "auto" despite TOML accepting it"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-363-stealth-env-auto-mode.md`

### TODO-364 - "Document relationship between dual 0-RTT config fields"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-364-dual-0rtt-config.md`

### TODO-365 - "server-linux.default.toml missing [anti_replay] section"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-365-server-toml-anti-replay.md`

### TODO-366 - "Extract duplicated Switch.svelte and Select.svelte to packages/ui"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-366-switch-select-duplication.md`

### TODO-367 - "Fix cn() import inconsistency between desktop and admin"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-367-cn-import-inconsistency.md`

### TODO-368 - "Move fatal-error-screen.test.ts to correct directory"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-368-fatal-error-test-misplaced.md`

### TODO-369 - "Add tests for 5 untested packages/ui components + 2 utilities"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-369-packages-ui-test-gaps.md`

### TODO-370 - "Remove fec_sim overlap between test-fec-simulation.sh and test-fec-e2e-loss.sh"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-370-fec-sim-overlap.md`

### TODO-371 - "Remove redundant smoke-fec-quick.sh"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-371-smoke-fec-redundant.md`

### TODO-372 - "Update README.md test count from "800+" to "900+""
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-372-readme-test-count.md`

### TODO-373 - "Add tests for desktop clipboard.ts"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-373-clipboard-ts-untested.md`

### TODO-374 - "Add tests for admin use-anchor-sync.ts"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-374-use-anchor-sync-untested.md`

### TODO-375 - "Replace unwrap() in quicfuscate-ctl with proper error handling"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-375-quicfuscate-ctl-unwrap.md`

### TODO-376 - "Test simd-selfcheck on macOS/Windows in CI feature-matrix"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-376-simd-selfcheck-cross-platform-ci.md`

### TODO-377 - "Add test for desktop +error.svelte page"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-377-desktop-error-page-untested.md`

### TODO-378 - "Review and resolve 7 TODO markers in Rust source code"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-378-code-todo-markers.md`

### TODO-379 - "Increase test coverage for stealth/mod.rs (5496 LOC, ~7 tests/1000 LOC)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-379-coverage-stealth-mod.md`

### TODO-380 - "Increase test coverage for simd.rs (6224 LOC, ~5 tests/1000 LOC)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-380-coverage-simd.md`

### TODO-381 - "Increase test coverage for transport/connection.rs (3399 LOC, ~7 tests/1000 LOC)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-381-coverage-transport-connection.md`

### TODO-382 - "Increase test coverage for transport/h3.rs (2033 LOC, ~8 tests/1000 LOC)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-382-coverage-transport-h3.md`

### TODO-383 - "Increase test coverage for implementations/server/mod.rs (4511 LOC, ~4 tests/1000 LOC)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-383-coverage-server-mod.md`

### TODO-384 - "Add inline tests for optimize/iter.rs (626 LOC, 0 inline)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-384-coverage-optimize-iter.md`

### TODO-385 - "Add external tests for optimize/unsafe.rs (1511 LOC, 11 inline only)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-385-coverage-optimize-unsafe.md`

### TODO-386 - "Add tests for server/fsutil.rs (50 LOC, 0 tests)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-386-coverage-fsutil.md`

### TODO-387 - "Add inline tests for transport/batch.rs (383 LOC, 0 inline)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-387-coverage-transport-batch.md`

### TODO-388 - "Add tests for client/subsystems.rs (61 LOC, 0 tests)"
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-388-coverage-client-subsystems.md`

### TODO-389 - Retire aegis128x4/x8 config override mapping drift
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-389-aegis-x4-x8-config-override.md`

### TODO-390 - AEAD selection uses MTU workload length
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-390-aead-selection-mtu-workload.md`

### TODO-391 - Eliminate double header parse in Connection::recv
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-391-double-header-parse-recv.md`

### TODO-392 - Eliminate FecPacket clone on send hot path
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-392-fec-send-clone-elimination.md`

### TODO-393 - Reuse AEGIS cipher state across packets
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-393-aegis-state-reuse.md`

### TODO-394 - Replace sent_bytes_by_pn full-scan ACK accounting
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-394-ack-accounting-data-structure.md`

### TODO-395 - MORUS in-place seal/open on trait path
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-395-morus-in-place-trait-path.md`

### TODO-396 - Brain apply_policy lock coalescing
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-396-brain-apply-policy-locks.md`

### TODO-397 - FEC encoder/decoder mutex contention
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-397-fec-mutex-contention.md`

### TODO-398 - CryptoContext RwLock scope reduction
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-398-crypto-rwlock-hot-path.md`

### TODO-399 - Criterion Connection send/recv bench
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-399-connection-criterion-bench.md`

### TODO-400 - Criterion ACK stress benchmark
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-400-ack-stress-bench.md`

### TODO-401 - Stealth-on vs stealth-off CI regression
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-401-stealth-regression-bench.md`

### TODO-402 - Batch AEAD seal/open
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-402-batch-aead.md`

### TODO-403 - Zero-copy inbound recv through FEC
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-403-zero-copy-recv.md`

### TODO-404 - Unify client pipeline with core pooled path
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-404-client-pipeline-unify.md`

### TODO-405 - Wire PN decode SIMD into production
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-405-pn-decode-simd-prod.md`

### TODO-406 - Consolidate dual stealth timing gates
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-406-dual-stealth-timing.md`

### TODO-407 - Enum AEAD dispatch instead of Box dyn
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-407-enum-aead-dispatch.md`

### TODO-408 - Fix VNNI aggregate_congestion heap allocs
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-408-vnni-aggregate-alloc-fix.md`

### TODO-409 - stream_ring_buffer throughput profile evaluation
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-409-stream-ring-buffer-default.md`

### TODO-410 - Zstd compression streaming into pool
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-410-compression-pool-streaming.md`

### TODO-411 - StrikeRegister 0-RTT anti-replay optimization
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-411-strike-register-optimization.md`

### TODO-412 - Server deploy and real-world profiling baseline
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-412-server-deploy-profiling.md`

### TODO-413 - TODO-System-Sanierung + CI-Gate for Status-Feld-Pflicht
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-413-todo-system-sanierung-ci-gate.md`

### TODO-414 - Streaming-FEC in adaptiven Loop integrieren (supersedes TODO-409)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-414-streaming-fec-adaptive-loop.md`

### TODO-415 - Reality-Grade TLS-Mimikry (3 Phasen, inkrementell)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-415-reality-grade-tls-mimikry.md`

### TODO-416 - Graduelle Stealth-Eskalation (3-Stufen-Rampe mit Hysterese)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-416-gradual-stealth-escalation.md`

### TODO-417 - Hot-Path-Lock-Entfernung (bündelt TODO-396 + TODO-397 + TODO-398)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-417-hotpath-lock-elimination.md`

### TODO-418 - Profiling-Baseline + tc-netem-Setup auf omega
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-418-profiling-baseline-tc-netem-setup.md`

### TODO-419 - Fix CI linux-fastpath-gates - uring_batch stale CQE drain
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-419-ci-linux-fastpath-stale-cqe-drain.md`

### TODO-420 - Update omega Go toolchain 1.22.2 → 1.26.4
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-420-omega-go-toolchain-update.md`

### TODO-421 - Verify GitHub contributors have no Devin/Claude co-authors
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-421-github-contributors-clean.md`

### TODO-422 - TUN VPN data plane end-to-end via MASQUE (CONNECT-UDP capsule <-> TUN routing)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-422-tun-vpn-data-plane-masque.md`

### TODO-424 - FEC full-stack performance benchmarks (encode/decode pipeline, mode switch, streaming)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-424-fec-full-stack-benchmarks.md`

### TODO-425 - FEC under network adversity (tc-netem loss/jitter/bandwidth/RTT simulation)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-425-fec-network-adversity.md`

### TODO-426 - FEC memory pressure and resource efficiency tests
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-426-fec-memory-pressure-tests.md`

### TODO-427 - FEC mode transition tests under active load
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-427-fec-transition-load-tests.md`

### TODO-428 - FEC adaptive intelligence deep optimization
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-428-fec-adaptive-deep-optimization.md`

### TODO-429 - Kill switch runtime integration - wire KillSwitch into ClientRuntime and engine lifecycle
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-429-killswitch-runtime-integration.md`

### TODO-430 - Multi-client TUN forwarding - per-client routing by destination IP
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-430-multi-client-tun-forwarding.md`

### TODO-431 - IPv6 support - dual-stack TUN, IPv6 NAT, IPv6 IP pool, IPv6 forwarding
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-431-ipv6-support.md`

### TODO-432 - ICMP handling - echo reply, packet-too-big, destination unreachable, time exceeded
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-432-icmp-handling.md`

### TODO-433 - InterleavedDecoder coefficient-to-packet-ID mapping bug - FEC recovery fails with interleave=1
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-433-interleaved-decoder-bug.md`

### TODO-434 - Production PKI (CA hierarchy, cert generation, no self-signed fallback)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-434-production-pki-ca-hierarchy.md`

### TODO-435 - DNS through tunnel (DoH wire-in, DNS proxy, server forwarding)
- Historical server-TUN slice is marked `DONE`, but the audit reconciliation records that client DoH/runtime wiring and the broader system-resolver proof are missing under TODO-771.
- Detail: `docs/todo/todo-435-dns-through-tunnel-doh-wirein.md`

### TODO-436 - Key rotation & immediate revocation (incl. race condition fix)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-436-key-rotation-immediate-revocation.md`

### TODO-437 - "IPv6 and DNS leak prevention in kill switch"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-437-ipv6-dns-leak-prevention.md`

### TODO-438 - Traffic isolation between clients
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-438-traffic-isolation-between-clients.md`

### TODO-439 - Security audit logging (SIEM-compatible)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-439-security-audit-logging-siem.md`

### TODO-440 - "Key erasure via zeroize and memory locking (mlock)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-440-key-erasure-memory-locking.md`

### TODO-441 - Privilege dropping (post-bind setuid/setgid)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-441-privilege-dropping-post-bind.md`

### TODO-442 - "Windows TUN via Wintun integration (client + server, dynamic DLL, ring buffer, kill switch)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-442-windows-tun-wintun.md`

### TODO-443 - Mobile platform TUN (iOS NetworkExtension + Android VpnService) and mobile kill switch
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-443-mobile-platforms.md`

### TODO-444 - "nftables backend for kill switch and routing (auto-detection with iptables fallback)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-444-nftables-support.md`

### TODO-445 - "Per-client bandwidth limits, traffic quotas, and fairness scheduling"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-445-per-client-bandwidth-limits.md`

### TODO-446 - "Production logging (structured JSON, rotation, file output, per-module levels, syslog)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-446-production-logging-rotation.md`

### TODO-448 - Graceful shutdown (SIGTERM, SIGHUP reload, drain mode, systemd notify)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-448-graceful-shutdown.md`

### TODO-449 - Multipath support (WiFi+LTE bonding)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-449-multipath-wifi-lte-bonding.md`

### TODO-450 - Connection migration fix (gentle cwnd handling)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-450-connection-migration-gentle-cwnd.md`

### TODO-451 - PMTUD enablement (DPLPMTUD, black hole detection)
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-451-pmtud-dplpmtud-black-hole.md`

### TODO-452 - CUBIC congestion control
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-452-cubic-congestion-control.md`

### TODO-453 - QUIC version negotiation
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-453-quic-version-negotiation.md`

### TODO-454 - NAT traversal (STUN/TURN/ICE) for restrictive firewalls
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-454-nat-traversal-stun-ice.md`

### TODO-455 - "Traffic analysis defense: chaffing, constant rates, full padding"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-455-traffic-analysis-defense-chaffing.md`

### TODO-456 - "Auth-specific rate limiting for QKey brute-force protection"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-456-auth-rate-limiting.md`

### TODO-457 - "Mutual authentication and replay protection for QKey transport"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-457-mutual-auth-replay-protection.md`

### TODO-458 - "Encryption at rest for QKey token storage (qkeys.json)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-458-qkey-token-storage-encryption.md`

### TODO-459 - "DDoS protection hardening (rate limits, burst, GeoIP, blacklist sync, challenge-response)"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-459-ddos-protection-hardening.md`

### TODO-460 - "Install script: create quicfuscate user, directories, and validate prerequisites"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-460-install-script-fix.md`

### TODO-461 - "TUN teardown retry, cleanup verification, and stale-rule cleanup on startup"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-461-tun-teardown-retry.md`

### TODO-462 - "TCP/ICMP fingerprint obfuscation through the VPN tunnel"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-462-tcp-icmp-fingerprint-obfuscation.md`

### TODO-463 - "Loss detection improvements: time-based loss, RACK, RTT variance, Reno bandwidth estimation"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-463-loss-detection-improvements.md`

### TODO-464 - Stealth persona wiring in Engine client
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-464-stealth-persona-engine-wiring.md`

### TODO-465 - Connection-scoped persona freeze and rotation semantics
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-465-stealth-persona-session-freeze.md`

### TODO-466 - Stealth mode policy rationalization and domain-fronting defaults
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-466-stealth-mode-policy-rationalization.md`

### TODO-467 - Randomized cover traffic and server-push variation
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-467-stealth-cover-traffic-variation.md`

### TODO-468 - StealthBrain actuator ownership and FEC hint cleanup
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-468-stealth-brain-policy-ownership.md`

### TODO-469 - MASQUE production path and experimental surface cleanup
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-469-stealth-masque-surface-cleanup.md`

### TODO-470 - Protocol mimicry flag truth and config cleanup
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-470-stealth-protocol-mimicry-flag-truth.md`

### TODO-472 - CI app backend release gate synchronization
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-472-ci-app-backend-release-gate-sync.md`

### TODO-473 - Linux production E2E proof hardening
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-473-linux-production-e2e-proof-hardening.md`

### TODO-474 - TUN/MASQUE hotpath and E2E lock hardening
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-474-tun-masque-hotpath-e2e-lock-hardening.md`

### TODO-475 - ACK accounting extract-if hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-475-ack-accounting-extract-if-hotpath.md`

### TODO-476 - FEC Lazy Receive Hotpath and Bounded Clean-Block Tracking
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-476-fec-lazy-receive-hotpath.md`

### TODO-477 - FEC zero-mode receive ownership preservation
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-477-fec-zero-receive-ownership.md`

### TODO-478 - Stealth H3 cover clean-path policy
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-478-stealth-h3-cover-clean-path-policy.md`

### TODO-479 - Transport stealth heuristic RNG hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-479-transport-stealth-heuristic-rng-hotpath.md`

### TODO-480 - FEC send output reuse hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-480-fec-send-output-reuse-hotpath.md`

### TODO-481 - FEC interleaved lazy gap tracking
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-481-fec-interleaved-lazy-gap-tracking.md`

### TODO-482 - Transport stealth padding decision fastpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-482-transport-stealth-padding-decision-fastpath.md`

### TODO-483 - Brain policy target cache hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-483-brain-policy-target-cache-hotpath.md`

### TODO-484 - FEC receive output reuse hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-484-fec-receive-output-reuse-hotpath.md`

### TODO-485 - ACK accounting split-drain hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-485-ack-accounting-split-drain-hotpath.md`

### TODO-486 - STREAM frame direct writer hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-486-stream-frame-direct-writer-hotpath.md`

### TODO-487 - ACK sparse prefix classification hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-487-ack-sparse-prefix-classification-hotpath.md`

### TODO-488 - FEC benchmark product-window calibration
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-488-fec-benchmark-product-window-calibration.md`

### TODO-489 - Connection benchmark hotpath isolation
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-489-connection-benchmark-hotpath-isolation.md`

### TODO-490 - FEC decode batch benchmark truth
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-490-fec-decode-batch-benchmark-truth.md`

### TODO-491 - FEC lazy full-recovery gating
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-491-fec-lazy-full-recovery-gating.md`

### TODO-492 - Transport adaptive padding power-of-two fastpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-492-transport-adaptive-padding-power-of-two-fastpath.md`

### TODO-493 - Runtime guardrail contract drift hardening
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-493-runtime-guardrail-contract-drift-hardening.md`

### TODO-494 - Transport default adaptive padding direct branch
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-494-transport-default-adaptive-padding-direct-branch.md`

### TODO-495 - QUIC padding direct writer hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-495-quic-padding-direct-writer-hotpath.md`

### TODO-496 - Transport adaptive default early return
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-496-transport-adaptive-default-early-return.md`

### TODO-497 - FEC active-mode lock bypass
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-497-fec-active-mode-lock-bypass.md`

### TODO-498 - FEC lazy source-buffer replay
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-498-fec-lazy-source-buffer-replay.md`

### TODO-499 - FEC send reuse hotpath benchmark truth
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-499-fec-send-reuse-hotpath-benchmark-truth.md`

### TODO-500 - AArch64 data AEAD selector evidence
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-500-aarch64-data-aead-selector-evidence.md`

### TODO-501 - FEC streaming lazy tail-loss gating
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-501-fec-streaming-lazy-tail-loss-gating.md`

### TODO-502 - Omega netfilter fastpath priority
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-502-omega-netfilter-fastpath-priority.md`

### TODO-503 - Svelte unit harness stability
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-503-svelte-unit-harness-stability.md`

### TODO-504 - FEC interleaved recovery isolation
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-504-fec-interleaved-recovery-isolation.md`

### TODO-505 - FEC repair telemetry fastpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-505-fec-repair-telemetry-fastpath.md`

### TODO-506 - FEC GF16 repair-burst hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-506-fec-gf16-repair-burst-hotpath.md`

### TODO-507 - Brain histogram direct divergence hotpath
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-507-brain-histogram-direct-divergence-hotpath.md`

### TODO-508 - Canonical docs SSOT cleanup after retiring local worklog files
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-508-canonical-docs-ssot-cleanup.md`

### TODO-509 - Post-clean local release gate replay
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-509-post-clean-local-release-gate-replay.md`

### TODO-511 - Security and ops acceptance audit closure
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-511-security-ops-acceptance-audit-closure.md`

### TODO-512 - Omega long-running production soak and chaos proof
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-512-omega-production-soak-chaos-proof.md`

### TODO-513 - Signed release, install, upgrade, and rollback proof
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-513-signed-release-install-upgrade-rollback-proof.md`

### TODO-514 - Stealth traffic realism validation and profile tuning
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-514-stealth-traffic-realism-validation.md`

### TODO-515 - Wire AuditLogger into server runtime so security events are actually emitted
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-515-wire-audit-logger-into-server-runtime.md`

### TODO-517 - HintChannel<T> abstraction for brain.rs hint atomics
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-517-hint-channel-abstraction.md`

### TODO-518 - Reconcile Global Atomic State Audit counts with code truth
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-518-global-atomic-audit-count-reconciliation.md`

### TODO-519 - "Windows desktop build: cfg-gate Unix-specific core library code for Windows compilation"
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-519-windows-desktop-core-porting.md`

### TODO-520 - Remove dead QKey transport-parameter channel and false confidentiality claims
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-520-remove-dead-qkey-transport-parameter-channel.md`

### TODO-522 - Close kill-switch automatic-loss handling and privileged runtime proof
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-522-kill-switch-loss-runtime-proof.md`

### TODO-524 - Prove interleaved FEC mapping and random plus burst recovery
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-524-interleaved-fec-recovery-proof.md`

### TODO-532 - Complete negotiated multipath wire and data-plane runtime
- Reconciled from current detail frontmatter status `SCRAP`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-532-negotiated-multipath-runtime.md`

### TODO-546 - Restore Windows SIMD dispatch and native core gate
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-546-windows-simd-native-core-gate.md`

### TODO-547 - Restore FEC wire framing and live 1-RTT integrity
- Reconciled from current detail frontmatter status `DONE`; retained as historical disposition, not an active queue item.
- Detail: `docs/todo/todo-547-fec-wire-framing-live-one-rtt-integrity.md`
### TODO-626 - Constant-time tag comparison claim reconciled
- The canonical helper delegates to `subtle::ConstantTimeEq`; all 13 production tag-verification call sites use it, byte-position-complete mismatch coverage passes inside the 141-test `qf-crypto` matrix, and strict crate Clippy passes.
- Detail: `docs/todo/done/todo-626-crypto-non-constant-time-tag-comparison.md`

### TODO-602 - Superseded by the canonical legacy client pipeline cleanup
- The dead `FecCodec` API finding is fully covered by TODO-625, which also owns the uncompiled `pipeline.rs` file and the latent packet-id bug.
- Detail: `docs/todo/todo-602-client-fec-codec-dead-apis.md`

### TODO-625 - Legacy client pipeline and FecCodec dead code removed
- Removed the uncompiled client adapter, its packet-id-zero wrapper, and the unused subsystem construction. Client tests pass 74/74; locked all-target checking, strict all-feature Clippy, format, diff, and source-reference gates pass. The full local library reached 2,193/2,195; the two unrelated failures remain owned by TODO-768 and TODO-807.
- Detail: `docs/todo/done/todo-625-client-legacy-pipeline-dead-code.md`

### TODO-627 - Crypto key and IV constructor boundaries closed
- Added typed exact-length rejection for ChaCha/AES/AEGIS/MORUS/data selector/benchmark builder, typed short HP-secret rejection, derived internal HP keys, and propagated all call sites. Serial crypto 143/143, qkey 11/11, packet 25/25, integration 6/6, 12/12, 24/24, all backend benchmark smokes, check/Clippy/format/diff pass; full local library 2,194/2,196 with TODO-768/TODO-807 unrelated failures.
- Detail: `docs/todo/done/todo-627-crypto-key-iv-zero-padding.md`

### TODO-629 - Header-protection samples and packet-number bounds closed
- Enforced exact 16-byte samples and 5-byte masks with propagated errors across AES and Rustls header protection, rejected missing receive samples and invalid PN bounds before mutation, and padded short-header sends to the sample minimum. Crypto 144/144, packet 29/29, integrations 6/6, 12/12, 24/24, check/Clippy/format/diff pass; full local library 2,199/2,201 with TODO-768/TODO-807 unrelated failures.
- Detail: `docs/todo/done/todo-629-aead-sample-bounds-bypass.md`

### TODO-630 - GHASH dispatch configuration cached
- The former production-test-hook claim was not confirmed because `GHASH_TEST_OVERRIDE` and `__test_set_ghash_override` are already test-only. Cached x86_64 and AArch64 startup configuration now removes per-call environment reads and string normalization; the short-packet GHASH benchmark runs through the existing microbench runner. Native all-target check, strict Clippy, Crypto 144/144, GCM 11/11 under both ARM PMULL gate values, release benchmark, and runner smoke pass. The x86 cross-check remains blocked by existing target-feature and `_mm_prefetch` compile errors.
- Detail: `docs/todo/done/todo-630-ghash-test-override-production.md`

### TODO-632 - QUIC nonce lifecycle guarded by connection-owned packet counters
- `make_nonce16` now documents its stateless IV/traffic-secret contract. The connection owner rejects packet numbers above the shared RFC 9000 62-bit maximum, advances counters with checked arithmetic across Initial/Handshake, normal 1-RTT, and targeted path-control sends, and preserves the Application counter across 1-RTT key updates. Connection regressions prove boundary, overflow, and pre-mutation rejection. Locked check/Clippy/format/diff, Connection 119/119, Crypto 144/144, Packet 28/28, integration 6/6 + 12/12 + 24/24 pass; full library 2,203/2,205 with only TODO-807/TODO-768 environment failures.
- Detail: `docs/todo/done/todo-632-quic-nonce-iv-reuse-risk.md`

### TODO-635 - Adaptive FEC emitted ID tracking is bounded
- CLOSED as stale. The canonical `qf-fec` controller evicts the oldest repair ID after `emitted_order` exceeds 4096, and the current 10,000-send resource test verifies both order depth and unique-ID telemetry stay at or below 4096.
- Detail: `docs/todo/done/todo-635-adaptive-fec-emitted-ids-unbounded.md`

### TODO-574 - Stabilize Windows audit rotation integrity gates
- Pathological tiny-segment integrity tests now use one explicit 30-second test-only durability bound while the production five-second timeout, write-through persistence, hash chain, and retention contract remain unchanged.
- Commit `54cd0b5` is exact with `origin/main`; CI `30640839744` completes successfully with all 14 executed jobs green and its conditional benchmark job skipped, including 2,005/2,005 non-ignored Windows core tests plus native Wintun/WFP and zero-residue gates. Clippy Matrix `30640839748` is fully green.
- Detail: `docs/todo/done/todo-574-audit-rotation-test-timeout.md`

### TODO-541 - Prove Linux installer across clean distro lifecycles
- The production installer now performs complete mutation-free preflight, converges exact Linux identities, permissions, config, QKey storage, and systemd state, preserves operator-owned state across reruns, and emits actionable startup diagnostics.
- Exact commit `9d3a446` is on `origin/main`. AlmaLinux 9.8 and Debian 12 both pass the byte-identical binary lifecycle with SHA-256 `2ce9281810895a90a61c629b8489b8bcc7f963264ada5915026aa006938cf791`; retained Omega evidence manifest SHA-256 is `defaa5eccc58e7a737690b275850311d4a22b97cbc83b867f7b809c9d2e875fa`. CI `30583976617` and Clippy Matrix `30583976629` are fully green.
- Detail: `docs/todo/done/todo-541-linux-installer-distro-proof.md`

### TODO-540 - Complete sustained DDoS policy and live proof
- One bounded admission owner now provides interval-correct PPS, monotonic sustained hysteresis, established-connection continuity, source-bound QUIC Retry, coherent GeoIP and blacklist enforcement, and atomic last-known-good feed persistence.
- Exact local and ARM64 Omega process gates pass with 820 controlled Initials, activation and clear, validated Retry, 120/120 established PING/ACK continuity, bounded CPU/RSS, zero protected-UI/process residue, and retained evidence SHA-256 `26cd028e2222458550099e326a90f1889958365951039320ee53725b0e1bdc5f`. Commit `b97b9aec` is on `origin/main`; CI `30572628697` attempt 2 and Clippy Matrix `30572628530` are fully green.
- Detail: `docs/todo/done/todo-540-sustained-ddos-policy-proof.md`

### TODO-569 - Replace invalid raw H3 cover stream with native H3 cover ownership
- Removed the invalid raw stream-248 injection and configuration-dependent H3 ignore bypass while preserving QUIC PING, H3-framed cover requests, Server Push/WebTransport, and transport padding/chaff.
- Exact ARM64 Omega FullPadding and ConstantRate TUN proofs pass bidirectionally with zero H3 errors. Commit `6fb4fe3` is on `origin/main`; CI `30560098207` and Clippy Matrix `30560098202` are fully green.
- Detail: `docs/todo/done/todo-569-h3-native-cover-stream-ownership.md`

### TODO-537 - Complete timer-owned traffic-analysis defense proof
- One transport-owned scheduler now controls idle and constant-rate chaff with bounded pending state, real-data priority, congestion deferral, soft stop, ramp-down, cancellation, authenticated policy activation, and runtime wakeups.
- Exact Omega captures pass 10 PPS FullPadding and 100 PPS ConstantRate cadence, wire-size, packet-capture, CPU, bandwidth, bidirectional TUN, and residue gates. Commit `2a62843` is on `origin/main`; CI `30556586065` and Clippy Matrix `30556585441` are fully green.
- Detail: `docs/todo/done/todo-537-traffic-analysis-runtime-proof.md`

### TODO-533 - Complete configurable migration and CC path adaptation
- Validated migration now uses bounded operator policy, typed path-change epochs across every congestion controller, validation RTT without false RTT sampling, preserved old-path accounting, and delayed server route commit.
- Path-control traffic bypasses and preempts FEC/stealth buffering; simultaneous validation retains peer responses. Local and exact ARM64 Omega authenticated transfer proofs exceed the throughput and recovery bounds with zero candidate residue.
- Commits `170269b` and `b581dd0` are on `origin/main`; CI `30545618521` and Clippy Matrix `30545616500` are fully green.
- Detail: `docs/todo/done/todo-533-migration-cc-path-adaptation.md`

### TODO-528 - Prove Wintun native adapter and data-plane lifecycle
- Native Wintun adapter, dual-stack packet I/O, bounded concurrent close, persistent WFP policy, process-exit retention, stale cleanup, authenticated QKey/MASQUE tunnel traffic, and signed MSI packaging are production-proved.
- Commit `281c629` is exact with `origin/main`; CI `30535580447`, Clippy Matrix `30535580572`, signed release `30533862566`, and consecutive same-server Windows-Omega runs `30535603045` / `30536002374` are green with 5/5 IPv4, 5/5 IPv6, zero WFP residue, and zero adapter residue.
- Detail: `docs/todo/done/todo-528-wintun-native-data-plane-proof.md`

### TODO-542 - Complete owned TUN and firewall cleanup lifecycle
- Every owned TUN, route, DNS, firewall, PF, and NetNat cleanup path now has exact identities, bounded retries, verified postconditions, idempotent startup/shutdown, and propagated permanent failures.
- Commit `702b903` is exact with `origin/main`; full local Rust gates, CI `30500727838`, Clippy Matrix `30500727779`, and byte-identical isolated Omega nftables/iptables lifecycle proof pass with zero unrelated-state changes.
- Detail: `docs/todo/done/todo-542-owned-cleanup-lifecycle.md`

### TODO-530 - Wire firewall backend override and privileged nftables proof
- One validated backend owner now controls client kill-switch and server routing construction with fail-closed explicit selection and no runtime re-detection.
- Exact local and isolated Omega nftables/iptables lifecycle and traffic proofs pass; commit `51e8c93` is on `origin/main`, with CI `30493587817` and Clippy Matrix `30493587906` green.
- Detail: `docs/todo/done/todo-530-firewall-backend-runtime-proof.md`

### TODO-529 - Wire per-client bandwidth, quota, and fairness enforcement
- Authenticated sessions now own independent bidirectional rate buckets, UTC daily/monthly quota accounting, QKey and admin policy precedence, typed audit/metrics outcomes, and exact lifecycle cleanup.
- The bounded downlink owner applies weighted DRR under optional shared capacity while preserving a direct unshaped fast path and a front-packet-bounded selection scan. Exact Omega source `73f2c10d...c062b` and binary `fa841b58...9434` pass unlimited, 10-Mbit/s, burst, quota, and real `1:2:1` three-client matrices with clean teardown.
- Full local workspace/all-target Rust tests, strict all-feature Clippy, runtime guardrails, diff hygiene, documentation, protected-UI isolation, CI `30487629259`, and Clippy Matrix `30487632307` pass for commit `b9a3383`.
- Detail: `docs/todo/done/todo-529-per-client-bandwidth-enforcement.md`

### TODO-538 - Complete QKey auth backoff and block lifecycle
- One bounded monotonic per-IP policy now owns configurable attempt accounting, capped exponential backoff, explicit blocking, success reset, pending/state capacity, and idle pruning before registry lookup.
- Exact local and isolated Omega ARM64 proofs pass, including 11 focused policy tests, CA-verified second-IP lifecycle, exact 100-attempt flood accounting, bounded resource growth, zero secret/UI/process residue, and verified candidate cleanup.
- Commits `6f8323a` and `49cd1d6` are on `origin/main`; CI `30470514675` attempt 2 and Clippy Matrix `30470515920` are green.
- Detail: `docs/todo/done/todo-538-auth-backoff-block-lifecycle.md`

### TODO-539 - Make QKey registry encryption fail closed
- QKey registry persistence now uses a versioned authenticated envelope, zeroizing current/previous key owners, fail-closed startup and mutation propagation, and crash-safe migration, recovery, downgrade rejection, and rotation.
- Exact local and isolated Omega proofs pass, including ARM64 release binary `160978324fb1ecb7bab776a4acbec60f9a8d98efa26868a295b7daa767bad7f3`; commit `fa4741f` is on `origin/main`, CI `30461879860` and Clippy Matrix `30461879937` are green.
- Detail: `docs/todo/done/todo-539-qkey-registry-fail-closed-encryption.md`

### TODO-526 - Close retained secret erasure boundaries
- AEGIS L/X4/X8 wrapper keys, IVs, and initialized state now erase on normal, replacement, and partial drop without changing the packet hot path.
- QKey issuance/import/authentication and QuicFuscate-owned TLS traffic, cache, ticket, and private-key-read material use explicit zeroizing owners with failable pre-deallocation proof.
- Final local Rust, Clippy, Tauri, runtime-guardrail, exact-source ARM64, QKey integration, storage, protected-UI, and cleanup gates pass for bundle `0c557e2a...e0df0`.
- Commit `6456b347` is on `origin/main`; CI `30452285223` and Clippy Matrix `30452283858` are green.
- Detail: `docs/todo/done/todo-526-secret-erasure-boundary-proof.md`

### TODO-525 - Complete audit durability, taxonomy, and throughput contract
- One bounded worker now owns typed schema-v2 serialization, ordering, hashing, segment rotation/retention, atomic checkpoints, acknowledged flush, and shutdown while producers remain non-blocking.
- Local full Rust/Clippy/runtime gates and exact-source native ARM64 tests pass. The Omega release probe durably accepted 10,000/10,000 events at 70,826.88 events/s with zero drops/errors and verified restart continuity.
- Detail: `docs/todo/done/todo-525-audit-durability-taxonomy-throughput.md`

### TODO-531 - Wire production logging configuration and lifecycle proof
- Archived after current-source revalidation on 2026-08-11. The extracted `qf-logging` owner retains bounded admission, stable NDJSON, sink failure accounting, FIFO flush/rotate/reopen acknowledgements, and joined failed-install cleanup through archived TODO-812.
- Effective validated configuration now owns one bounded production logger with explicit flush, fail-closed validation, stable NDJSON, and process-real sink, rotation, retention, failure, saturation, and lifecycle proof.
- Exact isolated Omega source bundle `7a013101...3a0e` passes the ARM64 release matrix `3/3` at `242 ns/record`, with `5,002` admin deliveries, zero drops, zero sink errors, verified binary hashes, clean candidate removal, and an untouched persistent checkout.
- Full local Rust check, strict Clippy, workspace/all-target test matrix, runtime guardrails, documentation consistency, and protected UI isolation pass.
- Detail: `docs/todo/done/todo-531-runtime-logging-configuration-proof.md`

### TODO-527 - Complete irreversible privilege reduction and post-drop proof
- Archived after current-source revalidation on 2026-08-11. The extracted `qf-privilege` owner retains opaque identity validation, typed partial-transition failures, complete setxid/capability reduction, every-thread verification, and isolated root-regain proof; successor TODO-849, TODO-850, and TODO-854 evidence is also closed.
- Linux startup now resolves and validates the final identity and required capabilities before privileged setup, then clears supplementary groups, all effective/permitted/inheritable/ambient capabilities, and all real/effective/saved IDs before verifying every runtime thread.
- Exact final-source Omega binary `969f7c03e755fd81f3a5302bfc9b8a49813844244249c665d0f56116feb2adbd` passed isolated root-regain proof, authenticated TLS, and five bidirectional TUN pings per direction with zero loss after the 11-thread drop.
- Full local Rust check, strict Clippy, workspace/all-target test matrix, focused privilege tests, runtime guardrails, documentation consistency, residue inspection, and protected UI isolation pass.
- Detail: `docs/todo/done/todo-527-privilege-boundary-runtime-proof.md`

### TODO-560 - Make active-connection FEC policy changes truthful
- Archived after current-source revalidation on 2026-08-11. Typed active/next acknowledgements, synchronous active policy replacement, queued-source preservation, repair retirement, fresh Zero bootstrap, reconnect projection, and `NextConnectionOnly` standalone reload semantics remain wired.
- Active Engine FEC commands now apply synchronously to live client connections or report exact next-connection scope; queued systematic sources remain byte-exact while repair-only ownership and stale codec/controller state are retired deterministically.
- Standalone reload reports `NextConnectionOnly` without misrepresenting active sessions. Embedded server construction and polling now share one dedicated Tokio reactor with bounded readiness and join ownership.
- Exact commit `ba56aae9a08ecb59bafacc8d0398c884d9db971e` passes full local Rust/Clippy/audit gates, CI `30416718625`, Clippy Matrix `30416718623`, Release Build `30416732399`, and native ARM64 Omega Engine plus two-client live reload/drain proof.
- Detail: `docs/todo/done/todo-560-active-fec-policy-control.md`

### TODO-557 - Make specialized FEC E2E acceptance executable and truthful
- Archived after revalidation. Uniform and burst runs retain collision-safe exact-binary manifests, raw measurements, machine-readable results, endpoint handshake evidence, and zero panic/decryption/runtime-liveness proof.
- Transition and adversity manifests reject panic, decryption, heartbeat, internal, and TUN-send failures. Repeated high-loss acceptance uses 200 packets per level across three isolated trials and rejects incomplete, hash-mismatched, runtime-failed, or out-of-bound child evidence.
- CUBIC Auto-versus-Off control now refuses existing artifacts and colliding topology, returns success explicitly from clean preflight, and scans all retained runtime logs. Omega passed all specialized matrices against binary `e09cad15…2f580`, including Uniform 6/6, Burst 2/2 aggregates, Transition 3/3, Adversity 25/25, repeated loss 18/18, and CUBIC Auto 99.60% versus Off 94.94% retention.
- Local Bash, ShellCheck, formatting, strict all-feature Clippy, runtime guardrails, and the complete `cargo test --workspace --all-targets --features rust-tests` gate pass. Omega ownership and collision-negative regressions pass with zero runtime residue.
- Detail: `docs/todo/done/todo-557-fec-e2e-acceptance-contract.md`

### TODO-559 - Make TUN/MASQUE sustained throughput backpressure-safe
- Detail: `docs/todo/done/todo-559-tun-masque-backpressure-throughput.md`
- Archived after current-source revalidation on 2026-08-11. Typed pressure propagation, bounded TUN/MASQUE retry ownership, the 10,000-PPS source limit, heartbeat progress, and fail-closed performance gates remain wired; native acceptance remains the exact final-source ARM64 evidence recorded below.
- Introduced `ConnectionError::DgramQueueFull` and propagated it through `transport::connection::dgram_send`, `transport::h3::send_masque_datagram`, `core::send_tunnel_packet`, and `core::send_masque_downlink`.
- Client TUN uplink (`src/main.rs`) now holds a backpressured frame and retries it before reading new frames.
- Server TUN downlink (`src/implementations/server/mod.rs`) now defers per-target downlinks in `LiveServerState::pending_tun_downlinks` and retries/flushes them each housekeeping tick.
- Server-generated MASQUE DNS and ICMP responses use a bounded per-connection queue and preserve the oldest response in a retry slot on `DgramQueueFull`; capacity, terminal-send, and shutdown outcomes are exported separately.
- Framed H3 fallback is no longer triggered by transient DATAGRAM queue pressure.
- Earlier Omega gates, not current-artifact proof: clippy clean, `cargo test --features rust-tests` passes, `tun-e2e-netns.sh` passes, and `tun-e2e-fec-netem-adversity.sh` passes (25/25).
- Historical clean-link TUN/MASQUE throughput baseline from `scripts/tests/tun-e2e-fec-netns.sh` iperf3: 1.05 Mbits/sec (0% loss).
- Commit `323fc45` passes the full GitHub CI and Clippy Matrix. Omega is now clean at that exact commit, and its ARM64 release artifact SHA-256 is `63e3e806cf7ea20c18265d4dee2ce0526805bc2ce7d2633c27fb02bda1a9c478`. The fresh UDP CUBIC matrix is a release-blocking failure: fairness passed, but the later clean baseline delivered 14/0/0 packets and all controlled 5% loss trials delivered zero. Root-cause isolation and a complete exact-artifact TCP/UDP rerun remain open.
- The exact same ARM64 artifact passes the isolated 25-case FEC Netem matrix, including loss through 50%, jitter through 500 ms, bandwidth through 1 Mbit, RTT through 300 ms, combined adversity, and clean-loss-clean recovery with no test residue. The failure is therefore narrowed to the sustained UDP CUBIC performance path.
- The exact `c609c68` ARM64 Dual-Stack TCP matrix historically passed its harness with floor trials 8.970/9.839/8.585 Mbit/s, opt-in trials 10.345/11.496/9.806 Mbit/s, and a 20.136-second 525,496-byte black-hole recovery transfer. Its 15.32% gain is not payload-efficiency evidence because the harness then capped both TUN interfaces at 1280.
- A controlled FEC-off rerun of the otherwise identical CUBIC matrix passes at 3.001 Mbit/s clean and 2.837 Mbit/s at 5% loss, retaining 94.54%. The sustained-UDP failure is isolated to Auto FEC and routes to TODO-557 for correction; TODO-559 cannot close until the repaired exact artifact reruns cleanly.
- The active FEC fixes now reject send-only recovery callbacks as loss-controller evidence, reserve repair MTU bytes, preserve queued MASQUE DATAGRAM space, and route FEC envelopes past stateless Version Negotiation. Exact ARM64 artifact `322060acffd79abe30ed7d8e4238933b0106c2df1ab3e116793e62073da8d32b` at commit `c609c68` passes the isolated CUBIC matrix: fairness `1.075`/`1.049` Mbit/s, Jain `0.999846`; Auto-FEC baseline `3.001` Mbit/s; controlled 5% loss `2.988` Mbit/s, retaining `99.56%`; cleanup leaves no namespaces and the remote source tree is clean. The Dual-Stack TCP PMTU-efficiency gate now also passes; remaining TODO-559 closure work is the bounded ownership and full performance-baseline contract, not these runtime gates.
- Durable control source `3b20cd1` reran the identical CUBIC path against that artifact with three clean and three 5%-loss trials per policy: Auto `3.001`/`2.982` Mbit/s and `99.38%`; FEC-off `3.001`/`2.830` Mbit/s and `94.32%`; measured Auto-minus-Off `0.152` Mbit/s and `5.06` percentage points. Fairness was `1.064`/`1.061` Mbit/s with Jain `0.999998`. The retained artifact is `/tmp/qf-3b20cd1-cubic.t2sP2k`; source, product processes, namespaces, bridge, and qdisc were clean after the run.
- TODO-557 is replacing the uniform-loss `iperf3` sender-text parser with a fail-closed JSON receiver gate: both endpoints must terminate successfully and sender/receiver bytes/rates plus every receiver interval must be positive. The harness supports an exact artifact through `QF_E2E_BINARY`; the runtime guardrail audit makes regression to a skipped or sender-only measurement fail.
- The initial exact ARM64 receiver-gate run measured `1.047610` Mbit/s at 0% and `1.038385` Mbit/s at 10%, but one clean-path TCP retransmission invalidated the old undocumented exact-zero assertion. Retransmits are now informational; successful delivery remains the hard gate.
- The single-source harness commit `a8c41aa` passed its Omega uniform matrix against binary SHA-256 `322060ac…da8d32b`: ping loss 0/1/2/27% at 0/5/10/25% netem and JSON-verified receiver throughput 1.047304/1.047557 Mbit/s at 0/10%; no owned process, namespace, veth, or source-tree residue remained.
- The same source executes the burst profiles from one contract: mild 2/1/0% (median 1%, maximum 2%) and heavy 3/1/3% (median 3%, maximum 3%) against binary `322060ac…da8d32b`, all cleanly torn down. Comparative FEC benefit remains separate TODO-557 work.
- TODO-557 inventory is complete; its active design work is a single scenario contract with explicit repetitions, raw evidence, aggregation, and distinct liveness, policy, and comparative-FEC claims.
- The `d714df3` single-source transition matrix passed on Omega against binary SHA-256 `322060ac…da8d32b`: Auto/moderate 0/12/0% within 5/35/10%, Off/moderate 0/18/0% with immutable Zero policy, and Auto/severe 0/42/0% within 5/60/10%. Each run printed its selected scenario row, passed telemetry assertions, and left no owned process, namespace, veth, or source-tree residue.
- Exact source `b52add5` passed the quantitative transition matrix on Omega with ARM64 Release Build bundle `dc6e91c1…371fe507` and binary `ee0243f6…61e95e88`: Auto/moderate 0/22/0% in 35,379 ms, Off/moderate 0/16/0% in 35,427 ms, and Auto/severe 0/37/0% in 35,426 ms. All passed their loss and 40,000-ms recovery limits, quantitative telemetry checks, and cleanup verification. Full CI and Clippy Matrix are green; the Release Build ARM64 job is green while its Windows signing job remains in progress.
- Adversity source `04eea5c` passed all 25 exact-artifact Omega liveness cases, including 50% loss, 500-ms jitter, 1-Mbit bandwidth, 300-ms RTT, mobile mix, and 0/18/0% recovery, with no residue. Quantitative comparison remains separate TODO-557 work.
- Single-source adversity source `09239da` is a current 23/25 negative matrix against the same binary: 50% netem loss reached 82% tunnel loss against 65%, and 500-ms jitter reached 28% against 10%. All other cases and teardown passed. This blocks TODO-557 closure until statistical qualification or a real runtime correction proves stable liveness.
- Isolated loss repeat `a81f7ad` confirms a high-loss instability: 25% netem loss reached 54% against its 40% limit, while 50% passed at 46% against 65%. The failure threshold shifts across runs, so no current passing production contract exists for high-loss liveness.
- Current adversity diagnostics now require both endpoint telemetry snapshots after each completed scenario and preserve only active-FEC, observed/lost-packet, repair, and mode-switch counters plus each measured loss, RTT, and bound with the exact binary hash and scenario contract in a new explicit artifact directory, including after a later harness failure. This is instrumentation for root-cause evidence, not a claim that the unstable high-loss contract passes.
- Diagnostic source `ae59a97` completed one exact-artifact Omega loss matrix within contract at 0/2/2/6/24/50% tunnel loss for 0/1/5/10/25/50% netem. Client telemetry at 25/50% recorded 16/28 observed losses, 2/18 repairs, and two mode switches, ruling out missing FEC controller feedback. Earlier high-loss failures remain a release blocker until a declared repeated acceptance contract proves stability.
- Repeated-contract source `6ac3917` closes the high-loss variance evidence gap: three exact-artifact Omega trials passed all 18 cases. At 25% netem loss, tunnel loss was 16/40/18% against 40%; at 50%, 46/52/56% against 65%. The raw evidence root is `/tmp/qf-6ac3917-stability.OOaYHG`; no product process, namespace, veth, or remote source-tree residue remained.
- Full-matrix source `9b57474` passed all 25 exact-artifact Omega adversity scenarios with all manifest bounds validated. Loss was 0/0/0/18/28/56%, jitter and bandwidth were 0% throughout, RTT was 4/4/4/4/2/6%, combined 2%, and recovery 0/14/0%. The local retained evidence root is `/tmp/qf-9b57474-adversity.Ul6zGU`; remote cleanup was clean.
- Exact source `b52add5` now has complete native proof: Release Build `30317521105`, including Linux, ARM64, Windows, and macOS jobs, completed successfully. Against its verified ARM64 binary `ee0243f6…61e95e88`, Uniform passed 6/6 with 0/2/4/21% tunnel loss and 1.047764/1.047857 Mbit/s receiver throughput; Burst passed mild 1/6/1% and heavy 2/1/1%; Transition passed Auto/moderate 0/22/0% in 35,379 ms, Off/moderate 0/16/0% in 35,427 ms, and Auto/severe 0/37/0% in 35,426 ms; Adversity passed all 25 cases with manifest `3cf3ac65…a0b3ff9c`. All retained the same binary identity and left no process, namespace, or veth residue.
- CUBIC harness commit `046a567` fixes the long-artifact-path Unix-socket failure without changing the product binary: the exact ARM64 bundle `c597ffb4…80a70983` contains the same verified binary `ee0243f6…61e95e88`. The live matched control passed with Auto 3.001/2.984 Mbit/s and 99.45%, Off 3.001/2.857 Mbit/s and 95.20%, delta 0.128 Mbit/s and 4.25 points, plus CUBIC/Reno Jain fairness 0.999726. Product process, namespaces, bridge, and veths were absent after cleanup.
- Current root-cause result: outer pacing generated a sub-millisecond release deadline, and `next_send_deadline()` omitted it. The Core method now includes the outer-pacer release for generic I/O-driver polling. Two exact ARM64 candidates that added direct Tokio release-time wake-ups to the standalone runtime both failed closed with client heartbeat timeouts: `14bb448` received 5.27 MiB while returning 70 KiB, and `3701737` reproduced the failure at 5.05 MiB/80 KiB. The standalone integration was removed. Local focused Core tests, all-target Rust check, and strict all-feature Clippy are green; the 15% PMTU performance gate remains unresolved and exact ARM64 revalidation is still required.
- Exact ARM64 source `47e0a82` revalidated the reverted runtime against binary `a884a6f9e930fc6c64d0641cac88eedf91dbd6414e7e3caa36930f3061cd87f5`: no heartbeat timeout was retained, but the third opt-in receiver failed to produce an artifact. The completed default trials were 2.536/7.789/8.210 Mbit/s and opt-in trials 9.393/10.337 Mbit/s; one client reached persistent congestion at 0.20% loss. Server metrics had zero TUN/MASQUE backpressure events and cleanup was zero process, namespace, host-veth, and qdisc residue. This remains a production blocker until a root-cause correction proves a complete receiver-valid run without weakening the 15% PMTU threshold.
- Recovery correction awaiting native proof: `src/transport/recovery.rs` previously retained a pending loss run across an acknowledged ack-eliciting packet that arrived after the prior loss window but before a later loss in a separate ACK frame. That could falsely bridge the run and collapse cwnd. The run now resets at every acknowledged ack-eliciting packet at or after its start, and ACK-only losses cannot establish persistent congestion. Four focused regressions, all-target check, and strict all-feature Clippy pass locally.

- Exact ARM64 source `9633afc` did not clear TODO-559: its 1280-byte phase completed at 8.859/9.270/9.439 Mbit/s (median 9.270), but the first 1500-byte receiver did not produce an artifact after client persistent congestion at 0.11% loss and cwnd 6000. Server loss and TUN/MASQUE backpressure counters remained zero; cleanup was clean. The cross-frame recovery bug is fixed but is not the sole runtime cause. Next work must expose ACK/loss provenance without altering scheduling or weakening the gate.
- Exact ARM64 source `3e64eaa` then completed all six receiver-valid trials without a persistent-congestion collapse: default 9.232/9.059/9.157 Mbit/s (median 9.157), opt-in 9.710/9.355/9.582 Mbit/s (median 9.582). Its 4.64% result is not payload-efficiency evidence because the harness capped both TUN interfaces at 1280; cleanup was clean. ACK/loss integrity is no longer the active root-cause surface.
- Root cause found in the comparison harness: its `start_phase()` passed `pmtu_max` to transport configuration but hard-coded server and client `--tun-mtu 1280`, then `configure_tun_routes()` reset every TUN to 1280. Therefore all historical PMTU gain figures are invalid as payload-efficiency evidence. The harness now gives both peers the phase ceiling, preserves client-side confirmed-MTU synchronization after startup, and a runtime guardrail fails if the 1280/1500 phase split or 15% threshold regresses. Local syntax, ShellCheck, and guardrails pass; exact ARM64 evidence is pending.
- The runtime route is IPv4 with a 1500-byte L3 MTU, so the corrected opt-in phase uses a 1472-byte QUIC UDP-payload ceiling while retaining a 1500-byte TUN ceiling. Black-hole and re-probe assertions now use 1472, and the runtime guardrail rejects regressions of this L3-versus-UDP boundary. Local Bash syntax, ShellCheck, and the full runtime-guardrails audit pass with 0 Critical and 0 Warnings; exact ARM64 proof remains pending.
- Exact ARM64 source `13f00f4` built to SHA-256 `2fcfef6e…609396` and passed the six receiver-valid throughput trials: default median `7.311` Mbit/s, opt-in median `10.631` Mbit/s, a `45.40%` gain against the unchanged 15% gate. Its black-hole recovery remains a real blocker: the client detected `1472 -> 1280` within the 12-second envelope, the filter was removed, and it re-probed only to 1328 before a 243-ms application-space persistent-congestion run. The 20-second receiver-valid TCP transfer did not complete. Server TUN/MASQUE queue, retry, and drop counters were all zero; process, namespace, qdisc, and host-veth cleanup was clean.
- The next transport correction admits a dedicated PMTU PING+PADDING probe through a closed congestion gate only when its configured interval is at least the live recovery RTT. It carries no queued control, STREAM, or DATAGRAM data and stays ack-eliciting/recovery-tracked. Positive and sub-RTT negative transport regressions, all-target Rust check, and strict library Clippy pass locally; fresh exact ARM64 black-hole proof is the remaining acceptance boundary.
- Native candidate `7b18e18` proved the congestion-gate bypass advances recovery to 1328 and 1400, but applying congestion-neutral loss tracking to every PMTU probe made a later regular probe loss unsafe. The current source keeps normal PMTU probes congestion-controlled and records only a probe that actually bypassed a closed gate outside bytes in flight, CC loss, and persistent-congestion runs. Focused no-CC-loss, gate-bypass, sub-RTT rejection, and regular-probe accounting regressions plus all-target Rust check and strict all-feature Clippy pass locally; the next exact ARM64 run is required.
- Exact ARM64 source `bfe8bd9` with binary SHA-256 `f6e3ecdeeac887478e12c0612cf990f3f2295c90a0b63a1df544b43818a4e129` passes the full three-client dual-stack PMTU gate: receiver-verified default median `7.757` Mbit/s, opt-in median `10.186` Mbit/s, `31.31%` gain; black-hole detection in `2s`; and an `18,022,400`-byte receiver-valid transfer in `20.732s`. Server TUN/MASQUE queue, retry, and drop counters were zero, and cleanup left no product process, namespace, qf523 link, or qdisc residue. TODO-559 remains open for its wider ownership, overload, impaired TCP/UDP, latency, CPU, allocation, and queue-depth acceptance gates.
- Historical source at this point passed 1,844 local library tests. TODO-559 was later closed by the final-source TCP/UDP runtime-performance evidence recorded below.
- Commit `d5e1937` makes the dual-stack throughput proof fail closed unless both pending-depth gauges and both TUN/MASQUE backpressure event-counter families are present and zero after each completed TCP phase. Its native default phase passed; two clean opt-in attempts failed earlier after application-space persistent congestion at 0.07% and 0.12% observed loss, with zero queue counters and clean residue. The current recovery correction retains packet-number-space-scoped loss candidates for reordered ACK invalidation and excludes losses sent before the first RTT sample; focused regressions, all-target check, and strict all-feature Clippy pass locally. Exact ARM64 revalidation remains required.
- Exact ARM64 revalidation of source `12da3cc` and binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26` completed the default TCP phase at 7.281 Mbit/s median but failed opt-in trial one before a receiver artifact. New bounded provenance proves a 12-packet application-space loss run from PN 10177 to 10191 over 108 ms against an 80-ms period, with ACK largest PN 10193 and 0.12% observed loss. Both queue families remained zero and teardown was clean. Do not retry unchanged behavior; diagnose the actual burst-loss source.
- A diagnostic replay of that exact binary with recovery debug tracing completed all six receiver-valid TCP trials: default median 7.655 Mbit/s, opt-in median 10.481 Mbit/s, and a 36.92% PMTU gain. The trace changes scheduling enough to remove the clean-path collapse, while the deliberate black-hole phase still correctly reached persistent congestion. The candidate runtime correction wakes the standalone client only for the outer pacing and stealth release deadline, leaving recovery/PTO on the 5 ms housekeeping owner. Local binary tests and all-target checking pass; native ARM64 proof is pending.
- Exact ARM64 source `3834141` disproved that bounded timer correction: binary `ec6187318c1b1cb6681358c13f9f48753c170ddb3a9b6289197fc9e633cb586a` reached default receiver trials 5.278/9.639/3.059 Mbit/s, then clients 2 and 3 failed closed on the 30-second heartbeat watchdog. Client 1 recorded two persistent-congestion events before the phase ended; opt-in started and then also recorded persistent congestion. Cleanup was zero product process, namespace, qf523 link, and qdisc residue. The standalone wakeup was reverted; do not attempt another direct Tokio timer variation without a new bounded root-cause design.
- Reverted diagnostic source `eeb7049` built binary `c54d2d5e1c600790fcc0c2d437fdb5f3942e8337dadd2138896f0bf958ac6a2e`. With `QF_E2E_CLIENT_TELEMETRY=1`, default receiver-valid TCP trials reached 7.425/7.470/6.955 Mbit/s before the telemetry snapshot stage, but clients 2 and 3 hit the 30-second heartbeat watchdog and their snapshot files were empty. Client 1 returned `GET /telemetry`; cleanup was zero product process, namespace, qf523 link, and qdisc residue. The passive observation mode itself is timing-sensitive in this runtime and was removed rather than treated as a root-cause fix.
- Commit `ca33b6a` snapshots the unique server UDP socket on port 4433 from the server network namespace immediately before and after every receiver-valid TCP throughput trial. Its exact ARM64 candidate built cleanly to `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`: default trials completed at 7.119/6.920/8.537 Mbit/s, opt-in trial one completed at 10.204 Mbit/s, and opt-in trial two failed before a receiver result. Every server socket drop delta, including the failure interval, was zero. Completed forward captures matched at client and server host-veth boundaries. Server kernel UDP receive-buffer overflow is excluded; next isolate server ACK emission, reverse bridge delivery, and client valid-packet processing without encrypted-payload inspection. Cleanup was zero product process, namespace, qf523 link, and qdisc.
- The next harness-only source revision records a per-trial start/end window and client exit status before it branches on client or receiver outcome, then captures the reverse encrypted UDP flow at both `qf523hs` and `qf523h1`. It reports zero reverse packets as evidence and preserves the summary on a failed trial. Local helper self-test, Bash syntax, warning-level ShellCheck, and runtime guardrails are green. Exact ARM64 proof is pending.
- Exact ARM64 harness `57a2eed` passes fully against the unchanged fresh `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26` binary: default 7.649 Mbit/s, opt-in 9.763 Mbit/s, 27.64% gain, and an 8,847,360-byte black-hole recovery transfer in 21.574 seconds. All forward and reverse client/server veth counts matched per trial, every server socket drop delta was zero, and teardown was clean. This proves server reply emission plus reverse bridge delivery for a clean full run. It does not yet capture a collapsed clean-path interval; retain the same boundary evidence on the next failure before changing runtime behavior.
- The three-run `57a2eed` stability attempt retained one complete pass and two failures. The relevant clean opt-in failure timed out with client exit status 124 after trial three: forward client/server counts were both 7,086, reverse server/client counts were both 6,072, and the server socket drop delta was zero. Underlay delivery, server receive, and server reply emission are excluded for that failure. Next isolate client valid-packet processing without changing runtime behavior. The other failed child completed clean throughput but failed in black-hole recovery. Cleanup was zero after every child.
- The next harness-only revision selects the connected client UDP socket by remote port 4433 and snapshots it before/after every throughput trial, including retained failure branches. It requires a stable local and remote endpoint and zero kernel receive-drop delta, without encrypted-payload inspection or product scheduling changes. Local helper self-test, Bash syntax, ShellCheck warning-level, and runtime guardrails pass. Exact ARM64 evidence is pending.
- Native evidence setup remains pending, not failed product proof: the first candidate invocation was rejected before setup because the SSH account was not root, the second lacked `QF_E2E_CA_KEY`, and the third incorrectly supplied the CA certificate/key as the server leaf pair, so all three children failed during TLS startup before throughput. The candidate source and host cleanup are clean. A valid retry must set only `QF_E2E_CA` and `QF_E2E_CA_KEY`, allowing the harness to generate its isolated leaf certificate.
- Exact ARM64 source `681705d` then completed the correct three-child run against unchanged binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`. Every one of the 18 clean throughput trials has a client socket summary with stable endpoint identity and zero kernel receive drops. Child one passed the full gate at default/opt-in medians 7.473/9.833 Mbit/s, 31.58% gain, and 17,498,112-byte black-hole recovery in 20.733 seconds. Children two and three passed all clean trials and failed only during deliberate black-hole recovery. Cleanup and candidate source were clean. Client kernel receive-buffer overflow is excluded from the observed clean trials; next isolate successful client `Connection::recv` processing on a retained clean collapse.
- The active source now exposes that next boundary with `QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS=1`: only a heartbeat failure logs socket datagrams/bytes, outer Core `recv` successes/errors, and successes that advanced the actual transport `last_activity` marker. The dual-stack harness defaults this opt-in on for test clients and stores the exact line only in a non-overwriting failed-trial artifact. Local focused Rust tests, syntax, ShellCheck, helper self-tests, and runtime guardrails pass. Exact ARM64 evidence remains pending; this is diagnostic evidence, not a runtime correction.
- Exact ARM64 source `a3ced4d` built after `cargo clean` to `bbdf747d8ad67ac5af5ccc1cb0904652d77cb1e84d25e34161ec6db20cad6616`. Children one and two passed all clean TCP trials at 7.241/9.965 and 7.824/10.478 Mbit/s before deliberate black-hole recovery failed. Child three reproduced a clean opt-in trial-one timeout with equal 8,667 forward and 4,965 reverse encrypted packets, zero client/server UDP socket drops, and no heartbeat yet, so the receive artifact was correctly unavailable. The preceding client log recorded application-space persistent congestion at cwnd 5,888: PN 8,549-8,564, 12 losses, 78-ms period, 109-ms run. Next isolate the transport provenance that creates that persistent-congestion decision without changing scheduling or weakening the acceptance gate.
- The active source now retains the triggering ACK newly-acked/lost counts, terminal packet/time-threshold classification, smoothed RTT, RTT variance, and loss delay in the existing persistent-congestion decision evidence. A TCP failure stores the last client event in a non-overwriting artifact. The focused recovery regression, syntax, ShellCheck, helper self-tests, and runtime guardrails pass locally. Exact ARM64 evidence remains pending; this is diagnostics only, not a recovery-policy change.
- Exact ARM64 source `36a97d0` built after `cargo clean` to `784f90a6db113439c907bd1056631dc3eca19f31aedfd6f44a077afddcfb85e1` and reproduced clean opt-in PC in all three children after their default phases. Each retained event had one newly ACKed packet and 12 losses; all terminal losses were time-threshold, only one also packet-threshold, with 92/133, 172/219, and 80/107 ms period/run pairs. Next isolate ACK progression and time-threshold loss provenance; do not weaken the RFC gate or alter scheduling without a source-grounded correction.
- The active source extends that non-scheduling provenance with decoded triggering ACK delay, largest-ACKed packet age, full packet/time-threshold loss counts, and exact-microsecond RTT/loss/period/run values. The focused recovery regression, Bash syntax, warning-level ShellCheck, and runtime guardrails pass locally. Exact ARM64 evidence is required before changing recovery behavior.
- Exact ARM64 source `d9149d0` built after `cargo clean` to `a4c31c030ffcdb6db05cf468723873dc7b1c7135fe73b10b1ab05e4aebeef7cb`. Children one and two failed only in deliberate IPv6 black-hole recovery, then their raw client logs recorded application-space persistent congestion after the 1472-to-1280 reset. The harness did not preserve a dedicated persistent-congestion artifact on that early path. Child three passed at 7.640/10.509 Mbit/s, 37.55% gain, 3-second detection, and 7,929,856 receiver bytes in 26.299s. Candidate source and runtime cleanup were clean. The black-hole recovery contract remains the active blocker.
- The active source preserves the last persistent-congestion event when black-hole recovery fails and records effective PMTU plus minimum/maximum packet size across the loss run. The focused recovery regression, Bash syntax, warning-level ShellCheck, and runtime guardrails passed before the required local `cargo clean`; free disk space is now 3.8 GB, so no further local Rust build may start until enough additional space exists for its expected 3.2-GB output.
- Exact ARM64 source `4a63c3b` retained that artifact on a failed black-hole recovery: `pmtu_effective=1280`, `run_min_packet_size=40`, and `run_max_packet_size=1280`. The loss run therefore contains no stale 1472-byte packet. Source inspection confirms FEC wire transmission already reserves the outer datagram overhead before transport packetization, so it is not yet a proven root cause.
- The active harness now captures client egress, server ingress, server return, and client ingress throughout the black-hole recovery interval, records a non-overwriting start/end/exit-status window, and writes the existing bounded four-boundary summary on either client or server recovery failure and on success. This is observation-only and does not change recovery policy.
- Exact ARM64 source `e47d3bf` built after `cargo clean` to `a6fa317fc3df9236552628bb3e9856a2503d56c818f25b81b0b5eeb25ed76aa8`. The three-child contract failed closed only because child one timed out in black-hole recovery. Its four host-veth observations matched exactly at 6,662 forward and 5,374 reverse packets, yet its client established persistent congestion at `pmtu_effective=1280` with a 40-to-1280-byte 119,988-us run against an 89,489-us period. Children two and three recovered in 2 seconds and completed 18,481,152 bytes in 20.689 seconds and 7,667,712 bytes in 23.803 seconds. Bridge delivery is excluded for this collapse; root cause remains open.
- Current source preserves frame-class provenance for that next native run: at the 1280-byte floor, Core accepts the IPv6-minimum TUN frame while effective MASQUE payload is 1180 bytes, selecting the existing H3 STREAM fallback. Persistent-congestion evidence now counts control, STREAM, and DATAGRAM carriers independently, including co-carriage. This is diagnostics only; recovery policy, scheduling, and the acceptance gate remain unchanged.
- Exact ARM64 source `7d866f6`, binary `70af5f218b611b5f0bad1ce18df3a9ffabb9b1afdba6b9fa4e2c90e9dccd7d79`, failed closed in children one and three. Child three's 1280-byte-floor persistent-congestion run contained 11 STREAM, 2 control, and 0 DATAGRAM carriers across 13 losses, proving the H3 STREAM fallback is the active collapse path. Child two passed at 43.91% gain with 17,170,432 black-hole recovery bytes in 22.086 seconds. The remaining root cause is why those STREAM carriers go unacknowledged; do not change recovery policy without source-grounded evidence.
- Current source separates those STREAM loss-run carriers into fresh range emissions and retransmissions. The next exact native run must use that bounded provenance to distinguish first-delivery loss from retransmission-loop behavior before any runtime correction.
- Exact ARM64 source `88a12ae`, binary `9088126f68f1bf37b05921f6216023b0bb41bd784b175fdb12ee6546d612610e`, produced a failed/passed/passed three-child stability contract. The failed clean opt-in trial lost 10 DATAGRAM and 2 control carriers across PN 28195-28207 before ACK 28209, with exact client-egress/server-ingress and server-return/client-ingress counts plus zero client/server UDP kernel drops. A successful child crossed the deliberate 1280-byte black hole with 11 fresh STREAM carriers, zero STREAM retransmissions, 2 control carriers, 2-second detection, and 8,912,896 receiver bytes in 24.655 seconds. STREAM retransmission is excluded as the black-hole blocker.
- Exact ARM64 source `82c954c` reused that binary with `QF_E2E_FEC_MODE=off`; all three children failed, excluding active-FEC wire admission. Child one passed both clean phases at 7.936/10.509 Mbit/s and failed black-hole recovery with 49 rate-limit events. Child two failed clean opt-in trial three after the same 10-DATAGRAM/2-control persistent-congestion shape and 37 rate-limit events. Child three completed a default receiver in 27.103 seconds after an 18.729-second host-veth gap and retained 52 rate-limit events. Clean comparison phases retained zero, and teardown left no process, namespace, link, or qdisc residue. The 1,000-PPS server default was dropping legitimate tunnel datagrams before QUIC receive. The code now restores the documented 10,000-PPS default; the harness fails closed on unbounded completed trials and any throughput-phase rate-limit event. Focused rate-limit tests pass 22/22.
- Exact harness source `b2a08d3` passes the corrected three-child stability contract against ARM64 product binary `781fbe6d…646c0`: 35.93%/43.95%/56.09% PMTU gain with a 43.95% median; black-hole detection in 3/3/2 seconds; 18,284,544/27,656,192/18,808,832 receiver-valid recovery bytes; zero rate-limit events across all 12 phase snapshots; zero UDP socket drops; and zero runtime residue. The repeated PMTU/black-hole blocker is closed. Remaining TODO-559 work is owned overload plus impaired TCP/UDP, latency, CPU, allocation, and queue-depth acceptance.
- Native runtime-performance instrumentation measures CPU, combined RSS, real pool-allocation outcomes, peak queue depth, rate-limit events, and p50/p95 latency through every CUBIC clean/loss phase. Exact final-source ARM64 binary `e09cad15…2f580` passes the tightened TCP and UDP gates: TCP medians 6.939/11.326 Mbit/s with 63.21% PMTU gain and 26,017,792-byte black-hole recovery; UDP Auto 99.71% retained versus Off 94.94%; 284.3-284.4 MiB combined RSS; 12.70-17.21% one-core CPU; 35.3-59.3-ms p95; 16,469-52,663 fallback allocations; zero queue/rate-limit events; and no heartbeat, internal, TUN-send, process, namespace, link, or qdisc residue. Deterministic real-helper overload tests expose packet, byte, per-target, and MASQUE capacity rejection by exact metric cause. Current local all-target checking, strict all-feature Clippy, and the complete `cargo test --features rust-tests` matrix pass.
- Exact commit `8271af9bb2128771ea4f5ab92206655e51543d93` closes the native release boundary: CI `30408735389`, Clippy Matrix `30408735413`, and Release Build `30408758903` completed successfully, including Linux, native ARM64, macOS, and signed Windows MSI jobs. The ARM64 server bundle SHA-256 is `17b16af6421fd803b63d7da6e1f256b9df48b006f51251c4c1850b0cf10df097`; its AArch64 binary SHA-256 is `dce1e6a924c85d94a3934999b2ff7e4d2d116d7407d441665ec369ce34591ea8`. The commit after the exact Omega runtime matrices changes only cross-platform-equivalent test assertions, so the measured product source and runtime behavior are unchanged.

### TODO-563 - Decompose monster source files into focused modules
- Detail: `docs/todo/todo-563-monster-file-decomposition.md`
- Split simd, stealth, server, connection, fec, optimize, admin_http, main, h3, and core owners under the 2500-line ceiling.
- Local proof: `cargo check --lib --features rust-tests` and `cargo test --lib --features rust-tests` (1846 passed).

### TODO-544 - RFC loss detection and network proof
- Detail: `docs/todo/todo-544-rfc-loss-detection-proof.md`
- Historical closure recorded the RFC 9002 recovery owner, per-space state, deadline wiring, CC propagation, TUN-ping correction, and named CI/Omega gates. Current follow-up gaps are explicitly owned by TODO-695 (bounded recovery scans/storage) and TODO-696 (terminal timeout cleanup); current artifact-status reconciliation belongs to TODO-561.
