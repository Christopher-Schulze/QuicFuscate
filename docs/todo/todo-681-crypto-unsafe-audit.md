---
id: TODO-681
title: Reconcile the retired custom-crypto unsafe audit with current packet providers
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-681: Reconcile the Retired Custom-Crypto Unsafe Audit with Current Packet Providers

## Current execution gate (2026-09-23)

The seven `src/crypto/*.rs` implementation files enumerated below no longer
exist. `src/crypto/mod.rs` is a compatibility re-export of `qf_crypto`.
`crates/qf-crypto/src/` currently has no textual `unsafe` or
`target_feature`; its packet implementations use the pinned `ring` and
`aegis = 0.9.18` dependencies in `crates/qf-crypto/Cargo.toml`. The unsafe
counts, ISA branches, custom MORUS, custom GHASH, and erasure claims below are
historical evidence about retired code. They must not block TODO-885 or send
Luna to implement fixes in deleted files.

Close this audit by tracing the **current** default and opt-in packet-owner
selection through `qf_crypto`, its root compatibility re-export, packet key
installation, and call sites. Re-run exact source inventory for local `unsafe`
and `target_feature`, verify removed custom modules have no compiled owner or
live call site, and record the current provider and dependency versions. Check
current key/nonce length validation, zeroizing owner boundaries, packet-number
limit, and error handling with focused real-code tests. If a current unsafe or
contract defect exists, create a concrete child finding with path, failure
mode, fix, and failable test. Provider security, native performance,
side-channel, and promotion decisions remain with TODO-884 and TODO-885;
this task must not duplicate those gates or claim their evidence. Completion
means the old unsafe inventory is explicitly retired, the current local
boundary is proven, and the board and product documentation no longer imply
that deleted custom code is shipped.

## Why

The crypto module uses `unsafe` for AES, AEGIS, MORUS, GHASH/GCM, Poly1305, and ChaCha20 SIMD and raw-key operations. Several correctness and side-channel issues remain tracked (TODO-627, TODO-629, TODO-630, TODO-631). The AEGIS mutex/unwrap surface formerly tracked by TODO-628 was resolved by TODO-582 on 2026-08-01. The fixed-width tag-comparison claim previously tracked by TODO-626 was reconciled as stale on 2026-08-01. The remaining unsafe blocks need a systematic audit for missing bounds checks, side-channel properties, and unsafe key/IV handling.

The original exhaustive audit is the 2026-08-03 baseline. The 2026-08-07 reconciliation rechecked the complete inventory against the current source after TODO-834 changed the feature-intersection dispatch in the crypto callers; it does not relabel native ISA execution, release configuration behavior, or compiler-level erasure as proven locally.

## Affected Files

- `src/crypto/aes.rs`
- `src/crypto/morus.rs`
- `src/crypto/gcm.rs`
- `src/crypto/poly1305.rs`
- `src/crypto/chacha.rs`
- `src/crypto/aegis.rs`
- `src/crypto/mod.rs`

The current source inventory below counts textual `unsafe` tokens, not unique
unsafe operations. The separate `unsafe fn` and `target_feature` counts are
included to prevent the historical line-list counts from being mistaken for a
complete safety proof.

| File | `unsafe` tokens | `unsafe fn` | `target_feature` attributes |
|------|----------------|------------|-----------------------------|
| `src/crypto/aes.rs` | 38 | 17 | 14 |
| `src/crypto/morus.rs` | 52 | 28 | 15 |
| `src/crypto/gcm.rs` | 18 | 15 | 11 |
| `src/crypto/poly1305.rs` | 23 | 13 | 6 |
| `src/crypto/chacha.rs` | 26 | 20 | 5 |
| `src/crypto/aegis.rs` | 12 | 4 | 5 |
| `src/crypto/mod.rs` | 8 | 4 | 0 |

## Audit Scope and Evidence

- Read all seven affected source files completely, including every unsafe
  function and block, fixed-size load/store, raw pointer operation, target
  feature attribute, runtime dispatch branch, constructor, Drop implementation,
  AEAD trait implementation, and batch path.
- Read `src/crypto/aead.rs`, `src/crypto/tests.rs`, the direct packet/TLS-cover
  callers in `src/transport/packet.rs`, and all crypto-specific runtime
  fixtures under `scripts/tests/rust/`.
- Read `scripts/tests/suites/test-crypto.sh`, the relevant audit/guardrail
  scripts, the current documentation claims, and the crypto history through
  TODO-582, TODO-627, TODO-630, TODO-631, and TODO-632.
- No production implementation, test execution, build, runtime probe, commit,
  or push was performed during this audit.

## Verified Unsafe-Site Inventory

The textual `unsafe` counts above are retained as a source snapshot. They are
not unique-operation counts and do not establish safety by themselves. The
audit mapped each unsafe function/block to its caller, feature gate, and data
shape; the remaining remediation items are listed after the findings.

### `src/crypto/aegis.rs`

- Fixed-width AES state loads/stores use `[u8; 16]` values and matching target
  feature intersections; no active OOB production caller was found.
- The former mutex/`unwrap` state surface is resolved by TODO-582. `AesBlock`
  is now explicitly non-`Copy`, has a `Drop` zeroization owner, and all state
  snapshots and repeated finalization inputs use explicit `Clone` or borrows.
  Compiler-level register erasure is still outside the local proof boundary.
- Single and batch seal paths still evaluate `len + 16` or
  `plaintext_len + 16` without checked addition.

### `src/crypto/morus.rs`

- SIMD state and block operations use fixed arrays, padded partial blocks, or
  guarded full chunks. Current production callers do not pass a short buffer to
  the raw loaders, and no active OOB caller was found.
- `load_block32` still relies on a debug-only `block.len() >= 32` precondition,
  so its private unsafe contract is not fail-closed in release if a future
  caller violates it.
- Runtime dispatch intersects SSE4.2 with SSSE3, SSE4.1 with SSSE3, and the
  lower SSE/ARM feature requirements before entering target-feature helpers.
  Native execution on every alternate ISA was not proved in this audit.

### `src/crypto/gcm.rs`

- GHASH fixed tables, stack blocks, and guarded partial/full-block loops were
  checked across x86 and ARM implementations; no active OOB caller was found.
- x86 `QUICFUSCATE_GHASH` and AArch64 `QUICFUSCATE_GHASH_PMULL` are separate
  production `OnceLock` controls. The old claim that the test hook itself is
  compiled into production is stale because the test-only override is behind
  `cfg(test)`.
- The dispatch feature intersections match the current target attributes, but
  the test suite does not prove every release override and native ISA branch.

### `src/crypto/poly1305.rs`

- The raw full-block loader reads exactly 16 bytes and is reached only after
  full-block or padded-local checks in the inspected paths. AVX2, AVX-512,
  SSE2, NEON, and SVE2 loops use guarded offsets; no active OOB caller was
  found.
- Public tag inputs use fixed 32-byte keys, so constructor length handling is
  not the current issue. The remaining proof gap is native backend coverage:
  ISA tests return early when the feature is absent and do not provide a
  fail-closed matrix.

### `src/crypto/chacha.rs`

- Scalar, SSE2, AVX2, AVX-512, NEON, and SVE2 paths use fixed key/nonce
  arrays and guarded chunk/tail loops. No active OOB production caller was
  found.
- SVE2 dispatch has a compile-time wrapper/fallback plus runtime feature
  selection; the active native lane-width path still lacks a dedicated
  cross-ISA execution proof.
- The older claim that runtime guards are absent is not confirmed. The
  remaining test weakness is that backend tests return early when the required
  ISA is missing.

### `src/crypto/mod.rs`

- Fixed-size tag comparison is an accumulated 16-byte XOR and the prior
  TODO-626 claim is reconciled. Exact key/IV constructors are enforced through
  `require_exact_key_iv` and TODO-627 is closed.
- `AesGcm128` zeroizes its key, IV, and x86 AES-NI schedule on Drop. The
  separate `Aes128Ctx` and temporary schedule findings above remain open.
- `make_nonce16` is intentionally stateless and relies on the connection owner
  for the QUIC 62-bit packet-number contract. Seal paths also share the
  unchecked `len + 16` boundary.

## Findings

### 1. `Aes128Ctx` retains key schedules without Drop zeroization
- **File:** `src/crypto/aes.rs:557-626`
- **Severity:** HIGH
- **Impact:** `Aes128Ctx` retains `round_keys`, `round_keys_words`, and on x86_64
  `round_keys_ssse3`, but defines no `Drop`. Direct owners include GCM and the
  TLS-cover cipher path.
- **Fix:** Define and prove target-complete erasure for every retained schedule
  representation, including the SIMD representation.

### 2. Temporary AES schedules lack an explicit erasure contract
- **Files:** `src/crypto/aes.rs:29-59`, `src/crypto/mod.rs:219-235,330-433`
- **Severity:** MEDIUM
- **Impact:** `key_expansion`, `expand_round_keys_array`, and
  `expand_aes128_schedule` create secret schedules in ordinary stack values.
  The source does not prove that compiler-visible temporary copies are erased
  before scope exit.
- **Fix:** Establish an explicit temporary-schedule lifecycle contract and a
  failable proof for the relevant targets.

### 3. Seal paths can overflow `len + 16`
- **Files:** `src/crypto/mod.rs:156,521`, `src/crypto/aegis.rs:1707-2066`,
  and the corresponding MORUS trait paths
- **Severity:** HIGH
- **Impact:** Several seal and batch paths evaluate `len + 16` or
  `plaintext_len + 16` before checking the destination length. A wrapped sum
  can bypass `BufferTooShort` and reach a later split or index panic. Normal
  packet sizes are bounded, but arbitrary malformed `usize` values do not have
  a fail-closed trait contract.
- **Fix:** Add checked length arithmetic and negative tests for overflow and
  short destination buffers.

### 4. Nonce and packet-number limits are enforced by owners, not primitives
- **Files:** `src/crypto/mod.rs:613-629`, `src/transport/packet.rs:498`, and
  the connection packet-number owners
- **Severity:** HIGH
- **Impact:** `make_nonce16` intentionally accepts any `u64` and documents that
  its owner must reject values above QUIC's 62-bit limit. TODO-632 guards the
  normal connection-owned 1-RTT path, but public packet encryption and
  stateless AEAD trait boundaries do not enforce the limit locally. The
  property fixture also generates arbitrary `u64` counters. The evidence proves
  an owner contract, not primitive-wide rejection.
- **Fix:** Decide and document the primitive/API boundary, then add a checked
  negative proof at the chosen owner boundary.

### 5. ChaCha wrapper retains nonce material after Drop
- **File:** `src/crypto/mod.rs:141-145`
- **Severity:** MEDIUM
- **Impact:** `ChaCha20Poly1305` is cloneable, stores key and nonce, and its Drop
  implementation zeroizes only the key. The base nonce is not erased, and
  cloned copies are outside the single-owner wipe. Exact constructor key/IV
  validation is already closed by TODO-627.
- **Fix:** Define the clone and nonce lifecycle explicitly and prove erasure for
  every retained copy that remains in scope.

### 6. AEGIS state copies weaken the erasure proof
- **File:** `src/crypto/aegis.rs:146`
- **Severity:** MEDIUM
- **Impact:** `AesBlock([u8; 16])` derives `Copy` and `Clone`, while AEGIS state
  and local AES intermediates use this value type. Wrapper and inner state Drop
  wipes are real, but they do not prove erasure of every transient copied
  value. TODO-526 therefore proves owner-level wiping, not complete
  compiler-level erasure.
- **Fix:** Establish whether copied state is in scope and add a design-level
  erasure proof or remove the copy semantics.

### 7. GHASH has separate production environment controls
- **File:** `src/crypto/gcm.rs:18-55,148-165`
- **Severity:** MEDIUM
- **Impact:** x86 reads `QUICFUSCATE_GHASH` into a production `OnceLock`, while
  AArch64 separately reads `QUICFUSCATE_GHASH_PMULL`. The test suite exercises
  the ARM variable but does not provide an equivalent release proof for the x86
  override. This is a real performance/configuration boundary, not the stale
  claim that the test-only hook is compiled into production.
- **Fix:** Define the supported release control surface and cover each backend
  override with an explicit release test or remove unsupported controls.

### 8. AES table fallback has no constant-time/cache-side-channel proof
- **File:** `src/crypto/aes.rs:195-242`
- **Severity:** HIGH
- **Impact:** The non-AESNI table implementation indexes lookup tables with
  state-derived bytes. The operation is functionally bounded, but no explicit
  constant-time/cache-side-channel contract or proof covers this fallback. The
  broad constant-time documentation claim is therefore not scoped correctly.
- **Fix:** Scope the claim to proven backends or provide a side-channel analysis
  and an accepted fallback policy.

### 9. Native unsafe proof coverage is incomplete despite bounded current callers
- **Files:** all seven crypto files
- **Severity:** HIGH
- **Impact:** Fixed-width SIMD loads/stores use fixed arrays or guarded loops,
  and no active OOB production caller was found in the inspected AES, AEGIS,
  MORUS, GHASH, Poly1305, or ChaCha paths. Runtime feature branches generally
  intersect the required target features before entering intrinsic helpers.
  However, MORUS `load_block32` relies on a debug-only precondition, SVE2 paths
  combine compile-time and runtime conditions, and ISA tests return early when
  a feature is unavailable. No native cross-ISA execution or sanitizer proof
  was run in this audit.
- **Fix:** Keep the remaining per-function safety documentation, fail-closed
  test behavior, and native proof work open under the subtasks below and the
  shared TODO-834/TODO-836 guardrail owners.

## Current Reconciliation (2026-08-07)

| Baseline surface | Current status | Ownership and proof boundary |
|---|---|---|
| AES/AEGIS/MORUS/GHASH runtime dispatch | TODO-834 changed the current callers to `features_full()` and exact intersections: AEGIS requires AES-NI before VAES/AES-NI, GHASH requires the complete VPCLMUL/PCLMUL/SSE feature sets, MORUS requires the matching SSE/SSSE3 or NEON capabilities, and AES contexts use the detected AES-NI/AES/NEON/SVE-AES capabilities | Current dispatch source is reconciled; native x86, AVX10, and ARM ISA execution remain unproved |
| Aes128Ctx and temporary AES schedules | The implementation pass now clears retained byte, word, and x86 SSSE3 schedules in `Aes128Ctx::Drop`; one-shot scalar, SVE, AES-NI, and ARM schedule representations are cleared before return | Compiler-level register erasure and native proof remain open; TODO-631 remains closed for the separate `AesGcm128` target-conditional schedule |
| AEAD seal lengths | TODO-716 now supplies checked `sealed_len`/capacity arithmetic across ChaCha, AES-GCM, MORUS, AEGIS, and batch paths, with overflow and short-buffer regressions | Local implementation and malformed-length proof are closed; native/compiler proof remains separate |
| QUIC nonce and packet-number boundary | The connection-owned lifecycle remains covered by TODO-632, and every qf-crypto AEAD trait boundary now rejects counters above QUIC's 62-bit limit before nonce derivation | Primitive/API validation is locally closed; traffic-secret uniqueness and native proof remain owner/external boundaries |
| ChaCha and AEGIS state erasure | ChaCha `Drop` now zeroizes key and base nonce, and seal/open clear derived nonces and Poly1305 one-time keys, including authentication failure; AEGIS `AesBlock` is non-`Copy` with `Drop` zeroization and explicit state cloning, while compiler-level register erasure remains unproved | TODO-681 |
| GHASH release controls | TODO-630 correctly caches x86 `QUICFUSCATE_GHASH` and AArch64 `QUICFUSCATE_GHASH_PMULL`, and the x86 test mutex remains `cfg(test)`; independent release controls are documented and parser-covered, while native backend execution remains unproved | TODO-681 retains native/release proof; TODO-630 owns the completed cache implementation |
| AES table fallback and MORUS loader | AES table fallback is explicitly documented as not constant-time or cache-side-channel resistant; MORUS `load_block32` now accepts only `&[u8; 32]` and `as_chunks::<32>()` proves the release-safe loader precondition | TODO-681; native side-channel and ISA proof remain open |
| Crypto unsafe safety inventory | All 101 `unsafe fn` declarations in `src/crypto` now have a local `# Safety` or equivalent contract, and declared `target_feature` wording matches the contract; the runtime guardrail reports `missing_contracts=0` and `feature_mismatches=0` | TODO-681; native execution and sanitizer proof remain open |
| ISA and negative proof | Backend parity tests still emit `SIMD_SKIP`/return when the required ISA is unavailable; no native x86/ARM alternate-ISA, sanitizer, or Miri execution was performed | TODO-681 with TODO-834/TODO-836 adjacent dispatch and safety-proof ownership |

## Acceptance

- Every affected source file, unsafe operation inventory, direct caller,
  feature gate, length/key/nonce contract, test surface, audit script, current
  documentation claim, and relevant history boundary has been read.
- Current findings distinguish resolved TODO-582/TODO-626/TODO-627/TODO-716
  claims from open lifecycle, side-channel, configuration, and native-proof gaps.
- The crypto lifecycle implementation pass and static guardrails are complete
  for the locally actionable boundaries; this does not imply Rust test, native
  ISA, sanitizer, Miri, compiler-erasure, or side-channel evidence.

## Sub-Tasks

- [x] Read all seven crypto source files and enumerate current unsafe functions,
  target-feature attributes, raw loads/stores, dispatch branches, and Drop
  implementations.
- [x] Read direct transport/TLS-cover callers, AEAD traits, crypto unit tests,
  runtime fixtures, the crypto suite, audit scripts, docs, and crypto history.
- [x] Reconcile stale constructor, AEGIS mutex, tag-comparison, GHASH test-hook,
  and AesGcm128 schedule claims against current source and history.
- [x] Add formal `# Safety` sections or equivalent checked boundaries for the
  complete unsafe entry-point inventory and verify the guardrail inventory.
- [x] Define and implement zeroization ownership for `Aes128Ctx`, temporary
  AES schedules, ChaCha nonce/derived state, and AEGIS `AesBlock` values;
  compiler-level register erasure remains open.
- [x] Replace every AEAD seal/batch `len + 16` computation with checked
  arithmetic and add overflow/short-buffer negative tests; TODO-716 owns the
  completed implementation boundary.
- [x] Define the primitive versus connection owner boundary for the QUIC
  62-bit packet-number contract and add fail-closed tests at that boundary;
  TODO-632 retains the connection path and traffic-secret uniqueness owner.
- [x] Define and document the GHASH release override policy and parser-cover
  the x86 and AArch64 controls independently; native execution proof remains
  open.
- [x] Scope the AES table fallback as functionally bounded but not
  constant-time or cache-side-channel resistant; a positive side-channel
  proof remains open.
- [ ] Reconcile the retired custom ISA/unsafe inventory with the active
  `qf_crypto` provider owners, prove the current local contracts with focused
  tests, and assign remaining provider-native proof to TODO-884/885.
- [x] Reconcile the TODO-834 crypto dispatch delta against the complete audit
  without converting exact source feature checks into native execution proof.

## Notes

- Related to TODO-626, TODO-627, TODO-629, TODO-630, TODO-631, TODO-632, TODO-633.
- The 2026-08-07 pass added production lifecycle handling for retained and
  temporary AES schedules, ChaCha key/nonce material, explicit GHASH control
  documentation/parser coverage, AES table-fallback scope, and local safety
  contracts for all 101 crypto `unsafe fn` declarations.
- `AesBlock` is deliberately non-`Copy` and owns byte zeroization on `Drop`.
  The AEGIS state flow uses borrows for arithmetic, an explicit state clone for
  the AES round snapshot, and explicit clones where the algorithm repeats an
  input block. This removes implicit semantic copies without claiming that a
  compiler preserves zeroization against every register spill or optimization.
-  2026-08-10 continuation: qf-crypto `--all-features` tests pass `137/137`,
  strict qf-crypto Clippy passes, and format/diff checks pass after the
  non-`Copy` state boundary. The native, sanitizer, Miri, and compiler-erasure
  proof lanes remain open.
- The pass did not claim release x86, native ARM alternate-ISA, sanitizer,
  Miri, compiler-erasure, or positive side-channel evidence. Checked AEAD
  length arithmetic and the primitive packet-number rejection are source-closed;
  TODO-632 still owns connection-level traffic-secret uniqueness.

## Verification

- Current continuation on 2026-08-10 passes qf-crypto `--all-features` library tests `137/137` and strict qf-crypto Clippy, the AEAD property suite `12/12`, and the root engine/config/QKey filter `77/77`. The complete workspace all-target `rust-tests` run has `119` result blocks, `3,093` passed, `0` failed, and `6` ignored. Workspace strict check/Clippy, all-feature lib/bin check/Clippy/tests, formatting, shell syntax, and `git diff --check` pass with the guarded Cargo workflow.
- The property suite now generates counters in `0..=(2^62-1)`, matching the primitive rejection contract. The negative qf-crypto regression covers all retained AEAD families at `2^62` and above; no test was weakened or skipped.
- Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-aegis-copy-final/audit-runtime-guardrails.log`. Seam evidence is `scripts/out/audits/workspace-seams-20260810T-backend-final/workspace-seams.json`: `36` packages, `322` Rust files, `206,258` source lines, `125` module edges, `106` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`.
- Release verification passes with `target/release/quicfuscate --help` exit `0`, a `9,991,520`-byte binary, and SHA-256 `72a4a685da7ec419e63392574ab7e8e803a376d1c6db66a8065617a58ba881e8`. All-feature/all-target check and Clippy remain platform-bounded only by the unchanged Linux guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8`; native cross-ISA, sanitizer, Miri, compiler-erasure, AEGIS copied-state, GHASH-native, and positive side-channel proof remain open.
- The target guard was applied before every Cargo build/test/check/Clippy command and cleaned after `12,638,284 KiB` target usage, removing `14.2 GiB`. The final target usage remained below `12,582,912 KiB` with free space above `2,097,152 KiB`.

## Historical Verification (2026-08-07)

- Commit `3ebb84d96eb6f050682ca6a513704d2c1ac14f5f` contains the implementation
  and static guardrail pass and is pushed to `main`. Local `HEAD`,
  `origin/main`, and `git ls-remote origin refs/heads/main` match exactly.
- `cargo fmt --all -- --check`, `bash -n
  scripts/tests/audits/audit-runtime-guardrails.sh`, and `git diff --check`
  passed for the implementation pass.
- The runtime guardrail reports `unsafe_functions=101 missing_contracts=0
  feature_mismatches=0`; the new crypto lifecycle checks are green. The
  aggregate script still reports four pre-existing critical findings and one
  warning outside this task.
- `bash scripts/audits/verify-graphify-evidence.sh` processed 697 uncached
  files and returned exit 2 with `GRAPHIFY_EVIDENCE_STATUS=BLOCKED`. Manifest:
  `scripts/out/audits/graphify-20260807T020511Z/graphify-evidence.json`.
  Reason: semantic extraction unavailable; raw AST dangling or duplicate IDs;
  normalized AST unresolved or ambiguous edges; incomplete language/file
  coverage; stale or provenance-incomplete legacy artifact.
- `bash scripts/tests/audits/verify-audit-completeness.sh` returned exit 0:
  `tracked=991`, `ignored=30854`, `accounted=31845`, `current_details=370/370`,
  `missing_current=0`, `done_archive=441`, `explicit_archive_exceptions=36`,
  tracker sections `Blocked=44`, `Queue=104`, `Completed=628`, Graphify
  `BLOCKED`.
- No Rust build or test suite was admitted because the current storage headroom
  would violate the repository's two-GiB free-space floor during compilation.
  No runtime probe, native cross-ISA execution, sanitizer, Miri, or positive
  compiler-erasure/side-channel proof was performed.

## Deviations

None.
