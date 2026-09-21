---
id: TODO-1069
title: Remove the write-only DATA_AEAD_OVERRIDE_MODE selector residue
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-22
depends_on: [TODO-1049]
---

# TODO-1069: Remove the write-only DATA_AEAD_OVERRIDE_MODE selector residue

## Why

`crates/qf-crypto/src/lib.rs` keeps a global `AtomicU8` (`DATA_AEAD_OVERRIDE_MODE`) plus
`DATA_AEAD_OVERRIDE_AUTO`/`DATA_AEAD_OVERRIDE_AEGIS_L` constants, a `set_data_aead_override_mode`
store, and a `#[cfg(test)]` getter `data_aead_override_mode`. `install_data_aead_selection` writes
the atomic (with a hardware-AES gate), but no production code ever reads it: the only reader is
`#[cfg(test)]`, and `install_data_aead_selection` itself has no production caller — only tests call
it, and `install_data_aead_config` in `src/crypto/mod.rs` forwards to it without an observed
call site either. The real payload-AEAD selection flows through `PrivateAeadFamily` /
`payload_protection_pin` / the private negotiation, not through this global. It is a vestige of the
removed multi-backend selector and keeps dead state plus test scaffolding alive.

## Current code

- `crates/qf-crypto/src/lib.rs:22-25` constants + `static DATA_AEAD_OVERRIDE_MODE: AtomicU8`.
- `lib.rs:502-507` `#[cfg(test)] fn data_aead_override_mode` and `fn set_data_aead_override_mode`.
- `lib.rs:692-737` `install_data_aead_selection` stores the mode for `"auto"`/`"aegis"`/fallback
  and for `DataAeadPreference::Auto`/`Aegis128L` (AES-hardware gated). Writes only; reads only in tests.
- `src/crypto/mod.rs` `install_data_aead_config` + `DataAeadConfig` trait forward into it.
- Test consumers: `crates/qf-crypto/src/tests.rs` lines ~75, 83-88, 235-238 assert the stored mode.
- Test callers outside qf-crypto that must be retargeted or the build breaks:
  `scripts/tests/fuzz/src/targets/crypto_operations.rs:44`,
  `scripts/tests/rust/rt-property-suite.rs:90,106,136,148,177`,
  `scripts/tests/rust/rt-security-suite.rs:223`.
  All of them call `install_data_aead_config(&cfg)` and then use `select_data_aead(key, iv)`
  directly — `select_data_aead` never reads the global, so these calls are already functional
  no-ops. Removing the machinery means deleting those call lines, not rewriting the tests.

## Target

- No write-only AEAD selection global remains in `qf-crypto`.
- `CryptoConfig::validate` stays the single authority that rejects unsupported `force_aead`
  spellings and `standard`+private conflicts (unchanged; it already is).
- `DataAeadPreference` and `PacketProtectionMode` stay public and unchanged.

## Non-goals

- Do not change the negotiated selection semantics (`payload_protection_pin`,
  `PrivateAeadFamily`, mode pins). They are the live path.
- Do not remove `force_aead` validation from `CryptoConfig::validate`.
- No frontend or wire change.

## Design

1. Verify again that no production caller invokes `install_data_aead_selection` or
   `install_data_aead_config` (`rg` over `src/`, `crates/`, and `scripts/tests/`).
   Expected: no production callers; test callers are `crates/qf-crypto/src/tests.rs` plus
   `crypto_operations.rs`, `rt-property-suite.rs`, and `rt-security-suite.rs`.
2. Remove the atomic, the constants, the setter, the cfg(test) getter, and
   `install_data_aead_selection`. If `install_data_aead_config`/`DataAeadConfig` in
   `src/crypto/mod.rs` then have no remaining purpose, remove them too; if an external
   caller exists, keep the trait but make the install a documented validation-only no-store path —
   prefer full removal if nothing calls it.
3. Retarget the tests: `data_aead_config_force_*` tests should assert on
   `CryptoConfig::validate()` accept/reject (the live gate) instead of the stored atomic mode;
   keep the fail-closed fallback assertions as validate()-error assertions. Delete the
   no-op `install_data_aead_config` calls in `crypto_operations.rs`, `rt-property-suite.rs`,
   and `rt-security-suite.rs` — the suites exercise `select_data_aead` directly, which never
   consulted the global.
4. Update the audit check 4n comment if it references the override mode names.

## Sub-Tasks

- [ ] Caller inventory re-run and recorded in Notes (expected: no production callers;
      test callers `qf-crypto/src/tests.rs` + `crypto_operations.rs` + `rt-property-suite.rs`
      + `rt-security-suite.rs`).
- [ ] Atomic, constants, getter/setter, `install_data_aead_selection` removed; compat adapter
      removed or reduced to its remaining purpose.
- [ ] No-op `install_data_aead_config` calls deleted in `crypto_operations.rs`,
      `rt-property-suite.rs`, `rt-security-suite.rs` (5+1+1 call sites).
- [ ] Tests retargeted to `CryptoConfig::validate` semantics; qf-crypto test count updated in
      `docs/todo.md` where quoted.
- [ ] `cargo test -p qf-crypto --lib --offline` green; `cargo check --all-targets` clean;
      rt-property-suite and rt-security-suite still compile and pass under `rust-tests`.

## Acceptance

- `rg 'DATA_AEAD_OVERRIDE'` finds nothing in `crates/` or `src/`.
- No `AtomicU8` selection state remains in qf-crypto.
- Validation behavior is unchanged: `"aegis-128x4"` etc. still fail closed in `validate`.
- All tests pass; clippy clean.

## Risks

- A hidden runtime caller of `install_data_aead_config` exists outside the grepped paths (engine
  config wiring). If found, keep the entry point but strip the dead global and make the function
  validate-only, and record the caller in this file.
