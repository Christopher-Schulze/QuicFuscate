---
id: TODO-1113
title: Remove HPKE hazmat private-key debug exposure
severity: MED
phase: S
priority: P2
status: DONE
created: 2026-09-23
depends_on: [TODO-1064]
---

# TODO-1113: HPKE private-key debug boundary

## Why and evidence

`crates/qf-hpke/Cargo.toml` enables `hpke-rs` 0.7 with `hazmat` so
`RustCryptoHpke::generate_key_pair` can call
`hpke_rs::HpkePrivateKey::as_slice()` and copy those bytes into rustls.
The pinned `hpke-rs` 0.7.0 source gates `as_slice` on `hazmat`, but also
gates `Debug` for `HpkePrivateKey` and `Context` on that feature; those
implementations print raw private-key and derived context bytes. The
adapter's own `Sealer`/`Opener` Debug implementations redact the context,
and no current production log of the upstream private-key type was found.
This is an unnecessary secret-exposure capability in the production build,
not an observed key leak.

The same pinned backend exposes the public `HpkeCrypto::prng` and
`HpkeCrypto::kem_key_gen` methods, implemented by `HpkeRustCrypto` for the
existing X25519/P-256/P-384 KEMs. Their `(public, private)` byte result
can cross the required rustls trait boundary without enabling `hazmat` or
adding a cryptographic implementation.

## Target contract

- Product builds do not enable `hpke-rs/hazmat`; the upstream private-key
  and context Debug paths are therefore redacted by the dependency itself.
  Keep rustls `HpkePrivateKey` as the zeroizing output owner and do not
  write custom KEM, KDF or AEAD code.
- `RustCryptoHpke::generate_key_pair` uses the already pinned RustCrypto
  backend's typed KEM generation with its supported PRNG, maps errors to
  rustls, and moves returned private bytes into the rustls zeroizing type.
  The reported suite IDs and all nine supported combinations remain exact.
- The adapter remains interoperable both ways with `hpke-rs` and with a
  rustls ECH ClientHello/decryption proof. No new default provider, native
  library, or runtime dependency is introduced.

## Implementation and proof

- [x] Read the exact pinned `HpkeCrypto` trait signatures, result order,
      error type, PRNG and `HpkeRustCrypto` implementation before editing;
      add `hpke-rs-crypto` as a direct dependency only if the trait cannot
      be accessed through the existing direct dependencies.
- [x] Remove `hazmat` from `crates/qf-hpke/Cargo.toml`. Update only the
      generated-key adapter and tests that currently inspect upstream
      secret bytes; preserve the nine static suite definitions and all
      open/seal behavior.
- [x] Add a regression proving the upstream private-key Debug output is
      redacted in the actual resolved Cargo feature set. Check `cargo tree
      -e features -p qf-hpke` to ensure another dependency does not
      re-enable `hazmat` through Cargo feature unification.
- [x] Run all `qf-hpke` suite roundtrips, cross-adapter tests, rustls ECH
      decryption test, and the relevant no-default-features/root build
      gates. Verify malformed-key errors remain fail-closed.

## Acceptance

- Resolved production `qf-hpke` dependency tree has no `hpke-rs/hazmat`;
  private-key/context Debug output contains no secret bytes.
- All nine suite IDs and bidirectional adapter interop remain correct;
  the real ECH proof and affected builds pass with the same wire behavior.

## Verification record

- The pinned `HpkeCrypto::kem_key_gen` returns `(public, private)` byte
  vectors. `HpkeRustCrypto::prng` and that KEM method replace the upstream
  key-pair wrapper only at the rustls ownership boundary; the private vector
  moves into rustls' zeroizing `HpkePrivateKey`. No KEM/KDF/AEAD implementation
  or suite definition changed.
- The upstream private-key Debug regression failed with `hazmat` enabled and
  passes after its removal. It also checks context key, nonce, exporter secret
  and sequence-number redaction. Resolved default and all-features root Cargo
  trees contain no `hpke-rs/hazmat` activation.
- `cargo test -p qf-hpke --locked --quiet`: 10/10 passed, including all nine
  suites, both adapter directions, malformed X25519/P-256/P-384 keys, and
  Debug redaction. `cargo test --features rust-tests --lib
  qftls::tests::ech_tests --locked --quiet`: 8/8 passed, including real wire
  ECH payload decryption. `cargo clippy -p qf-hpke --all-targets --locked --
  -D warnings`, `cargo fmt --all -- --check`, and `cargo check
  --no-default-features --locked` passed. The no-default root build emits
  pre-existing warnings tracked under TODO-1079.
