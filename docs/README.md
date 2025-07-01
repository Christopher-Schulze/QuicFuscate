# Rust Workspace Documentation

This directory contains documentation for the Rust reimplementation of **QuicFuscate**. The
original C++ code base is documented in [`DOCUMENTATION.md`](DOCUMENTATION.md).
The Rust modules mirror the same high level design while taking advantage of
Rust's safety guarantees and build tooling.

## Module Overview

### Core Crate
The `core` crate will provide the QUIC connection management layer. The C++
version features connection migration, BBRv2 congestion control and XDP
zero‑copy networking as outlined in the *Core Module* section of the original
documentation【F:docs/DOCUMENTATION.md†L134-L139】. The Rust crate aims to
replicate these features and expose a safe API for the rest of the workspace.

### Crypto Crate
`crypto` contains hardware accelerated cipher implementations with automatic
selection logic. The algorithms and selection strategy come from the
*Cryptography Module* description【F:docs/DOCUMENTATION.md†L2013-L2047】. The Rust
code reuses the same concepts of AEGIS‑128X/L and MORUS‑1280‑128 with a
`CipherSuiteSelector` to pick the optimal cipher based on CPU features.

### FEC Crate
The Forward Error Correction crate implements adaptive FEC similar to the C++
module described in the documentation【F:docs/DOCUMENTATION.md†L173-L202】. SIMD
optimised Galois field arithmetic and zero‑copy memory pools are planned for the
Rust version as well.

### Stealth Crate
Traffic obfuscation is handled by the `stealth` crate. It follows the design of
DNS over HTTPS, Domain Fronting and FakeTLS in the *Stealth Module* section of
the C++ docs【F:docs/DOCUMENTATION.md†L1888-L1905】. uTLS fingerprinting and
HTTP/3 masquerading will also be ported.

## Building the Workspace
Ensure the patched `quiche` submodule is built and then compile the Rust
workspace:

```bash
git submodule update --init --recursive libs/quiche-patched
cd libs/quiche-patched && cargo build --release && cd ../..
```

To build the Rust crates run:

```bash
cd rust
cargo build --workspace
```

The same steps are listed in the repository README【F:README.md†L150-L168】.

## Examples
At the current stage the Rust crates provide basic structures only. You can use
`cargo test` within each crate as a starting point while the full
implementation is in progress. For example:

```bash
cd rust/crypto
cargo test
```

## Migration Notes
The repository is gradually being refactored from C++ to Rust for improved
performance and security, as noted in the main README【F:README.md†L52-L60】. The
Rust workspace mirrors the directory layout of the C++ modules and will replace
them piece by piece while keeping the core functionality intact.

