# Rust Workspace Documentation

This directory contains documentation for the Rust reimplementation of **QuicFuscate**. The
original C++ code base is documented in [`DOCUMENTATION.md`](DOCUMENTATION.md).
The Rust modules mirror the same high level design while taking advantage of
Rust's safety guarantees and build tooling.

> **Note:** Only one Rust workspace exists. All crates reside under the `rust/`
directory and there is no separate `Rust-QuicFuscate` folder.

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
The Forward Error Correction crate now provides working encoder and decoder
implementations.  It replaces the previous `FEC_Modul.cpp` logic and offers
adaptive redundancy with memory-pooled buffers.  SIMD optimised Galois field
arithmetic continues to be developed as described in the original
documentation【F:docs/DOCUMENTATION.md†L173-L202】.

### Stealth Crate
Traffic obfuscation is handled by the `stealth` crate.  Basic XOR obfuscation,
DoH tunnelling and domain fronting are already functional.  uTLS
fingerprinting and HTTP/3 masquerading are in active development as outlined in
the *Stealth Module* section of the C++ documentation【F:docs/DOCUMENTATION.md†L1888-L1905】.

## Building the Workspace
Ensure the patched `quiche` submodule is built and then compile the Rust
workspace:

```bash
git submodule update --init --recursive libs/quiche-patched
cd libs/quiche-patched && cargo build --release && cd ../..
```

To build **only** the Rust workspace and execute its unit tests run:

```bash
cd rust
cargo build --workspace
cargo test --workspace
```

The same steps are listed in the repository README【F:README.md†L150-L168】.

## Examples
If you want to work on a single crate you can still run its tests individually.
For example:

```bash
cd rust/crypto
cargo test
```

## Migration Notes
The repository is gradually being refactored from C++ to Rust for improved
performance and security, as noted in the main README【F:README.md†L52-L60】. The
Rust workspace mirrors the directory layout of the C++ modules and will replace
them piece by piece while keeping the core functionality intact.

