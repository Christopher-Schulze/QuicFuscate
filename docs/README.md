# Rust Workspace Documentation

This directory contains documentation for the Rust reimplementation of **QuicFuscate**. The
original C++ code base is documented in [`DOCUMENTATION.md`](DOCUMENTATION.md).
The Rust modules mirror the same high level design while taking advantage of
Rust's safety guarantees and build tooling. The `core`, `crypto`, `fec` and
`stealth` crates are being ported from C++ and have not yet reached full
feature parity. Further work continues in Rust only. The legacy C++ modules are
deprecated and kept only for reference.

> **Note:** Only one Rust workspace exists. All crates reside under the `rust/`
directory and there is no separate `Rust-QuicFuscate` folder.

## Module Overview

### Core Crate
The `core` crate will provide the QUIC connection management layer. The C++
version features connection migration, BBRv2 congestion control and XDP
zero‑copy networking as outlined in the *Core Module* section of the original
documentation【F:docs/DOCUMENTATION.md†L134-L139】. The Rust crate aims to
replicate these features and expose a safe API for the rest of the workspace.
Recent updates added stubbed support for connection migration and a
placeholder BBRv2 controller so that higher layers can be exercised in tests.
The CLI can now toggle these features via `--migration` and `--bbr`.

### Crypto Crate
`crypto` contains hardware accelerated cipher implementations with automatic
selection logic. The algorithms and selection strategy come from the
*Cryptography Module* description【F:docs/DOCUMENTATION.md†L2013-L2047】. The Rust
code reuses the same concepts of AEGIS‑128X/L and MORUS‑1280‑128 with a
`CipherSuiteSelector` to pick the optimal cipher based on CPU features.

### FEC Crate
The Forward Error Correction crate offers a memory pooled encoder and decoder.
An internal `MetricsSampler` now tracks loss history and optional adaptive
callbacks can adjust the redundancy ratio dynamically. A simple stealth mode
applies random padding to repair packets. SIMD optimised Galois field
arithmetic remains under development as described in the original
documentation【F:docs/DOCUMENTATION.md†L173-L202】. The module is still
experimental.

### Stealth Crate
Traffic obfuscation is handled by the `stealth` crate.  Basic XOR obfuscation,
DoH tunnelling and domain fronting are already functional. The DoH client now
supports cached lookups with a configurable TTL (set via `--doh-ttl`). uTLS fingerprinting and
HTTP/3 masquerading remain in active development as outlined in the *Stealth
Module* section of the C++ documentation【F:docs/DOCUMENTATION.md†L1888-L1905】.
Like the FEC crate, this module is considered experimental and not production ready.

## Building & Testing the Rust Workspace
First build the patched `quiche` submodule, then compile and test the Rust workspace:

```bash
git submodule update --init --recursive libs/quiche-patched
cd libs/quiche-patched && cargo build --release && cd ../..
```

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

