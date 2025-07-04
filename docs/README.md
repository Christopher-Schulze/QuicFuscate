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

### Crypto Crate
`crypto` contains hardware accelerated cipher implementations with automatic
selection logic. The algorithms and selection strategy come from the
*Cryptography Module* description【F:docs/DOCUMENTATION.md†L2013-L2047】. The Rust
code reuses the same concepts of AEGIS‑128X/L and MORUS‑1280‑128 with a
`CipherSuiteSelector` to pick the optimal cipher based on CPU features.

Runtime detection is implemented in [`features.rs`] using the functions
`vaes_available()`, `neon_available()` and `aesni_available()`【F:rust/crypto/src/lib.rs†L38-L48】【F:rust/crypto/src/features.rs†L1-L44】.
`CipherSuiteSelector::select_best_cipher_suite_internal` chooses
`AEGIS-128X` when VAES512 is present, `AEGIS-128L` when NEON or AES-NI is
available and otherwise falls back to `MORUS-1280-128`.  Setting the
environment variable `FORCE_SOFTWARE` disables hardware checks so that all
functions return `false`【F:rust/crypto/src/features.rs†L1-L33】.

| Function             | CPU feature      | Selected suite      |
|----------------------|------------------|---------------------|
| `vaes_available()`   | VAES + AVX-512   | AEGIS-128X          |
| `neon_available()`   | NEON (ARM)       | AEGIS-128L          |
| `aesni_available()`  | AES-NI (x86)     | AEGIS-128L          |
| *(none detected)*    | --               | MORUS-1280-128      |

Example forcing the software fallback:

```bash
FORCE_SOFTWARE=1 cargo test -p crypto
```

### FEC Crate
The Forward Error Correction crate currently offers a basic encoder and decoder
and is intended to replace the old C++ implementation. Adaptive redundancy with
memory-pooled buffers and SIMD optimised Galois field arithmetic are still in
development as described in the original
documentation【F:docs/DOCUMENTATION.md†L173-L202】. The module is experimental
and not yet production ready.

### Stealth Crate
Traffic obfuscation is handled by the `stealth` crate.  Basic XOR obfuscation,
DoH tunnelling and domain fronting are already functional.  uTLS
fingerprinting and HTTP/3 masquerading are in active development as outlined in
the *Stealth Module* section of the C++ documentation【F:docs/DOCUMENTATION.md†L1888-L1905】.
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

