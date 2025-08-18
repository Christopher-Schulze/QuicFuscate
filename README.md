<div align="center">
  <img src="ui/logo/QuicFuscate.png" alt="QuicFuscate Logo" width="300">
  
  [![QUIC](https://img.shields.io/badge/QUIC-Protocol-009DFF?style=for-the-badge&logo=internet-explorer)](https://datatracker.ietf.org/doc/html/rfc9000)
  [![HTTP/3](https://img.shields.io/badge/HTTP-3-FF6B6B?style=for-the-badge&logo=internet-explorer)](https://en.wikipedia.org/wiki/HTTP/3)
  [![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
  [![SIMD](https://img.shields.io/badge/SIMD-Optimized-FFA500?style=for-the-badge&logo=cpu)](https://en.wikipedia.org/wiki/SIMD)
  [![AEGIS-128](https://img.shields.io/badge/Encryption-AEGIS--128-2F855A?style=for-the-badge)](https://en.wikipedia.org/wiki/AEGIS)
  [![MORUS-1280](https://img.shields.io/badge/Encryption-MORUS--1280--128-2B6CB0?style=for-the-badge)](https://en.wikipedia.org/wiki/MORUS_(cipher))
  [![FEC](https://img.shields.io/badge/FEC-Tetrys-9F7AEA?style=for-the-badge)](https://en.wikipedia.org/wiki/Forward_error_correction)
  [![Cross-Platform](https://img.shields.io/badge/Cross--Platform-✓-38A169?style=for-the-badge&logo=windows&logoColor=white)](https://en.wikipedia.org/wiki/Cross-platform_software)
</div>

<!-- Quick Links -->
**Quick Links:** [Documentation](./docs/DOCUMENTATION.md) · [Contributing](./docs/CONTRIBUTING.md) · [Scripts Reference](./docs/DOCUMENTATION.md#scripts-reference-authoritative) · [Example Config](./docs/example_config.toml)
<br>

## 🚀 Introduction
QuicFuscate aims to deliver a state-of-the-art, QUIC-based VPN that maximizes efficiency and performance while being highly resilient to network censorship. By fusing modern transport, cryptography, adaptive forward error correction (FEC), and a cohesive stealth stack, the system enables reliable, high-throughput connectivity under adversarial conditions. The project supports democratic values by facilitating open access to information and freedom of speech.

## ⭐️ Highlights
- State-of-the-art censorship resistance with coherent browser-grade fingerprints 
  (uTLS/FakeTLS, HTTP/3 QPACK header shaping, domain fronting, DoH, optional XOR)
- Adaptive SIMD dispatch (AVX2/AVX‑512/NEON) to match platform capabilities
- AEAD selection at runtime (AEGIS-128X/L, MORUS-1280-128) aligned to CPU features; 
  PFS by default; optional post-quantum handshake
- Adaptive RLNC FEC for stability on lossy/high‑jitter paths with bitsliced GF kernels
- Zero‑copy I/O with tunable memory pool and optional XDP fast path; BBRv2 congestion control and 0-RTT
- Full Rust rewrite, consolidated modules, and strong quality gates
- Modular script suite: dedicated shell scripts for build/utils, tests (incl. optional fuzz), 
  E2E TLS verification (decode/verify .chlo), benchmarks (Criterion, FEC CSV), 
  TLS profile tools (list/probe/sidecars), and patched quiche rebuild

## 🔖 Table of Contents
- [Protocol Architecture](#protocol-architecture)
- [Core Features](#-core-features)
- [Design Deep Dive](#-design-deep-dive)
  - [Cohesive Stealth Stack](#cohesive-stealth-stack-hard-to-detect--to-block)
  - [Performance & Hardware Acceleration](#performance-architecture--hardware-acceleration)
  - [Cryptography Rationale](#cryptography-rationale-aeadfirst)
  - [FEC Internals](#fec-internals-stability-under-loss)
- [Project Status](#-project-status)
  - [Origins & Rewrite](#origins--rewrite)
- [Technical Specifications](#-technical-specifications)
- [Build Instructions](#-build-instructions)
- [Contributing](#-contributing)
- [License](#-license)

### Mission & Principles
- Optimal efficiency and performance: streamlined architecture, CPU‑optimized hot paths, and zero‑copy I/O
- Censorship resistance: coherent, browser‑grade fingerprints and traffic shaping designed to remain reliable in restrictive networks
- Stability by design: adaptive FEC for consistent delivery on lossy and high‑latency paths
- Unified, modular architecture: one active browser profile drives TLS, HTTP/3, QPACK and fronting for a single, believable fingerprint
- Safety & maintainability: full Rust rewrite with clear module boundaries and a consolidated codebase

The codebase has been simplified into a single crate rooted in the `src/`
directory. Historical references to a `rust/` workspace are obsolete because all
modules now live under `src/`.

## ✨ Core Features

### 🛡️ Stealth Techniques
- **Curated Browser Fingerprints**: Fully tuned, real‑world ClientHello profiles (`.chlo`) per browser/OS, versioned and selectable at runtime<br>
- **uTLS Fingerprinting Protection**: Mimics browser TLS fingerprints to evade deep packet inspection<br>
- **TLS Handshake Spoofing**: Replays captured ClientHello messages for realistic fingerprints<br>
- **FakeTLS Handshake**: Sends a lightweight forged handshake without establishing real TLS<br>
- **Domain Fronting**: Masks traffic by routing through trusted CDN providers
  - Rotates across vetted provider domains to decouple the visible SNI from the true origin<br>
- **HTTP/3 Masquerading**: Disguises traffic as standard HTTP/3 web traffic
  - Aligns ALPN, header sets, and framing to common web patterns<br>
- **Traffic Obfuscation**: XOR-based packet transformation to defeat pattern recognition
  - Constant‑time XOR transform applied post‑encryption; toggleable via CLI/config<br>
- **DNS-over-HTTPS (DoH)**: Resolves DNS via HTTPS to hide queries from on‑path resolvers<br>
- **QPACK Header Shaping**: Encodes realistic HTTP/3 headers with QPACK for indistinguishable request patterns<br>
- **Profile Cycling**: Optional rotation across browser/OS profiles on an interval to diversify observable fingerprints<br>
- **Spin Bit Randomization**: Planned feature for masking QUIC traffic metadata

FakeTLS differs from the real uTLS-based fingerprinting by avoiding a complete TLS session.
Instead it emits a static ClientHello and immediately returns a fake ServerHello
with a placeholder certificate. This keeps the handshake lightweight while still
presenting TLS-like traffic to network monitors. Should FakeTLS be unavailable, the library falls back to loading a real fingerprint via the FFI interface.

### 🔒 Next‑Gen Hardware‑Accelerated AEAD Cryptography
- **AEGIS-128L/X**: Authenticated encryption with hardware acceleration<br>
- **MORUS-1280-128**: Lightweight cipher for resource-constrained environments<br>
- **Perfect Forward Secrecy**: ephemeral key exchange; past sessions remain safe if long‑term keys leak<br>
- **Post-Quantum Ready**: Optional Kyber/Dilithium handshake support<br>
Runtime AEAD selection: A dispatcher auto-selects the best suite for your CPU — AEGIS-128X (VAES-512) → AEGIS-128L (AES-NI/ARM Crypto Extensions) → MORUS-1280-128 (portable fallback). This maximizes multi-Gbps throughput on modern CPUs while preserving constant-time hot paths and Perfect Forward Secrecy. See "Cryptography Design" in ./docs/DOCUMENTATION.md.<br>
AEGIS‑128X/L and MORUS‑1280‑128 are modern, high‑assurance AEAD ciphers; runtime selection leverages hardware acceleration where available to sustain high throughput.

### ⚡ Performance Optimizations
- **SIMD Acceleration**: ARM NEON and x86 AVX2/AVX-512 optimizations
  - Hot loops (FEC arithmetic, crypto glue) vectorized where safe for multi‑Gbps throughput<br>
- **Bit-Sliced GF Multiplication**: Faster FEC arithmetic via dedicated AVX2/AVX512/NEON kernels
  - Field ops implemented with bit‑slicing and tableless strategies to minimize cache pressure<br>
- **Zero-Copy Architecture**: Minimizes memory allocations for maximum throughput
  - Lock‑free buffer pool with tunables `--pool-capacity` and `--pool-block`<br>
- **Adaptive RLNC FEC**: Sliding-window RLNC encoder/decoder with SIMD acceleration
  - Systematic, windowed coding with on‑the‑fly redundancy tuned to loss/latency<br>
- **XDP Fast Path**: Optional AF_XDP‑based I/O path to reduce kernel overhead on supported systems<br>
- **Tunable Memory Pool**: Pre‑allocated buffers for zero‑copy I/O; adjust capacity/block size per workload<br>
- **Connection Multiplexing**: Multiple streams over a single connection<br>
- **0-RTT Handshake**: Reduced latency for subsequent connections

## 🧠 Design Deep Dive

### Cohesive Stealth Stack (Hard to detect & to block)
All stealth components share a single, active browser/OS profile for coherence:
- TLS: ClientHello layout, extensions, and cipher priorities mirror real browsers (uTLS mode) or are replayed (FakeTLS) from curated `.chlo` artifacts
- HTTP/3: ALPN, header sets and framing appear indistinguishable from typical web traffic; QPACK shaping aligns to realistic patterns
- Domain Fronting: visible SNI decoupled from origin; rotations over vetted front domains diversify exposure
- DoH and XOR Obfuscation: hides DNS and breaks payload regularity post‑encryption
This unity yields a homogeneous and believable network fingerprint that is difficult to reliably classify by DPI systems.

### Performance Architecture & Hardware Acceleration
- Central feature detection and dispatch: selects optimal code paths per CPU (x86: SSE2/AVX2/AVX‑512; ARM: NEON), with safe scalar fallbacks
- Zero‑copy memory pool: lock‑free, cache‑friendly buffer reuse (`--pool-capacity`, `--pool-block`), minimizing allocations and copies
- Batched processing: QUIC I/O and FEC arithmetic processed in cache‑hot batches to maximize throughput
- XDP Fast Path: optional AF_XDP bypass reduces kernel overhead on supported Linux systems
- Telemetry hooks: performance counters and gauges expose throughput/latency/repair effectiveness for tuning

### Cryptography Rationale (AEAD‑First)
- AEAD choices: AEGIS‑128L/X (AES‑round‑based, excellent on AES‑NI/VAES) and MORUS‑1280‑128 (lightweight, high‑throughput on wide SIMD)
- Per‑packet nonces and constant‑time glue ensure side‑channel robustness in hot paths
- Perfect Forward Secrecy: ephemeral X25519 handshake for session keys; optional post‑quantum experiments may be integrated behind feature flags
- Dispatcher: runtime selects the AEAD implementation best suited to the host CPU for maximum practical Gbps

### FEC Internals (Stability Under Loss)
- Adaptive RLNC, sliding‑window, systematic: data packets are sent intact; repair packets are emitted when the window is full and are cleared after emission to bound latency
- GF arithmetic kernels: bit‑sliced GF(2^8) and GF(2^16) variants with SIMD where available; consistent byte‑width policy across encoder/decoder
- Decoder: sparse elimination tuned for windowed systems; early repairs and fast‑path paths minimize recovery latency
- Adaptation: redundancy factor and window size adjust to observed loss/RTT to balance overhead and delivery probability
Result: high stability on lossy/high‑jitter paths with minimal overhead.

#### Architecture Diagram

```mermaid
flowchart LR
  subgraph App
    A[Client/Server CLI]
  end
  subgraph Core
    C[core.rs<br/>QUIC session/I-O]
    S[stealth.rs<br/>DoH/HTTP3/FakeTLS/Fronting/QPACK]
    F[fec.rs<br/>Adaptive RLNC + GF Kernels]
    K[crypto.rs<br/>AEAD Glue (AEGIS/MORUS)]
  end
  P[src/browser_profiles/*.chlo<br/>Curated ClientHello]

  A --> C
  C --> K
  C --> F
  C --> S
  S --> P
  S -->|ALPN/QPACK| C
  F -->|repairs| C
  K -->|AEAD| C

  subgraph IO
    X[XDP/UDP Sockets]
  end
  C <--> X
```



## 🏗️ Project Status

The codebase is now entirely written in Rust. Development focuses on expanding features and improving stability.

### Origins & Rewrite
QuicFuscate started as a C++ prototype and underwent a complete rewrite and extensive refactoring in Rust. The result is a clean, modular, consolidated layout:
- `src/core.rs` (QUIC session and I/O), `src/crypto.rs` (AEAD and handshake glue),
- `src/fec.rs` (encoder/decoder/adaptive/GF tables inline),
- `src/stealth.rs` (DoH, HTTP/3 masquerading, FakeTLS, domain fronting, QPACK helpers),
- `src/browser_profiles/*.chlo` (curated ClientHello profiles).
This consolidation improves safety, performance, and maintainability.

## 🛠️ Technical Specifications

| Component           | Technology                          |
|---------------------|-------------------------------------|
| Transport Protocol  | QUIC v1 / HTTP/3                   |
| Encryption         | AEGIS-128L/X, MORUS-1280-128       |
| Key Exchange       | X25519, X448                       |
| Error Correction   | ASW-RLNC-X FEC       |
| Obfuscation       | XOR-based, Traffic Shaping, TLS Handshake Spoofing |
| Platforms          | Linux, macOS, Windows (planned)     |
| Architecture       | x86_64, ARM64                      |
| Performance        | Multi-Gigabit capable              |

## 🔧 Build Instructions

This repository uses a Git submodule to include a patched QUIC library. The
`libs/patched_quiche` directory is intentionally left empty to keep the checkout
small.

Use the build scripts to fetch/patch/build the vendored quiche and export `QUICHE_PATH`:

 - Run: `./scripts/Build/build-quiche-and-check.sh`
 - Alternative: `./scripts/Build/build-quiche-rebuild-and-test.sh`
 - Or set `QUICHE_PATH` to an existing checkout before building

After the workflow finishes you can build the rest of the project with Cargo as
usual:

```bash
cargo build --release
```

Browser fingerprints are stored as base64 encoded `.chlo` files under
`src/browser_profiles/` (preferred). As a fallback, the top-level
`browser_profiles/` directory is also supported.
When the patched quiche is built, these files are
fed into the `ChloBuilder` API to recreate the exact ClientHello
layout during connection setup.

If the command fails with a missing commit error (e.g.
```
fatal: remote error: upload-pack: not our ref 5700a7c74927d2c4912ac95e904c6ad3642b6868
Fetched in submodule path 'libs/patched_quiche', but it did not contain 5700a7c74927d2c4912ac95e904c6ad3642b6868.
```
), the upstream `quiche` repository might not contain the pinned
revision `5700a7c74927d2c4912ac95e904c6ad3642b6868`. Update the
submodule URL to a mirror that includes this commit and retry:

```bash
git submodule set-url libs/patched_quiche <mirror-url>
# Then use the build script: ./scripts/Build/build-quiche-and-check.sh
# Optionally rebuild: ./scripts/Build/build-quiche-rebuild-and-test.sh
```

These scripts replace the old TUI and can be
re-run at any time. If a local copy of quiche already exists, set the
`QUICHE_PATH` environment variable to use that path instead.
When building manually make sure this variable points to
`libs/patched_quiche/quiche`:

```bash
export QUICHE_PATH=$(pwd)/libs/patched_quiche/quiche
```

### ⚠️ Fetch before build

`cargo build` will fail if `libs/patched_quiche/quiche` does not exist yet.
First fetch/patch/build the vendored quiche using the script:

 - `./scripts/Build/build-quiche-and-check.sh`

### Building quiche

Compile the patched **quiche** library using Cargo:

```bash
cd libs/patched_quiche
cargo build --release
cd ..
```

### Building

## Build the crate using Cargo:


```bash
cargo build --release
```

### Running the tests

Execute the test suite with Cargo:

```bash
cargo test
```

## 👷 Developer Notes

Ensure submodules are initialized:

```bash
git submodule update --init --recursive
```

Build and test using Cargo:

```bash
cargo build --release
cargo test
```

### Troubleshooting build issues

If the workflow fails despite all dependencies being met, detailed logs can be
found under `libs/logs/`. A common cause is an uninitialized submodule. In that
case, run:

```bash
git submodule update --init libs/patched_quiche
```

Then build quiche via the scripts:

 - `./scripts/Build/build-quiche-and-check.sh`

### Project Layout

All Rust sources reside in the `src/` directory. Modules such as `core`, `crypto`, `fec`, and `stealth` are compiled as part of a single crate. The crate exposes a library and one main CLI binary named `quicfuscate` with subcommands.

Build the crate locally:

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release
```

## 🖥️ Command-Line Usage

The single binary `quicfuscate` provides two subcommands: `client` and `server`.

Show help:

```bash
quicfuscate --help
quicfuscate client --help
quicfuscate server --help
```

Global flags:

```
  -v, --verbose          Enable verbose logging
      --telemetry        Enable Prometheus-style metrics on 0.0.0.0:9898
```

#### Configuration

Full, commented configuration: see `./docs/example_config.toml`.

Typical client example:

```bash
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --local 0.0.0.0:0 \
  --url https://example.com \
  --profile chrome \
  --os windows \
  --fec-mode zero \
  --pool-capacity 1024 \
  --pool-block 4096 \
  --xdp \
  --config ./docs/example_config.toml \
  --front-domain cdn.example.com \
  --verify-peer
```

Typical server example:

```bash
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile chrome \
  --os windows \
  --fec-mode zero \
  --pool-capacity 1024 \
  --pool-block 4096 \
  --xdp \
  --config ./docs/example_config.toml
```

Important flags (selection):

```
  --no-utls               Disable uTLS and use regular TLS
  --verify-peer           Validate the server certificate
  --ca-file <path>        CA file for verification (client only)
  --debug-tls             Show TLS debug information
  --list-fingerprints     List available browser fingerprints
  --fec-mode <mode>       Initial FEC mode (zero|light|normal|medium|strong|extreme)
  --fec-config <path>     Load Adaptive FEC settings from TOML
  --doh-provider <url>    Custom DNS-over-HTTPS resolver
  --front-domain <d>      Domain used for fronting (repeatable or comma-separated)
  --disable-doh           Disable DNS over HTTPS
  --disable-fronting      Disable domain fronting
  --disable-xor           Disable XOR obfuscation
  --disable-http3         Disable HTTP/3 masquerading
```
### 🔄 Continuous Integration

The repository includes a GitHub Actions workflow that builds and tests the
project on Linux, macOS and Windows. The workflow also performs static
analysis and uploads the release binaries as artifacts. You can find the
workflow in `.github/workflows/ci.yml`. It executes the following tasks:

1. Fetches and builds the patched `quiche` library (equivalent to running `./scripts/Build/build-quiche-and-check.sh`).
2. Runs `cargo clippy` and `cppcheck` for linting on all platforms.
3. Builds the crate and executes all integration tests.
4. Uploads the release binaries for each operating system.

To reproduce the CI steps locally run:

```bash
git submodule update --init --recursive
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

## 📦 Releases

Pre-built binaries are automatically generated for the `main` and `master`
branches. Visit the [GitHub Releases](https://github.com/yourname/QuicFuscate/releases)
page to download the latest `quicfuscate` executables for your platform.
Each release bundles the patched `quiche` library together with the
`quicfuscate_*` binaries.

## 🤝 Contributing

We welcome contributions from the community. Please read our guidelines before opening an issue or pull request:

- Start here: [CONTRIBUTING.md](./docs/CONTRIBUTING.md)
- Follow the consolidated module layout (`src/core.rs`, `src/crypto.rs`, `src/fec.rs`, `src/stealth.rs`) and keep documentation changes in `docs/DOCUMENTATION.md`
- Ensure CI, linters, and the static hardening audit pass locally before proposing changes
- Update `docs/Changelog.md`, `docs/example_config.toml`, and user‑facing docs when behavior or flags change

## 📜 License

This project is licensed under the MIT License. You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the terms of the MIT License. 

See [LICENSE](./docs/LICENSE) for details.

## ⚠️ Important Notice

This software is provided "as is" without any warranties. The developers assume no responsibility for any damage caused by the use of this software. Use at your own risk.
