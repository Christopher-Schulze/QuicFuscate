# QuicFuscate

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

## 🚀 Next-Generation Stealth VPN Technology

QuicFuscate represents the pinnacle of privacy-focused networking, combining cutting-edge encryption, adaptive error correction, and advanced traffic obfuscation to create an impenetrable communication channel. Built on the QUIC protocol with HTTP/3 support, it delivers both speed and security without compromise.

> **Note:** The project has been fully migrated to Rust for improved safety and performance.

The repository contains a **single** Rust workspace located in the `rust/`
directory. Historical references to a `Rust-QuicFuscate` directory are obsolete
because all crates have been consolidated under `rust/`.

## ✨ Core Features

### 🛡️ Advanced Stealth Technology
- **uTLS Fingerprinting Protection**: Mimics browser TLS fingerprints to evade deep packet inspection
- **Fake TLS Handshake**: Implements TLS handshakes that appear legitimate to network inspection while encapsulating the real traffic
- **Domain Fronting**: Masks traffic by routing through trusted CDN providers
- **HTTP/3 Masquerading**: Disguises traffic as standard HTTP/3 web traffic
- **Traffic Obfuscation**: XOR-based packet transformation to defeat pattern recognition
- **Spin Bit Randomization**: Prevents network analysis through QUIC protocol fingerprinting

### 🔒 Military-Grade Encryption
- **AEGIS-128L/X**: Authenticated encryption with hardware acceleration
- **MORUS-1280-128**: Lightweight cipher for resource-constrained environments
- **Perfect Forward Secrecy**: Ephemeral key exchange for maximum security
- **Post-Quantum Ready**: Designed to resist quantum computing attacks

### ⚡ Performance Optimizations
- **SIMD Acceleration**: ARM NEON and x86 AVX2/AVX-512 optimizations
- **Zero-Copy Architecture**: Minimizes memory allocations for maximum throughput
- **Adaptive RLNC FEC**: Sliding-window RLNC encoder/decoder with SIMD acceleration
- **Connection Multiplexing**: Multiple streams over a single connection
- **0-RTT Handshake**: Reduced latency for subsequent connections

- **ASW-RLNC-X FEC (experimental)**: Adaptive systematic sliding-window scheme
- **Dynamic Redundancy**: Automatic adjustments to network conditions
- **Packet Recovery**: Robust reconstruction for lossy networks
- **Bandwidth-Efficient**: Minimal overhead thanks to RLNC

> **Note:** The FEC and Stealth modules are experimental and not yet production ready.

## 🏗️ Project Status

The codebase is now entirely written in Rust. Development focuses on expanding features and improving stability.

## 🛠️ Technical Specifications

| Component           | Technology                          |
|---------------------|-------------------------------------|
| Transport Protocol  | QUIC v1 / HTTP/3                   |
| Encryption         | AEGIS-128L/X, MORUS-1280-128       |
| Key Exchange       | X25519, X448                       |
| Error Correction   | ASW-RLNC-X FEC (experimental)       |
| Obfuscation       | XOR-based, Traffic Shaping, Fake TLS (experimental) |
| Platforms          | Linux, macOS, Windows (planned)     |
| Architecture       | x86_64, ARM64                      |
| Performance        | Multi-Gigabit capable              |

## 🔧 Build Instructions

This repository uses a Git submodule to include a patched QUIC library.
The `libs/patched_quiche` directory is intentionally left empty to keep the
checkout small. Fetch the sources after cloning by running the workflow
script below.
After cloning simply run the workflow script which fetches the sources and
initializes the submodule automatically. The script exports `QUICHE_PATH`
to `libs/patched_quiche/quiche` so that Cargo can find the library:

```bash
./scripts/quiche_workflow.sh --step fetch
```

Quick start after cloning:

```bash
./scripts/quiche_workflow.sh --step fetch
cargo build --workspace --release
```

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
./scripts/quiche_workflow.sh --step fetch
```

The workflow script replaces the old `fetch_quiche.sh` helper and can be
re-run at any time. If a local copy of quiche already exists, set the
`QUICHE_PATH` environment variable to use that path instead.
When building manually make sure this variable points to
`libs/patched_quiche/quiche`:

```bash
export QUICHE_PATH=$(pwd)/libs/patched_quiche/quiche
```

### Building quiche

Compile the patched **quiche** library using Cargo:

```bash
cd libs/patched_quiche
cargo build --release
cd ..
```

### Building

Build the entire workspace using Cargo:

```bash
cd rust
cargo build --workspace --release
```

### Running the tests

Execute the test suite with Cargo:

```bash
cargo test --workspace
```

## 👷 Developer Notes

Ensure submodules are initialized:

```bash
git submodule update --init --recursive
```

Build and test using Cargo:

```bash
cd rust
cargo build --workspace --release
cargo test --workspace
```

### Rust Workspace

The Rust implementation lives in the `rust/` directory. It contains the
`core`, `crypto`, `fec`, `stealth` and `cli` crates along with integration
tests. The workspace root `rust/Cargo.toml` uses the edition 2021 resolver.
Build all crates locally with:

```bash
cd rust
cargo build --workspace
```


## 🖥️ Command-Line Usage

The project provides several binaries once built:

- **quicfuscate_demo** – feature-rich demo tool with many options.
- **quicfuscate_client** – minimal client accepting `<host> <port>` arguments.
- **quicfuscate_server** – placeholder server without arguments.

Run `quicfuscate_demo --help` to see all available options. Important flags include:

```
  -s, --server <host>        Server hostname (default: example.com)
  -p, --port <port>          Server port (default: 443)
  -f, --fingerprint <name>   Browser fingerprint (chrome, firefox, safari, ...)
      --no-utls              Disable uTLS and use regular TLS
      --verify-peer          Enable certificate validation
      --ca-file <path>       CA file for peer verification
  -v, --verbose              Verbose logging
      --debug-tls            Show TLS debug information
      --list-fingerprints    List available browser fingerprints
      --fec-mode <mode>      Initial FEC mode (zero|light|normal|medium|strong|extreme)
      --disable-doh          Disable DNS over HTTPS
      --disable-fronting     Disable domain fronting
      --disable-xor          Disable XOR obfuscation
      --disable-http3        Disable HTTP/3 masquerading
```

## 🔄 Continuous Integration

The repository includes a GitHub Actions workflow that builds and tests the
project on Linux, macOS and Windows. The workflow also performs static
analysis and uploads the release binaries as artifacts. You can find the
workflow in `.github/workflows/ci.yml`. It executes the following tasks:

1. Fetches and builds the patched `quiche` library via `scripts/fetch_quiche.sh`.
2. Runs `cargo clippy` and `cppcheck` for linting on all platforms.
3. Builds the Rust workspace and executes all integration tests.
4. Uploads the release binaries for each operating system.

To reproduce the CI steps locally run:

```bash
git submodule update --init --recursive
cd rust
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## 📦 Releases

Pre-built binaries are automatically generated for the `main` and `master`
branches. Visit the [GitHub Releases](https://github.com/yourname/QuicFuscate/releases)
page to download the latest `quicfuscate` executables for your platform.
Each release bundles the patched `quiche` library together with the
`quicfuscate_*` binaries.

## 📜 License

This software is provided under a custom license that allows:
- Private, non-commercial use
- Modification and personal use
- Educational purposes

Commercial use, distribution, or incorporation into commercial products is strictly prohibited without explicit permission.

See [LICENSE](./LICENSE) for details.

## ⚠️ Important Notice

This software is provided "as is" without any warranties. The developers assume no responsibility for any damage caused by the use of this software. Use at your own risk.

---

*QuicFuscate - The last line of defense for your digital privacy.*
