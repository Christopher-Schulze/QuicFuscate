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



The codebase has been simplified into a single crate rooted in the `src/`
directory. Historical references to a `rust/` workspace are obsolete because all
modules now live under `src/`.

## ✨ Core Features

### 🛡️ Advanced Stealth Technology
- **uTLS Fingerprinting Protection**: Mimics browser TLS fingerprints to evade deep packet inspection
- **TLS Handshake Spoofing**: Replays captured ClientHello messages for realistic fingerprints ([Issue #002](docs/issues/002-real-tls-fingerprints.md))
- **FakeTLS Handshake**: Sends a lightweight forged handshake without establishing real TLS
- **Domain Fronting**: Masks traffic by routing through trusted CDN providers
- **HTTP/3 Masquerading**: Disguises traffic as standard HTTP/3 web traffic
- **Traffic Obfuscation**: XOR-based packet transformation to defeat pattern recognition
- **Spin Bit Randomization**: Planned feature for masking QUIC traffic metadata

FakeTLS differs from the real uTLS-based fingerprinting by avoiding a complete TLS session.
Instead it emits a static ClientHello and immediately returns a fake ServerHello
with a placeholder certificate. This keeps the handshake lightweight while still
presenting TLS-like traffic to network monitors.

### 🔒 Military-Grade Encryption
- **AEGIS-128L/X**: Authenticated encryption with hardware acceleration
- **MORUS-1280-128**: Lightweight cipher for resource-constrained environments
- **Perfect Forward Secrecy**: Ephemeral key exchange for maximum security
- **Post-Quantum Ready**: PQ algorithms planned but not yet implemented

### ⚡ Performance Optimizations
- **SIMD Acceleration**: ARM NEON and x86 AVX2/AVX-512 optimizations
- **Bit-Sliced GF Multiplication**: Faster FEC arithmetic via dedicated AVX2/AVX512/NEON kernels
- **Zero-Copy Architecture**: Minimizes memory allocations for maximum throughput
- **Adaptive RLNC FEC**: Sliding-window RLNC encoder/decoder with SIMD acceleration
- **Connection Multiplexing**: Multiple streams over a single connection
- **0-RTT Handshake**: Reduced latency for subsequent connections

- **ASW-RLNC-X FEC**: Adaptive systematic sliding-window scheme
- **Dynamic Redundancy**: Automatic adjustments to network conditions
- **Packet Recovery**: Robust reconstruction for lossy networks
- **Bandwidth-Efficient**: Minimal overhead thanks to RLNC



## 🏗️ Project Status

The codebase is now entirely written in Rust. Development focuses on expanding features and improving stability.

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

Simply invoke the workflow script once after cloning. It fetches the sources,
applies all patches and builds the library automatically while exporting
`QUICHE_PATH` so that Cargo can locate the compiled quiche:

```bash
./scripts/quiche_workflow.sh --non-interactive
```

After the workflow finishes you can build the rest of the project with Cargo as
usual:

```bash
cargo build --release
```

Browser fingerprints are stored as base64 encoded `.chlo` files under
`browser_profiles/`. When the patched quiche is built, these files are
fed into the new `ChloBuilder` API to recreate the exact ClientHello
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
./scripts/quiche_workflow.sh --non-interactive
```

The workflow script replaces the old `fetch_quiche.sh` helper and can be
re-run at any time. If a local copy of quiche already exists, set the
`QUICHE_PATH` environment variable to use that path instead.
When building manually make sure this variable points to
`libs/patched_quiche/quiche`:

```bash
export QUICHE_PATH=$(pwd)/libs/patched_quiche/quiche
```

### ⚠️ Ohne Fetch kein Build

`cargo build` schlägt fehl, wenn das Verzeichnis `libs/patched_quiche/quiche`
noch nicht existiert. Führe deshalb vor dem Bauen immer zuerst den Workflow aus:

```bash
./scripts/quiche_workflow.sh --non-interactive
```

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

### Build-Probleme beheben

Schlägt der Workflow trotz erfüllter Abhängigkeiten fehl, finden sich detailierte
Logs unter `libs/logs/`. Ein häufiger Grund ist ein nicht initialisiertes
Submodul. In diesem Fall hilft folgender Befehl:

```bash
git submodule update --init libs/patched_quiche
```

Anschließend den Workflow erneut starten:

```bash
./scripts/quiche_workflow.sh --non-interactive
```

### Project Layout

All Rust sources reside in the `src/` directory. Modules such as `core`, `crypto`, `fec`, `stealth` and others are compiled as part of the single crate. The crate exposes both a library and the main CLI binary.

Build the crate locally:

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release


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
      --verify-peer          Validate the server certificate (disabled by default)
      --ca-file <path>       CA file for peer verification
  -v, --verbose              Verbose logging
      --debug-tls            Show TLS debug information
      --list-fingerprints    List available browser fingerprints
      --fec-mode <mode>      Initial FEC mode (zero|light|normal|medium|strong|extreme)
      --fec-config <path>    Load Adaptive FEC settings from TOML file
      --doh-provider <url>   Custom DNS-over-HTTPS resolver
      --front-domain <d>     Domain used for fronting (repeat or comma separated)
      --disable-doh          Disable DNS over HTTPS
      --disable-fronting     Disable domain fronting
      --disable-xor          Disable XOR obfuscation
      --disable-http3        Disable HTTP/3 masquerading
```

Example FEC configuration:

```toml
[adaptive_fec]
lambda = 0.05
burst_window = 30
```

## 🔄 Continuous Integration

The repository includes a GitHub Actions workflow that builds and tests the
project on Linux, macOS and Windows. The workflow also performs static
analysis and uploads the release binaries as artifacts. You can find the
workflow in `.github/workflows/ci.yml`. It executes the following tasks:

1. Fetches and builds the patched `quiche` library via `scripts/fetch_quiche.sh`.
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
