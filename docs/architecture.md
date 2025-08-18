# QuicFuscate Architecture

## Overview

QuicFuscate aims to deliver a state-of-the-art VPN protocol that maximizes efficiency and performance while remaining exceptionally resilient against network censorship. By fusing modern transport, cryptography, forward error correction (FEC), and coherent stealth techniques, the system enables reliable, high-throughput connectivity under adversarial conditions. The project supports democratic values by facilitating open access to information and freedom of speech.

Key capabilities:
- **Cohesive stealth**: Browser‑grade TLS fingerprints via uTLS or replayed ClientHello profiles (patched‑quiche FFI); HTTP/3 masquerading with realistic ALPN/QPACK; domain fronting; DNS‑over‑HTTPS; optional XOR post‑encryption shaping.
- **Performance**: Runtime hardware dispatch (AVX2/AVX‑512/NEON); zero‑copy memory pool; batched I/O; optional AF_XDP fast path on Linux.
- **Cryptography**: AEAD runtime selection between AEGIS‑128L/X and MORUS‑1280‑128; constant‑time glue; Perfect Forward Secrecy.
- **Reliability**: Adaptive sliding‑window RLNC FEC; 0‑RTT; stream multiplexing; optional connection migration.
- **Maintainability**: Consolidated Rust crate under `src/`; curated ClientHello profiles in `src/browser_profiles/`; deterministic workflows and CI.

## Core Components

### 1. Rust Core (`src/`)

#### Main Binary (`src/main.rs`)
- Entry point for the QuicFuscate application
- Command-line interface with subcommands
- Configuration management and validation

#### Core Modules
- **`src/lib.rs`**: Library interface and public API
- **`src/config.rs`**: Configuration parsing and validation
- **`src/crypto/`**: Cryptographic operations and stealth algorithms
- **`src/net/`**: Network handling and QUIC integration
- **`src/profile/`**: Traffic profile management
- **`src/utils/`**: Utility functions and helpers

#### Hidden Subcommands (Internal Tools)
- `CrossFadeSim`: Cross-fade simulation for traffic patterns
- `HighLossSim`: High packet loss simulation
- `OptimizeProbe`: Probe optimization algorithms
- `XdpSmoke`: XDP smoke testing
- `FecBench`: Forward Error Correction benchmarks
- `PoolBench`: Memory pool benchmarks
- `CryptoBench`: Cryptographic operation benchmarks
- `NetBench`: Network performance benchmarks
- `Capabilities`: System capability detection

### 2. Patched Quiche Integration (`libs/patched_quiche/`)

- Custom Quiche library with QuicFuscate-specific patches
- Stealth modifications for traffic obfuscation
- Integration with Rust core via FFI

### 3. Script Architecture

The project uses a modular script architecture organized into dedicated directories:

#### Build Scripts (`scripts/Build/`)
- **`build-quiche-and-check.sh`**: Build patched Quiche and run checks
- **`build-quiche-rebuild-and-test.sh`**: Rebuild and test patched Quiche
- **`build-fmt-check.sh`**: Formatting and basic cargo checks
- **`env-doctor.sh`**: Development environment diagnostics

#### Test Scripts (`scripts/Tests/`)
- **`tests-comprehensive-runner.sh`**: Execute full Rust test suite
- **`tests-all-release.sh`**: Run tests in release mode
- **`tests-advanced-with-optional-fuzz.sh`**: Advanced tests (optional fuzz hooks)

#### Benchmark Scripts (`scripts/Benchmarks/`)
- **`bench-crypto-quick.sh`**: Cryptographic microbenchmarks (quick)
- **`bench-fec-quick-smoke.sh`**: FEC-specific microbenchmarks (quick smoke)
- **`bench-net-quick.sh`**: Network throughput measurements (quick)
- **`bench-performance-comprehensive.sh`**: Execute comprehensive benchmark suite

#### Audit Scripts (`scripts/Audits/`)
- **`audit-static-hardening.sh`**: Static code analysis for security hardening
- **`audit-dependency-cargo-audit.sh`**: Dependency vulnerability scanning
- **`audit-policy-cargo-deny.sh`**: Policy and license audit
- **`audit-code-quality-comprehensive.sh`**: Comprehensive code quality checks
- **`audit-unsafe-usage.sh`**: Unsafe code usage scanning

#### Utility Scripts (`scripts/Utils/`)
- **`e2e-decode-all-profiles.sh`**: Decode all TLS ClientHello profiles
- **`e2e-verify-current.sh`**: Verify current profile integrity
- **`e2e-verify-all.sh`**: Verify all profiles
- **`tls-generate-sha256-sidecars.sh`**: Generate SHA256 sidecars for profiles
- **`utils-project-cleanup.sh`**: Clean build outputs and temporary files

## Configuration System

### Configuration Files
- **`docs/example_config.toml`**: Example configuration template
- **Environment Variables**: `QUICFUSCATE_*` prefix for runtime configuration
- **CLI Flags**: Command-line overrides for configuration options

### Configuration Hierarchy
1. CLI flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## Data Flow

### Traffic Processing Pipeline
1. **Input**: Raw QUIC traffic
2. **Profile Selection**: Choose stealth profile based on configuration
3. **Obfuscation**: Apply cryptographic transformations
4. **Output**: Obfuscated QUIC traffic

### Build Pipeline
1. **Environment Setup**: Initialize development environment
2. **Dependency Build**: Build patched Quiche library
3. **Rust Compilation**: Compile QuicFuscate core
4. **Testing**: Execute test suites
5. **Benchmarking**: Performance validation
6. **Auditing**: Security and quality checks

## Security Architecture

### Stealth Features
- **Traffic Pattern Obfuscation**: Modify packet timing and sizes
- **Cryptographic Stealth**: Advanced encryption with custom algorithms
- **Profile-based Adaptation**: Dynamic behavior based on traffic profiles

### Security Hardening
- **Static Analysis**: Automated code security scanning
- **Dependency Auditing**: Regular vulnerability assessments
- **Memory Safety**: Rust's memory safety guarantees
- **No Unsafe Operations**: Elimination of `unwrap`, `expect`, `panic!`, etc.

## Development Workflow

### Initial Setup
```bash
./scripts/Build/env-doctor.sh
./scripts/Build/build-quiche-and-check.sh
```

### Development Cycle
```bash
# Build and test
./scripts/Build/build-fmt-check.sh
./scripts/Tests/tests-comprehensive-runner.sh

# Performance validation
./scripts/Benchmarks/bench-performance-comprehensive.sh

# Security audit
./scripts/Audits/audit-static-hardening.sh
```

### Release Preparation
```bash
# Full test suite
./scripts/Tests/tests-all-release.sh

# Complete audit
./scripts/Audits/audit-code-quality-comprehensive.sh

# Profile verification
./scripts/Utils/e2e-verify-all.sh
```

## Complete File Structure and Wiremap

This section provides a comprehensive overview of every file and directory in the QuicFuscate project, serving as both a file map and wiring diagram.

### Root Level Files
```
QuicFuscate/
├── .gitattributes               # Git line ending and file handling rules
├── .gitignore                   # Git ignore patterns for build artifacts and temp files
├── .gitmodules                  # Git submodule configuration for patched_quiche
├── Cargo.toml                   # Rust workspace configuration and dependencies
├── README.md                    # Project overview and quick start guide
└── build.rs                     # Rust build script for compilation customization
```

### GitHub Workflows (`.github/workflows/`)
```
.github/workflows/
├── build-quiche.yml             # CI workflow for building patched Quiche library
└── ci.yml                       # Main CI/CD pipeline for testing and validation
```

### Documentation (`docs/`)
```
docs/
├── CONTRIBUTING.md              # Development guidelines and contribution process
├── Changelog.md                 # Chronological record of all project changes
├── DOCUMENTATION.md             # Comprehensive user and developer documentation
├── LICENSE                      # Project license (legal terms and conditions)
├── architecture.md              # This file - complete architectural overview
└── example_config.toml          # Template configuration file with all options
```

### Source Code (`src/`)
```
src/
├── main.rs                      # Application entry point with CLI and subcommands
├── lib.rs                       # Public library interface and module exports
├── config.rs                    # Configuration parsing, validation, and management
├── core.rs                      # Core QuicFuscate logic and orchestration
├── crypto.rs                    # Cryptographic operations and stealth algorithms
├── fec.rs                       # Forward Error Correction implementation
├── optimize.rs                  # Performance optimization algorithms
├── stealth.rs                   # Traffic obfuscation and stealth mechanisms
└── bin/                         # Binary executables (deprecated e2e_tls.rs removed)
```

### Libraries and Dependencies (`libs/`)
```
libs/
├── logs/                        # Runtime log files and debugging output
├── patches/                     # Patch files for external dependencies
├── vanilla_quiche/              # Original unmodified Quiche library (reference)
└── patched_quiche/              # Custom Quiche with QuicFuscate modifications
    ├── CODEOWNERS               # GitHub code ownership definitions
    ├── COPYING                  # Quiche library license
    ├── Cargo.toml               # Quiche workspace configuration
    ├── Dockerfile               # Container build configuration
    ├── Makefile                 # Build automation for C components
    ├── README.md                # Quiche library documentation
    ├── catalog-info.yaml        # Service catalog metadata
    ├── clippy.toml              # Rust linting configuration
    ├── quiche.svg               # Project logo/icon
    ├── rustfmt.toml             # Code formatting rules
    ├── apps/                    # Quiche example applications
    │   ├── Cargo.toml           # Application dependencies
    │   ├── run_endpoint.sh      # Endpoint testing script
    │   └── src/                 # Application source code
    │       ├── args.rs          # Command-line argument parsing
    │       ├── bin/             # Binary executables
    │       ├── client.rs        # QUIC client implementation
    │       ├── common.rs        # Shared utilities
    │       ├── lib.rs           # Application library
    │       └── sendto.rs        # UDP sending utilities
    ├── buffer-pool/             # Memory buffer management
    ├── datagram-socket/         # UDP socket abstraction
    ├── fuzz/                    # Fuzzing tests and corpus
    ├── h3i/                     # HTTP/3 interactive tool
    ├── octets/                  # Byte buffer utilities
    ├── qlog/                    # QUIC logging framework
    ├── quiche/                  # Core QUIC implementation
    │   ├── Cargo.toml           # Core library dependencies
    │   ├── deps/boringssl/      # BoringSSL cryptographic library
    │   ├── examples/            # Usage examples and test programs
    │   ├── include/quiche.h     # C header for FFI
    │   └── src/                 # Core QUIC protocol implementation
    ├── task-killswitch/         # Async task management
    ├── tokio-quiche/            # Tokio async integration
    ├── target/                  # Compiled artifacts and build cache
    └── tools/                   # Development and debugging tools
```

### Automation Scripts (`scripts/`)

This architecture document shows only the structure and examples of the script layout. For the authoritative, complete and up‑to‑date list of scripts with descriptions, see `docs/DOCUMENTATION.md#scripts-reference-authoritative`. Common workflows are illustrated in the "Development Workflow" section above.

## Component Wiring and Dependencies

This section documents the interconnections and dependencies between different components of the QuicFuscate system.

### Core Application Wiring
```
main.rs
├── Imports lib.rs (public API)
├── Uses config.rs (configuration management)
├── Calls core.rs (main application logic)
└── Provides CLI subcommands:
    ├── CrossFadeSim → core.rs + crypto.rs
    ├── HighLossSim → core.rs + fec.rs
    ├── OptimizeProbe → optimize.rs
    ├── XdpSmoke → core.rs (XDP testing)
    ├── FecBench → fec.rs (benchmarking)
    ├── PoolBench → optimize.rs (memory pools)
    ├── CryptoBench → crypto.rs (crypto benchmarks)
    ├── NetBench → core.rs (network benchmarks)
    └── Capabilities → core.rs (system detection)
```

### Library Module Dependencies
```
lib.rs
├── Exports public API from:
│   ├── config.rs (configuration types)
│   ├── core.rs (main functionality)
│   ├── crypto.rs (cryptographic operations)
│   ├── fec.rs (Forward Error Correction)
│   ├── optimize.rs (performance optimizations)
│   └── stealth.rs (traffic obfuscation)
└── Provides unified interface for external consumers
```

### Patched Quiche Integration
```
src/core.rs
├── Links to libs/patched_quiche/target/release/libquiche.a
├── Uses FFI bindings from libs/patched_quiche/include/quiche.h
├── Integrates with:
│   ├── quiche/src/lib.rs (core QUIC protocol)
│   ├── quiche/src/crypto/ (TLS integration)
│   ├── quiche/src/h3/ (HTTP/3 support)
│   └── apps/src/common.rs (shared utilities)
└── Receives stealth modifications from patches/
```

### Script Execution Flow
```
Development Workflow:
1. scripts/Build/env-doctor.sh
   └── Initializes development environment
2. scripts/Build/build-quiche-and-check.sh
   ├── Builds libs/patched_quiche/
   └── Runs cargo check on src/
3. scripts/Tests/tests-comprehensive-runner.sh
   └── Executes tests in src/
4. scripts/Benchmarks/bench-crypto-quick.sh
   └── Runs crypto benchmarks via src/main.rs CryptoBench
5. scripts/Audits/audit-static-hardening.sh
   └── Scans src/ for security issues

Profile Management:
1. scripts/Utils/e2e-decode-all-profiles.sh
   └── Processes profile data
2. scripts/Utils/e2e-verify-current.sh
   └── Validates profile integrity
3. scripts/Utils/tls-generate-sha256-sidecars.sh
   └── Creates checksums for profiles
```

### Configuration Flow
```
Configuration Priority (highest to lowest):
1. CLI Arguments (main.rs command-line parsing)
2. Environment Variables (QUICFUSCATE_* prefix)
3. Configuration File (docs/example_config.toml)
4. Default Values (config.rs defaults)

Configuration Usage:
main.rs → config.rs → core.rs → {crypto.rs, fec.rs, stealth.rs, optimize.rs}
```

### Build System Wiring
```
Cargo.toml (workspace root)
├── Defines workspace members
├── Specifies dependencies
└── Links to:
    ├── build.rs (custom build logic)
    ├── src/ (main application)
    └── libs/patched_quiche/Cargo.toml (submodule)

libs/patched_quiche/Makefile
├── Builds BoringSSL (deps/boringssl/)
├── Compiles C components
└── Generates libquiche.a for Rust FFI
```

### Data Flow Architecture
```
Traffic Processing Pipeline:
Input → main.rs → core.rs → stealth.rs → crypto.rs → fec.rs → Output
                     ↓
                 config.rs (configuration)
                     ↓
                 optimize.rs (performance tuning)

Profile Processing:
Profile Files → scripts/Utils/e2e-decode-all-profiles.sh → src/main.rs → core.rs
                                                      ↓
                                              stealth.rs (profile application)
```

### Testing and Validation Wiring
```
Testing Hierarchy:
1. Unit Tests (scripts/Tests/tests-comprehensive-runner.sh)
   └── Tests individual modules in src/
2. Integration Tests (scripts/Tests/tests-all-release.sh)
   └── Tests component interactions
3. Profile Tests (scripts/Utils/e2e-verify-all.sh)
   └── Validates stealth functionality
4. Configuration Tests (scripts/Tests/tests-comprehensive-runner.sh)
   └── Ensures config parsing works (covered by comprehensive runner)

Validation Chain:
scripts/Audits/audit-static-hardening.sh → src/ analysis
scripts/Audits/audit-dependency-cargo-audit.sh → Cargo.toml analysis
scripts/Audits/audit-code-quality-comprehensive.sh → Complete system review
```

### External Dependencies
```
Runtime Dependencies:
├── BoringSSL (cryptographic operations)
├── Tokio (async runtime)
├── Clap (CLI parsing)
└── Serde (serialization)

Build Dependencies:
├── cc (C compiler integration)
├── bindgen (FFI binding generation)
└── pkg-config (library detection)

Development Dependencies:
├── Criterion (benchmarking)
├── Proptest (property testing)
└── Tempfile (test utilities)
```

## Integration Points

### Quiche Integration
- **FFI Bindings**: Rust-to-C interface for Quiche library
- **Custom Patches**: Stealth modifications in patched Quiche
- **Build Integration**: Automated building and linking

### System Integration
- **XDP Support**: Kernel-level packet processing (optional)
- **Network Interfaces**: Raw socket and standard socket support
- **Platform Compatibility**: Linux, macOS, and Windows support

## Performance Considerations

### Optimization Strategies
- **Zero-copy Operations**: Minimize memory allocations
- **Async Processing**: Non-blocking I/O operations
- **SIMD Instructions**: Vectorized cryptographic operations
- **Memory Pools**: Efficient memory management

### Benchmarking
- **Throughput Measurements**: Packets per second and bandwidth
- **Latency Analysis**: End-to-end processing delays
- **Resource Usage**: CPU and memory consumption
- **Scalability Testing**: Multi-connection performance

## Future Architecture Considerations

### Planned Enhancements
- **Plugin Architecture**: Modular stealth algorithm plugins
- **Distributed Processing**: Multi-node traffic processing
- **Machine Learning**: AI-driven traffic pattern adaptation
- **Hardware Acceleration**: GPU-based cryptographic processing

### Maintenance Strategy
- **Automated Testing**: Continuous integration and testing
- **Security Updates**: Regular dependency and vulnerability updates
- **Performance Monitoring**: Ongoing performance regression detection
- **Documentation Maintenance**: Keep documentation synchronized with code